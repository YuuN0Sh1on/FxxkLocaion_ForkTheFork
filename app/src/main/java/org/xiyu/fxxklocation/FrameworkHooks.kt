package org.xiyu.fxxklocation

import android.location.Location
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.lang.reflect.Modifier

// ============================================================
//  BACKUP: Hook UsageStatsManager.queryUsageStats
//  Returns EMPTY list to blind foreground detection.
// ============================================================
internal fun ModuleMain.installUsageStatsHook() {
    try {
        val usmClass = android.app.usage.UsageStatsManager::class.java
        XposedHelpers.findAndHookMethod(
            usmClass,
            "queryUsageStats",
            Int::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    try {
                        val trace = android.util.Log.getStackTraceString(Throwable())
                        if (trace.contains("androidx.appcompat.view.widget")) {
                            param.result = ArrayList<android.app.usage.UsageStats>()
                        }
                    } catch (_: Throwable) {}
                }
            })
        log("[SYS] UsageStatsManager.queryUsageStats hooked (conditional empty list)")
    } catch (e: Throwable) {
        log("[SYS] UsageStats hook FAILED: ${e.message}")
    }

    // Clear stale cachedResult in ForegroundDetect (if accessible)
    try {
        val fdClass = Class.forName("androidx.appcompat.view.widget.\u0EAB")
        // Find static List<String> field (cachedResult is the only one)
        val cachedField = fdClass.declaredFields.firstOrNull {
            Modifier.isStatic(it.modifiers) && it.type == List::class.java
        }
        if (cachedField != null) {
            cachedField.isAccessible = true
            cachedField.set(null, null)
            log("[SYS] ForegroundDetect.cachedResult cleared (${cachedField.name})")
        }
    } catch (e: Throwable) {
        log("[SYS] ForegroundDetect cache clear: ${e.javaClass.simpleName}")
    }
}

// Framework-level fallback: prevent test provider removal
internal fun ModuleMain.installFrameworkFallbackHooks() {
    try {
        XposedHelpers.findAndHookMethod(
            android.location.LocationManager::class.java,
            "removeTestProvider",
            String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        if (bypassRemoveProvider.get() == true) return
                        val provider = param.args[0] as? String
                        if (provider == "gps" || provider == "network") {
                            param.result = null
                        }
                    } catch (_: Throwable) {}
                }
            })
        log("[SYS-FB] removeTestProvider hooked")
    } catch (e: Throwable) {
        log("[SYS-FB] removeTestProvider FAILED: ${e.message}")
    }
    try {
        XposedHelpers.findAndHookMethod(
            android.location.LocationManager::class.java,
            "clearTestProviderLocation",
            String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val provider = param.args[0] as? String
                        if (provider == "gps" || provider == "network") {
                            param.result = null
                        }
                    } catch (_: Throwable) {}
                }
            })
        log("[SYS-FB] clearTestProviderLocation hooked")
    } catch (e: Throwable) {
        log("[SYS-FB] clearTestProviderLocation FAILED: ${e.message}")
    }
}

// ============================================================
//  Strip mock flag at framework level (system_server).
// ============================================================
internal fun ModuleMain.installMockFlagStrip() {
    // Strategy 1: Hook Location.writeToParcel to clear mock flag before sending to apps
    try {
        XposedHelpers.findAndHookMethod(
            Location::class.java, "writeToParcel",
            android.os.Parcel::class.java, Int::class.javaPrimitiveType,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val loc = param.thisObject as Location
                        stripMockFlag(loc)
                    } catch (_: Throwable) {}
                }
            })
        log("[SYS-MOCK] writeToParcel hook installed")
    } catch (e: Throwable) {
        log("[SYS-MOCK] writeToParcel hook FAILED: $e")
    }

    // Strategy 2: Prevent mock flag from being set at all
    for (methodName in arrayOf("setMock", "setIsFromMockProvider")) {
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, methodName,
                Boolean::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = false
                    }
                })
            log("[SYS-MOCK] $methodName hook installed")
        } catch (_: Throwable) {}
    }
}

internal fun stripMockFlag(loc: Location) {
    for (fieldName in arrayOf("mIsMock", "mIsFromMockProvider")) {
        try {
            val f = Location::class.java.getDeclaredField(fieldName)
            f.isAccessible = true
            f.setBoolean(loc, false)
        } catch (_: Throwable) {}
    }
    try { loc.extras?.remove("mockProvider") } catch (_: Throwable) {}
}

/**
 * Disable mock_location developer setting from system_server.
 * Some paranoid apps check Settings.Secure.getString("mock_location").
 * Setting it to "0" from system UID makes all apps see mock locations disabled,
 * while our system-level test provider injection still works (system UID bypasses the check).
 */
internal fun ModuleMain.disableMockLocationSetting() {
    Thread {
        try {
            // Wait for system to be ready
            Thread.sleep(5000)
            val ctx = getSystemServerContext() ?: return@Thread
            val resolver = ctx.contentResolver
            android.provider.Settings.Secure.putInt(resolver, "mock_location", 0)
            log("[SYS-MOCK] mock_location setting disabled (all apps see 0)")
        } catch (e: Throwable) {
            log("[SYS-MOCK] disableMockLocationSetting failed: $e")
        }
    }.apply { name = "FL-MockSetting"; isDaemon = true }.start()
}

// ============================================================
//  System-level step sensor injection — v48
//
//  ===== 架构说明 =====
//
//  主方法: 传感器劫持 (Sensor Listener Proxy)
//    在 registerListener beforeHook 中用 Proxy 包裹 listener，
//    拦截 onSensorChanged 并就地替换步频值。
//    最通用、跨系统兼容性最好。
//    限制: 只在当前进程（system_server）内生效。
//    → 对其他 APP: 需要在 Layer 3 (AntiMockDetection.kt) per-app 实现
//
//  HAL 注入 (SensorManager.injectSensorData)
//    通过 sensorservice Binder 启用 DATA_INJECTION 模式，
//    调用 injectSensorData 推送步频数据。
//    理论上全局生效（所有 APP 都能收到），无需 per-app 钩子。
//    实际: 部分 ROM/设备静默丢弃数据，不一定可靠。
//
//  副方法: Feeder 线程 (补充)
//    向 system_server 内捕获的 listener 定时推送假事件。
//    当真实传感器空闲时（proxy 没有事件可改），补充假事件。
// ============================================================
@Volatile
private var stepInjectionActive = false
// Proxy map: original listener → proxy wrapper (for unregister cleanup)
private val stepProxyMap = java.util.concurrent.ConcurrentHashMap<Any, Any>()

internal fun ModuleMain.installStepSensorFromServer() {
    val sensorClass = android.hardware.Sensor::class.java
    val listenerClass = try {
        Class.forName("android.hardware.SensorEventListener")
    } catch (_: Throwable) {
        log("[STEP-SYS] SensorEventListener class not found"); return
    }

    // === MAIN: Listener Proxy Wrapping ===
    // Wraps step sensor listeners to intercept real events and replace step data
    val proxyHook = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            try {
                val listener = param.args[0] ?: return
                val sensor = param.args[1] ?: return
                if (!listenerClass.isInstance(listener)) return
                if (!sensorClass.isInstance(sensor)) return
                val sensorType = sensorClass.getMethod("getType").invoke(sensor) as Int
                if (sensorType != 19 && sensorType != 18) return

                // Skip if already proxied by Zygote hook
                if (ZygoteStepHook.isOurProxy(listener)) return

                // Already wrapped by SYS?
                if (stepProxyMap.containsKey(listener)) {
                    param.args[0] = stepProxyMap[listener]
                    return
                }

                // Create a proxy that wraps the original listener
                val proxy = java.lang.reflect.Proxy.newProxyInstance(
                    listener.javaClass.classLoader ?: ClassLoader.getSystemClassLoader(),
                    arrayOf(listenerClass),
                    StepListenerProxy(listener, sensorType, this@installStepSensorFromServer)
                )
                stepProxyMap[listener] = proxy
                param.args[0] = proxy
                log("[STEP-SYS] proxied step listener type=$sensorType")
            } catch (_: Throwable) {}
        }
    }

    // Hook unregister — replace original listener with proxy so system can find/remove it
    val unregisterHook = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            try {
                val listener = param.args?.firstOrNull() ?: return
                val proxy = stepProxyMap.remove(listener)
                if (proxy != null) {
                    param.args[0] = proxy // system knows the proxy, not the original
                }
                capturedStepListeners.remove(proxy ?: listener)
                stepListenerTypes.remove(proxy ?: listener)
            } catch (_: Throwable) {}
        }
    }

    try {
        val smClass = Class.forName("android.hardware.SensorManager")
        for (m in smClass.declaredMethods) {
            if (m.name == "registerListener") {
                val params = m.parameterTypes
                if (params.size >= 2 && listenerClass.isAssignableFrom(params[0]) && sensorClass.isAssignableFrom(params[1])) {
                    XposedBridge.hookMethod(m, proxyHook)
                }
            }
            if (m.name == "unregisterListener") {
                XposedBridge.hookMethod(m, unregisterHook)
            }
        }
        try {
            val ssmClass = Class.forName("android.hardware.SystemSensorManager")
            for (m in ssmClass.declaredMethods) {
                if (m.name == "registerListenerImpl") {
                    val params = m.parameterTypes
                    if (params.size >= 2 && listenerClass.isAssignableFrom(params[0]) && sensorClass.isAssignableFrom(params[1])) {
                        XposedBridge.hookMethod(m, proxyHook)
                        log("[STEP-SYS] also hooked SystemSensorManager.registerListenerImpl")
                    }
                }
            }
        } catch (_: Throwable) {}
        log("[STEP-SYS] proxy + capture hooks installed")
    } catch (e: Throwable) {
        log("[STEP-SYS] hook install failed: $e")
    }

    // Hook Sensor.isDataInjectionSupported → return true for step sensors (for Tier 2)
    try {
        for (m in sensorClass.declaredMethods) {
            if (m.name == "isDataInjectionSupported") {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            val type = (param.thisObject as android.hardware.Sensor).type
                            if (type == 19 || type == 18) param.result = true
                        } catch (_: Throwable) {}
                    }
                })
                log("[STEP-SYS] hooked Sensor.isDataInjectionSupported")
                break
            }
        }
    } catch (_: Throwable) {}

    // === TIER 2 + 3: Feeder thread (HAL injection + listener dispatch) ===
    Thread {
        try {
            Thread.sleep(15000) // Wait for system ready

            val ctx = try { getSystemServerContext() } catch (_: Throwable) { null }
            val sm = try {
                ctx?.getSystemService(android.content.Context.SENSOR_SERVICE) as? android.hardware.SensorManager
            } catch (_: Throwable) { null }
            val stepCounter = try { sm?.getDefaultSensor(19) } catch (_: Throwable) { null }
            val stepDetector = try { sm?.getDefaultSensor(18) } catch (_: Throwable) { null }
            log("[STEP-SYS] sensors: counter=${stepCounter != null} detector=${stepDetector != null}")

            // Tier 2: Try HAL injection
            var halInjectionOk = false
            if (sm != null) {
                halInjectionOk = tryEnableHalInjection(sm, stepCounter, stepDetector)
            }
            val injectMethod = if (halInjectionOk && sm != null) findInjectMethod(sm) else null
            var halInjectFails = 0

            // Tier 3: Prepare listener feeder
            val sensorEventCls = Class.forName("android.hardware.SensorEvent")
            val onChangedMethod = listenerClass.getMethod("onSensorChanged", sensorEventCls)
            val seCtor = sensorEventCls.getDeclaredConstructor(Int::class.javaPrimitiveType)
            seCtor.isAccessible = true
            val valuesField = sensorEventCls.getField("values")
            val timestampField = sensorEventCls.getField("timestamp")
            val sensorField = sensorEventCls.getField("sensor")
            val accuracyField = sensorEventCls.getField("accuracy")
            val handler = android.os.Handler(android.os.Looper.getMainLooper())

            stepInjectionActive = true
            log("[STEP-SYS] feeder started (hal=$halInjectionOk, proxies=${stepProxyMap.size})")

            while (!Thread.interrupted()) {
                val mlb = ourMlBinder
                if (mlb?.mocking != true) {
                    Thread.sleep(500); continue
                }

                val rawSpeed = mlb.stepSpeed
                val effectiveSpeed = if (rawSpeed > 0.1f) rawSpeed
                    else mlb.currentLocation?.speed?.let { if (it > 0.1f) it else null } ?: 1.5f
                val speed = effectiveSpeed.coerceIn(0.5f, 30.0f)
                val stepsPerSecond = speed / 0.7
                val intervalMs = (1000.0 / stepsPerSecond).toLong().coerceIn(200, 2000)

                advanceStepCount(stepsPerSecond)
                val currentSteps = getCurrentStepCount()
                val ts = android.os.SystemClock.elapsedRealtimeNanos()

                // Tier 2: HAL injection (reaches ALL apps)
                if (halInjectionOk && injectMethod != null) {
                    try {
                        if (stepCounter != null)
                            injectMethod.invoke(sm, stepCounter, floatArrayOf(currentSteps.toFloat()), 3, ts)
                        if (stepDetector != null)
                            injectMethod.invoke(sm, stepDetector, floatArrayOf(1.0f), 3, ts)
                    } catch (e: Throwable) {
                        halInjectFails++
                        if (halInjectFails <= 3)
                            log("[STEP-SYS] HAL inject failed ($halInjectFails/3): ${e.message}")
                        if (halInjectFails >= 3) {
                            log("[STEP-SYS] HAL inject permanently failed — proxy + feeder only")
                            halInjectionOk = false
                        }
                    }
                }

                // Tier 3: Direct listener feeder (system_server listeners)
                if (capturedStepListeners.isNotEmpty()) {
                    for (listener in ArrayList(capturedStepListeners)) {
                        val type = stepListenerTypes[listener] ?: 19
                        handler.post {
                            try {
                                val event = seCtor.newInstance(1)
                                val vals = valuesField.get(event) as FloatArray
                                vals[0] = if (type == 19) currentSteps.toFloat() else 1.0f
                                timestampField.setLong(event, ts)
                                accuracyField.setInt(event, 3)
                                val sRef = if (type == 19) stepCounter else stepDetector
                                if (sRef != null) sensorField.set(event, sRef)
                                onChangedMethod.invoke(listener, event)
                            } catch (e: Throwable) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.targetException else e
                                if (cause is android.os.DeadObjectException) {
                                    capturedStepListeners.remove(listener)
                                    stepListenerTypes.remove(listener)
                                }
                            }
                        }
                    }
                }

                Thread.sleep(intervalMs)
            }
        } catch (_: InterruptedException) {
        } catch (e: Throwable) {
            log("[STEP-SYS] feeder error: $e")
            stepInjectionActive = false
        }
    }.apply { name = "FL-SysStepFeed"; isDaemon = true; start() }
}

// Captured listeners for Tier 3 feeder (includes proxied listeners)
private val capturedStepListeners = java.util.concurrent.CopyOnWriteArrayList<Any>()
private val stepListenerTypes = java.util.concurrent.ConcurrentHashMap<Any, Int>()

/**
 * InvocationHandler for step sensor listener proxies.
 * Intercepts onSensorChanged — when mocking is active, replaces step values.
 * All other method calls (onAccuracyChanged, hashCode, equals, toString) delegate to original.
 */
private class StepListenerProxy(
    private val original: Any,
    private val sensorType: Int,
    private val module: ModuleMain
) : java.lang.reflect.InvocationHandler {

    override fun invoke(proxy: Any?, method: java.lang.reflect.Method, args: Array<out Any>?): Any? {
        // Handle Object methods on the proxy itself
        if (method.declaringClass == Any::class.java) {
            return when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                "toString" -> "StepProxy($sensorType)@${Integer.toHexString(System.identityHashCode(proxy))}"
                else -> method.invoke(original, *(args ?: emptyArray()))
            }
        }

        if (method.name == "onSensorChanged" && args != null && args.isNotEmpty()) {
            try {
                if (module.ourMlBinder?.mocking == true) {
                    val event = args[0]
                    val valuesField = event.javaClass.getField("values")
                    val vals = valuesField.get(event) as FloatArray
                    if (sensorType == 19) {
                        vals[0] = getCurrentStepCount().toFloat()
                    } else {
                        vals[0] = 1.0f
                    }
                }
            } catch (_: Throwable) {}
        }

        // Delegate to original listener
        return try {
            method.invoke(original, *(args ?: emptyArray()))
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.targetException
        }
    }
}

/**
 * Try to enable HAL-level data injection.
 * Android < 16: enableDataInjection + requestDataInjection (full path)
 * Android 16+: enableDataInjection only (requestDataInjection removed)
 */
private fun ModuleMain.tryEnableHalInjection(
    sm: android.hardware.SensorManager,
    stepCounter: android.hardware.Sensor?,
    stepDetector: android.hardware.Sensor?
): Boolean {
    var enableOk = false
    try {
        val smClass = Class.forName("android.os.ServiceManager")
        val getService = smClass.getMethod("getService", String::class.java)
        val sensorBinder = getService.invoke(null, "sensorservice") as? android.os.IBinder
        if (sensorBinder != null) {
            val data = android.os.Parcel.obtain()
            val reply = android.os.Parcel.obtain()
            try {
                data.writeInterfaceToken("android.gui.SensorServer")
                data.writeInt(1)
                sensorBinder.transact(3, data, reply, 0)
                val status = reply.readInt()
                log("[STEP-SYS] enableDataInjection: status=$status")
                enableOk = (status == 0)
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
    } catch (e: Throwable) {
        log("[STEP-SYS] enableDataInjection failed: $e")
    }

    if (!enableOk) return false

    // requestDataInjection (Android < 16 only, optional on 16+)
    var requestFound = false
    for (cls in arrayOf(sm.javaClass, android.hardware.SensorManager::class.java)) {
        for (m in cls.declaredMethods) {
            if (m.name != "requestDataInjection") continue
            requestFound = true
            m.isAccessible = true
            try {
                if (stepCounter != null) {
                    val r = m.invoke(sm, stepCounter, true)
                    log("[STEP-SYS] requestDataInjection(counter): $r")
                }
                if (stepDetector != null) {
                    val r = m.invoke(sm, stepDetector, true)
                    log("[STEP-SYS] requestDataInjection(detector): $r")
                }
            } catch (e: Throwable) {
                log("[STEP-SYS] requestDataInjection: ${e.message}")
            }
        }
    }
    if (!requestFound) log("[STEP-SYS] requestDataInjection not found (Android 16+)")
    log("[STEP-SYS] HAL injection ENABLED")
    return true
}

private fun findInjectMethod(sm: android.hardware.SensorManager): java.lang.reflect.Method? {
    for (cls in arrayOf(sm.javaClass, android.hardware.SensorManager::class.java)) {
        for (m in cls.declaredMethods) {
            if (m.name == "injectSensorData") {
                m.isAccessible = true
                log("[STEP-SYS] found ${cls.simpleName}.injectSensorData")
                return m
            }
        }
    }
    log("[STEP-SYS] injectSensorData not found")
    return null
}

// Step counter state
@Volatile private var stepAccumulator = 0L
@Volatile private var lastStepTime = 0L

private fun advanceStepCount(stepsPerSecond: Double) {
    val now = System.currentTimeMillis()
    if (lastStepTime == 0L) { lastStepTime = now; return }
    val elapsed = (now - lastStepTime) / 1000.0
    val stepsToAdd = (elapsed * stepsPerSecond).toLong()
    if (stepsToAdd > 0) {
        stepAccumulator += stepsToAdd
        lastStepTime = now
    }
}

private fun getCurrentStepCount(): Long = stepAccumulator
