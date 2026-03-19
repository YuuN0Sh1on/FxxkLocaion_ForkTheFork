package org.xiyu.fxxklocation

import android.os.IBinder
import android.os.Parcel
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge

// ============================================================
//  LAYER 3: Optional per-app hooks (only for apps in LSPosed scope)
//
//  Mock flag stripping and GNSS injection are now handled entirely
//  in system_server — no per-app hook needed for those.
//  This file only contains step sensor spoofing, which requires
//  in-process hook because SensorEvents are dispatched locally.
//
//  Only apps explicitly added to LSPosed scope get step spoofing.
//  For basic GPS/GNSS spoofing, only "system" + FL is needed.
// ============================================================

/**
 * Install optional per-app hooks. Currently only step sensor spoofing.
 * Called for every app in LSPosed scope that isn't FL or system_server.
 */
internal fun ModuleMain.hookAntiMockDetection() {
    hookStepSensorInjection()
}

// ============================================================
//  Step sensor spoofing — Layer 3 (target apps)
//
//  主方法: 传感器劫持 (Sensor Listener Proxy)
//    Hook registerListener → 用 java.lang.reflect.Proxy 包裹
//    SensorEventListener → 拦截 onSensorChanged，就地替换步频值。
//    真实传感器事件流入时被劫持修改，最通用、跨系统兼容性最好。
//
//  副方法: Feeder 线程 (补充)
//    当真实传感器空闲（用户静坐模拟运动）时，主动推送假事件。
//    与主方法互补——主方法改真实事件，副方法补充虚假事件。
// ============================================================

// Shared state: feeder thread updates, proxy reads
@Volatile private var l3MockingActive = false
@Volatile private var l3StepSpeed = 1.5f
private val l3StepAccum = java.util.concurrent.atomic.AtomicLong(0)
@Volatile private var l3LastStepTime = 0L

@Volatile private var stepFeederStarted = false
private val stepListeners = java.util.concurrent.CopyOnWriteArrayList<Any>()
private val stepSensorTypes = java.util.concurrent.ConcurrentHashMap<Any, Int>()
private val stepProxyMapL3 = java.util.concurrent.ConcurrentHashMap<Any, Any>()

internal fun ModuleMain.hookStepSensorInjection() {
    val sensorClass = android.hardware.Sensor::class.java
    val listenerClass = try {
        Class.forName("android.hardware.SensorEventListener")
    } catch (_: Throwable) {
        log("[STEP-L3] SensorEventListener class not found"); return
    }

    // === 主方法: Proxy 包裹 ===
    val proxyHook = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            try {
                val listener = param.args[0] ?: return
                val sensor = param.args[1] ?: return
                if (!listenerClass.isInstance(listener)) return
                if (!sensorClass.isInstance(sensor)) return
                val sensorType = sensorClass.getMethod("getType").invoke(sensor) as Int
                if (sensorType != 19 && sensorType != 18) return

                // Skip if already proxied by Zygote hook or another layer
                if (ZygoteStepHook.isOurProxy(listener)) return

                // Already wrapped by L3?
                if (stepProxyMapL3.containsKey(listener)) {
                    val proxy = stepProxyMapL3[listener]!!
                    param.args[0] = proxy
                    if (!stepListeners.contains(proxy)) {
                        stepListeners.add(proxy)
                        stepSensorTypes[proxy] = sensorType
                    }
                    return
                }

                val proxy = java.lang.reflect.Proxy.newProxyInstance(
                    listener.javaClass.classLoader ?: ClassLoader.getSystemClassLoader(),
                    arrayOf(listenerClass),
                    L3StepListenerProxy(listener, sensorType)
                )
                stepProxyMapL3[listener] = proxy
                param.args[0] = proxy

                // Also track for feeder
                stepListeners.add(proxy)
                stepSensorTypes[proxy] = sensorType

                log("[STEP-L3] proxied step listener type=$sensorType (total=${stepProxyMapL3.size})")
                ensureStepFeederRunning()
            } catch (_: Throwable) {}
        }
    }

    val unregisterHook = object : XC_MethodHook() {
        override fun beforeHookedMethod(param: MethodHookParam) {
            try {
                val listener = param.args?.firstOrNull() ?: return
                val proxy = stepProxyMapL3.remove(listener)
                if (proxy != null) {
                    param.args[0] = proxy
                }
                stepListeners.remove(proxy ?: listener)
                stepSensorTypes.remove(proxy ?: listener)
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
                        log("[STEP-L3] also hooked SystemSensorManager.registerListenerImpl")
                    }
                }
            }
        } catch (_: Throwable) {}
        log("[STEP-L3] proxy + capture hooks installed")
    } catch (e: Throwable) {
        log("[STEP-L3] hookStepSensorInjection failed: $e")
    }
}

/**
 * 主方法: Proxy InvocationHandler — 劫持步频传感器事件
 * 当 mocking 激活时，替换 onSensorChanged 中的步频数据；
 * 其余方法（onAccuracyChanged、Object 方法等）直接委托给原始 listener。
 */
private class L3StepListenerProxy(
    private val original: Any,
    private val sensorType: Int
) : java.lang.reflect.InvocationHandler {

    override fun invoke(proxy: Any?, method: java.lang.reflect.Method, args: Array<out Any>?): Any? {
        if (method.declaringClass == Any::class.java) {
            return when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                "toString" -> "L3StepProxy($sensorType)@${Integer.toHexString(System.identityHashCode(proxy))}"
                else -> method.invoke(original, *(args ?: emptyArray()))
            }
        }

        if (method.name == "onSensorChanged" && args != null && args.isNotEmpty()) {
            try {
                if (l3MockingActive) {
                    val event = args[0]
                    val vals = event.javaClass.getField("values").get(event) as FloatArray
                    vals[0] = if (sensorType == 19) l3StepAccum.get().toFloat() else 1.0f
                }
            } catch (_: Throwable) {}
        }

        return try {
            method.invoke(original, *(args ?: emptyArray()))
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.targetException
        }
    }
}

// === 副方法: Feeder 线程 ===
// 定期查询 mocking 状态、更新步数，并向捕获的 listener 推送假事件
private fun ModuleMain.ensureStepFeederRunning() {
    if (stepFeederStarted) return
    stepFeederStarted = true

    Thread {
        try {
            val sensorEventCls = Class.forName("android.hardware.SensorEvent")
            val listenerCls = Class.forName("android.hardware.SensorEventListener")
            val onChangedMethod = listenerCls.getMethod("onSensorChanged", sensorEventCls)

            val seCtor = sensorEventCls.getDeclaredConstructor(Int::class.javaPrimitiveType)
            seCtor.isAccessible = true
            val valuesField = sensorEventCls.getField("values")
            val timestampField = sensorEventCls.getField("timestamp")
            val sensorField = sensorEventCls.getField("sensor")
            val accuracyField = sensorEventCls.getField("accuracy")

            val smService = try {
                val atMethod = Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication")
                val app = atMethod.invoke(null) as? android.content.Context
                app?.getSystemService(android.content.Context.SENSOR_SERVICE) as? android.hardware.SensorManager
            } catch (_: Throwable) { null }

            val stepCounterSensor = smService?.getDefaultSensor(19)
            val stepDetectorSensor = smService?.getDefaultSensor(18)

            val smClass = Class.forName("android.os.ServiceManager")
            val getService = smClass.getMethod("getService", String::class.java)

            val handler = android.os.Handler(android.os.Looper.getMainLooper())

            log("[STEP-L3] feeder started (counter=${stepCounterSensor != null}, detector=${stepDetectorSensor != null})")
            Thread.sleep(1000)

            while (!Thread.interrupted()) {
                if (stepListeners.isEmpty()) {
                    Thread.sleep(500); continue
                }

                // Query service_fl_ml for mocking status + step speed
                var isMocking = false
                var stepSpeed = 1.5f
                try {
                    val binder = getService.invoke(null, "service_fl_ml") as? IBinder
                    if (binder != null) {
                        val mockData = Parcel.obtain()
                        val mockReply = Parcel.obtain()
                        try {
                            mockData.writeInterfaceToken(FL_AIDL_DESCRIPTOR)
                            binder.transact(22, mockData, mockReply, 0)
                            mockReply.readException()
                            isMocking = mockReply.readInt() != 0
                        } finally { mockData.recycle(); mockReply.recycle() }
                        if (isMocking) {
                            val speedData = Parcel.obtain()
                            val speedReply = Parcel.obtain()
                            try {
                                speedData.writeInterfaceToken(FL_AIDL_DESCRIPTOR)
                                binder.transact(15, speedData, speedReply, 0)
                                speedReply.readException()
                                val s = speedReply.readFloat()
                                if (s > 0.1f) stepSpeed = s
                            } finally { speedData.recycle(); speedReply.recycle() }
                        }
                    }
                } catch (_: Throwable) {}

                // Update shared state for proxy
                l3MockingActive = isMocking
                l3StepSpeed = stepSpeed

                if (!isMocking) {
                    Thread.sleep(500); continue
                }

                val speed = stepSpeed.coerceIn(0.5f, 30.0f)
                val stepsPerSecond = speed / 0.7
                val intervalMs = (1000.0 / stepsPerSecond).toLong().coerceIn(100, 2000)

                // Advance shared step counter
                val now = System.currentTimeMillis()
                if (l3LastStepTime == 0L) l3LastStepTime = now
                val elapsed = (now - l3LastStepTime) / 1000.0
                val stepsToAdd = (elapsed * stepsPerSecond).toLong()
                if (stepsToAdd > 0) {
                    l3StepAccum.addAndGet(stepsToAdd)
                    l3LastStepTime = now
                }

                val currentSteps = l3StepAccum.get()
                val ts = android.os.SystemClock.elapsedRealtimeNanos()

                // 向所有捕获的 listener 推送假事件
                for (listener in ArrayList(stepListeners)) {
                    val type = stepSensorTypes[listener] ?: 19
                    handler.post {
                        try {
                            val event = seCtor.newInstance(1)
                            val vals = valuesField.get(event) as FloatArray
                            vals[0] = if (type == 19) currentSteps.toFloat() else 1.0f
                            timestampField.setLong(event, ts)
                            accuracyField.setInt(event, 3)
                            val sRef = if (type == 19) stepCounterSensor else stepDetectorSensor
                            if (sRef != null) sensorField.set(event, sRef)
                            onChangedMethod.invoke(listener, event)
                        } catch (_: Throwable) {}
                    }
                }

                Thread.sleep(intervalMs)
            }
        } catch (_: InterruptedException) {
        } catch (e: Throwable) {
            log("[STEP-L3] feeder error: $e")
        }
    }.apply {
        name = "FL-StepFeed"
        isDaemon = true
        start()
    }
}
