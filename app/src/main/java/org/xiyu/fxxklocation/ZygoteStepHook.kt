package org.xiyu.fxxklocation

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge

/**
 * Zygote-level step sensor hook — 主方法: 传感器劫持
 *
 * 在 initZygote() 安装，Zygote fork 出的所有子进程继承此 hook。
 * 无需将目标 APP 加入 LSPosed 作用域。
 *
 * 原理:
 *   1. Hook SensorManager.registerListener 的 beforeHook
 *   2. 对步频传感器 (TYPE_STEP_COUNTER=19, TYPE_STEP_DETECTOR=18) 的 listener
 *      用 java.lang.reflect.Proxy 包裹
 *   3. Proxy 拦截 onSensorChanged，当 mocking 激活时替换步频数据
 *   4. 副方法 feeder 线程定期查询 service_fl_ml binder 获取状态，
 *      更新步数，并在真实传感器空闲时主动推送假事件
 *
 * 检测抗性:
 *   - 不触发 per-app Xposed 加载 (handleLoadPackage 不被调用)
 *   - Hook 在 framework 类上，非 APP 自身的类
 *   - Proxy 是标准 Java 动态代理，看起来正常
 *
 * 每个进程拥有独立的步数累加器和 binder 连接 (fork 后各自独立)。
 */
object ZygoteStepHook {

    // Per-process state (each process has independent copy after fork)
    @Volatile private var mockingActive = false
    @Volatile private var stepSpeed = 1.5f
    private val stepAccum = java.util.concurrent.atomic.AtomicLong(0)
    @Volatile private var lastStepTime = 0L
    @Volatile private var feederStarted = false

    private val proxyMap = java.util.concurrent.ConcurrentHashMap<Any, Any>()
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<Any>()
    private val listenerTypes = java.util.concurrent.ConcurrentHashMap<Any, Int>()

    fun install() {
        val sensorClass = android.hardware.Sensor::class.java
        val listenerClass = try {
            Class.forName("android.hardware.SensorEventListener")
        } catch (_: Throwable) {
            log("[STEP-ZYGOTE] SensorEventListener class not found"); return
        }

        val proxyHook = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val listener = param.args[0] ?: return
                    val sensor = param.args[1] ?: return
                    if (!listenerClass.isInstance(listener)) return
                    if (!sensorClass.isInstance(sensor)) return
                    val sensorType = sensorClass.getMethod("getType").invoke(sensor) as Int
                    if (sensorType != 19 && sensorType != 18) return

                    // Skip if already proxied (by us, Layer 3, or FrameworkHooks)
                    if (isOurProxy(listener)) return

                    // Reuse existing proxy for same listener
                    if (proxyMap.containsKey(listener)) {
                        val proxy = proxyMap[listener]!!
                        param.args[0] = proxy
                        if (!listeners.contains(proxy)) {
                            listeners.add(proxy)
                            listenerTypes[proxy] = sensorType
                        }
                        return
                    }

                    val proxy = java.lang.reflect.Proxy.newProxyInstance(
                        listener.javaClass.classLoader ?: ClassLoader.getSystemClassLoader(),
                        arrayOf(listenerClass),
                        ZygoteStepListenerProxy(listener, sensorType)
                    )
                    proxyMap[listener] = proxy
                    param.args[0] = proxy

                    listeners.add(proxy)
                    listenerTypes[proxy] = sensorType

                    log("[STEP-ZYGOTE] proxied step listener type=$sensorType (total=${proxyMap.size})")
                    ensureFeederRunning()
                } catch (_: Throwable) {}
            }
        }

        val unregisterHook = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val listener = param.args?.firstOrNull() ?: return
                    val proxy = proxyMap.remove(listener)
                    if (proxy != null) param.args[0] = proxy
                    listeners.remove(proxy ?: listener)
                    listenerTypes.remove(proxy ?: listener)
                } catch (_: Throwable) {}
            }
        }

        try {
            val smClass = Class.forName("android.hardware.SensorManager")
            for (m in smClass.declaredMethods) {
                if (m.name == "registerListener") {
                    val params = m.parameterTypes
                    if (params.size >= 2
                        && listenerClass.isAssignableFrom(params[0])
                        && sensorClass.isAssignableFrom(params[1])
                    ) {
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
                        if (params.size >= 2
                            && listenerClass.isAssignableFrom(params[0])
                            && sensorClass.isAssignableFrom(params[1])
                        ) {
                            XposedBridge.hookMethod(m, proxyHook)
                        }
                    }
                }
            } catch (_: Throwable) {}
            log("[STEP-ZYGOTE] hooks installed on SensorManager")
        } catch (e: Throwable) {
            log("[STEP-ZYGOTE] install failed: $e")
        }
    }

    /** Check if a listener is one of our step sensor proxies (Zygote / L3 / SYS) */
    internal fun isOurProxy(listener: Any): Boolean {
        if (listener !is java.lang.reflect.Proxy) return false
        return try {
            val handler = java.lang.reflect.Proxy.getInvocationHandler(listener)
            handler.javaClass.name.contains("StepListenerProxy")
        } catch (_: Throwable) { false }
    }

    fun getCurrentSteps(): Long = stepAccum.get()
    fun isMocking(): Boolean = mockingActive

    // ===== Feeder thread =====
    // Periodically queries service_fl_ml binder for mocking state + speed.
    // Updates shared atomics that the proxy reads.
    // Also pushes fake events to captured listeners (when real sensor is idle).
    private fun ensureFeederRunning() {
        if (feederStarted) return
        feederStarted = true

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
                    val app = Class.forName("android.app.ActivityThread")
                        .getMethod("currentApplication").invoke(null) as? android.content.Context
                    app?.getSystemService(android.content.Context.SENSOR_SERVICE)
                        as? android.hardware.SensorManager
                } catch (_: Throwable) { null }

                val stepCounterSensor = smService?.getDefaultSensor(19)
                val stepDetectorSensor = smService?.getDefaultSensor(18)

                val smClass = Class.forName("android.os.ServiceManager")
                val getService = smClass.getMethod("getService", String::class.java)

                val handler = android.os.Handler(android.os.Looper.getMainLooper())

                log("[STEP-ZYGOTE] feeder started (counter=${stepCounterSensor != null}, detector=${stepDetectorSensor != null})")
                Thread.sleep(2000)

                while (!Thread.interrupted()) {
                    if (listeners.isEmpty()) { Thread.sleep(500); continue }

                    // Query service_fl_ml binder
                    var isMocking = false
                    var speed = 1.5f
                    try {
                        val binder = getService.invoke(null, "service_fl_ml") as? android.os.IBinder
                        if (binder != null) {
                            val d = android.os.Parcel.obtain()
                            val r = android.os.Parcel.obtain()
                            try {
                                d.writeInterfaceToken(FL_AIDL_DESCRIPTOR)
                                binder.transact(22, d, r, 0)
                                r.readException()
                                isMocking = r.readInt() != 0
                            } finally { d.recycle(); r.recycle() }
                            if (isMocking) {
                                val d2 = android.os.Parcel.obtain()
                                val r2 = android.os.Parcel.obtain()
                                try {
                                    d2.writeInterfaceToken(FL_AIDL_DESCRIPTOR)
                                    binder.transact(15, d2, r2, 0)
                                    r2.readException()
                                    val s = r2.readFloat()
                                    if (s > 0.1f) speed = s
                                } finally { d2.recycle(); r2.recycle() }
                            }
                        }
                    } catch (_: Throwable) {}

                    // Update shared state for proxy
                    mockingActive = isMocking
                    stepSpeed = speed

                    if (!isMocking) { Thread.sleep(500); continue }

                    val spd = speed.coerceIn(0.5f, 30.0f)
                    val stepsPerSec = spd / 0.7
                    val intervalMs = (1000.0 / stepsPerSec).toLong().coerceIn(200, 2000)

                    // Advance step counter
                    val now = System.currentTimeMillis()
                    if (lastStepTime == 0L) lastStepTime = now
                    val elapsed = (now - lastStepTime) / 1000.0
                    val stepsToAdd = (elapsed * stepsPerSec).toLong()
                    if (stepsToAdd > 0) {
                        stepAccum.addAndGet(stepsToAdd)
                        lastStepTime = now
                    }

                    val currentSteps = stepAccum.get()
                    val ts = android.os.SystemClock.elapsedRealtimeNanos()

                    // Push fake events to captured listeners
                    for (listener in ArrayList(listeners)) {
                        val type = listenerTypes[listener] ?: 19
                        handler.post {
                            try {
                                val event = seCtor.newInstance(1)
                                (valuesField.get(event) as FloatArray)[0] =
                                    if (type == 19) currentSteps.toFloat() else 1.0f
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
                log("[STEP-ZYGOTE] feeder error: $e")
            }
        }.apply { name = "FL-ZygoteStep"; isDaemon = true; start() }
    }

    /**
     * Proxy InvocationHandler — intercepts step sensor events.
     * When mocking is active, replaces step values before delegating to original listener.
     */
    private class ZygoteStepListenerProxy(
        private val original: Any,
        private val sensorType: Int
    ) : java.lang.reflect.InvocationHandler {

        override fun invoke(proxy: Any?, method: java.lang.reflect.Method, args: Array<out Any>?): Any? {
            if (method.declaringClass == Any::class.java) {
                return when (method.name) {
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.firstOrNull()
                    "toString" -> "ZygoteStepListenerProxy($sensorType)@${
                        Integer.toHexString(System.identityHashCode(proxy))
                    }"
                    else -> method.invoke(original, *(args ?: emptyArray()))
                }
            }

            if (method.name == "onSensorChanged" && args != null && args.isNotEmpty()) {
                try {
                    if (mockingActive) {
                        val vals = args[0].javaClass.getField("values").get(args[0]) as FloatArray
                        vals[0] = if (sensorType == 19) stepAccum.get().toFloat() else 1.0f
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
}
