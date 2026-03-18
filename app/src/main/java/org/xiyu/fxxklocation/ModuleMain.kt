package org.xiyu.fxxklocation

import android.app.Application
import android.content.Context
import android.location.Location
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.util.Log
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.lang.reflect.Modifier
import java.lang.reflect.ParameterizedType

private const val TAG = "FxxkLocation"
private const val TARGET_PKG = "com.lerist.fakelocation"

// ---- Obfuscated class names (verified via runtime logs) ----
private const val CLS_BLACKLIST    = "androidx.appcompat.view.widget.\u03AC"
private const val CLS_CONFIG       = "androidx.appcompat.view.widget.\u0E1E"
private const val CLS_USER_SESSION = "androidx.appcompat.view.widget.\u015E\u085B\u015E$\u0DBD"
private const val CLS_USER_MODEL   = "androidx.appcompat.view.widget.qc2"
private const val CLS_ENFORCER     = "androidx.appcompat.view.widget.\u01C5\u036C\u01C5"
private const val CLS_SERVICE      = "androidx.appcompat.view.widget.\u0DC4\u036B\u0DC4"
private const val CLS_ROUTE_CTRL   = "androidx.appcompat.view.widget.\u02A9\u0368\u02A9"
private const val CLS_AIDL_PROXY   = "androidx.appcompat.view.widget.\u0268\u01DC\u0268$\u0D88$\u0D88"
private const val CLS_MOCK_CTRL    = "androidx.appcompat.view.widget.\u0E0F\u036D\u0E0F"
private const val CLS_DEFAULTS     = "androidx.appcompat.view.widget.\u0283\u05E5"
private const val CLS_JED_BL       = "androidx.appcompat.view.widget.gt0"
private const val CLS_ENF_LOADER   = "androidx.appcompat.view.widget.ft0"
private const val CLS_TOKEN_CHECKER = "androidx.appcompat.view.widget.tc2"
private const val CLS_PRO_VALIDATOR  = "androidx.appcompat.view.widget.pc2"
private const val CLS_DEBUG_DETECT   = "androidx.appcompat.view.widget.cp2"
private const val CLS_ANTI_DEBUG     = "androidx.appcompat.view.widget.\u06BD"

// Mode0Binder (C8160) — routes MODE_0 mock to service_fl_ml
private const val CLS_MODE0_BINDER   = "androidx.appcompat.view.widget.\u0C08\u0369\u0C08"  // C8160 ఈͩఈ

// FL-Xposed XP mode classes
private const val CLS_XP_AP2         = "androidx.appcompat.view.widget.ap2"
private const val CLS_XP_READY       = "androidx.appcompat.view.widget.\u0582\u0430\u0582"  // C5039

private const val FL_AIDL_DESCRIPTOR = "com.lerist.aidl.fakelocation.IMockLocationManager"
private const val FL_XP_DESCRIPTOR   = "com.lerist.aidl.fakelocation.IXPServer"

private val DUMMY_BLACKLIST: List<String> = List(15) { "x${it}.nonexistent.fake.app" }

@Volatile private var selinuxPolicyPatched = false

private fun log(msg: String) {
    Log.d(TAG, msg)
    XposedBridge.log("$TAG: $msg")
}

/**
 * Apply targeted SELinux policy rules so ServiceManager add/find works
 * for our custom service names. SELinux stays Enforcing — only adds
 * specific allow rules.
 *
 * Auto-detects root manager:
 *   KernelSU  → ksud sepolicy patch
 *   Magisk    → magiskpolicy --live
 *   APatch    → apd sepolicy patch  (same syntax as ksud)
 *   Fallback  → setenforce 0 as last resort
 */
private fun applySELinuxPolicy(): Boolean {
    if (selinuxPolicyPatched) return true
    synchronized(ModuleMain::class.java) {
        if (selinuxPolicyPatched) return true
        try {
            // Rules needed:
            // 1. system_server can add services of type default_android_service
            // 2. any app domain can find services of type default_android_service
            val rules = listOf(
                "allow system_server default_android_service service_manager { add find }",
                "allow * default_android_service service_manager { find }"
            )

            // Detect root manager and build commands
            val policyTool = detectPolicyTool()
            if (policyTool != null) {
                for (rule in rules) {
                    val cmd = policyTool.buildCommand(rule)
                    val p = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                    val exit = p.waitFor()
                    if (exit != 0) {
                        val err = p.errorStream.bufferedReader().readText()
                        log("[SEPOL] rule failed (exit=$exit): $cmd -> $err")
                    }
                }
                selinuxPolicyPatched = true
                log("[SEPOL] policy patched via ${policyTool.name} (SELinux stays Enforcing)")
                return true
            }

            // No policy tool found — try magiskpolicy in PATH as last attempt
            var anySuccess = false
            for (rule in rules) {
                try {
                    val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "magiskpolicy --live \"$rule\""))
                    val exit = p.waitFor()
                    if (exit == 0) anySuccess = true
                } catch (_: Throwable) {}
            }
            if (anySuccess) {
                selinuxPolicyPatched = true
                log("[SEPOL] policy patched via generic magiskpolicy fallback")
                return true
            }
            log("[SEPOL] no policy tool found and fallback failed — SELinux may block service registration")
            return false
        } catch (e: Throwable) {
            log("[SEPOL] policy patch failed: $e")
            return false
        }
    }
}

private data class PolicyTool(val name: String, val buildCommand: (String) -> String)

private fun detectPolicyTool(): PolicyTool? {
    // KernelSU: ksud sepolicy patch "<rule>"
    for (path in arrayOf("/data/adb/ksu/bin/ksud", "/data/adb/ksud")) {
        try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "test -x $path && echo ok"))
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            if (out == "ok") {
                return PolicyTool("ksud") { rule -> "$path sepolicy patch \"$rule\"" }
            }
        } catch (_: Throwable) {}
    }
    // APatch: apd sepolicy patch "<rule>"
    for (path in arrayOf("/data/adb/ap/bin/apd", "/data/adb/apd")) {
        try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "test -x $path && echo ok"))
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            if (out == "ok") {
                return PolicyTool("apd") { rule -> "$path sepolicy patch \"$rule\"" }
            }
        } catch (_: Throwable) {}
    }
    // Magisk: magiskpolicy --live "<rule>"
    try {
        val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "which magiskpolicy"))
        val out = p.inputStream.bufferedReader().readText().trim()
        p.waitFor()
        if (out.isNotEmpty()) {
            return PolicyTool("magiskpolicy") { rule -> "magiskpolicy --live \"$rule\"" }
        }
    } catch (_: Throwable) {}
    return null
}

class ModuleMain : IXposedHookLoadPackage {

    @Volatile private var hooked = false
    @Volatile private var sysHooked = false

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        log("[INIT] pkg=${lpparam.packageName} proc=${lpparam.processName}")
        when {
            // ===== Layer 1: FL app hooks =====
            lpparam.packageName == TARGET_PKG -> {
                log("[FL] handleLoadPackage pid=${android.os.Process.myPid()}")
                XposedHelpers.findAndHookMethod(
                    Application::class.java, "attach", Context::class.java,
                    object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            if (hooked) return
                            hooked = true
                            val ctx = param.args[0] as Context
                            log("[FL] Application.attach: got real ClassLoader")
                            performFlHooks(ctx.classLoader)
                        }
                    }
                )
            }

            // ===== Layer 2: system_server enforcement bypass =====
            lpparam.packageName == "android" || lpparam.processName == "system_server" -> {
                log("[SYS] handleLoadPackage: pkg=${lpparam.packageName} proc=${lpparam.processName}")
                hookSystemServer()
            }

            // ===== Layer 3: target app anti-mock-detection =====
            else -> {
                hookAntiMockDetection()
            }
        }
    }

    // ============================================================
    //  LAYER 2: system_server enforcement bypass (v25)
    //  
    //  ROOT CAUSE: Enforcer.enforceLocation() guard:
    //    if (isNullOrEmpty(MockController.getCloudBlacklist()))
    //  getCloudBlacklist() → aidl_getCloudBlacklist() → HARDCODED null
    //  So isNullOrEmpty(null) = true → enforcement ALWAYS runs
    //
    //  SOLUTION: Hook aidl_getCloudBlacklist() on the binder class
    //  (we have binder.javaClass!) to return non-empty list
    //  → isNullOrEmpty returns false → checkForegroundAllowed SKIPPED
    //  → stopMocking NEVER called → mock persists for ALL apps
    //
    //  Defense layers:
    //  A) PRIMARY: Hook binder AIDL methods (getCloudBlacklist → DUMMY)
    //  B) BACKUP:  Hook UsageStatsManager (fake FL stats → safe cachedResult)
    //  C) EXTRA:   CL discovery → hook Enforcer directly if possible
    //  D) SAFETY:  Block removeTestProvider/clearTestProviderLocation
    // ============================================================
    private fun hookSystemServer() {
        if (sysHooked) return
        sysHooked = true

        log("[SYS] v41 Installing immediate system_server hooks...")

        // SELinux policy is patched from FL app process where su is reliable.
        // system_server (uid 1000) doesn't need su anymore.

        hookServiceManagerAddService()
        installUsageStatsHook()
        installFrameworkFallbackHooks()
        installMockFlagStrip()
        installGnssHooks()
        installActiveGnssFromServer()

        Thread {
            try {
                val smClass = Class.forName("android.os.ServiceManager")
                val getService = smClass.getMethod("getService", String::class.java)

                // Phase 1: Proactively register service_fl_ml — don't depend on FL's service_fl_xp.
                // FL may never register service_fl_xp on some devices/ROMs (Android 16 / ColorOS / Samsung).
                var mlReady = false
                var secs = 0
                while (!mlReady && secs < 120) {
                    // Check if service_fl_ml already exists (from FL or hookServiceManagerAddService callback)
                    val existing = getService.invoke(null, "service_fl_ml") as? IBinder
                    if (existing != null) {
                        mlReady = true
                        log("[SYS] service_fl_ml already registered (${secs}s), class=${existing.javaClass.name}")
                        processServiceFlMlFinder(existing)
                        break
                    }
                    // No service yet — try to register our own
                    if (ourMlBinder == null) {
                        try {
                            registerMockLocationService()
                            if (ourMlBinder != null) {
                                mlReady = true
                                log("[SYS] service_fl_ml self-registered at ${secs}s")
                                break
                            }
                        } catch (e: Throwable) {
                            if (secs % 10 == 0) log("[SYS] service_fl_ml register attempt (${secs}s): ${e.message}")
                        }
                    } else {
                        mlReady = true
                        break
                    }
                    Thread.sleep(1000); secs += 1
                    if (secs % 30 == 0) log("[SYS] Waiting to register service_fl_ml... (${secs}s)")
                }
                if (!mlReady) {
                    log("[SYS] WARN: service_fl_ml not registered after 120s — SELinux policy may not be patched yet")
                }

                // Phase 2: Watch for service_fl_xp (optional — FL may or may not register it)
                Thread {
                    try {
                        var xpSecs = 0
                        while (xpSecs < 120) {
                            val b = getService.invoke(null, "service_fl_xp") as? IBinder
                            if (b != null) {
                                log("[SYS] service_fl_xp found (${xpSecs}s), class=${b.javaClass.name}")
                                processServiceFlMlFinder(b)
                                break
                            }
                            Thread.sleep(2000); xpSecs += 2
                        }
                        if (xpSecs >= 120) log("[SYS] service_fl_xp not found after 120s (OK — not required)")
                    } catch (e: Throwable) {
                        log("[SYS] service_fl_xp poll error: $e")
                    }
                }.apply { name = "FL-XpPoll"; isDaemon = true }.start()

                // ---- Periodic heartbeat so we can verify hook status ----
                while (true) {
                    Thread.sleep(60000) // Every 60s
                    val mlb = ourMlBinder
                    val mocking = mlb?.mocking == true
                    val hasLoc = mlb?.currentLocation != null
                    val gnssCount = sysGnssListeners.size
                    log("[SYS] heartbeat: alive | mocking=$mocking hasLoc=$hasLoc gnssListeners=$gnssCount")
                }

            } catch (e: Throwable) {
                log("[SYS] SYS_CRITICAL: $e")
            }
        }.apply {
            name = "FxxkLocation-SysPoll"
            isDaemon = true
        }.start()
    }

    @Volatile private var mlBinderHooked = false
    @Volatile private var ourMlBinder: MockLocationBinder? = null
    private val bypassRemoveProvider = ThreadLocal<Boolean>()

    private fun processServiceFlMlFinder(binder: IBinder) {
        // Determine binder type by checking AIDL interface descriptor
        val binderCls = binder.javaClass
        val aidlIface = binderCls.interfaces.firstOrNull { iface ->
            android.os.IInterface::class.java.isAssignableFrom(iface)
        }
        val descriptor = try {
            binder.interfaceDescriptor
        } catch (_: Throwable) { null }
        log("[SYS] Processing binder: class=${binderCls.name} descriptor=$descriptor aidl=${aidlIface?.name}")

        if (descriptor == FL_XP_DESCRIPTOR || aidlIface?.name?.contains("IXPServer") == true) {
            // This is FL-Xposed's IXPServer binder (service_fl_xp)
            // Do NOT apply IMockLocationManager hooks — they have different AIDL methods.
            // Let it pass through unmolested so FL app can use it for XP init.
            log("[SYS] service_fl_xp (IXPServer) detected — skipping IMockLocationManager hooks")
            return
        }

        // Skip if this is our own service_fl_ml binder
        if (binder === ourMlBinder) {
            mlBinderHooked = true
            log("[SYS] service_fl_ml is our own binder — no additional hooks needed")
            return
        }

        // This is FL's service_fl_ml binder (IMockLocationManager)
        synchronized(this) {
            if (mlBinderHooked) return
            mlBinderHooked = true
        }
        log("[SYS] service_fl_ml (IMockLocationManager) detected — installing hooks")
        val binderCl = binderCls.classLoader
        hookBinderAidlMethods(binderCls)

        val flCl = tryFindFlClassLoader(binder)
        if (flCl != null) {
            installSystemServerHooks(flCl)
        } else if (binderCl != null) {
            val enfCls = findEnforcerByStructure(binderCl)
            if (enfCls != null) {
                hookEnforcerClass(enfCls)
            } else {
                log("[SYS] CL strategies all failed (binder hooks are primary)")
            }
        }
    }

    private fun hookServiceManagerAddService() {
        try {
            val smClass = Class.forName("android.os.ServiceManager")
            val hook = object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val name = param.args[0] as? String ?: return
                    if (name == "service_fl_ml" || name == "service_fl_xp") {
                        log("[SYS] addService('$name') BEFORE — about to register")
                    }
                }
                override fun afterHookedMethod(param: MethodHookParam) {
                    val name = param.args[0] as? String ?: return
                    if (name == "service_fl_ml" || name == "service_fl_xp") {
                        if (param.throwable != null) {
                            log("[SYS] addService('$name') FAILED: ${param.throwable}")
                        } else {
                            log("[SYS] addService('$name') SUCCESS")
                        }
                        val binder = param.args[1] as? IBinder ?: return
                        processServiceFlMlFinder(binder)
                        // When service_fl_xp is registered, also register our service_fl_ml
                        if (name == "service_fl_xp" && param.throwable == null && ourMlBinder == null) {
                            registerMockLocationService()
                        }
                    }
                }
            }
            for (m in smClass.declaredMethods) {
                if (m.name == "addService") {
                    XposedBridge.hookMethod(m, hook)
                }
            }
        } catch (e: Throwable) {
            log("[SYS] ServiceManager hook failed: $e")
        }
    }

    // ============================================================
    //  Mock Location Service (service_fl_ml) — IMockLocationManager
    //
    //  FL app MODE_0 needs service_fl_ml to inject mock locations.
    //  We register our own Binder in system_server that handles all
    //  36 AIDL transaction codes using addTestProvider/setTestProviderLocation.
    //  SELinux policy is patched by FL app at startup to allow add/find.
    // ============================================================
    private fun registerMockLocationService() {
        try {
            val ctx = getSystemServerContext()
            if (ctx == null) {
                log("[SYS-ML] Cannot get system context for service_fl_ml")
                return
            }
            val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
            val binder = MockLocationBinder(lm)
            ourMlBinder = binder
            val smClass = Class.forName("android.os.ServiceManager")
            smClass.getMethod("addService", String::class.java, IBinder::class.java)
                .invoke(null, "service_fl_ml", binder)
            log("[SYS-ML] service_fl_ml registered!")
        } catch (e: Throwable) {
            log("[SYS-ML] service_fl_ml registration FAILED: $e")
        }
    }

    private fun getSystemServerContext(): Context? {
        return try {
            val at = Class.forName("android.app.ActivityThread")
                .getMethod("currentActivityThread").invoke(null)
            at?.javaClass?.getMethod("getSystemContext")?.invoke(at) as? Context
        } catch (e: Throwable) {
            log("[SYS-ML] getSystemServerContext: $e")
            null
        }
    }

    /**
     * Binder stub implementing IMockLocationManager AIDL (36 transaction codes).
     * Runs in system_server. Uses LocationManager to inject mock locations
     * via addTestProvider + setTestProviderLocation with system UID privileges.
     */
    private inner class MockLocationBinder(
        private val lm: android.location.LocationManager
    ) : android.os.Binder() {
        @Volatile var mocking = false
        @Volatile var currentLocation: Location? = null
        @Volatile var loopInterval: Long = 1000L
        @Volatile var autoMode = false
        @Volatile var enforcementFlag = false
        @Volatile var enforcementThread: Thread? = null

        // Step simulation state
        @Volatile var stepSimActive = false
        @Volatile var stepSpeed: Float = 1.5f    // meters/second
        @Volatile var stepBaseline: Long = 0L     // hardware step counter baseline
        @Volatile var stepStartTime: Long = 0L    // when step sim started

        private val PROVIDERS = arrayOf("gps", "network")

        init {
            attachInterface(null, FL_AIDL_DESCRIPTOR)
        }

        override fun getInterfaceDescriptor(): String = FL_AIDL_DESCRIPTOR

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            try {
                if (code in 1..36) data.enforceInterface(FL_AIDL_DESCRIPTOR)
                if (code == INTERFACE_TRANSACTION) {
                    reply?.writeString(FL_AIDL_DESCRIPTOR)
                    return true
                }
                val r = reply ?: return false
                when (code) {
                    1 -> { data.readString(); data.readString(); r.writeNoException() }                // setConfigKV
                    2 -> { doStartMock(); startEnforcementLoop(); r.writeNoException() }               // startMock
                    3 -> { doStopMock(); r.writeNoException() }                                        // stopMock
                    4 -> { r.writeNoException(); r.writeInt(if (mocking) 1 else 0) }                   // isMocking2
                    5 -> {                                                                              // setLocation
                        val loc = if (data.readInt() != 0) Location.CREATOR.createFromParcel(data) else null
                        if (loc != null) {
                            if (!mocking) { doStartMock(); startEnforcementLoop() }
                            doSetLocation(loc)
                        }
                        r.writeNoException()
                    }
                    6 -> {                                                                              // getLastLocation
                        r.writeNoException()
                        val loc = currentLocation
                        if (loc != null) { r.writeInt(1); loc.writeToParcel(r, 0) } else r.writeInt(0)
                    }
                    7 -> { loopInterval = data.readLong(); r.writeNoException() }                      // setDelay
                    8 -> { r.writeNoException(); r.writeLong(loopInterval) }                            // getInterval
                    9 -> { data.createStringArrayList(); r.writeNoException() }                         // setLocalBlacklist
                    10 -> { r.writeNoException(); r.writeStringList(ArrayList(DUMMY_BLACKLIST)) }       // getLocalBlacklist
                    11 -> {                                                                             // startStepSim
                        stepSimActive = true
                        stepStartTime = System.currentTimeMillis()
                        log("[SYS-ML] step sim started (speed=${stepSpeed}, baseline=${stepBaseline})")
                        r.writeNoException()
                    }
                    12 -> {                                                                             // stopStepSim
                        stepSimActive = false
                        log("[SYS-ML] step sim stopped")
                        r.writeNoException()
                    }
                    13 -> { r.writeNoException(); r.writeInt(0) }                                       // isFeatureEnabled
                    14 -> {                                                                             // setSpeed (step cadence)
                        stepSpeed = data.readFloat()
                        log("[SYS-ML] step speed set: $stepSpeed")
                        r.writeNoException()
                    }
                    15 -> { r.writeNoException(); r.writeFloat(stepSpeed) }                             // getSpeed
                    16 -> { data.readLong(); r.writeNoException() }                                     // setTiming2
                    17 -> { r.writeNoException(); r.writeLong(0L) }                                     // getTimestamp
                    18 -> { data.readStrongBinder(); r.writeNoException() }                             // addListener
                    19 -> { data.readStrongBinder(); r.writeNoException() }                             // removeListener
                    20 -> { r.writeNoException() }                                                      // setCellInfos
                    21 -> { r.writeNoException(); r.writeInt(-1) }                                      // getCellInfos → null
                    22 -> { r.writeNoException(); r.writeInt(if (mocking) 1 else 0) }                   // isMocking
                    23 -> { autoMode = data.readInt() != 0; r.writeNoException() }                      // setAutoMode
                    24 -> { enforcementFlag = data.readInt() != 0; r.writeNoException() }               // setFlag
                    25 -> { r.writeNoException(); r.writeInt(if (enforcementFlag) 1 else 0) }           // getEnforcementFlag
                    26 -> { r.writeNoException(); r.writeInt(0) }                                       // isFeature2
                    27 -> { data.readInt(); r.writeNoException() }                                      // setEnabled2
                    28 -> { r.writeNoException() }                                                      // setSubInfos
                    29 -> { r.writeNoException(); r.writeInt(-1) }                                      // getSubInfos → null
                    30 -> { data.readInt(); r.writeNoException() }                                      // setEnabled4
                    31 -> { r.writeNoException(); r.writeInt(0) }                                       // isFeature1
                    32 -> { data.createStringArrayList(); r.writeNoException() }                        // setCloudBlacklist
                    33 -> { r.writeNoException(); r.writeStringList(ArrayList(DUMMY_BLACKLIST)) }       // getCloudBlacklist
                    34 -> {                                                                             // setTiming (step baseline)
                        stepBaseline = data.readLong()
                        log("[SYS-ML] step baseline set: $stepBaseline")
                        r.writeNoException()
                    }
                    35 -> { r.writeNoException(); r.writeInt(if (autoMode) 1 else 0) }                  // isAutoMode
                    36 -> { autoMode = data.readInt() != 0; r.writeNoException() }                      // setEnabled3
                    else -> return super.onTransact(code, data, r, flags)
                }
                return true
            } catch (e: Throwable) {
                log("[SYS-ML] onTransact($code) SAFE-CATCH: $e")
                try { reply?.writeException(Exception(e)) } catch (_: Throwable) {}
                return true
            }
        }

        private fun doStartMock() {
            mocking = true  // Set BEFORE thread starts so enforcement loop doesn't exit immediately
            Thread {
                val token = android.os.Binder.clearCallingIdentity()
                try {
                    for (p in PROVIDERS) {
                        try {
                            bypassRemoveProvider.set(true)
                            lm.removeTestProvider(p)
                        } catch (_: Throwable) {
                        } finally {
                            bypassRemoveProvider.set(false)
                        }
                        try {
                            lm.addTestProvider(p, false, false, false, false, true, true, true, 1, 1)
                            lm.setTestProviderEnabled(p, true)
                        } catch (e: Throwable) {
                            log("[SYS-ML] addTestProvider($p) skipped: ${e.message}")
                        }
                    }
                    log("[SYS-ML] startMock: test providers ready")
                } catch (e: Throwable) {
                    log("[SYS-ML] startMock FAILED: $e")
                    mocking = false
                } finally {
                    android.os.Binder.restoreCallingIdentity(token)
                }
            }.apply { name = "FL-StartMock"; isDaemon = true; start() }
        }

        private fun doStopMock() {
            mocking = false
            enforcementThread?.interrupt()
            enforcementThread = null
            currentLocation = null
            Thread {
                val token = android.os.Binder.clearCallingIdentity()
                try {
                    for (p in PROVIDERS) {
                        try {
                            bypassRemoveProvider.set(true)
                            lm.removeTestProvider(p)
                        } catch (_: Throwable) {}
                        finally { bypassRemoveProvider.set(false) }
                    }
                } catch (_: Throwable) {}
                finally {
                    android.os.Binder.restoreCallingIdentity(token)
                }
                log("[SYS-ML] stopMock: cleaned up")
            }.apply { name = "FL-StopMock"; isDaemon = true; start() }
        }

        private fun doSetLocation(location: Location) {
            currentLocation = location
            pushLocation(location)
        }

        /** Push location to all test providers with fresh timestamps and realistic GPS metadata. */
        private fun pushLocation(location: Location) {
            val token = android.os.Binder.clearCallingIdentity()
            try {
                val now = System.currentTimeMillis()
                val elapsed = android.os.SystemClock.elapsedRealtimeNanos()
                for (p in PROVIDERS) {
                    try {
                        val loc = Location(location)
                        loc.provider = p
                        loc.time = now
                        loc.elapsedRealtimeNanos = elapsed
                        if (loc.accuracy <= 0f) loc.accuracy = 3.0f
                        // Realistic GPS metadata — many apps check these
                        if (!loc.hasAltitude()) loc.altitude = 45.0 + (Math.random() * 5)
                        if (!loc.hasBearing()) loc.bearing = (Math.random() * 360).toFloat()
                        if (!loc.hasSpeed()) loc.speed = (0.2 + Math.random() * 0.3).toFloat()
                        try {
                            loc.verticalAccuracyMeters = 8.0f + (Math.random() * 4).toFloat()
                            loc.bearingAccuracyDegrees = 10.0f + (Math.random() * 5).toFloat()
                            loc.speedAccuracyMetersPerSecond = 0.5f + (Math.random() * 0.5).toFloat()
                        } catch (_: Throwable) {}
                        // Satellite count in extras Bundle — apps read this
                        val extras = loc.extras ?: Bundle()
                        extras.putInt("satellites", 12)
                        extras.putInt("satellitesInFix", 10)
                        extras.remove("mockProvider")
                        loc.extras = extras
                        lm.setTestProviderLocation(p, loc)
                    } catch (e: Throwable) {
                        // Auto-recover: re-add test provider if removed
                        if (e.message?.contains("not a test provider") == true) {
                            try {
                                lm.addTestProvider(p, false, false, false, false, true, true, true, 1, 1)
                                lm.setTestProviderEnabled(p, true)
                            } catch (_: Throwable) {}
                        }
                    }
                }
            } finally {
                android.os.Binder.restoreCallingIdentity(token)
            }
        }

        /**
         * Continuous loop in system_server that refreshes test provider locations
         * every 800ms. Prevents location staleness when FL app is throttled in background.
         * Also auto-recovers if test providers get removed unexpectedly.
         */
        private fun startEnforcementLoop() {
            enforcementThread?.interrupt()
            enforcementThread = Thread {
                log("[SYS-ML] enforcement loop started")
                try {
                    while (mocking && !Thread.interrupted()) {
                        try {
                            val loc = currentLocation
                            if (loc != null) pushLocation(loc)
                        } catch (e: Throwable) {
                            log("[SYS-ML] enforcement push error: ${e.message}")
                        }
                        Thread.sleep(800)
                    }
                } catch (_: InterruptedException) {}
                log("[SYS-ML] enforcement loop stopped")
            }.apply {
                name = "FL-MockEnforce"
                isDaemon = true
                start()
            }
        }
    }

    // ============================================================
    //  PRIMARY BYPASS: Hook binder stub's AIDL methods directly
    //  
    //  In system_server, MockController.getCloudBlacklist() calls
    //  binderProxy.aidl_getCloudBlacklist() which is a LOCAL call
    //  (same process → asInterface returns Stub directly, no onTransact).
    //
    //  We hook the actual method on binder.javaClass to return
    //  DUMMY_BLACKLIST instead of null. This makes the enforcement
    //  guard isNullOrEmpty() return false → enforcement SKIPPED.
    // ============================================================
    private fun hookBinderAidlMethods(binderCls: Class<*>) {
        var hookCount = 0

        // Find the AIDL interface (extends IInterface)
        val aidlIface = binderCls.interfaces.firstOrNull { iface ->
            android.os.IInterface::class.java.isAssignableFrom(iface)
        }
        log("[SYS-BINDER] AIDL interface: ${aidlIface?.name ?: "NOT FOUND"}")

        // We REMOVED the wildcard generic List<> hooks because they were catching non-string lists like:
        // List<CellInfo> and List<SubscriptionInfo> used for mock cell towers and mock SIMs.
        // Passing a List<String> (our DUMMY_BLACKLIST) into those methods causes catastrophic TypeCastExceptions 
        // within FakeLocation's mock engine, completely crashing the mock service for ALL applications.
        //
        // In Android binder stubs, local calls use the direct interface methods, 
        // but cross-process calls go through `onTransact`. 
        // FakeLocation calls `Proxy.aidl_getCloudBlacklist()` locally from within system_server 
        // so it uses the direct getter method (not onTransact).
        // We must identify the *correct* List<String> methods by checking generics,
        // and falling back to onTransact for external calls.
        // Instead, we will rely entirely on specific transaction codes and explicit names where possible.

        // Catch-all: hook onTransact for cross-process calls
        try {
            var targetTransact = binderCls
            var transactMethod = targetTransact.declaredMethods.firstOrNull { it.name == "onTransact" && it.parameterCount == 4 }
            
            while (transactMethod == null && targetTransact.superclass != null) {
                targetTransact = targetTransact.superclass as Class<*>
                transactMethod = targetTransact.declaredMethods.firstOrNull { it.name == "onTransact" && it.parameterCount == 4 }
            }

            if (transactMethod != null) {
                transactMethod.isAccessible = true
                XposedBridge.hookMethod(transactMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try {
                            val code = param.args[0] as Int
                            if (code == 3) {
                                param.result = true
                                return
                            }
                            if (code == 33 || code == 10) { 
                                val reply = param.args[2] as? Parcel ?: return
                                reply.setDataPosition(0)
                                reply.setDataSize(0)
                                reply.writeNoException()
                                reply.writeStringList(ArrayList(DUMMY_BLACKLIST))
                            }
                        } catch (_: Throwable) {}
                    }
                })
                hookCount++
                log("[SYS-BINDER] onTransact hooked on class: ${targetTransact.name}")
            } else {
                log("[SYS-BINDER] onTransact not found in hierarchy")
            }
        } catch (e: Throwable) {
            log("[SYS-BINDER] onTransact hook failed: ${e.message}")
        }

        // Hook local direct methods safely by scanning method generic return types
        // Only hook methods returning EXACTLY List<String> or unknown generic types if we can't tell.
        for (m in binderCls.declaredMethods) {
            if (m.parameterCount == 0 && List::class.java.isAssignableFrom(m.returnType)) {
                var isStringList = false
                try {
                    val genType = m.genericReturnType
                    if (genType is ParameterizedType) {
                        val typeArg = genType.actualTypeArguments.firstOrNull()
                        if (typeArg == String::class.java) isStringList = true
                    } else {
                        // Erased generics — DO NOT hook (could be List<CellInfo>/List<SubscriptionInfo>)
                        isStringList = false
                    }
                } catch (e: Throwable) { isStringList = false /* Don't guess — could be List<CellInfo> */ }

                if (isStringList) {
                    m.isAccessible = true
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            try { param.result = ArrayList(DUMMY_BLACKLIST) } catch (_: Throwable) {}
                        }
                    })
                    hookCount++
                }
            }
        }

        log("[SYS-BINDER] ====== $hookCount binder hooks installed ======")
    }

    // Try multiple strategies to find a ClassLoader that can load FL's classes
    private fun tryFindFlClassLoader(binder: IBinder): ClassLoader? {
        val binderCl = binder.javaClass.classLoader

        // S1: From binder CL + parent chain
        var cl: ClassLoader? = binderCl
        while (cl != null) {
            try { cl.loadClass(CLS_ENFORCER); log("[SYS] S1: found in CL chain"); return cl }
            catch (_: ClassNotFoundException) {}
            cl = cl.parent
        }

        // S2: System ClassLoader
        try {
            val scl = ClassLoader.getSystemClassLoader()
            scl.loadClass(CLS_ENFORCER); log("[SYS] S2: system CL"); return scl
        } catch (_: ClassNotFoundException) {}

        // S3: Thread context ClassLoaders
        try {
            for (t in Thread.getAllStackTraces().keys) {
                val tcl = t.contextClassLoader ?: continue
                try { tcl.loadClass(CLS_ENFORCER); log("[SYS] S3: thread '${t.name}'"); return tcl }
                catch (_: ClassNotFoundException) {}
            }
        } catch (_: Throwable) {}

        // S4: Field traversal — find objects loaded by a different CL
        if (binderCl != null) {
            val testedCls = HashSet<Int>()
            testedCls.add(System.identityHashCode(binderCl))
            val visited = HashSet<Int>()

            fun scan(obj: Any, depth: Int): ClassLoader? {
                if (depth > 3) return null
                val id = System.identityHashCode(obj)
                if (!visited.add(id)) return null
                val ocl = obj.javaClass.classLoader
                if (ocl != null && testedCls.add(System.identityHashCode(ocl))) {
                    try { ocl.loadClass(CLS_ENFORCER); return ocl }
                    catch (_: ClassNotFoundException) {}
                }
                var c: Class<*>? = obj.javaClass
                while (c != null && c != Any::class.java && c != android.os.Binder::class.java) {
                    for (f in c.declaredFields) {
                        if (f.type.isPrimitive) continue
                        try {
                            f.isAccessible = true
                            val v = if (Modifier.isStatic(f.modifiers)) f.get(null) else f.get(obj)
                            if (v != null) { scan(v, depth + 1)?.let { return it } }
                        } catch (_: Throwable) {}
                    }
                    c = c.superclass
                }
                return null
            }

            val found = scan(binder, 0)
            if (found != null) { log("[SYS] S4: field traversal"); return found }
        }

        log("[SYS] S1-S4 all failed: no ClassLoader can load CLS_ENFORCER by name")
        return null
    }

    // Find the enforcement class by structural signature in the binder's DEX
    private fun findEnforcerByStructure(cl: ClassLoader): Class<*>? {
        try {
            // Navigate: BaseDexClassLoader → pathList → dexElements → DexFile → entries()
            val pathListField = findFieldInHierarchy(cl.javaClass, "pathList")
            if (pathListField == null) { log("[SYS] S5: not a BaseDexClassLoader"); return null }
            pathListField.isAccessible = true
            val pathList = pathListField.get(cl) ?: return null

            val dexElemsField = findFieldInHierarchy(pathList.javaClass, "dexElements")
                ?: return null
            dexElemsField.isAccessible = true
            val dexElements = dexElemsField.get(pathList) as? Array<*> ?: return null

            var total = 0
            for (elem in dexElements) {
                if (elem == null) continue
                val dexFileField = findFieldInHierarchy(elem.javaClass, "dexFile") ?: continue
                dexFileField.isAccessible = true
                val dexFile = dexFileField.get(elem) ?: continue
                val entriesMethod = dexFile.javaClass.getDeclaredMethod("entries")
                @Suppress("UNCHECKED_CAST")
                val entries = entriesMethod.invoke(dexFile) as java.util.Enumeration<String>
                val names = mutableListOf<String>()
                while (entries.hasMoreElements()) names.add(entries.nextElement())
                total += names.size
                log("[SYS] S5: DEX with ${names.size} classes")

                for (name in names) {
                    try {
                        val cls = cl.loadClass(name)
                        if (matchesEnforcerSignature(cls)) {
                            log("[SYS] S5: FOUND enforcer by structure: $name")
                            return cls
                        }
                    } catch (_: Throwable) {}
                }
            }
            log("[SYS] S5: scanned $total classes, no match")
        } catch (e: Throwable) {
            log("[SYS] S5 error: ${e.message}")
        }
        return null
    }

    // C2553-equivalent structural signature:
    // non-static boolean(String) + void(Location) + void(List) + LocationManager field
    private fun matchesEnforcerSignature(cls: Class<*>): Boolean {
        val methods = cls.declaredMethods
        val hasCheck = methods.any {
            !Modifier.isStatic(it.modifiers)
                && it.returnType == Boolean::class.javaPrimitiveType
                && it.parameterTypes.let { p -> p.size == 1 && p[0] == String::class.java }
        }
        if (!hasCheck) return false
        val hasLoc = methods.any {
            !Modifier.isStatic(it.modifiers)
                && it.returnType == Void.TYPE
                && it.parameterTypes.let { p -> p.size == 1 && p[0] == Location::class.java }
        }
        if (!hasLoc) return false
        val hasList = methods.any {
            !Modifier.isStatic(it.modifiers)
                && it.returnType == Void.TYPE
                && it.parameterTypes.let { p -> p.size == 1 && p[0] == List::class.java }
        }
        if (!hasList) return false
        val hasLmField = cls.declaredFields.any {
            it.type == android.location.LocationManager::class.java
        }
        return hasLmField
    }

    private fun findFieldInHierarchy(cls: Class<*>, name: String): java.lang.reflect.Field? {
        var c: Class<*>? = cls
        while (c != null) {
            try { return c.getDeclaredField(name) } catch (_: NoSuchFieldException) {}
            c = c.superclass
        }
        return null
    }

    // Hook the enforcer class found by structural matching
    private fun hookEnforcerClass(enfCls: Class<*>) {
        if (sysHooked) return
        sysHooked = true
        var count = 0
        for (m in enfCls.declaredMethods) {
            if (Modifier.isStatic(m.modifiers)) continue
            if (m.returnType == Boolean::class.javaPrimitiveType
                && m.parameterTypes.let { it.size == 1 && it[0] == String::class.java }
            ) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) { param.result = true }
                })
                count++; log("[SYS] struct-hook: ${m.name}(String)->true")
            }
            if (m.returnType == Void.TYPE
                && m.parameterTypes.let { it.size == 1 && it[0] == Location::class.java }
            ) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) { param.result = null }
                })
                count++; log("[SYS] struct-hook: ${m.name}(Location)->noop")
            }
            if (m.returnType == Void.TYPE
                && m.parameterTypes.let { it.size == 1 && it[0] == List::class.java }
            ) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = ArrayList(DUMMY_BLACKLIST)
                    }
                })
                count++; log("[SYS] struct-hook: ${m.name}(List)->dummy")
            }
        }
        log("[SYS] ====== structural hooks installed: $count ======")
    }

    private fun installSystemServerHooks(cl: ClassLoader) {
        if (sysHooked) return
        sysHooked = true
        var count = 0
        try {
            val enfCls = cl.loadClass(CLS_ENFORCER)
            for (m in enfCls.declaredMethods) {
                if (Modifier.isStatic(m.modifiers)) continue
                if (m.returnType == Boolean::class.javaPrimitiveType
                    && m.parameterTypes.let { it.size == 1 && it[0] == String::class.java }
                ) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) { param.result = true }
                    })
                    count++; log("[SYS] hooked ${m.name}(String)->true")
                }
                if (m.returnType == Void.TYPE
                    && m.parameterTypes.let { it.size == 1 && it[0] == Location::class.java }
                ) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) { param.result = null }
                    })
                    count++; log("[SYS] hooked ${m.name}(Location)->noop")
                }
                if (m.returnType == Void.TYPE
                    && m.parameterTypes.let { it.size == 1 && it[0] == List::class.java }
                ) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.args[0] = ArrayList(DUMMY_BLACKLIST)
                        }
                    })
                    count++; log("[SYS] hooked ${m.name}(List)->dummy")
                }
            }
        } catch (e: Throwable) { log("[SYS] C2553 hook error: ${e.message}") }

        try {
            val defCls = cl.loadClass(CLS_DEFAULTS)
            for (m in defCls.declaredMethods) {
                if (Modifier.isStatic(m.modifiers)
                    && m.returnType == ArrayList::class.java
                    && m.parameterTypes.isEmpty()
                ) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = ArrayList<String>()
                        }
                    })
                    count++; log("[SYS] hooked ${m.name}()->empty [defaults]")
                }
            }
        } catch (e: Throwable) { log("[SYS] C3131 hook error: ${e.message}") }

        log("[SYS] ====== named hooks installed: $count ======")
    }

    // ============================================================
    //  BACKUP: Hook UsageStatsManager.queryUsageStats
    //  Returns EMPTY list to blind foreground detection.
    //
    //  v25 bug: returning FL package as fake stats triggered
    //  enforcement because FL is in its OWN default blacklist!
    //  Fix: return empty list → iterator doesn't run → z=true
    //  → (non-null empty list && true) = true → ALLOWED
    //
    //  Stale cachedResult concern: if cachedResult was set before
    //  our hook installed, ForegroundDetect falls back to it.
    //  We also null out the static cachedResult field to prevent this.
    // ============================================================
    private fun installUsageStatsHook() {
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
                            val trace = Log.getStackTraceString(Throwable())
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
            // ForegroundDetect class might not be loadable — that's OK,
            // it means it hasn't been loaded yet and cachedResult is null
            log("[SYS] ForegroundDetect cache clear: ${e.javaClass.simpleName}")
        }
    }

    // Framework-level fallback: prevent test provider removal
    private fun installFrameworkFallbackHooks() {
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
    //  Location.writeToParcel() is hooked to clear mIsMock before
    //  ANY Location is parceled to client apps. This means ALL apps
    //  receive locations with isMock()=false/isFromMockProvider()=false,
    //  even if our Xposed module is NOT loaded into those apps.
    // ============================================================
    private fun installMockFlagStrip() {
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

    private fun stripMockFlag(loc: Location) {
        for (fieldName in arrayOf("mIsMock", "mIsFromMockProvider")) {
            try {
                val f = Location::class.java.getDeclaredField(fieldName)
                f.isAccessible = true
                f.setBoolean(loc, false)
            } catch (_: Throwable) {}
        }
        try { loc.extras?.remove("mockProvider") } catch (_: Throwable) {}
    }

    // ============================================================
    //  Fake GnssStatus injection — system_server (passive)
    //
    //  Modifies any real GnssStatus data passing through to replace
    //  with fake satellites. This is the belt-and-suspenders approach
    //  for when real GPS data IS flowing but with poor signal.
    //  Active injection for "no GPS signal" is handled by Layer 3.
    // ============================================================
    private fun installGnssHooks() {
        var hookCount = 0

        // Hook GnssStatus.Callback.onSatelliteStatusChanged to replace with fake status
        try {
            val gnssCallbackCls = Class.forName("android.location.GnssStatus\$Callback")
            val onSatChanged = gnssCallbackCls.getMethod(
                "onSatelliteStatusChanged", Class.forName("android.location.GnssStatus")
            )
            XposedBridge.hookMethod(onSatChanged, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        if (ourMlBinder?.mocking != true) return
                        val fakeStatus = buildFakeGnssStatus()
                        if (fakeStatus != null) param.args[0] = fakeStatus
                    } catch (_: Throwable) {}
                }
            })
            hookCount++
            log("[SYS-GNSS] onSatelliteStatusChanged hook installed")
        } catch (e: Throwable) {
            log("[SYS-GNSS] Callback hook failed: $e")
        }

        // Hook LocationManager.getGnssYearOfHardware to return recent year
        try {
            XposedHelpers.findAndHookMethod(
                android.location.LocationManager::class.java,
                "getGnssYearOfHardware",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        try { if (ourMlBinder?.mocking == true) param.result = 2024 } catch (_: Throwable) {}
                    }
                })
            hookCount++
        } catch (_: Throwable) {}

        log("[SYS-GNSS] $hookCount passive GNSS hooks installed")
    }

    /**
     * Build a fake GnssStatus with 12 GPS satellites.
     * Uses AOSP internal constructor via reflection.
     * svidWithFlags encoding: (svid << 12) | (constellation << 8) | flags
     *   flags: HAS_EPHEMERIS=1, HAS_ALMANAC=2, USED_IN_FIX=4, HAS_CARRIER_FREQ=8, HAS_BASEBAND_CN0=16
     *   constellation: GPS=1
     */
    private fun buildFakeGnssStatus(): Any? {
        try {
            val gnssStatusCls = Class.forName("android.location.GnssStatus")
            val svCount = 12
            val svidWithFlags = IntArray(svCount)
            val cn0s = FloatArray(svCount)
            val elevations = FloatArray(svCount)
            val azimuths = FloatArray(svCount)
            val carrierFreqs = FloatArray(svCount)
            val basebandCn0s = FloatArray(svCount)
            val rng = java.util.Random()
            for (i in 0 until svCount) {
                val svid = i + 1
                // flags: ephemeris(1) + almanac(2) + usedInFix(4, first 10) + carrierFreq(8) + basebandCn0(16)
                val flags = 1 or 2 or (if (i < 10) 4 else 0) or 8 or 16
                val constellation = 1 // GPS
                svidWithFlags[i] = (svid shl 12) or (constellation shl 8) or flags
                cn0s[i] = 25.0f + rng.nextFloat() * 20.0f        // 25-45 dB-Hz
                elevations[i] = 15.0f + rng.nextFloat() * 65.0f  // 15-80 degrees
                azimuths[i] = rng.nextFloat() * 360.0f           // 0-360 degrees
                carrierFreqs[i] = 1575.42f                       // GPS L1 frequency
                basebandCn0s[i] = cn0s[i] - 3.0f
            }

            // Try wrap() static method first (API 30+)
            try {
                val wrap = gnssStatusCls.getMethod(
                    "wrap", Int::class.javaPrimitiveType, IntArray::class.java,
                    FloatArray::class.java, FloatArray::class.java,
                    FloatArray::class.java, FloatArray::class.java,
                    FloatArray::class.java
                )
                return wrap.invoke(null, svCount, svidWithFlags, cn0s, elevations, azimuths, carrierFreqs, basebandCn0s)
            } catch (_: Throwable) {}

            // Fallback: constructor with 7 args
            try {
                val ctor = gnssStatusCls.getDeclaredConstructor(
                    Int::class.javaPrimitiveType, IntArray::class.java,
                    FloatArray::class.java, FloatArray::class.java,
                    FloatArray::class.java, FloatArray::class.java,
                    FloatArray::class.java
                )
                ctor.isAccessible = true
                return ctor.newInstance(svCount, svidWithFlags, cn0s, elevations, azimuths, carrierFreqs, basebandCn0s)
            } catch (_: Throwable) {}

            // Fallback: constructor with 6 args (no basebandCn0s, older AOSP)
            val ctor6 = gnssStatusCls.getDeclaredConstructor(
                Int::class.javaPrimitiveType, IntArray::class.java,
                FloatArray::class.java, FloatArray::class.java,
                FloatArray::class.java, FloatArray::class.java
            )
            ctor6.isAccessible = true
            return ctor6.newInstance(svCount, svidWithFlags, cn0s, elevations, azimuths, carrierFreqs)
        } catch (e: Throwable) {
            log("[GNSS] buildFakeGnssStatus failed: $e")
            return null
        }
    }

    // ============================================================
    //  Active GNSS injection from system_server — v40
    //
    //  Hooks GNSS status listener registration in GnssManagerService
    //  to capture IGnssStatusListener binder proxies from apps.
    //  A daemon thread then dispatches fake satellite data to ALL
    //  registered listeners via IPC, so apps see GPS satellites
    //  regardless of whether our module is loaded in their process.
    //  This replaces the dependency on Layer 3 GNSS injection.
    // ============================================================
    private val sysGnssListeners = java.util.concurrent.CopyOnWriteArrayList<Any>()
    @Volatile private var sysGnssFeederStarted = false

    private fun installActiveGnssFromServer() {
        val listenerCls = try {
            Class.forName("android.location.IGnssStatusListener")
        } catch (_: Throwable) {
            log("[SYS-GNSS] IGnssStatusListener not found, skipping active injection")
            return
        }

        // Scan GnssManagerService / LocationManagerService for register methods
        val candidates = listOf(
            "com.android.server.location.gnss.GnssManagerService",
            "com.android.server.location.gnss.GnssStatusProvider",
            "com.android.server.LocationManagerService"
        )

        var hooked = false
        for (clsName in candidates) {
            val cls = try { Class.forName(clsName) } catch (_: Throwable) { continue }
            for (m in cls.declaredMethods) {
                // Hook register methods that accept IGnssStatusListener
                if (!m.name.lowercase().let { it.contains("register") && it.contains("gnss") }) continue
                val hasListener = m.parameterTypes.any { listenerCls.isAssignableFrom(it) }
                if (!hasListener) continue
                try {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            try {
                                if (param.throwable != null) return
                                val listener = param.args.firstOrNull { listenerCls.isInstance(it) }
                                if (listener != null && sysGnssListeners.addIfAbsent(listener)) {
                                    log("[SYS-GNSS] captured listener via ${m.name} (total=${sysGnssListeners.size})")
                                    ensureSysGnssFeederRunning()
                                }
                            } catch (_: Throwable) {}
                        }
                    })
                    hooked = true
                    log("[SYS-GNSS] hooked ${clsName}.${m.name}")
                } catch (e: Throwable) {
                    log("[SYS-GNSS] hook ${m.name} failed: $e")
                }
            }
            // Hook unregister methods to clean up dead listeners
            for (m in cls.declaredMethods) {
                if (!m.name.lowercase().let { it.contains("unregister") && it.contains("gnss") }) continue
                val hasListener = m.parameterTypes.any { listenerCls.isAssignableFrom(it) }
                if (!hasListener) continue
                try {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            try {
                                val listener = param.args.firstOrNull { listenerCls.isInstance(it) }
                                if (listener != null) sysGnssListeners.remove(listener)
                            } catch (_: Throwable) {}
                        }
                    })
                } catch (_: Throwable) {}
            }
            if (hooked) break
        }

        if (!hooked) log("[SYS-GNSS] WARNING: no GNSS registration hook found in known classes")
    }

    private fun ensureSysGnssFeederRunning() {
        if (sysGnssFeederStarted) return
        sysGnssFeederStarted = true

        Thread {
            try {
                val listenerCls = Class.forName("android.location.IGnssStatusListener")
                val onStarted = try { listenerCls.getMethod("onGnssStarted") } catch (_: Throwable) { null }
                // Find onSvStatusChanged dynamically (parameter count varies by API)
                val onSvChanged = listenerCls.methods.firstOrNull { it.name == "onSvStatusChanged" }
                if (onSvChanged == null) {
                    log("[SYS-GNSS] FATAL: onSvStatusChanged not found on IGnssStatusListener")
                    sysGnssFeederStarted = false
                    return@Thread
                }
                log("[SYS-GNSS] onSvStatusChanged signature: ${onSvChanged.parameterTypes.joinToString { it.simpleName }}")

                Thread.sleep(500)

                // Fire onGnssStarted for initial listeners
                if (onStarted != null) {
                    for (l in ArrayList(sysGnssListeners)) {
                        try { onStarted.invoke(l) } catch (_: Throwable) {}
                    }
                }

                log("[SYS-GNSS] active feeder started (${sysGnssListeners.size} listeners)")

                while (!Thread.interrupted()) {
                    Thread.sleep(1000)
                    if (sysGnssListeners.isEmpty() || ourMlBinder?.mocking != true) continue

                    val args = buildFakeGnssArgs(onSvChanged.parameterTypes)
                    for (l in ArrayList(sysGnssListeners)) {
                        try {
                            onSvChanged.invoke(l, *args)
                        } catch (e: Throwable) {
                            val cause = if (e is java.lang.reflect.InvocationTargetException) e.targetException else e
                            if (cause is android.os.DeadObjectException) {
                                sysGnssListeners.remove(l)
                                log("[SYS-GNSS] removed dead listener (remaining=${sysGnssListeners.size})")
                            }
                        }
                    }
                }
            } catch (_: InterruptedException) {
            } catch (e: Throwable) {
                log("[SYS-GNSS] feeder error: $e")
                sysGnssFeederStarted = false
            }
        }.apply {
            name = "FL-SysGnssFeed"
            isDaemon = true
            start()
        }
    }

    /**
     * Build fake GNSS parameter array matching the discovered onSvStatusChanged signature.
     * Handles both 7-param (with basebandCn0s) and 6-param (without) variants.
     */
    private fun buildFakeGnssArgs(paramTypes: Array<Class<*>>): Array<Any> {
        val svCount = 12
        val svidWithFlags = IntArray(svCount)
        val cn0s = FloatArray(svCount)
        val elevations = FloatArray(svCount)
        val azimuths = FloatArray(svCount)
        val carrierFreqs = FloatArray(svCount)
        val basebandCn0s = FloatArray(svCount)
        val rng = java.util.Random()
        for (i in 0 until svCount) {
            val svid = i + 1
            val flags = 1 or 2 or (if (i < 10) 4 else 0) or 8 or 16
            svidWithFlags[i] = (svid shl 12) or (1 shl 8) or flags
            cn0s[i] = 25.0f + rng.nextFloat() * 20.0f
            elevations[i] = 15.0f + rng.nextFloat() * 65.0f
            azimuths[i] = rng.nextFloat() * 360.0f
            carrierFreqs[i] = 1575.42f
            basebandCn0s[i] = cn0s[i] - 3.0f
        }
        return when (paramTypes.size) {
            7 -> arrayOf(svCount, svidWithFlags, cn0s, elevations, azimuths, carrierFreqs, basebandCn0s)
            6 -> arrayOf(svCount, svidWithFlags, cn0s, elevations, azimuths, carrierFreqs)
            else -> arrayOf(svCount, svidWithFlags, cn0s, elevations, azimuths, carrierFreqs, basebandCn0s)
        }
    }

    // ============================================================
    //  LAYER 3: target app anti-mock-detection
    //  Hooks Location class in all non-FL apps to hide mock flags.
    //  Also hooks Settings.Secure to hide mock_location setting.
    // ============================================================
    private fun hookAntiMockDetection() {
        // Location.isFromMockProvider() → false (API 18+)
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isFromMockProvider",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
        } catch (_: Throwable) {}

        // Location.isMock() → false (API 31+)
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isMock",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
        } catch (_: Throwable) {}

        // Location.getExtras() → remove "mockProvider" key
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "getExtras",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val extras = param.result as? Bundle ?: return
                        extras.remove("mockProvider")
                    }
                })
        } catch (_: Throwable) {}

        // Settings.Secure.getString: hide "mock_location" = "0"
        try {
            XposedHelpers.findAndHookMethod(
                "android.provider.Settings\$Secure", null,
                "getString",
                android.content.ContentResolver::class.java,
                String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.args[1] == "mock_location") {
                            param.result = "0"
                        }
                    }
                })
        } catch (_: Throwable) {}

        // Active GnssStatus injection: hook registerGnssStatusCallback to capture
        // callbacks, then feed them fake satellite data from a daemon thread.
        // This is needed because test providers DON'T trigger GnssStatus callbacks,
        // so apps see "no GPS signal" even though Location data is correct.
        hookGnssCallbackInjection()

        // Step sensor spoofing: hook SensorManager to intercept step counter/detector
        // registrations, then inject fake step events matching FL's step simulation.
        hookStepSensorInjection()
    }

    @Volatile private var gnssFeederStarted = false
    private val gnssCallbacks = java.util.concurrent.CopyOnWriteArrayList<Any>()

    private fun hookGnssCallbackInjection() {
        try {
            val gnssCallbackCls = Class.forName("android.location.GnssStatus\$Callback")
            val lmClass = android.location.LocationManager::class.java

            // Hook all overloads of registerGnssStatusCallback
            for (m in lmClass.declaredMethods) {
                if (m.name != "registerGnssStatusCallback") continue
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.throwable != null) return
                        val cb = param.args.firstOrNull {
                            it != null && gnssCallbackCls.isInstance(it)
                        }
                        if (cb != null && !gnssCallbacks.contains(cb)) {
                            gnssCallbacks.add(cb)
                            log("[GNSS-L3] captured GnssStatus.Callback (total=${gnssCallbacks.size})")
                            ensureGnssFeederRunning()
                        }
                    }
                })
            }

            // Hook unregisterGnssStatusCallback to clean up
            for (m in lmClass.declaredMethods) {
                if (m.name != "unregisterGnssStatusCallback") continue
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val cb = param.args.firstOrNull {
                            it != null && gnssCallbackCls.isInstance(it)
                        }
                        if (cb != null) gnssCallbacks.remove(cb)
                    }
                })
            }

            log("[GNSS-L3] registerGnssStatusCallback hooks installed")
        } catch (e: Throwable) {
            log("[GNSS-L3] hookGnssCallbackInjection failed: $e")
        }
    }

    /**
     * Starts a daemon thread that periodically dispatches fake GnssStatus
     * (12 GPS satellites, good signal) to all captured callbacks.
     * Fires onStarted + onFirstFix initially, then onSatelliteStatusChanged every 1s.
     */
    private fun ensureGnssFeederRunning() {
        if (gnssFeederStarted) return
        gnssFeederStarted = true

        Thread {
            try {
                val gnssCallbackCls = Class.forName("android.location.GnssStatus\$Callback")
                val onStarted = gnssCallbackCls.getMethod("onStarted")
                val onSatChanged = gnssCallbackCls.getMethod(
                    "onSatelliteStatusChanged",
                    Class.forName("android.location.GnssStatus")
                )
                val onFirstFix = gnssCallbackCls.getMethod(
                    "onFirstFix", Int::class.javaPrimitiveType
                )

                Thread.sleep(500)

                // Initial: fire onStarted + onFirstFix for all callbacks
                val handler = android.os.Handler(android.os.Looper.getMainLooper())
                for (cb in gnssCallbacks) {
                    handler.post {
                        try { onStarted.invoke(cb) } catch (_: Throwable) {}
                        try { onFirstFix.invoke(cb, 800) } catch (_: Throwable) {}
                    }
                }

                log("[GNSS-L3] feeder started, dispatching to ${gnssCallbacks.size} callbacks")

                // Continuous: dispatch fake satellite status every 1s
                while (!Thread.interrupted()) {
                    Thread.sleep(1000)
                    if (gnssCallbacks.isEmpty()) continue
                    val fakeStatus = buildFakeGnssStatus() ?: continue
                    for (cb in gnssCallbacks) {
                        handler.post {
                            try { onSatChanged.invoke(cb, fakeStatus) } catch (_: Throwable) {}
                        }
                    }
                }
            } catch (_: InterruptedException) {
            } catch (e: Throwable) {
                log("[GNSS-L3] feeder error: $e")
            }
        }.apply {
            name = "FL-GnssFeed"
            isDaemon = true
            start()
        }
    }

    // ============================================================
    //  Step sensor spoofing — Layer 3 (target apps)
    //  Intercepts SensorManager.registerListener for TYPE_STEP_COUNTER(19)
    //  and TYPE_STEP_DETECTOR(18), feeds fake events matching FL step sim.
    // ============================================================
    @Volatile private var stepFeederStarted = false
    private val stepListeners = java.util.concurrent.CopyOnWriteArrayList<Any>()
    private val stepSensorTypes = java.util.concurrent.ConcurrentHashMap<Any, Int>() // listener -> sensor type

    private fun hookStepSensorInjection() {
        try {
            val smClass = Class.forName("android.hardware.SensorManager")
            val sensorClass = Class.forName("android.hardware.Sensor")
            val listenerClass = Class.forName("android.hardware.SensorEventListener")

            val captureHook = object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    try {
                        if (param.throwable != null) return
                        val listener = param.args[0] ?: return
                        val sensor = param.args[1] ?: return
                        if (!listenerClass.isInstance(listener)) return
                        if (!sensorClass.isInstance(sensor)) return
                        val sensorType = sensorClass.getMethod("getType").invoke(sensor) as Int
                        if (sensorType == 19 || sensorType == 18) {
                            if (!stepListeners.contains(listener)) {
                                stepListeners.add(listener)
                                stepSensorTypes[listener] = sensorType
                                log("[STEP-L3] captured step listener type=$sensorType (total=${stepListeners.size})")
                                ensureStepFeederRunning()
                            }
                        }
                    } catch (_: Throwable) {}
                }
            }

            // Hook all overloads of SensorManager.registerListener
            for (m in smClass.declaredMethods) {
                if (m.name != "registerListener") continue
                val params = m.parameterTypes
                if (params.size < 2) continue
                if (!listenerClass.isAssignableFrom(params[0])) continue
                if (!sensorClass.isAssignableFrom(params[1])) continue
                XposedBridge.hookMethod(m, captureHook)
            }

            // Also hook SystemSensorManager.registerListenerImpl (internal implementation)
            try {
                val ssmClass = Class.forName("android.hardware.SystemSensorManager")
                for (m in ssmClass.declaredMethods) {
                    if (m.name != "registerListenerImpl") continue
                    val params = m.parameterTypes
                    if (params.size < 2) continue
                    if (!listenerClass.isAssignableFrom(params[0])) continue
                    if (!sensorClass.isAssignableFrom(params[1])) continue
                    XposedBridge.hookMethod(m, captureHook)
                    log("[STEP-L3] also hooked SystemSensorManager.registerListenerImpl")
                }
            } catch (_: Throwable) {}

            // Hook unregisterListener to clean up
            for (m in smClass.declaredMethods) {
                if (m.name != "unregisterListener") continue
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val listener = param.args?.firstOrNull() ?: return
                        stepListeners.remove(listener)
                        stepSensorTypes.remove(listener)
                    }
                })
            }

            log("[STEP-L3] step sensor hooks installed")
        } catch (e: Throwable) {
            log("[STEP-L3] hookStepSensorInjection failed: $e")
        }
    }

    /**
     * Daemon thread that injects fake SensorEvent to all captured step listeners.
     * For TYPE_STEP_COUNTER(19): values[0] = total accumulated steps
     * For TYPE_STEP_DETECTOR(18): values[0] = 1.0 (step detected event)
     *
     * Step frequency derived from FL's stepSpeed (m/s) → stride ≈ 0.7m → steps/sec = speed/0.7
     * Queries service_fl_ml via ServiceManager binder IPC instead of ourMlBinder (which is null in app process).
     */
    private fun ensureStepFeederRunning() {
        if (stepFeederStarted) return
        stepFeederStarted = true

        Thread {
            try {
                val sensorEventCls = Class.forName("android.hardware.SensorEvent")
                val sensorCls = Class.forName("android.hardware.Sensor")
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

                // Get binder to service_fl_ml via ServiceManager for querying step state
                val smClass = Class.forName("android.os.ServiceManager")
                val getService = smClass.getMethod("getService", String::class.java)

                log("[STEP-L3] feeder started (counter=${stepCounterSensor != null}, detector=${stepDetectorSensor != null})")

                val handler = android.os.Handler(android.os.Looper.getMainLooper())
                var localStepAccum = 0L
                var lastInjectTime = 0L

                Thread.sleep(1000)

                while (!Thread.interrupted()) {
                    if (stepListeners.isEmpty()) {
                        Thread.sleep(500)
                        continue
                    }

                    // Query service_fl_ml for mocking status and step speed via binder IPC
                    var isMocking = false
                    var stepSpeed = 3.0f  // default ~running pace
                    try {
                        val binder = getService.invoke(null, "service_fl_ml") as? IBinder
                        if (binder != null) {
                            // tx22 = isMocking
                            val mockData = Parcel.obtain()
                            val mockReply = Parcel.obtain()
                            try {
                                mockData.writeInterfaceToken(FL_AIDL_DESCRIPTOR)
                                binder.transact(22, mockData, mockReply, 0)
                                mockReply.readException()
                                isMocking = mockReply.readInt() != 0
                            } finally {
                                mockData.recycle()
                                mockReply.recycle()
                            }
                            // tx15 = getSpeed
                            if (isMocking) {
                                val speedData = Parcel.obtain()
                                val speedReply = Parcel.obtain()
                                try {
                                    speedData.writeInterfaceToken(FL_AIDL_DESCRIPTOR)
                                    binder.transact(15, speedData, speedReply, 0)
                                    speedReply.readException()
                                    val s = speedReply.readFloat()
                                    if (s > 0.1f) stepSpeed = s
                                } finally {
                                    speedData.recycle()
                                    speedReply.recycle()
                                }
                            }
                        }
                    } catch (_: Throwable) {}

                    if (!isMocking) {
                        Thread.sleep(500)
                        continue
                    }

                    val speed = stepSpeed.coerceIn(0.5f, 30.0f)
                    val strideLength = 0.7
                    val stepsPerSecond = speed / strideLength
                    val intervalMs = (1000.0 / stepsPerSecond).toLong().coerceIn(100, 2000)

                    val now = System.currentTimeMillis()
                    if (lastInjectTime == 0L) lastInjectTime = now
                    val elapsed = (now - lastInjectTime) / 1000.0
                    val stepsToAdd = (elapsed * stepsPerSecond).toLong()
                    if (stepsToAdd > 0) {
                        localStepAccum += stepsToAdd
                        lastInjectTime = now
                    }

                    for (listener in stepListeners) {
                        val type = stepSensorTypes[listener] ?: 19
                        handler.post {
                            try {
                                val event = seCtor.newInstance(1)
                                val vals = valuesField.get(event) as FloatArray
                                if (type == 19) {
                                    vals[0] = localStepAccum.toFloat()
                                } else {
                                    vals[0] = 1.0f
                                }
                                timestampField.setLong(event, android.os.SystemClock.elapsedRealtimeNanos())
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

    // ============================================================
    //  LAYER 1: FL app hooks (Mode 0: app-side + Binder poison)
    // ============================================================
    private fun performFlHooks(cl: ClassLoader) {
        // Patch SELinux asynchronously — don't block Application.attach.
        // Must complete before jed dex sends ADD_XP_SERVICE broadcast.
        patchSelinuxAsync()

        safeHook("AntiXposedDetect") { hookAntiXposedDetect(cl) }
        safeHook("BlacklistManager") { hookBlacklistManager(cl) }
        safeHook("BlacklistTransport") { hookBlacklistTransport(cl) }
        safeHook("EnforcementBypass") { hookEnforcementBypass(cl) }
        safeHook("StopMockBlock") { hookStopMockBlock(cl) }
        // DexLoader (ft0) must NOT be blocked — it loads the jed dex that sends
        // ADD_XP_SERVICE broadcast to activate FL-Xposed's service_fl_xp chain.
        safeHook("DexLoaderDebug") { hookDexLoaderDebug(cl) }
        safeHook("DisabledLists") { hookDisabledLists(cl) }
        safeHook("TokenVerifier") { hookTokenVerifier(cl) }
        safeHook("ProValidator") { hookProValidator(cl) }
        safeHook("UserSession") { hookUserSession(cl) }
        safeHook("UserModel") { hookUserModel(cl) }
        safeHook("XpModeEnable") { hookXpModeEnable(cl) }
        safeHook("Mode0Binder") { hookMode0Binder(cl) }
        safeHook("AgreementDialog") { hookAgreementDialog(cl) }
        log("[FL] All hooks installed (v41: proactive service_fl_ml + compat fixes + SELinux + agreement + step + enforcement + mock flag strip + Mode0Binder)")

        // Force BlacklistManager class initialization to trigger jed dex loading.
        triggerJedDexLoading(cl)

        // Also send ADD_XP_SERVICE broadcast from FL app process as backup.
        // FL-Xposed's receiver in system_server will catch this and call addService.
        sendAddXpServiceBroadcast(cl)
    }

    // ==================== Agreement Dialog Block (gc2) ====================
    // FL shows a non-cancelable user agreement dialog (协议) on startup via
    // gc2.m3023(Context). Dismiss/reject kills the app (System.exit(0)).
    // Hook to skip the dialog entirely and mark as agreed in SharedPreferences.
    private fun hookAgreementDialog(cl: ClassLoader) {
        val gc2 = XposedHelpers.findClass("androidx.appcompat.view.widget.gc2", cl)
        // Method name may be obfuscated — find static void method(Context)
        val targetMethod = gc2.declaredMethods.firstOrNull { m ->
            Modifier.isStatic(m.modifiers)
                && m.returnType == Void.TYPE
                && m.parameterTypes.size == 1
                && m.parameterTypes[0] == Context::class.java
        }
        if (targetMethod == null) {
            log("[FL] AgreementDialog: no matching static void(Context) in gc2")
            return
        }
        XposedBridge.hookMethod(targetMethod, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val ctx = param.args[0] as Context
                val prefs = ctx.getSharedPreferences("ua", 0)
                if (!prefs.getBoolean("agreed", false) || prefs.getString("id", null).isNullOrEmpty()) {
                    prefs.edit()
                        .putBoolean("agreed", true)
                        .putInt("local_version", 9999)
                        .putString("id", "hooked")
                        .apply()
                    log("[FL] Agreement dialog blocked, marked as agreed")
                }
                param.result = null  // skip entire method
            }
        })
        log("[FL] AgreementDialog: hooked ${targetMethod.name}(Context)")
    }

    // ==================== XP Mode Enable (ap2 + C5039) ====================
    // FL app checks ap2.m642() to decide whether to use FL-Xposed (service_fl_xp).
    // It's hardcoded to return false, so XP init never runs.
    // Also, C5039.f22603 ("isXpReady") is never set to true, causing infinite wait
    // in MODE_0's RunnableC3916 at while(!C5039.m18324()) { sleep(200) }.
    // Fix: hook m642() → true, set f22603 = true.
    private fun hookXpModeEnable(cl: ClassLoader) {
        var hooked = 0
        // Hook ap2.m642(Context) → true
        try {
            val ap2Cls = cl.loadClass(CLS_XP_AP2)
            for (m in ap2Cls.declaredMethods) {
                if (!Modifier.isStatic(m.modifiers)
                    && m.returnType == Boolean::class.javaPrimitiveType
                    && m.parameterTypes.size == 1
                    && m.parameterTypes[0] == Context::class.java
                ) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = true
                            log("[FL] XP-MODE: ap2.m642() → true (enable XP)")
                        }
                    })
                    hooked++
                }
            }
        } catch (e: Throwable) { log("[FL] XP-MODE ap2 FAILED: ${e.message}") }

        // Set C5039 singleton's boolean fields to true (bypass XP ready wait loop)
        // f22603 (real name: ඈ) is the "isXpReady" flag
        try {
            val c5039Cls = cl.loadClass(CLS_XP_READY)
            // Get singleton: C5042.f22607
            val holderCls = c5039Cls.declaredClasses.firstOrNull { cls ->
                cls.declaredFields.any { it.type == c5039Cls && Modifier.isStatic(it.modifiers) }
            }
            if (holderCls != null) {
                val singletonField = holderCls.declaredFields.first {
                    it.type == c5039Cls && Modifier.isStatic(it.modifiers)
                }
                singletonField.isAccessible = true
                val singleton = singletonField.get(null)
                if (singleton != null) {
                    // Set ALL non-static boolean fields to true (covers f22603/ඈ and f22602/ஆ)
                    for (f in c5039Cls.declaredFields) {
                        if (!Modifier.isStatic(f.modifiers) && f.type == Boolean::class.javaPrimitiveType) {
                            f.isAccessible = true
                            f.setBoolean(singleton, true)
                            hooked++
                            log("[FL] XP-MODE: C5039.${f.name} = true")
                        }
                    }
                }
            }
            // Also hook m18332()/m18330() as belt-and-suspenders
            for (m in c5039Cls.declaredMethods) {
                if (!Modifier.isStatic(m.modifiers)
                    && m.returnType == Boolean::class.javaPrimitiveType
                    && m.parameterTypes.isEmpty()
                ) {
                    // Need to distinguish: m18338 already returns true, m18330/m18332 return f22603
                    // Hook all non-static boolean() methods to return true
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = true
                        }
                    })
                    hooked++
                }
            }
        } catch (e: Throwable) { log("[FL] XP-MODE C5039 FAILED: ${e.message}") }
        log("[FL] XP-MODE: $hooked hooks/fields set")
    }

    // ==================== Mode0Binder proxy injection ====================
    // FL app's Mode0Binder.getProxy() tries to get service_fl_ml binder
    // via b31.getBinderFromSysCL(ClassLoader.getSystemClassLoader(), "service_fl_ml").
    // This may fail silently (catch Throwable). We hook getProxy() to force-connect
    // to our binder registered in system_server.
    private fun hookMode0Binder(cl: ClassLoader) {
        val mode0Cls = try { cl.loadClass(CLS_MODE0_BINDER) } catch (e: Throwable) {
            log("[FL] MODE0: class not found: ${e.message}"); return
        }
        var hooked = 0

        // Cache aidlIfaceType and asInterface method for reuse
        val proxyGetterMethod = mode0Cls.declaredMethods.firstOrNull { m ->
            !Modifier.isStatic(m.modifiers) && m.parameterTypes.isEmpty()
                && m.returnType.isInterface
                && android.os.IInterface::class.java.isAssignableFrom(m.returnType)
        }
        val aidlIfaceType = proxyGetterMethod?.returnType
        // Find asInterface equivalent: static method(IBinder) → aidlIfaceType
        // It's on the inner abstract Stub class (AbstractBinderC3032)
        var asIfaceMethod: java.lang.reflect.Method? = null
        if (aidlIfaceType != null) {
            for (innerCls in aidlIfaceType.declaredClasses) {
                for (m in innerCls.declaredMethods) {
                    if (Modifier.isStatic(m.modifiers)
                        && m.parameterTypes.size == 1
                        && m.parameterTypes[0] == IBinder::class.java
                        && aidlIfaceType.isAssignableFrom(m.returnType)
                    ) {
                        asIfaceMethod = m
                        break
                    }
                }
                if (asIfaceMethod != null) break
            }
        }
        val proxyField = if (aidlIfaceType != null) {
            mode0Cls.declaredFields.firstOrNull {
                !Modifier.isStatic(it.modifiers) && it.type == aidlIfaceType
            }?.apply { isAccessible = true }
        } else null

        log("[FL] MODE0: aidlIface=${aidlIfaceType?.name} asInterface=${asIfaceMethod?.name} proxyField=${proxyField?.name}")

        // Helper to poll service_fl_ml with retries
        // SELinux policy already patched at startup — no setenforce needed
        fun tryConnectServiceFlMl(instance: Any, blocking: Boolean): Any? {
            val smClass = Class.forName("android.os.ServiceManager")
            val getServiceMethod = smClass.getMethod("getService", String::class.java)
            val maxAttempts = if (blocking) 60 else 1
            for (attempt in 1..maxAttempts) {
                val binder = getServiceMethod.invoke(null, "service_fl_ml") as? IBinder
                if (binder != null && asIfaceMethod != null) {
                    val proxy = asIfaceMethod.invoke(null, binder)
                    if (proxy != null) {
                        proxyField?.set(instance, proxy)
                        log("[FL] MODE0: connected to service_fl_ml (attempt $attempt, blocking=$blocking)")
                        return proxy
                    }
                }
                if (attempt < maxAttempts) Thread.sleep(500)
            }
            if (blocking) log("[FL] MODE0: service_fl_ml not found after 30s polling")
            return null
        }

        // Background thread to pre-cache proxy as soon as service_fl_ml is available
        Thread {
            try {
                Thread.sleep(3000) // Give service_fl_xp time to register first
                val smClass = Class.forName("android.os.ServiceManager")
                val getServiceMethod = smClass.getMethod("getService", String::class.java)
                val holderCls = mode0Cls.declaredClasses.firstOrNull { cls ->
                    cls.declaredFields.any { it.type == mode0Cls && Modifier.isStatic(it.modifiers) }
                }
                val instanceField = holderCls?.declaredFields?.firstOrNull {
                    it.type == mode0Cls && Modifier.isStatic(it.modifiers)
                }
                instanceField?.isAccessible = true
                val instance = instanceField?.get(null)
                if (instance == null) {
                    log("[FL] MODE0-BG: cannot get singleton instance"); return@Thread
                }
                for (attempt in 1..120) { // Up to 60s
                    val binder = getServiceMethod.invoke(null, "service_fl_ml") as? IBinder
                    if (binder != null && asIfaceMethod != null) {
                        val proxy = asIfaceMethod.invoke(null, binder)
                        if (proxy != null) {
                            proxyField?.set(instance, proxy)
                            log("[FL] MODE0-BG: pre-cached proxy (${attempt}×500ms)")
                            return@Thread
                        }
                    }
                    Thread.sleep(500)
                }
                log("[FL] MODE0-BG: service_fl_ml never appeared")
            } catch (e: Throwable) {
                log("[FL] MODE0-BG: error: $e")
            }
        }.apply { name = "FL-Mode0Preconnect"; isDaemon = true }.start()

        for (m in mode0Cls.declaredMethods) {
            if (Modifier.isStatic(m.modifiers)) continue

            // Hook getProxy() to poll for our binder
            if (m == proxyGetterMethod) {
                m.isAccessible = true
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.result != null) return
                        // Original returned null — try non-blocking first
                        try {
                            val proxy = tryConnectServiceFlMl(param.thisObject, false)
                            if (proxy != null) {
                                param.result = proxy
                                return
                            }
                            // If non-blocking failed and we're NOT on main thread, do blocking poll
                            if (android.os.Looper.myLooper() != android.os.Looper.getMainLooper()) {
                                val retryProxy = tryConnectServiceFlMl(param.thisObject, true)
                                if (retryProxy != null) param.result = retryProxy
                            }
                        } catch (e: Throwable) {
                            log("[FL] MODE0: getProxy poll failed: $e")
                        }
                    }
                })
                hooked++
                log("[FL] MODE0: hooked getProxy() = ${m.name}")
            }

            // Hook isConnected()
            if (m.parameterTypes.isEmpty() && m.returnType == Boolean::class.javaPrimitiveType) {
                m.isAccessible = true
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.result == true) return
                        try {
                            val smClass = Class.forName("android.os.ServiceManager")
                            val binder = smClass.getMethod("getService", String::class.java)
                                .invoke(null, "service_fl_ml") as? IBinder
                            if (binder != null) {
                                param.result = true
                                log("[FL] MODE0: isConnected() → true")
                            }
                        } catch (_: Throwable) {}
                    }
                })
                hooked++
                log("[FL] MODE0: hooked isConnected() = ${m.name}")
            }
        }
        log("[FL] MODE0: $hooked hooks installed")
    }

    private fun patchSelinuxAsync() {
        // Apply targeted SELinux policy rules at startup.
        // This adds specific allow rules without toggling setenforce.
        // SELinux stays Enforcing — no more permissive mode flapping.
        Thread {
            try {
                Thread.sleep(500) // Brief wait for su daemon
                val success = applySELinuxPolicy()
                if (!success) {
                    log("[FL] SELinux policy patch failed — service connection may fail")
                }
            } catch (e: Throwable) {
                log("[FL] patchSelinuxAsync error: $e")
            }
        }.apply { name = "FL-SEPolicy"; isDaemon = true }.start()
    }

    // ==================== DexLoader debug tracing ====================
    private fun hookDexLoaderDebug(cl: ClassLoader) {
        var hookCount = 0
        // Hook loadDynamicDex to log calls
        val loaderCls = try { cl.loadClass(CLS_ENF_LOADER) } catch (_: Exception) {
            log("[FL] DEX-DBG: DexLoader class not found"); return
        }
        for (m in loaderCls.declaredMethods) {
            if (!Modifier.isStatic(m.modifiers) || m.returnType != Void.TYPE) continue
            val params = m.parameterTypes
            if (params.size == 2 && params[0] == Context::class.java && params[1] == String::class.java) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val key = (param.args[1] as? String)?.take(30) ?: "null"
                        log("[FL] DEX-DBG: loadDynamicDex CALLED key=$key")
                    }
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.throwable != null) {
                            log("[FL] DEX-DBG: loadDynamicDex EXCEPTION: ${param.throwable}")
                        } else {
                            log("[FL] DEX-DBG: loadDynamicDex returned normally")
                        }
                    }
                })
                hookCount++
            }
            // Also hook loadDynamicDexInner (3 args: Context, String, String)
            if (params.size == 3 && params[0] == Context::class.java
                && params[1] == String::class.java && params[2] == String::class.java) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val data = (param.args[2] as? String)
                        log("[FL] DEX-DBG: loadDynamicDexInner CALLED dataLen=${data?.length ?: -1}")
                    }
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.throwable != null) {
                            log("[FL] DEX-DBG: loadDynamicDexInner EXCEPTION: ${param.throwable}")
                        } else {
                            log("[FL] DEX-DBG: loadDynamicDexInner completed")
                        }
                    }
                })
                hookCount++
            }
        }
        // Hook JedBlacklist.readBlacklist() to log return value
        try {
            val jedBlCls = cl.loadClass(CLS_JED_BL)
            for (m in jedBlCls.declaredMethods) {
                if (Modifier.isStatic(m.modifiers)) continue
                if (m.returnType == String::class.java && m.parameterTypes.isEmpty()
                    && m.name != "toString") {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            val result = param.result as? String
                            val desc = if (result.isNullOrBlank()) "EMPTY" else "${result.length}chars"
                            log("[FL] DEX-DBG: JedBL.${m.name}() => $desc")
                        }
                    })
                    hookCount++
                }
            }
        } catch (_: Exception) { log("[FL] DEX-DBG: JedBlacklist class not found") }
        log("[FL] DEX-DBG: $hookCount debug hooks installed")
    }

    private fun triggerJedDexLoading(cl: ClassLoader) {
        Thread {
            try {
                // Wait for SELinux patch + app init (async SELinux takes ~1-2s)
                Thread.sleep(5000)
                log("[FL] JED-TRIGGER: forcing BlacklistManager class init...")
                Class.forName(CLS_BLACKLIST, true, cl)
                log("[FL] JED-TRIGGER: BlacklistManager initialized (jed dex should load)")
            } catch (e: Throwable) {
                log("[FL] JED-TRIGGER: failed: $e")
            }
        }.apply { name = "FL-JedTrigger"; isDaemon = true }.start()
    }

    private fun sendAddXpServiceBroadcast(cl: ClassLoader) {
        Thread {
            try {
                // Wait for jed dex to finish loading + FL-Xposed receiver registration (5s delay in C0012)
                Thread.sleep(8000)
                val ctx = try {
                    Class.forName("android.app.ActivityThread")
                        .getMethod("currentApplication")
                        .invoke(null) as? android.content.Context
                } catch (_: Throwable) { null }
                if (ctx == null) {
                    log("[FL] Could not get FL app context for broadcast"); return@Thread
                }
                val action = "com.lerist.fakelocation.action.ADD_XP_SERVICE"
                // SELinux policy already patched at startup — no setenforce needed
                // Ensure policy is applied before sending broadcast
                applySELinuxPolicy()
                // Send broadcast multiple times
                for (i in 1..3) {
                    ctx.sendBroadcast(android.content.Intent(action))
                    log("[FL] Sent ADD_XP_SERVICE broadcast #$i from FL app")
                    Thread.sleep(2000)
                }
            } catch (e: Throwable) {
                log("[FL] ADD_XP_SERVICE broadcast from FL failed: $e")
            }
        }.apply { name = "FL-XpBroadcast"; isDaemon = true }.start()
    }

    private inline fun safeHook(name: String, block: () -> Unit) {
        try { block() } catch (e: Throwable) { log("[FL] SAFE-FAIL $name: ${e.message}") }
    }

    // ==================== Anti-Xposed detection bypass (cp2 + C5617) ====================
    private fun hookAntiXposedDetect(cl: ClassLoader) {
        var hooked = 0
        // cp2: Hook m1405() (isDebugMode) → false, m1404(Throwable) → noop, reset f2117
        try {
            val cp2Cls = cl.loadClass(CLS_DEBUG_DETECT)
            for (m in cp2Cls.declaredMethods) {
                if (Modifier.isStatic(m.modifiers) && m.returnType == Boolean::class.javaPrimitiveType && m.parameterTypes.isEmpty()) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = false
                        }
                    })
                    hooked++
                }
                // m1404(Throwable) → noop (prevents stack trace scanning)
                if (Modifier.isStatic(m.modifiers) && m.returnType == Void.TYPE
                    && m.parameterTypes.size == 1 && m.parameterTypes[0] == Throwable::class.java) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                        }
                    })
                    hooked++
                }
            }
            // Reset the debug flag
            try {
                val f = cp2Cls.getDeclaredField("f2117")
                f.isAccessible = true
                f.setBoolean(null, false)
                hooked++
            } catch (_: Throwable) {}
        } catch (e: Throwable) { log("[FL] DETECT cp2 FAILED: ${e.message}") }

        // C5617: antiDebugCheck() → noop
        try {
            val antiCls = cl.loadClass(CLS_ANTI_DEBUG)
            for (m in antiCls.declaredMethods) {
                if (Modifier.isStatic(m.modifiers) && m.returnType == Void.TYPE && m.parameterTypes.isEmpty()) {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = null
                        }
                    })
                    hooked++
                }
            }
        } catch (e: Throwable) { log("[FL] DETECT C5617 FAILED: ${e.message}") }
        log("[FL] AntiXposedDetect: $hooked hooks installed")
    }

    // ==================== Blacklist UI bypass ====================
    private fun hookBlacklistManager(cl: ClassLoader) {
        val blCls: Class<*>
        val cfgCls: Class<*>
        try {
            blCls = cl.loadClass(CLS_BLACKLIST)
            cfgCls = cl.loadClass(CLS_CONFIG)
        } catch (e: ClassNotFoundException) {
            log("[FL] BL: class NOT FOUND: ${e.message}"); return
        }

        var hooked = 0
        for (m in blCls.declaredMethods) {
            if (!Modifier.isStatic(m.modifiers)) continue
            when {
                // boolean(String) → true
                m.returnType == Boolean::class.javaPrimitiveType
                    && m.parameterTypes.size == 1
                    && m.parameterTypes[0] == String::class.java -> {
                    XposedBridge.hookMethod(m, hookReturnTrue); hooked++
                }
                // boolean(String, boolean) → true
                m.returnType == Boolean::class.javaPrimitiveType
                    && m.parameterTypes.size == 2
                    && m.parameterTypes[0] == String::class.java
                    && m.parameterTypes[1] == Boolean::class.javaPrimitiveType -> {
                    XposedBridge.hookMethod(m, hookReturnTrue); hooked++
                }
                // void(Config) → neutralize config
                m.returnType == Void.TYPE
                    && m.parameterTypes.size == 1
                    && m.parameterTypes[0] == cfgCls -> {
                    XposedBridge.hookMethod(m, hookNeutralizeConfig); hooked++
                }
            }
        }
        log("[FL] BL-UI: $hooked methods hooked")
    }

    // ==================== Blacklist transport ====================
    private fun hookBlacklistTransport(cl: ClassLoader) {
        try {
            val svcCls = cl.loadClass(CLS_SERVICE)
            val listMethods = svcCls.declaredMethods.filter { m ->
                !Modifier.isStatic(m.modifiers)
                    && m.returnType == Void.TYPE
                    && m.parameterTypes.size == 1
                    && m.parameterTypes[0] == List::class.java
            }
            var svcHooked = 0
            for (m in listMethods) {
                var isStringList = false
                try {
                    val genType = m.genericParameterTypes[0]
                    if (genType is ParameterizedType) {
                        isStringList = genType.actualTypeArguments.firstOrNull() == String::class.java
                    }
                } catch (_: Throwable) {}
                if (!isStringList) {
                    log("[FL] TRANSPORT-svc: SKIP ${m.name} (not List<String>)")
                    continue
                }
                m.isAccessible = true
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val orig = param.args[0] as? List<*>
                        param.args[0] = ArrayList(DUMMY_BLACKLIST)
                        log("[FL] TRANSPORT-svc: ${(param.method as java.lang.reflect.Method).name} -> dummy (was ${orig?.size ?: 0})")
                    }
                })
                svcHooked++
            }
            log("[FL] TRANSPORT-svc: $svcHooked methods hooked (of ${listMethods.size} candidates)")
        } catch (e: Exception) {
            log("[FL] TRANSPORT-svc FAILED: ${e.message}")
        }

        try {
            val defCls = cl.loadClass(CLS_DEFAULTS)
            val m14591 = defCls.declaredMethods.firstOrNull { m ->
                Modifier.isStatic(m.modifiers)
                    && m.returnType == ArrayList::class.java
                    && m.parameterTypes.isEmpty()
            }
            if (m14591 != null) {
                XposedBridge.hookMethod(m14591, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = ArrayList<String>()
                    }
                })
                log("[FL] TRANSPORT-defaults: C3131 -> empty")
            }
        } catch (e: Exception) {
            log("[FL] TRANSPORT-defaults FAILED: ${e.message}")
        }
    }

    // ==================== Enforcement bypass (C2553 app-side) ====================
    private fun hookEnforcementBypass(cl: ClassLoader) {
        val enfCls = try { cl.loadClass(CLS_ENFORCER) } catch (_: Exception) {
            log("[FL] ENFORCE: NOT FOUND"); return
        }
        var hooked = 0
        for (m in enfCls.declaredMethods) {
            if (Modifier.isStatic(m.modifiers)) continue
            if (m.returnType == Boolean::class.javaPrimitiveType
                && m.parameterTypes.size == 1
                && m.parameterTypes[0] == String::class.java
            ) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = true
                    }
                })
                hooked++; log("[FL] ENFORCE: ${m.name}(String)->true")
            }
            if (m.returnType == Void.TYPE
                && m.parameterTypes.size == 1
                && m.parameterTypes[0] == Location::class.java
            ) {
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                    }
                })
                hooked++; log("[FL] ENFORCE: ${m.name}(Location)->noop")
            }
        }
        log("[FL] ENFORCE: $hooked methods")
    }

    // ==================== Enforcement guard ====================
    // RouteController.pause() is NO LONGER blocked — user can pause/resume freely.
    // Enforcement path is already cut at enforceLocation() → no-op.
    // hookStopMockBlock now only hooks checkForegroundAllowed as extra safety.
    private fun hookStopMockBlock(cl: ClassLoader) {
        // Extra safety: force checkForegroundAllowed → true
        // (enforceLocation is already no-op, this is belt-and-suspenders)
        try {
            val enfCls = cl.loadClass(CLS_ENFORCER)
            for (m in enfCls.declaredMethods) {
                if (m.returnType == Boolean::class.javaPrimitiveType
                    && m.parameterTypes.size == 1
                    && m.parameterTypes[0] == String::class.java
                    && !Modifier.isStatic(m.modifiers)
                ) {
                    // Already hooked in hookEnforcementBypass, but log here for clarity
                    log("[FL] GUARD: checkForegroundAllowed already hooked via enforcementBypass")
                }
            }
        } catch (e: Exception) {
            log("[FL] GUARD: ${e.message}")
        }
        log("[FL] GUARD: pause() NOT blocked (user control allowed)")
    }

    // ==================== DexLoader block (ft0) ====================
    private fun hookDexLoader(cl: ClassLoader) {
        val loaderCls = try { cl.loadClass(CLS_ENF_LOADER) } catch (_: Exception) {
            log("[FL] DexLoader NOT FOUND"); return
        }
        var hooked = 0
        for (m in loaderCls.declaredMethods) {
            if (!Modifier.isStatic(m.modifiers) || m.returnType != Void.TYPE) continue
            val params = m.parameterTypes
            if ((params.size == 2 && params[0] == Context::class.java && params[1] == String::class.java) ||
                (params.size == 3 && params[0] == Context::class.java && params[1] == String::class.java && params[2] == String::class.java)) {
                m.isAccessible = true
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                        log("[FL] DEX-BLOCK: ${m.name}(${params.size} args) → noop")
                    }
                })
                hooked++
            }
        }
        log("[FL] DexLoader: $hooked methods blocked")
    }

    // ==================== Disabled lists bypass ====================
    private fun hookDisabledLists(cl: ClassLoader) {
        val blCls = try { cl.loadClass(CLS_BLACKLIST) } catch (_: Exception) {
            log("[FL] DisabledLists: NOT FOUND"); return
        }
        var hooked = 0
        for (m in blCls.declaredMethods) {
            if (!Modifier.isStatic(m.modifiers)) continue
            if (m.parameterTypes.isNotEmpty()) continue
            if (List::class.java.isAssignableFrom(m.returnType)) {
                m.isAccessible = true
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = ArrayList<String>()
                    }
                })
                hooked++
            }
        }
        log("[FL] DisabledLists: $hooked static List() methods → empty")
    }

    // ==================== Token verifier block (tc2) ====================
    private fun hookTokenVerifier(cl: ClassLoader) {
        val tc2Cls = try { cl.loadClass(CLS_TOKEN_CHECKER) } catch (_: Exception) {
            log("[FL] TokenVerifier NOT FOUND"); return
        }
        var hooked = 0
        // m8669 is the only static synchronized void(1-arg) method — the token validation entry point
        for (m in tc2Cls.declaredMethods) {
            if (Modifier.isStatic(m.modifiers)
                && m.returnType == Void.TYPE
                && m.parameterTypes.size == 1
                && m.parameterTypes[0].isInterface
            ) {
                m.isAccessible = true
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                        log("[FL] TOKEN-CHECK: blocked server validation")
                        // Call onFinish() so UI doesn't hang waiting
                        try {
                            val cb = param.args[0] ?: return
                            for (cbm in cb.javaClass.declaredMethods) {
                                if (cbm.name == "onFinish" && cbm.parameterTypes.isEmpty()) {
                                    cbm.isAccessible = true
                                    cbm.invoke(cb)
                                    break
                                }
                            }
                        } catch (_: Throwable) {}
                    }
                })
                hooked++
            }
        }
        log("[FL] TokenVerifier: $hooked methods blocked")
    }

    // ==================== Pro validator bypass (pc2) ====================
    // pc2 logic:
    //   m7043() = currentTime >= m7047()  → true = EXPIRED (bad)
    //   m7044() = currentTime >= m7051()  → true = EXPIRED (bad)
    //   m7049() = !m7044() && !m7043()    → true = Pro valid (good)
    //   m7050() = f9496.equals(m7045())   → true = type match (good)
    // Strategy: hook Long returns → MAX_VALUE so m7043/m7044 compute false naturally;
    //           hook String returns → non-null to prevent NPE;
    //           do NOT blanket-hook booleans (m7043/m7044 would become true = "expired")
    private fun hookProValidator(cl: ClassLoader) {
        val pc2Cls = try { cl.loadClass(CLS_PRO_VALIDATOR) } catch (_: Exception) {
            log("[FL] ProValidator NOT FOUND"); return
        }
        var hooked = 0
        for (m in pc2Cls.declaredMethods) {
            if (!Modifier.isStatic(m.modifiers)) continue
            m.isAccessible = true
            when {
                // m7047() m7051() expiry timestamps → far future (so m7043/m7044 return false)
                m.returnType == Long::class.javaPrimitiveType && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = Long.MAX_VALUE
                            log("[FL] PRO-VAL: ${m.name}() → MAX_VALUE")
                        }
                    })
                    hooked++
                }
                // m7045() m7046() m7048() token/key strings → non-null dummy
                m.returnType == String::class.java && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = "fxxk_pro"
                        }
                    })
                    hooked++
                }
            }
        }
        // Also patch the static f9497 (cached isPro) and f9496 (expected type) fields
        try {
            val cachedField = pc2Cls.getDeclaredField("f9497")
            cachedField.isAccessible = true
            cachedField.setBoolean(null, true)
            hooked++
        } catch (_: Throwable) {}
        try {
            // Set f9496 (expected type string) to match our m7045() return "fxxk_pro"
            val typeField = pc2Cls.getDeclaredField("f9496")
            typeField.isAccessible = true
            typeField.set(null, "fxxk_pro")
            hooked++
        } catch (_: Throwable) {}
        log("[FL] ProValidator: $hooked methods/fields hooked")
    }

    // ==================== User session (C2124) ====================
    private fun hookUserSession(cl: ClassLoader) {
        val sessCls = try { cl.loadClass(CLS_USER_SESSION) } catch (_: Exception) {
            log("[FL] Session NOT FOUND"); return
        }
        val userModelCls = try { cl.loadClass(CLS_USER_MODEL) } catch (_: Exception) { null }
        var hooked = 0
        for (m in sessCls.declaredMethods) {
            m.isAccessible = true
            when {
                m.returnType == Boolean::class.javaPrimitiveType && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, hookReturnTrue); hooked++
                }
                m.returnType == Int::class.javaPrimitiveType && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, hookReturnInt99); hooked++
                }
                m.returnType == Long::class.javaPrimitiveType && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, hookReturnFutureLong); hooked++
                }
                m.returnType == String::class.java && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            if (param.result == null) param.result = "fxxk_dummy"
                        }
                    }); hooked++
                }
                m.returnType == Void.TYPE && m.parameterTypes.size == 1
                    && userModelCls != null && m.parameterTypes[0] == userModelCls -> {
                    XposedBridge.hookMethod(m, hookPatchUserModel); hooked++
                }
                m.returnType == userModelCls && m.parameterTypes.isEmpty() -> {
                    XposedBridge.hookMethod(m, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            if (param.result == null && userModelCls != null) {
                                val model = userModelCls.newInstance()
                                patchUserModelFull(model)
                                param.result = model
                            } else if (param.result != null) {
                                patchUserModelFull(param.result!!)
                            }
                        }
                    }); hooked++
                }
            }
        }
        log("[FL] Session: $hooked methods")
    }

    // ==================== User model (qc2) ====================
    private fun hookUserModel(cl: ClassLoader) {
        val qc2 = try { cl.loadClass(CLS_USER_MODEL) } catch (_: Exception) {
            log("[FL] Model NOT FOUND"); return
        }
        var hooked = 0
        for (m in qc2.declaredMethods) {
            when (m.name) {
                "getIdentity"  -> { XposedBridge.hookMethod(m, hookReturnInt99); hooked++ }
                "getType"      -> { XposedBridge.hookMethod(m, hookReturnInt1); hooked++ }
                "getProindate" -> { XposedBridge.hookMethod(m, hookReturnFutureLong); hooked++ }
                "getToken"     -> { XposedBridge.hookMethod(m, hookReturnDummyString); hooked++ }
                "getKey"       -> { XposedBridge.hookMethod(m, hookReturnDummyString); hooked++ }
                "getUserId"    -> { XposedBridge.hookMethod(m, hookReturnDummyString); hooked++ }
                "getUserName"  -> { XposedBridge.hookMethod(m, hookReturnProString); hooked++ }
            }
        }
        log("[FL] Model: $hooked methods")
    }

    // ==================== Shared callbacks ====================
    private val hookReturnTrue = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) { p.result = true }
    }
    private val hookReturnInt99 = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) { p.result = 99 }
    }
    private val hookReturnInt1 = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) { p.result = 1 }
    }
    private val hookReturnFutureLong = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) { p.result = 4070908800000L }
    }
    private val hookNeutralizeConfig = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) {
            val cfg = p.args[0] ?: return
            try {
                val clz = cfg.javaClass
                clz.getField("isAllowRun").setInt(cfg, 1)
                clz.getField("notice").set(cfg, "")
                clz.getField("disas").set(cfg, null)
                clz.getField("disfs").set(cfg, null)
                clz.getField("disis").set(cfg, null)
            } catch (_: Exception) {}
        }
    }
    private val hookPatchUserModel = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) {
            val u = p.args[0]
            if (u == null) {
                // Block setUserModel(null) — prevents logout/session clearing
                p.result = null
                log("[FL] BLOCKED setUserModel(null) — preventing logout")
                return
            }
            patchUserModelFull(u)
        }
    }
    private val hookReturnDummyString = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) { p.result = "fxxk_dummy" }
    }
    private val hookReturnProString = object : XC_MethodHook() {
        override fun beforeHookedMethod(p: MethodHookParam) { p.result = "Pro" }
    }

    private fun patchUserModelFull(u: Any) {
        try {
            val clz = u.javaClass
            clz.getField("identity").setInt(u, 99)
            clz.getField("type").setInt(u, 1)
            clz.getField("proindate").setLong(u, 4070908800000L)
            clz.getField("token").set(u, "fxxk_pro_token")
            clz.getField("key").set(u, "fxxk_pro_key")
        } catch (_: Exception) {}
        try {
            val clz = u.javaClass
            clz.getDeclaredField("userId").apply { isAccessible = true }.set(u, "fxxk_user")
            clz.getDeclaredField("userName").apply { isAccessible = true }.set(u, "Pro")
            clz.getDeclaredField("loginType").apply { isAccessible = true }.set(u, "xposed")
            clz.getDeclaredField("loginName").apply { isAccessible = true }.set(u, "FxxkLocation")
            clz.getDeclaredField("loginTime").apply { isAccessible = true }.setLong(u, System.currentTimeMillis())
        } catch (_: Exception) {}
    }
}
