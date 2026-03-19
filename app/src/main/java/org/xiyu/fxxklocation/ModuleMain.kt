package org.xiyu.fxxklocation

import android.app.Application
import android.content.Context
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage

class ModuleMain : IXposedHookLoadPackage, IXposedHookZygoteInit {

    @Volatile internal var hooked = false
    @Volatile internal var sysHooked = false
    @Volatile internal var mlBinderHooked = false
    @Volatile internal var ourMlBinder: MockLocationBinder? = null
    internal val bypassRemoveProvider = ThreadLocal<Boolean>()

    // Active GNSS injection state (system_server)
    internal val sysGnssListeners = java.util.concurrent.CopyOnWriteArrayList<Any>()
    @Volatile internal var sysGnssFeederStarted = false
    @Volatile internal var sysClassLoader: ClassLoader? = null

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        log("[ZYGOTE] initZygote: installing global step sensor hook")
        ZygoteStepHook.install()
    }

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
                sysClassLoader = lpparam.classLoader
                hookSystemServer()
            }

            // ===== Layer 3: target app anti-mock-detection =====
            else -> {
                hookAntiMockDetection()
            }
        }
    }
}
