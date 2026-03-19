package de.robv.android.xposed;

/** Compile-time stub for IXposedHookZygoteInit (provided by Xposed at runtime) */
public interface IXposedHookZygoteInit {
    void initZygote(StartupParam startupParam) throws Throwable;

    final class StartupParam {
        public String modulePath;
        public boolean startsSystemServer;
    }
}
