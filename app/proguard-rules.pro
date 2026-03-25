# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Strip verbose/debug/info log calls from release builds to prevent
# information leakage of volume metadata, cluster counts, timing data, etc.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Keep JNI native method names (called from Kotlin via external fun)
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep crypto classes that are accessed via reflection or JNI
-keep class com.androidcrypt.crypto.NativeXTS { *; }
-keep class com.androidcrypt.crypto.NativeSerpentXTS { *; }
-keep class com.androidcrypt.crypto.NativeTwofishXTS { *; }
-keep class com.androidcrypt.crypto.NativeCascadeXTS { *; }
-keep class com.androidcrypt.crypto.NativeCascadeSTA_XTS { *; }

# Keep DocumentsProvider (accessed by system via manifest)
-keep class com.androidcrypt.app.VeraCryptDocumentsProvider { *; }

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile