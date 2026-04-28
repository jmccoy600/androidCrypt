plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.androidcrypt"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.androidcrypt"
        minSdk = 24
        targetSdk = 36
        versionCode = 14
        versionName = "1.0.14"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Sign release builds with the debug keystore so they can be
            // installed directly. Replace with a production signing config
            // before distributing to users.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    testOptions {
        unitTests.isReturnDefaultValues = true  // android.util.Log → no-op in JVM unit tests
        unitTests.all { test ->
            // Make the Linux host build of libxts_aes_native.so visible to the JVM test runner
            val nativeLibDir = layout.projectDirectory.dir("src/test/resources/lib/linux-x86_64").asFile
            test.jvmArgs("-Djava.library.path=${nativeLibDir.absolutePath}")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    ndkVersion = "28.2.13676358"
    buildToolsVersion = "36.0.0"
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.documentfile:documentfile:1.0.1")
    testImplementation(libs.junit)
    // Kotest property-based testing (shrinking-capable Arb generators).
    // Used standalone via io.kotest.property.checkAll inside JUnit4 @Test fns.
    testImplementation("io.kotest:kotest-property:5.9.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.1")
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}