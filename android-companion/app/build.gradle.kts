plugins {
    id("com.android.application")
}

android {
    namespace = "com.identityshield.companion"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.identityshield.companion"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    // PUBLIC debug-only key, committed so every builder produces the same debug
    // signing fingerprint. Standard well-known debug credentials ("android").
    // NEVER use it to sign a release build. Release signing is not configured here.
    signingConfigs {
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
