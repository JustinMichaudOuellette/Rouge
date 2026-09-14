plugins {
  alias(libs.plugins.android.application)
}

// tools/release.py builds one optimized APK per minimum SDK by running
// `./gradlew :app:assembleRelease -PminSdk=<n>` once per value, so this has to
// be a property rather than a constant.  The fallback keeps a plain
// `./gradlew :app:assembleRelease` byte-identical to before the property
// existed.
val minSdkOverride = (findProperty("minSdk") as String?)?.toIntOrNull() ?: 37

android {
  namespace = "ca.justinmo.r"
  compileSdk = 37

  defaultConfig {
    applicationId = "ca.justinmo.r"
    minSdk = minSdkOverride
    targetSdk = 37
    versionCode = 1
    versionName = "1"
  }

  buildTypes {
    release {
      isMinifyEnabled = true
      isShrinkResources = true
      vcsInfo.include = false
      signingConfig = signingConfigs.getByName("debug")
      proguardFiles(
        getDefaultProguardFile("proguard-android-optimize.txt"),
        "proguard-rules.pro"
      )
    }
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
  }
}
