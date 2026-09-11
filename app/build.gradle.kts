plugins {
  alias(libs.plugins.android.application)
}

android {
  namespace = "ca.justinmo.r"
  compileSdk = 37

  defaultConfig {
    applicationId = "ca.justinmo.r"
    minSdk = 37
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
