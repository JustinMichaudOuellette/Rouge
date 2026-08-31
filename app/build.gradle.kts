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

  androidResources {
    localeFilters += "en"
  }

  buildFeatures {
    buildConfig = false
    resValues = false
    aidl = false
    renderScript = false
    shaders = false
  }

  buildTypes {
    release {
      isMinifyEnabled = true
      isShrinkResources = true
      vcsInfo.include = false
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
  packaging {
    resources {
      excludes += "META-INF/**"
    }
  }
}

androidComponents {
  onVariants(selector().all()) { variant ->
    variant.packaging.resources.excludes.add("META-INF/com/android/build/gradle/app-metadata.properties")
  }
}

tasks.matching { it.name.contains("appMetadata", ignoreCase = true) }.configureEach {
  enabled = false
}

dependencies {
}
