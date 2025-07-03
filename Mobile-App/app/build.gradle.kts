plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("kotlin-kapt") // لتشغيل Annotation Processing
}

android {
    namespace = "com.example.possible"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.possible"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    // Room Runtime (يتضمن Room الأساسية)
    implementation("androidx.room:room-runtime:2.6.1")

    // Room Compiler (لعملية Annotation Processing)
    kapt("androidx.room:room-compiler:2.6.1")

    // Room مع دعم Kotlin Extensions و Coroutines
    implementation("androidx.room:room-ktx:2.6.1")

    // Coroutines الأساسية
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")

    // Coroutines لدعم Android
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    // Glide لتحميل وعرض الصور
    implementation("com.github.bumptech.glide:glide:4.16.0")

    // معالج الشروح (Annotation Processor) لـ Glide
    kapt("com.github.bumptech.glide:compiler:4.16.0")
// Lottie للرسوم المتحركة
    implementation("com.airbnb.android:lottie:6.3.0")
    implementation ("androidx.appcompat:appcompat:1.6.1")
    implementation ("com.google.android.material:material:1.9.0")
    //dots indicator
    implementation ("com.tbuonomo:dotsindicator:4.3")


    //Retrofit
    implementation ("com.squareup.retrofit2:retrofit:2.9.0") // Retrofit
    implementation ("com.squareup.retrofit2:converter-gson:2.9.0") // Gson Converter (لتحويل JSON إلى كائنات Java/Kotlin)
    implementation ("com.squareup.okhttp3:logging-interceptor:4.9.3") // OkHttp Logging Interceptor (اختياري، لتسجيل طلبات الشبكة)
    //viewmodel
    implementation ("androidx.lifecycle:lifecycle-viewmodel-ktx:2.6.2")
    implementation ("com.squareup.retrofit2:converter-scalars:2.9.0")
}