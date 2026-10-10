plugins { id("com.android.application") }
android { namespace="com.cybershield.ai"; compileSdk=35; defaultConfig { applicationId="com.cybershield.ai"; minSdk=26; targetSdk=35; versionCode=1; versionName="1.0" } }
dependencies { /* Pin: org.pytorch:executorch-android:<validated-version> */ }
