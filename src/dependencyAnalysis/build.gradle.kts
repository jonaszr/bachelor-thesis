import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile

val kotlinVersion = "1.9.24"

plugins {
    `java-library`
    application
    kotlin("jvm") version "1.9.24"
    id("com.google.devtools.ksp") version "1.9.24-1.0.20"
    id("org.jetbrains.kotlinx.dataframe") version "0.13.1"
    id ("com.github.ben-manes.versions") version "0.51.0"
    kotlin("plugin.serialization") version "1.9.24"
}

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    implementation("com.google.dagger:dagger-compiler:2.51.1")
    ksp("com.google.dagger:dagger-compiler:2.51.1")
    
    implementation("ch.qos.logback:logback-classic:1.5.7")
    implementation("ch.qos.logback:logback-core:1.5.7")
    
    implementation("com.github.javaparser:javaparser-core-serialization:3.26.1")
    implementation("com.github.javaparser:javaparser-symbol-solver-core:3.26.1")
    implementation("com.github.oshi:oshi-core:6.6.3")
    
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("com.squareup.moshi:moshi:1.15.1")
    implementation("io.github.cdimascio:dotenv-kotlin:6.4.1")
    implementation("io.github.classgraph:classgraph:4.8.166-SNAPSHOT")

    implementation("org.apache.commons:commons-compress:1.27.1")
    implementation("org.eclipse.jgit:org.eclipse.jgit:6.10.0.202406032230-r")
    implementation("org.jbpt:jbpt-deco:0.3.1")
    
    implementation("org.jetbrains.kotlin:kotlin-reflect:$kotlinVersion")
    implementation("org.jetbrains.kotlin:kotlin-scripting-common:$kotlinVersion")
    implementation("org.jetbrains.kotlin:kotlin-scripting-dependencies:$kotlinVersion")
    implementation("org.jetbrains.kotlin:kotlin-scripting-dependencies-maven:$kotlinVersion")
    implementation("org.jetbrains.kotlin:kotlin-scripting-jvm:$kotlinVersion")
    implementation(kotlin("stdlib-jdk8"))
    // implementation("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")

    implementation("org.jetbrains.kotlinx:dataframe:0.13.1")
    implementation("org.jetbrains.kotlinx:kandy-api:0.6.0")
    implementation("org.jetbrains.kotlinx:kandy-echarts:0.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.jetbrains.lets-plot:lets-plot-image-export:4.3.2")
    implementation("org.jetbrains.lets-plot:lets-plot-kotlin:4.7.2")
    implementation("org.jetbrains.lets-plot:lets-plot-kotlin-jvm:4.7.2")
    implementation("org.jetbrains.lets-plot:platf-awt-jvm:4.3.2")
    
    implementation("org.jgrapht:jgrapht-core:1.5.2")
    implementation("org.jgrapht:jgrapht-guava:1.5.2")
    implementation("org.jgrapht:jgrapht-io:1.5.2")
    implementation("org.jgrapht:jgrapht-opt:1.5.2")
    
    implementation("org.litote.kmongo:kmongo:5.1.0")
    implementation("org.lz4:lz4-java:1.8.0")
    implementation("org.mongodb:mongodb-driver-kotlin-coroutine:5.1.3")
    implementation("org.mongodb:mongodb-driver-kotlin-sync:5.1.3")
    implementation("org.nield:kotlin-statistics:1.2.1")
}

group = "ca.uwaterloo"
version = "1.0.0"
description = "dependencyAnalysis"

kotlin {
    jvmToolchain(11)
}

val _jvmOptions = listOf(
    "--add-opens",
    "java.base/java.util=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.lang=ALL-UNNAMED",
    "--add-opens",
    "java.base/jdk.internal=ALL-UNNAMED",
    "--add-opens",
    "java.base/jdk.internal.reflect=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.io=ALL-UNNAMED",
    "--add-opens",
    "java.base/java.nio=ALL-UNNAMED",
    "--add-opens",
    "java.base/sun.nio.ch=ALL-UNNAMED",
    "--add-opens",
    "java.base/sun.net=ALL-UNNAMED",
    "--add-opens",
    "java.base/sun.net.www=ALL-UNNAMED",
)

application {
    applicationDefaultJvmArgs += _jvmOptions
}

tasks.withType<KotlinJvmCompile> {
    kotlinOptions {
        freeCompilerArgs += "-Xdebug"
    }
}

