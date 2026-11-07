#!/usr/bin/env bash
PKG=com.istorychnirozumy.vartovipravdy
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb shell getprop ro.build.version.release
adb shell dumpsys package com.google.android.webview | grep -m1 versionName || true
adb logcat -c
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
for t in 5 15 30; do
  sleep $([ $t = 5 ] && echo 5 || echo 10)
  echo "=== after ${t}s: process alive? ==="; adb shell pidof $PKG || echo "NOT RUNNING"
done
echo "=== CRASH / ERRORS ==="
adb logcat -d -b crash | tail -80
adb logcat -d | grep -E "AndroidRuntime|FATAL|OutOfMemory|lowmemorykiller|Capacitor|chromium|cr_|WebView|ActivityManager.*$PKG|Console" | tail -150
echo "=== screen ==="
adb shell dumpsys activity activities | grep -E "mResumedActivity|topResumedActivity" || true
