---
id: "mobile-application-testing"
title: "Mobile Application Testing Methodology - OWASP MASTG Aligned"
type: "methodology"
category: "mobile"
subcategory: "android"
tags: ["mobile", "android", "ios", "owasp-mastg", "masvs", "static-analysis", "dynamic-analysis", "frida", "binary-analysis", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["frida-apk-testing", "api-penetration-testing"]
updated: "2026-04-14"
---

## Overview

Mobile application testing combines static analysis (code/binary review), dynamic analysis (runtime instrumentation), network analysis (API traffic), and binary analysis (reverse engineering). Aligned with OWASP MASTG (Mobile Application Security Testing Guide) and MASVS (Mobile Application Security Verification Standard). Mobile bugs often chain to high-severity: hardcoded secrets, insecure storage, and API auth bypass. Payout: $500-$25k+.

## Phase 1: Setup & Reconnaissance

### Android setup
```bash
# Get the APK
# From device
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/.../base.apk

# From stores
apkeep -a com.target.app -d google-play .
# Or: apkpure.com, apkmirror.com

# Emulator with root (for testing)
# Android Studio AVD with Google APIs (not Play Store) image
# Or: Genymotion with root

# Install Frida
pip install frida-tools
adb push frida-server-android-arm64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
```

### iOS setup
```bash
# Get the IPA
# Jailbroken device: use frida-ios-dump or CrackerXI
# Or: decrypt from App Store with bagbak

# Frida on iOS
# Jailbroken: install via Cydia/Sileo
# Non-jailbroken: use frida-gadget injection
```

### Basic app information
```bash
# Android manifest analysis
apktool d target.apk -o target_decompiled
cat target_decompiled/AndroidManifest.xml
# Check: exported components, permissions, deeplinks, backup enabled

# iOS Info.plist
plutil -p Payload/App.app/Info.plist
# Check: URL schemes, ATS exceptions, background modes
```

## Phase 2: Static Analysis

### Automated scanning
```bash
# MobSF (Mobile Security Framework)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK/IPA via web UI
# Review: hardcoded secrets, insecure storage, weak crypto, exported components

# Android-specific
# Decompile to Java source
jadx -d output/ target.apk
# Or: apktool for smali, then smali2java

# iOS-specific
# class-dump for headers
class-dump -H App.app -o headers/
```

### Manual code review targets
```bash
# Hardcoded secrets
grep -rE "(api[_-]?key|secret|password|token|auth|bearer)" --include="*.java" --include="*.xml" .
grep -rE "(https?://[^ ]+)" --include="*.java" .  # API endpoints
grep -rE "(BEGIN (RSA|EC|DSA|PRIVATE))" .  # Private keys

# Firebase misconfigurations
grep -rE "firebaseio\.com|firebase\.google\.com" .
# Test: https://PROJECT.firebaseio.com/.json (unauthenticated read)

# AWS keys
grep -rE "AKIA[A-Z0-9]{16}" .
grep -rE "amzn\\.mws\\.[0-9a-f]{8}" .

# Insecure data storage
grep -rE "SharedPreferences|getSharedPreferences" --include="*.java" .
grep -rE "openFileOutput|MODE_WORLD_READABLE" --include="*.java" .
grep -rE "SQLiteDatabase|openOrCreateDatabase" --include="*.java" .
# iOS: NSUserDefaults, Keychain (check accessibility level), CoreData, plist

# Weak cryptography
grep -rE "DES|RC4|MD5|SHA1|ECB" --include="*.java" .
grep -rE "SecretKeySpec|Cipher.getInstance" --include="*.java" .

# WebView vulnerabilities
grep -rE "setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess" --include="*.java" .
grep -rE "loadUrl|evaluateJavascript" --include="*.java" .

# Deeplink handling (intent-based attacks)
grep -rE "intent-filter|scheme=|host=" AndroidManifest.xml
# Test: adb shell am start -a android.intent.action.VIEW -d "scheme://path?param=evil"
```

### Binary analysis
```bash
# Check binary protections
# Android
apkinfo target.apk  # Check for debuggable, backup

# iOS
otool -l App.app/App | grep -A2 LC_ENCRYPTION  # Encryption
otool -hv App.app/App  # PIE check
codesign -dvvv App.app  # Entitlements
```

## Phase 3: Dynamic Analysis

### SSL pinning bypass
```javascript
// Frida universal SSL pinning bypass
// frida -U -f com.target.app -l ssl_bypass.js

Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', 
        '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
    };
});

// Or use objection
// objection -g com.target.app explore
// android sslpinning disable
```

### Runtime hooking
```javascript
// Hook login function to see credentials
Java.perform(function() {
    var LoginActivity = Java.use('com.target.app.LoginActivity');
    LoginActivity.login.implementation = function(username, password) {
        console.log('[+] Login: ' + username + ':' + password);
        return this.login(username, password);
    };
});

// Hook encryption/decryption
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[+] Cipher input: ' + byteArrayToHex(input));
        var result = this.doFinal(input);
        console.log('[+] Cipher output: ' + byteArrayToHex(result));
        return result;
    };
});

// Dump all method calls on a class
Java.perform(function() {
    var target = Java.use('com.target.app.SecretClass');
    var methods = target.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log('[+] Method: ' + method.getName());
    });
});
```

### Root/jailbreak detection bypass
```javascript
// Frida root detection bypass
Java.perform(function() {
    // Common root checks
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
    
    // File existence checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        if (name.indexOf('su') !== -1 || name.indexOf('Superuser') !== -1 
            || name.indexOf('magisk') !== -1) {
            return false;
        }
        return this.exists();
    };
});
```

### Data storage inspection
```bash
# Android
adb shell run-as com.target.app ls /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
# Pull and inspect SQLite databases

# iOS (jailbroken)
find /var/mobile/Containers/Data/Application/ -name "*.sqlite" -o -name "*.plist"
# Check Keychain: keychain-dumper
```

## Phase 4: Network Analysis

### Traffic interception
```bash
# Proxy setup
# Burp Suite / mitmproxy with device-trusted CA
# Android: install CA in user certs (Android 7+: need network_security_config bypass)
# iOS: install profile via Settings

# Capture all traffic
mitmproxy -p 8080 -w captured_traffic.flow

# Focus areas:
# - Authentication tokens in headers/cookies
# - API endpoints and parameters
# - Unencrypted HTTP traffic
# - Certificate pinning errors (indicates custom pinning)
```

### API testing from mobile
```
# Common mobile API vulnerabilities:
# - No rate limiting on OTP verification
# - JWT with weak secrets
# - Device ID as sole authentication factor
# - Hardcoded API keys granting excessive access
# - Different auth for mobile vs web (mobile often weaker)
# - Push notification token leakage
# - In-app purchase receipt validation bypass
```

## Phase 5: Component Testing

### Exported components (Android)
```bash
# Find exported activities/services/receivers
drozer console connect
run app.activity.info -a com.target.app
run app.service.info -a com.target.app
run app.broadcast.info -a com.target.app
run app.provider.info -a com.target.app

# Test content providers
run app.provider.query content://com.target.app.provider/users
run app.provider.read content://com.target.app.provider/../../etc/passwd  # Path traversal
run scanner.provider.injection -a com.target.app  # SQLi in content providers

# Test deeplinks
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://auth/callback?token=stolen" com.target.app
```

### WebView attacks
```javascript
// If addJavascriptInterface is used (Android < 4.2: RCE)
// Test XSS in WebViews loading user-controlled content
// Check file:// access in WebViews (local file read)

// Frida: hook WebView.loadUrl to see all loaded URLs
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[+] WebView loading: ' + url);
        this.loadUrl(url);
    };
});
```

## Testing Checklist (MASVS Aligned)

```
STORAGE:
[ ] Sensitive data not stored in plaintext (SharedPrefs, NSUserDefaults, SQLite)
[ ] Keychain/Keystore used correctly for secrets
[ ] No sensitive data in logs (adb logcat / Console.app)
[ ] No sensitive data in backups
[ ] Clipboard data cleared for sensitive fields
[ ] No sensitive data in screenshots/task switcher

CRYPTO:
[ ] No hardcoded encryption keys
[ ] No weak algorithms (DES, RC4, MD5, SHA1)
[ ] Proper key storage (Keystore/Keychain, not SharedPrefs)
[ ] Secure random number generation

AUTH:
[ ] Token-based auth (not just device ID)
[ ] Session invalidation on logout
[ ] Biometric auth properly implemented (not bypassable)
[ ] Certificate pinning implemented

NETWORK:
[ ] All traffic encrypted (no HTTP)
[ ] Certificate pinning present and effective
[ ] No sensitive data in URLs (use POST body)
[ ] Custom certificate validation is correct

PLATFORM:
[ ] No exported components with sensitive functionality
[ ] WebView hardened (no JS bridge on untrusted content)
[ ] Deeplink validation (no open redirect/injection)
[ ] No path traversal in content providers

RESILIENCE:
[ ] Root/jailbreak detection (can it be bypassed?)
[ ] Anti-tampering (repackaging detection)
[ ] Anti-debugging measures
[ ] Code obfuscation
```

## Tools

- **MobSF** -- Automated mobile app analysis (static + dynamic)
- **Frida** -- Runtime instrumentation
- **Objection** -- Frida-powered mobile exploration
- **jadx** -- Android APK decompiler
- **Ghidra** -- Binary reverse engineering
- **Burp Suite** -- Network traffic interception
- **drozer** -- Android component testing
- **apktool** -- APK decompilation/recompilation
- **class-dump** -- iOS header extraction
- **Keychain-Dumper** -- iOS keychain extraction
