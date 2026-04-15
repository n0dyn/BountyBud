---
id: "frida-apk-testing"
title: "Mobile Hunting: Frida + APK Masterclass (Android/iOS 2026)"
type: "technique"
category: "mobile"
subcategory: "android"
tags: ["mobile", "frida", "objection", "android", "ios", "apk", "ssl-pinning", "runtime-hooking", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["android-intent-deeplink-attacks", "android-webview-exploitation", "ios-keychain-pasteboard", "ssl-pinning-bypass", "root-jailbreak-bypass"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Mobile Hunting: Frida + APK Masterclass (Android/iOS 2026)

## Workflow
1. APK download / IPA extraction
2. Frida server + Objection setup
3. Runtime hooking & dynamic analysis
4. SSL pinning bypass for traffic interception
5. Root/jailbreak detection bypass
6. Deep method hooking (auth, crypto, API calls)

## Setup

### Frida Server on Android
```bash
# Check device arch
adb shell getprop ro.product.cpu.abi

# Download matching frida-server from https://github.com/frida/frida/releases
wget https://github.com/frida/frida/releases/download/16.x.x/frida-server-16.x.x-android-arm64.xz
unxz frida-server-16.x.x-android-arm64.xz

# Push and run
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Verify
frida-ps -U
```

### Objection Setup
```bash
pip install objection
# Patch APK (injects frida-gadget, disables cert pinning)
objection patchapk -s target.apk
# Connect to running app
objection -g com.target.app explore
```

## SSL Pinning Bypass

### Objection One-Liner
```bash
# Android
objection -g com.target.app explore --startup-command "android sslpinning disable"

# iOS
objection -g com.target.app explore --startup-command "ios sslpinning disable"
```

### Universal Frida SSL Bypass Script
```javascript
// ssl_bypass.js - Universal Android SSL Pinning Bypass
Java.perform(function() {
    // 1. Bypass default TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, TrustManagers, null);

    // 2. Bypass OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            console.log('[+] OkHttp pinning bypassed for: ' + hostname);
        };
    } catch(e) { console.log('[-] OkHttp not found'); }

    // 3. Bypass Conscrypt (modern Android)
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.implementation = function() {
            console.log('[+] Conscrypt pinning bypassed');
        };
    } catch(e) {}

    console.log('[*] SSL Pinning bypass loaded');
});
```

```bash
# Execute
frida -U -f com.target.app --no-pause -l ssl_bypass.js
```

### network_security_config.xml Bypass
```xml
<!-- Decompile APK, add/modify res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
<!-- Reference in AndroidManifest.xml: android:networkSecurityConfig="@xml/network_security_config" -->
<!-- Repack & resign APK -->
```

### Magisk Module Approach
```bash
# Install "Move Certs" Magisk module to move user certs to system store
# Or use MagiskTrustUserCerts module
# This avoids APK modification entirely
```

## Root/Jailbreak Detection Bypass

### Frida Generic Root Bypass
```javascript
// root_bypass.js
Java.perform(function() {
    // Bypass RootBeer library
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() -> false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            return false;
        };
    } catch(e) {}

    // Bypass generic root checks
    var RootDetection = Java.use('java.io.File');
    RootDetection.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
                         '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
                         '/system/sd/xbin/su', '/system/bin/failsafe/su',
                         '/data/local/su', '/su/bin/su', '/magisk'];
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                console.log('[+] Hiding root path: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    // Bypass SafetyNet / Play Integrity (basic)
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace('test-keys', 'release-keys');
    } catch(e) {}

    console.log('[*] Root detection bypass loaded');
});
```

### Magisk DenyList (Zygisk)
```bash
# Magisk v23.0+ uses Zygisk DenyList instead of MagiskHide
# In Magisk app:
# 1. Settings > Enable Zygisk
# 2. Settings > Configure DenyList
# 3. Add target app to DenyList
# 4. Reboot

# For advanced bypass, install Shamiko module alongside Zygisk
# Shamiko hides Magisk root from apps on the DenyList
```

### iOS Jailbreak Detection Bypass
```bash
# Objection
objection -g com.target.app explore --startup-command "ios jailbreak disable"

# Liberty Lite (Cydia/Sileo)
# Install from repo, enable per-app

# Frida script for common jailbreak checks
```

```javascript
// ios_jb_bypass.js
if (ObjC.available) {
    // Hook NSFileManager fileExistsAtPath
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            var jbPaths = ['/Applications/Cydia.app', '/usr/sbin/sshd',
                          '/bin/bash', '/etc/apt', '/private/var/lib/apt/',
                          '/Library/MobileSubstrate/MobileSubstrate.dylib'];
            for (var i = 0; i < jbPaths.length; i++) {
                if (this.path.indexOf(jbPaths[i]) !== -1) {
                    retval.replace(0x0);
                    return;
                }
            }
        }
    });

    // Hook canOpenURL for cydia:// scheme
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.indexOf('cydia') !== -1) {
                retval.replace(0x0);
            }
        }
    });
}
```

## iOS Keychain & Pasteboard Exploitation

### Keychain Dumping
```bash
# Objection
objection -g com.target.app explore
> ios keychain dump
> ios keychain dump --json keychain_dump.json

# Look for:
# - Plaintext passwords/PINs
# - API keys and tokens
# - OAuth tokens
# - Encryption keys with weak kSecAttrAccessible settings
```

### Keychain Access Control Issues
```
# Dangerous kSecAttrAccessible values (data available without device unlock):
# - kSecAttrAccessibleAlways (deprecated but still used)
# - kSecAttrAccessibleAlwaysThisDeviceOnly
# - kSecAttrAccessibleAfterFirstUnlock (available after first unlock until reboot)

# Safe values:
# - kSecAttrAccessibleWhenUnlocked
# - kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
```

### Pasteboard/Clipboard Monitoring
```bash
# Objection - monitor clipboard
objection -g com.target.app explore
> ios pasteboard monitor

# Check if app copies sensitive data to general pasteboard
# General pasteboard is shared across ALL apps
# Named pasteboards (app-specific) are safer
```

```javascript
// Frida clipboard monitor
if (ObjC.available) {
    var UIPasteboard = ObjC.classes.UIPasteboard;
    Interceptor.attach(UIPasteboard['+ generalPasteboard'].implementation, {
        onLeave: function(retval) {
            var pb = ObjC.Object(retval);
            var str = pb.string();
            if (str) {
                console.log('[CLIPBOARD] ' + str);
            }
        }
    });
}
```

### Other iOS Data Storage Checks
```bash
# NSUserDefaults
objection -g com.target.app explore
> ios nsuserdefaults get

# Cookies
> ios cookies get

# Binary Cookies
# Check for sensitive data in app sandbox:
> env  # shows app paths
# Then explore Documents/, Library/, tmp/
```

## Deep Dig Prompts
```
For this APK/IPA [describe or paste logs]:
Write a Frida script to:
1. Bypass SSL pinning (new 2026 cert checks)
2. Hook critical methods (login, purchase, JWT generation)
3. Dump all in-memory secrets and API calls
4. Bypass root/jailbreak detection
5. Monitor clipboard for sensitive data leaks
6. Intercept all WebView URL loads
```

## High-Value Findings
- Root/jailbreak detection bypass
- SSL pinning bypass -> credential interception
- In-app purchase manipulation
- Local DB encryption keys in keychain/SharedPrefs
- Backend token stealing
- WebView JavaScript bridge abuse
- Deeplink hijacking -> account takeover
- Clipboard data leakage (passwords, tokens)
- Insecure keychain storage (kSecAttrAccessibleAlways)

## Tools
- **Frida** — Dynamic instrumentation toolkit
- **Objection** — Runtime mobile exploration (v1.12.4, March 2026)
- **Ghidra/IDA** — Native code reverse engineering
- **Jadx** — Java decompiler for APK
- **MobSF** — Automated mobile security framework
- **apktool** — APK decompile/recompile
- **dex2jar** — DEX to JAR conversion
- **Magisk** — Android root with Zygisk DenyList
- **Shamiko** — Hide Magisk from detection
- **Liberty Lite** — iOS jailbreak detection bypass
