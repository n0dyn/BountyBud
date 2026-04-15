---
id: "objection"
title: "Objection - Mobile Runtime Exploration Toolkit"
type: "tool"
category: "mobile"
subcategory: "runtime-analysis"
tags: ["mobile", "objection", "frida", "ssl-pinning", "ios", "android", "hooking", "runtime"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
source_url: "https://github.com/sensepost/objection"
related: ["burpsuite", "mobsf-api"]
updated: "2026-04-14"
---

## Overview

Objection is a runtime mobile exploration toolkit powered by Frida. It enables security testing of iOS and Android apps without jailbreak/root by injecting into running applications. Provides SSL pinning bypass, method hooking, filesystem access, keychain/keystore dumping, SQLite interaction, and memory analysis through an interactive command line.

## Installation

```bash
# Install via pip
pip3 install objection

# Requires Frida
pip3 install frida-tools

# Verify
objection version

# For Android: ensure adb is available
# For iOS: ensure iproxy/usbmuxd is available
```

## Setup

### Android (No Root Required)
```bash
# 1. Patch APK with Frida gadget
objection patchapk -s target.apk

# 2. Install patched APK
adb install target.objection.apk

# 3. Launch app on device, then connect
objection -g com.target.app explore

# Or specify gadget name
objection -g "Target App" explore

# With network connection (remote device)
objection -N -h 192.168.1.100 -p 27042 -g com.target.app explore
```

### iOS (No Jailbreak Required)
```bash
# 1. Patch IPA with Frida gadget
objection patchipa -s target.ipa

# 2. Sideload patched IPA (use ios-deploy or Xcode)
ios-deploy --bundle target-frida.ipa

# 3. Connect
objection -g com.target.app explore

# With USB
objection -g com.target.app explore --startup-command "ios sslpinning disable"
```

## SSL Pinning Bypass

```bash
# Android - disable SSL pinning
android sslpinning disable

# iOS - disable SSL pinning
ios sslpinning disable

# Now proxy traffic through Burp/Caido at 127.0.0.1:8080
# The app will accept the proxy's certificate
```

## Filesystem Commands

```bash
# List files
ls
ls /data/data/com.target.app/

# Change directory
cd shared_prefs
cd /data/data/com.target.app/databases/

# Download file from device
file download /data/data/com.target.app/databases/app.db ./app.db

# Upload file to device
file upload local_file.txt /data/data/com.target.app/files/remote_file.txt

# Print working directory
pwd

# Cat file contents
cat config.xml
```

## Keychain & Keystore

```bash
# iOS - dump keychain
ios keychain dump
ios keychain dump --json

# iOS - clear keychain
ios keychain clear

# Android - list keystore entries
android keystore list
android keystore clear

# Android - dump shared preferences
android hooking list activities
```

## SQLite Database Interaction

```bash
# List databases
sqlite connect app.db

# Execute queries
sqlite execute query select * from users;
sqlite execute query select * from sessions;

# Dump tables
sqlite execute query .tables

# Close connection
sqlite disconnect
```

## Memory Analysis

```bash
# Dump memory
memory dump all dump.bin
memory dump from_base 0x12345 1024 dump.bin

# Search memory
memory search "password" --string
memory search "admin@target.com" --string

# List loaded modules
memory list modules
memory list exports libnative.so
```

## Method Hooking (Android)

```bash
# List classes
android hooking list classes
android hooking list classes --filter com.target

# List methods of a class
android hooking list class_methods com.target.app.AuthManager

# Watch method invocations (see args and return values)
android hooking watch class_method com.target.app.AuthManager.login --dump-args --dump-return

# Watch all methods in a class
android hooking watch class com.target.app.AuthManager

# Set return value (bypass checks)
android hooking set return_value com.target.app.AuthManager.isAdmin true

# List activities
android hooking list activities

# List services
android hooking list services

# List broadcast receivers
android hooking list receivers

# Start activity
android intent launch_activity com.target.app.AdminActivity
```

## Method Hooking (iOS)

```bash
# List classes
ios hooking list classes
ios hooking list classes --filter Auth

# List methods
ios hooking list class_methods AuthManager

# Watch method
ios hooking watch method "+[AuthManager isLoggedIn]" --dump-args --dump-return

# Watch class
ios hooking watch class AuthManager

# Set return value
ios hooking set return_value "+[AuthManager isAdmin]" true

# List URL schemes
ios bundles list_frameworks
```

## Cookie & Storage Dumps

```bash
# iOS - dump cookies
ios cookies get

# iOS - dump NSUserDefaults
ios nsuserdefaults get

# iOS - dump plist files
ios plist cat Info.plist

# Android - dump shared preferences
cat /data/data/com.target.app/shared_prefs/prefs.xml

# Android - list activities
android hooking list activities
```

## Root/Jailbreak Detection Bypass

```bash
# iOS - bypass jailbreak detection
ios jailbreak disable

# iOS - simulate non-jailbroken environment
ios jailbreak simulate

# Android - bypass root detection
android root disable
android root simulate
```

## Network Analysis

```bash
# iOS - list registered URL handlers
ios info binary

# Android - list exported components
android hooking list activities
android hooking list services
android hooking list receivers
```

## Custom Frida Scripts

```bash
# Import and run custom Frida script
import /path/to/custom_script.js

# Execute Frida JavaScript inline
!eval console.log("Hello from Frida")
```

## Integration with Other Tools

### With Burp Suite / Caido
```bash
# 1. Start objection and disable SSL pinning
objection -g com.target.app explore
# > android sslpinning disable

# 2. Configure device proxy to point to Burp/Caido
# Android: Settings > Wi-Fi > Proxy > Manual > 192.168.1.x:8080
# iOS: Settings > Wi-Fi > HTTP Proxy > Manual > 192.168.1.x:8080

# 3. Install Burp/Caido CA certificate on device
```

### Startup Commands
```bash
# Run commands on connect
objection -g com.target.app explore --startup-command "android sslpinning disable"

# Multiple startup commands
objection -g com.target.app explore \
  --startup-command "android sslpinning disable" \
  --startup-command "android root disable"
```

## Bug Bounty Workflow

1. **Patch**: `objection patchapk -s app.apk` to inject Frida gadget
2. **Install**: `adb install patched.apk` on test device/emulator
3. **Connect**: `objection -g com.target.app explore`
4. **Bypass SSL**: `android sslpinning disable` to intercept traffic
5. **Explore**: Browse filesystem, dump databases, check shared prefs
6. **Hook**: Watch auth methods, bypass root detection, modify returns
7. **Extract**: Dump keystore, cookies, tokens, hardcoded secrets
8. **Proxy**: Route traffic through Burp/Caido for deeper API testing

## Pro Tips

- Use `--startup-command` to auto-bypass SSL pinning on connect
- Patch APK once, then just reconnect for subsequent sessions
- Combine with Burp/Caido for full API traffic interception
- Hook authentication methods to understand token generation
- Set return values to bypass client-side security checks
- Dump SQLite databases to find cached sensitive data
- Check shared preferences for hardcoded API keys/tokens
- Memory search can find credentials stored in plaintext
- Use `android hooking watch class` to monitor all methods at once
- For apps with advanced anti-frida, try the gadget configuration options
