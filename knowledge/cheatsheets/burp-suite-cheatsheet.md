---
id: "burp-suite-cheatsheet"
title: "Burp Suite Cheatsheet - Essential Techniques & Shortcuts"
type: "cheatsheet"
category: "web-application"
subcategory: "xss"
tags: ["burp-suite", "cheatsheet", "proxy", "intruder", "repeater", "scanner", "extensions", "quick-reference"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["burpsuite", "zaproxy"]
updated: "2026-03-30"
---

## Proxy Setup

```
Proxy Listener: 127.0.0.1:8080
Browser Config: Set HTTP/HTTPS proxy to 127.0.0.1:8080
CA Certificate: http://burp → download and install in browser

# Firefox recommended settings
about:preferences → Network Settings → Manual proxy → 127.0.0.1:8080
Check "Also use this proxy for HTTPS"
```

## Essential Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+Shift+R` | Repeat last request |
| `Ctrl+Space` | Forward intercepted request |
| `Ctrl+Shift+Space` | Drop intercepted request |
| `Ctrl+F` | Search in response |
| `Ctrl+U` | URL encode selection |
| `Ctrl+Shift+U` | URL decode selection |
| `Ctrl+B` | Base64 encode |
| `Ctrl+Shift+B` | Base64 decode |
| `Ctrl+H` | Send to Comparer |

## Repeater Workflow

1. Capture request in Proxy → `Ctrl+R` to send to Repeater
2. Modify parameters and resend
3. Compare responses to baseline
4. Use `Inspector` tab for structured parameter editing
5. Right-click → "Change request method" to switch GET/POST

## Intruder Attack Types

| Type | Use Case |
|------|----------|
| **Sniper** | Single payload position, cycle through list one at a time |
| **Battering Ram** | Same payload in all positions simultaneously |
| **Pitchfork** | Parallel iteration of multiple payload lists (1:1 mapping) |
| **Cluster Bomb** | All combinations of multiple payload lists (cartesian product) |

### Common Intruder Uses
```
# Brute force login
Positions: username=§admin§&password=§FUZZ§
Attack: Cluster Bomb
Payloads: Set 1 = usernames, Set 2 = passwords
Grep: "Invalid" or "Welcome"

# ID enumeration (IDOR)
Positions: /api/users/§1§
Attack: Sniper
Payloads: Numbers 1-10000
Filter: Different response sizes

# Parameter fuzzing
Positions: /search?q=§FUZZ§
Attack: Sniper
Payloads: XSS/SQLi payload list
Grep: Reflected values or errors
```

## Scanner Tips

```
# Active scan specific insertion points
Right-click request → "Actively scan defined insertion points"
Select only the parameters you want to test

# Scan configuration
- Reduce thread count for stability
- Set scope to target domain only
- Use "Audit items" for specific vuln types
- Enable "JavaScript analysis" for DOM-XSS detection
```

## Match & Replace Rules

```
# Auto-add headers to every request
Match: (empty, type: Request header)
Replace: X-Forwarded-For: 127.0.0.1

# Bypass client-side validation
Match: disabled="true"
Replace: (empty)

# Force HTTP to test mixed content
Match: https://
Replace: http://

# Remove security headers for testing
Match: X-Frame-Options: DENY
Replace: (empty)
```

## Essential Extensions

| Extension | Purpose |
|-----------|---------|
| **Autorize** | Automatic authorization testing (IDOR/BOLA) |
| **AuthMatrix** | Role-based access control testing |
| **Logger++** | Enhanced request/response logging |
| **Param Miner** | Hidden parameter discovery |
| **Active Scan++** | Enhanced active scanning |
| **Turbo Intruder** | High-speed request sending (race conditions) |
| **Collaborator Everywhere** | Inject Collaborator payloads in every request |
| **Hackvertor** | Advanced encoding/decoding |
| **JSON Beautifier** | Pretty-print JSON responses |
| **InQL** | GraphQL introspection and testing |
| **JWT Editor** | JWT manipulation and attacks |
| **SAML Raider** | SAML message manipulation |
| **Upload Scanner** | File upload vulnerability testing |
| **IP Rotate** | Rotate source IPs via cloud providers |

## Collaborator Usage

```
# Generate Collaborator payload
Burp menu → Collaborator client → Copy to clipboard

# Use in:
- SSRF testing (URL parameters, webhook URLs)
- Blind XSS (callback payloads)
- Out-of-band SQLi (DNS exfiltration)
- Email header injection
- XXE (external entity callbacks)

# Payload format: RANDOM.burpcollaborator.net
# Supports: HTTP, HTTPS, DNS, SMTP
```

## Scope Configuration

```
# Target scope (regex)
Include: .*\.target\.com$
Exclude: .*\.google\.com$

# Apply scope to:
- Proxy: Only intercept in-scope
- Scanner: Only scan in-scope
- Logger: Only log in-scope
- Sitemap: Filter by scope
```
