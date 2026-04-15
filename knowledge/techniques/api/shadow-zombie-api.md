---
id: "shadow-zombie-api"
title: "Shadow & Zombie API Discovery"
type: "technique"
category: "api-security"
subcategory: "rest"
tags: ["api", "shadow-api", "zombie-api", "discovery", "enumeration", "owasp-api-top-10", "recon", "bug-bounty"]
platforms: ["linux", "macos", "windows"]
related: ["bfla-authorization-testing", "swagger-exploitation", "api-resource-consumption"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Shadow & Zombie API Discovery (OWASP API9:2023)

## Overview

- **Shadow APIs**: Undocumented endpoints in actual traffic, not in the API specification. Created by developers who skip documentation, or from microservices that bypass the API gateway.
- **Zombie APIs**: Deprecated endpoints that were supposed to be removed but remain accessible. Present in old specs but not in current spec, yet still responding to traffic.
- **Orphan APIs**: Endpoints with no owner or maintenance team.

57% of organizations experienced an API-related breach in recent years. Shadow and zombie APIs are primary targets because they lack monitoring, patching, and proper authorization.

## Discovery Techniques

### 1. API Version Enumeration

```bash
# Brute-force API version prefixes
for v in v0 v1 v2 v3 v4 v5 v6 v7 v8 v9 v10 beta alpha staging internal dev test debug; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/$v/users")
  if [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
    echo "[+] Found: /$v/users -> $CODE"
  fi
done

# Try version in different positions
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/api/v1/users"
curl -s -o /dev/null -w "%{http_code}" "https://v1.api.target.com/users"
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/users" -H "Api-Version: 1"
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/users" -H "X-API-Version: 2023-01-01"
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/users?version=1"
curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/users" -H "Accept: application/vnd.target.v1+json"
```

### 2. Wayback Machine / Historical Analysis

```bash
# Find old API endpoints from archived pages
waybackurls api.target.com | grep -E '/api/|/v[0-9]/' | sort -u

# GAU (GetAllURLs) - combines Wayback, Common Crawl, OTX
gau api.target.com | grep -E '/api/|/v[0-9]/' | sort -u

# Check if old endpoints still respond
gau api.target.com | grep '/api/' | sort -u | while read url; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$CODE" = "200" ] || [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
    echo "[ALIVE] $url -> $CODE"
  fi
done

# Archive.org API for historical snapshots
curl "https://web.archive.org/cdx/search/cdx?url=api.target.com/*&output=text&fl=original&collapse=urlkey" | sort -u
```

### 3. JavaScript File Analysis

```bash
# Crawl and extract JS files
katana -u https://target.com -jc -d 3 -ef png,jpg,gif,css,svg | grep '\.js$' | sort -u > js_files.txt

# Extract API endpoints from JS
while read jsurl; do
  curl -s "$jsurl" | grep -oE '["'"'"'](/api/[^"'"'"']*|/v[0-9]+/[^"'"'"']*)["'"'"']' | tr -d "\"'" | sort -u
done < js_files.txt

# Tools for automated JS analysis
# LinkFinder
python3 linkfinder.py -i https://target.com -d -o results.html

# JSParser
python3 jsfinder.py -u https://target.com
```

### 4. Swagger/OpenAPI Spec Discovery

```bash
# Common spec file locations
PATHS=(
  "/swagger.json" "/swagger.yaml" "/openapi.json" "/openapi.yaml"
  "/api-docs" "/api/swagger.json" "/api/openapi.json"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/swagger/v1/swagger.json" "/swagger-ui.html"
  "/api/v1/api-docs" "/api/v2/api-docs" "/api/v3/api-docs"
  "/docs" "/redoc" "/api/docs" "/graphql" "/graphiql"
  "/.well-known/openapi.json" "/.well-known/swagger.json"
  "/api/swagger/ui" "/swagger-resources"
  "/api-docs.json" "/api/api-docs"
)

for path in "${PATHS[@]}"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$CODE" = "200" ]; then
    echo "[FOUND] https://target.com$path"
  fi
done
```

### 5. Subdomain-Based API Discovery

```bash
# API-specific subdomains
subfinder -d target.com | grep -iE 'api|dev|staging|internal|backend|gateway|graphql|ws|grpc'

# Probe found subdomains
echo "api.target.com
api-dev.target.com
api-staging.target.com
api-internal.target.com
api-v2.target.com
gateway.target.com
backend.target.com" | httpx -sc -title -tech-detect
```

### 6. Mobile App Decompilation

```bash
# Android APK
apktool d target.apk -o decompiled
grep -rn "api\." decompiled/ | grep -oE 'https?://[^"'"'"' ]*' | sort -u
grep -rn "/v[0-9]/" decompiled/ | sort -u

# Look for hardcoded API endpoints
jadx-gui target.apk
# Search: BuildConfig, BASE_URL, API_URL, ENDPOINT

# iOS IPA
unzip target.ipa -d extracted
strings extracted/Payload/*.app/* | grep -E 'https?://.*api' | sort -u
```

### 7. DNS and Certificate Transparency

```bash
# CT logs for API subdomains
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u | grep -i api

# DNS brute-force
dnsrecon -d target.com -t brt -D api_wordlist.txt
```

### 8. Traffic Diff Against Spec

```bash
# Compare actual traffic (from proxy) against OpenAPI spec
# Any endpoint in traffic NOT in spec = shadow API

# Using mitmproxy
mitmdump -w traffic.flow
# Export unique endpoints from flow

# Using Burp Suite
# Target > Site Map > export all endpoints
# Diff against swagger.json paths
```

## Exploitation of Found APIs

### Old Version Vulnerabilities
```bash
# Old API versions often lack:
# - Rate limiting
# - Input validation
# - Authentication/authorization checks
# - Logging/monitoring

# Test v1 for vulns fixed in v2
curl "https://api.target.com/v1/users?admin=true"          # Mass assignment
curl "https://api.target.com/v1/users/1"                    # No auth check
curl -X DELETE "https://api.target.com/v1/users/1"          # No authz
curl "https://api.target.com/v1/users?fields=password_hash" # Data exposure
```

### Undocumented Debug Endpoints
```bash
# Common debug/internal endpoints
curl https://api.target.com/api/debug
curl https://api.target.com/api/health
curl https://api.target.com/api/status
curl https://api.target.com/api/info
curl https://api.target.com/api/env
curl https://api.target.com/api/config
curl https://api.target.com/api/metrics
curl https://api.target.com/api/actuator  # Spring Boot
curl https://api.target.com/api/actuator/env
curl https://api.target.com/api/actuator/heapdump
curl https://api.target.com/api/elmah.axd  # .NET
curl https://api.target.com/api/__debug__  # Django
curl https://api.target.com/api/graphql    # GraphQL without auth
```

## Wordlists

```
# Recommended wordlists for API endpoint discovery:
# - SecLists/Discovery/Web-Content/api/
# - SecLists/Discovery/Web-Content/swagger.txt
# - fuzzdb/discovery/predictable-filepaths/webservers-appservers/
# - Assetnote Wordlists: https://wordlists.assetnote.io
# - kiterunner wordlists (specifically designed for API routes)
```

### Kiterunner (API-Aware Discovery)
```bash
# kiterunner understands API route patterns
kr scan https://api.target.com -w routes-large.kite -x 5
kr scan https://api.target.com -w routes-large.kite --fail-status-codes 404,400

# Brute with multiple wordlists
kr brute https://api.target.com -w wordlist.txt -x 10
```

## Tools
- **kiterunner** — API-aware endpoint discovery
- **Autoswagger** — Swagger/OpenAPI discovery and testing
- **gau / waybackurls** — Historical URL collection
- **katana** — Modern web crawler
- **LinkFinder** — JS endpoint extraction
- **subfinder** — Subdomain enumeration
- **httpx** — HTTP probing
- **ffuf** — Web fuzzing
- **Burp Suite** — Traffic analysis and diff
- **mitmproxy** — Traffic capture for mobile apps
