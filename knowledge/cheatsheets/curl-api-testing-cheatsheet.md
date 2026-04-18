---
id: "curl-api-testing-cheatsheet"
title: "curl for API Testing - Complete Reference"
type: "cheatsheet"
category: "web-application"
subcategory: "api-testing"
tags: ["curl", "api", "http", "rest", "cheatsheet", "testing", "authentication", "proxy"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["ffuf-cheatsheet", "burp-suite-cheatsheet"]
updated: "2026-04-14"
---

## Essential Flags

| Flag | Description |
|------|-------------|
| `-X METHOD` | HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) |
| `-H "Header: Value"` | Add request header |
| `-d "data"` | Request body (POST data) |
| `-s` | Silent mode (no progress bar) |
| `-S` | Show errors in silent mode |
| `-i` | Include response headers in output |
| `-I` | Fetch headers only (HEAD request) |
| `-v` | Verbose (full request/response) |
| `-o file` | Save response body to file |
| `-O` | Save with remote filename |
| `-w "format"` | Write-out format string |
| `-L` | Follow redirects |
| `-k` | Skip SSL/TLS certificate verification |
| `-K file` | Read config from file |
| `-x proxy` | Use proxy |
| `-b "cookies"` | Send cookies |
| `-c file` | Save cookies to file |
| `-u user:pass` | Basic authentication |
| `-A "agent"` | User-Agent string |
| `-e "referer"` | Referer header |
| `-D file` | Save response headers to file |
| `--compressed` | Request gzip/deflate encoding |
| `--connect-timeout N` | Connection timeout (seconds) |
| `-m N` / `--max-time N` | Max total time (seconds) |
| `--retry N` | Retry count on failure |
| `-f` | Fail silently on HTTP errors |

## HTTP Methods

```bash
# GET (default)
curl https://api.target.com/users

# POST
curl -X POST https://api.target.com/users -d '{"name":"test"}'

# PUT
curl -X PUT https://api.target.com/users/1 -d '{"name":"updated"}'

# PATCH
curl -X PATCH https://api.target.com/users/1 -d '{"name":"patched"}'

# DELETE
curl -X DELETE https://api.target.com/users/1

# OPTIONS (CORS preflight)
curl -X OPTIONS https://api.target.com/users -i

# HEAD (headers only)
curl -I https://api.target.com/users
```

## Request Headers

```bash
# Content-Type
curl -H "Content-Type: application/json" https://api.target.com/users

# Multiple headers
curl -H "Content-Type: application/json" \
     -H "Accept: application/json" \
     -H "X-Custom-Header: value" \
     https://api.target.com/users

# User-Agent
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://api.target.com

# Referer
curl -e "https://target.com" https://api.target.com/users

# Host header (for vhost testing)
curl -H "Host: admin.target.com" http://10.10.10.1/
```

## Request Body

```bash
# JSON body
curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@example.com"}'

# Form data (URL-encoded)
curl -X POST https://api.target.com/login \
  -d "username=admin&password=admin"

# Multipart form (file upload)
curl -X POST https://api.target.com/upload \
  -F "file=@/path/to/file.jpg" \
  -F "description=test upload"

# Read body from file
curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" \
  -d @payload.json

# Read from stdin
echo '{"name":"test"}' | curl -X POST https://api.target.com/users \
  -H "Content-Type: application/json" -d @-

# XML body
curl -X POST https://api.target.com/soap \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><request><name>test</name></request>'

# Raw binary
curl -X POST https://api.target.com/binary \
  -H "Content-Type: application/octet-stream" \
  --data-binary @file.bin

# GraphQL
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id name email } }"}'
```

## Authentication

```bash
# Basic Auth
curl -u username:password https://api.target.com/users
curl -H "Authorization: Basic $(echo -n 'user:pass' | base64)" https://api.target.com/users

# Bearer Token / JWT
curl -H "Authorization: Bearer eyJhbG..." https://api.target.com/users

# API Key (header)
curl -H "X-API-Key: your-api-key" https://api.target.com/users

# API Key (query param)
curl "https://api.target.com/users?api_key=your-api-key"

# OAuth2 Token Request
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET"

# Digest Auth
curl --digest -u username:password https://api.target.com/users

# NTLM Auth
curl --ntlm -u domain\\user:password https://api.target.com/users

# Client Certificate
curl --cert client.pem --key client-key.pem https://api.target.com/users

# AWS Signature (use aws-cli instead or)
curl -H "Authorization: AWS4-HMAC-SHA256 ..." https://s3.amazonaws.com/bucket
```

## Cookie Handling

```bash
# Send cookies
curl -b "session=abc123; theme=dark" https://api.target.com/profile

# Save cookies to file
curl -c cookies.txt https://api.target.com/login -d "user=admin&pass=admin"

# Use saved cookies
curl -b cookies.txt https://api.target.com/profile

# Save and use (session flow)
curl -c cookies.txt -b cookies.txt https://api.target.com/login -d "user=admin&pass=admin"
curl -c cookies.txt -b cookies.txt https://api.target.com/dashboard
```

## Proxy Usage

```bash
# HTTP proxy
curl -x http://127.0.0.1:8080 https://api.target.com/users

# SOCKS5 proxy
curl --socks5 127.0.0.1:1080 https://api.target.com/users

# SOCKS5 with DNS resolution
curl --socks5-hostname 127.0.0.1:1080 https://api.target.com/users

# Proxy with authentication
curl -x http://user:pass@proxy:8080 https://api.target.com/users

# Burp Suite / Caido proxy (skip cert verification)
curl -x http://127.0.0.1:8080 -k https://api.target.com/users

# Environment variable proxy
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
curl https://api.target.com/users

# No proxy for specific hosts
curl --noproxy "localhost,127.0.0.1" https://api.target.com/users
```

## Verbose & Debugging

```bash
# Verbose output (full headers + body)
curl -v https://api.target.com/users

# Very verbose (includes TLS handshake)
curl -vvv https://api.target.com/users

# Save verbose output separately
curl -v -o response.json 2>debug.log https://api.target.com/users

# Trace output (hex dump)
curl --trace trace.log https://api.target.com/users
curl --trace-ascii trace.txt https://api.target.com/users

# Timing information
curl -w "\nHTTP Code: %{http_code}\nTime Total: %{time_total}s\nTime Connect: %{time_connect}s\nTime TTFB: %{time_starttransfer}s\nSize Download: %{size_download}\n" -o /dev/null -s https://api.target.com/users

# Response code only
curl -o /dev/null -s -w "%{http_code}" https://api.target.com/users

# Response headers only
curl -sI https://api.target.com/users
curl -s -D - -o /dev/null https://api.target.com/users

# Redirect chain
curl -sIL https://api.target.com/redirect
```

## Write-Out Format Variables

```bash
curl -w "format_string" -o /dev/null -s URL

# Key variables:
# %{http_code}         - HTTP response code
# %{time_total}        - Total time in seconds
# %{time_connect}      - Time to connect
# %{time_starttransfer} - Time to first byte (TTFB)
# %{time_namelookup}   - DNS resolution time
# %{size_download}     - Downloaded bytes
# %{size_header}       - Header size
# %{url_effective}     - Final URL after redirects
# %{redirect_url}      - Redirect URL
# %{num_redirects}     - Number of redirects
# %{ssl_verify_result} - SSL verification result
# %{content_type}      - Content-Type header
# %{remote_ip}         - Remote IP address
# %{local_ip}          - Local IP address
```

## Security Testing Patterns

```bash
# IDOR testing (iterate IDs)
for i in $(seq 1 100); do
  echo "$i: $(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer TOKEN' https://api.target.com/users/$i)"
done

# Header injection
curl -H "X-Forwarded-For: 127.0.0.1" https://api.target.com/admin
curl -H "X-Original-URL: /admin" https://api.target.com/
curl -H "X-Rewrite-URL: /admin" https://api.target.com/

# Method override
curl -X POST -H "X-HTTP-Method-Override: DELETE" https://api.target.com/users/1

# CORS testing
curl -H "Origin: https://evil.com" -I https://api.target.com/users

# SSRF testing
curl -X POST https://api.target.com/fetch -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

# Host header injection
curl -H "Host: evil.com" https://api.target.com/password-reset

# Content-Type switching
curl -X POST https://api.target.com/login \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><user>admin</user><pass>admin</pass></root>'

# Rate limit testing
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/login -d "user=admin&pass=test$i"; done

# Response header security check
curl -sI https://target.com | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy)"

# SSL/TLS info
curl -vvv --tlsv1.2 https://target.com 2>&1 | grep -E "(SSL|TLS|subject|issuer|expire)"
```

## Scripting Patterns

```bash
# Save response and check status
RESPONSE=$(curl -s -w "\n%{http_code}" https://api.target.com/users)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$ d')

# Conditional on status
if [ "$HTTP_CODE" -eq 200 ]; then
  echo "Success: $BODY"
fi

# Extract JSON value (with jq)
TOKEN=$(curl -s https://api.target.com/login -d 'user=admin&pass=admin' | jq -r '.token')
curl -H "Authorization: Bearer $TOKEN" https://api.target.com/profile

# Loop through endpoints
while read -r endpoint; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "https://api.target.com$endpoint")
  echo "$CODE $endpoint"
done < endpoints.txt

# Parallel requests (GNU parallel)
cat urls.txt | parallel -j 10 'curl -s -o /dev/null -w "%{http_code} {}\n" {}'
```

## Pro Tips

- Use `-s -S` together: silent but still show errors
- Use `-w "\n"` to add newline after response body
- `--compressed` may reveal different content than uncompressed
- `-k` skips SSL verification (needed for proxy intercept)
- Use `@-` to read body from stdin for piping
- `curl -w "%{http_code}"` is fastest way to check response codes
- Combine `-o /dev/null` with `-w` for clean status code checks
- Use `--retry 3` for flaky endpoints
- `--connect-timeout 5` prevents hanging on unresponsive hosts
- Save full sessions with `-c` (cookies) and `-b` (use cookies)

---

## Advanced Auditing Syntax (2026)

### 1. Hydration Mining (Next.js / Nuxt)
Extract the unauthenticated application state from the HTML source.
```bash
curl -s [URL] | grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">).*?(?=</script>)' | jq .
```

### 2. Differentiator Probing (SPA vs API)
Check if different sub-paths return the same byte count (indicates frontend masking).
```bash
for p in /api/v1 /auth /config /unauth; do curl -s -o /dev/null -w "%{size_download} %{http_code}\n" "https://target.com$p"; done
```

### 3. JS Byte-Offset Extraction
Extract a specific logic block from a massive minified bundle.
```bash
# Find the byte offset of a function
OFFSET=$(grep -b -o "functionName" file.js | head -n 1 | cut -d: -f1)
# Read 2000 characters starting from that offset
tail -c +$((OFFSET+1)) file.js | head -c 2000
```

### 4. Infrastructure Header Reflection
Test if proxy headers are reflected in cookie domains or redirects.
```bash
curl -s -I -H "X-Forwarded-Host: attacker.com" "https://target.com/" | grep -iE "Set-Cookie|Location"
```
