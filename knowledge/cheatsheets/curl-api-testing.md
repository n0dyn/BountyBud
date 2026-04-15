---
id: "curl-api-testing"
title: "curl Cheatsheet for API Testing"
type: "cheatsheet"
category: "web-application"
subcategory: "api"
tags: ["curl", "api", "http", "testing", "authentication", "proxy"]
platforms: ["linux", "macos", "windows"]
related: ["rate-limiting-bypass", "graphql-grpc"]
difficulty: "beginner"
updated: "2026-04-14"
---

# curl Cheatsheet for API Testing

## Basic Requests
```bash
curl https://target.com/api/users                    # GET
curl -X POST https://target.com/api/users -d 'data'  # POST
curl -X PUT https://target.com/api/users/1 -d 'data' # PUT
curl -X DELETE https://target.com/api/users/1         # DELETE
curl -X PATCH https://target.com/api/users/1 -d 'data' # PATCH
curl -X OPTIONS https://target.com/api/users          # OPTIONS (CORS)
```

## Headers & Content Types
```bash
curl -H "Content-Type: application/json" -d '{"key":"value"}' URL
curl -H "Authorization: Bearer TOKEN" URL
curl -H "Cookie: session=abc123" URL
curl -H "X-Forwarded-For: 127.0.0.1" URL
curl -H "User-Agent: Mozilla/5.0" URL
curl -H "Origin: https://evil.com" URL               # CORS test
curl -H "Referer: https://evil.com" URL
```

## Authentication
```bash
curl -u username:password URL                         # Basic auth
curl -H "Authorization: Basic $(echo -n user:pass | base64)" URL
curl -H "Authorization: Bearer eyJhbG..." URL         # JWT
curl -H "X-API-Key: key123" URL                       # API key
curl -b "session=token" URL                           # Cookie auth
curl -c cookies.txt -b cookies.txt URL                # Cookie jar
```

## JSON Data
```bash
curl -X POST URL -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'

# From file:
curl -X POST URL -H "Content-Type: application/json" -d @payload.json
```

## File Upload
```bash
curl -X POST URL -F "file=@/path/to/shell.php"
curl -X POST URL -F "file=@shell.php;type=image/jpeg"   # MIME type spoof
curl -X POST URL -F "file=@shell.php;filename=image.jpg" # Filename spoof
```

## Verbose & Debug
```bash
curl -v URL                      # Verbose (see headers)
curl -I URL                      # HEAD request (headers only)
curl -sS URL                     # Silent but show errors
curl -o /dev/null -w "%{http_code}" URL  # Just status code
curl -w "\n%{time_total}s\n" URL # Response time
curl -D - URL                    # Dump headers to stdout
```

## Proxy & SSL
```bash
curl -x http://127.0.0.1:8080 URL     # HTTP proxy (Burp)
curl -x socks5://127.0.0.1:9050 URL   # SOCKS proxy (Tor)
curl -k URL                            # Skip SSL verification
curl --cacert ca.pem URL               # Custom CA cert
```

## Follow Redirects & Timing
```bash
curl -L URL                      # Follow redirects
curl -L --max-redirs 5 URL       # Limit redirects
curl --connect-timeout 5 URL     # Connection timeout
curl --max-time 10 URL           # Total timeout
```

## Useful Patterns
```bash
# Test CORS:
curl -H "Origin: https://evil.com" -I URL | grep -i access-control

# Test for open redirect:
curl -sI "URL?redirect=https://evil.com" | grep -i location

# Check security headers:
curl -sI URL | grep -iE "x-frame|x-content|strict-transport|content-security"

# Brute force with seq:
for i in $(seq 1 100); do curl -s "URL/api/users/$i" | grep -v "not found"; done
```
