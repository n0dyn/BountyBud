---
id: "nuclei-templates"
title: "Nuclei Custom Template Writing Guide"
type: "tool"
category: "web-application"
subcategory: "vuln-scanning"
tags: ["nuclei", "templates", "yaml", "matchers", "extractors", "workflows", "custom-detection"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/nuclei-templates"
related: ["nuclei-full", "nuclei-api", "interactsh"]
updated: "2026-04-14"
---

## Overview

Nuclei templates are YAML files that define how to detect vulnerabilities, misconfigurations, and exposures. Templates specify the request, conditions for matching, and data extraction. The template engine supports HTTP, DNS, TCP, SSL, headless, and code protocols with powerful matcher and extractor DSL.

## Basic Template Structure

```yaml
id: my-custom-check

info:
  name: My Custom Vulnerability Check
  author: yourname
  severity: high          # info, low, medium, high, critical
  description: Description of what this detects
  reference:
    - https://example.com/advisory
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cvss-score: 7.5
    cve-id: CVE-2024-XXXX
    cwe-id: CWE-200
  tags: sqli,injection,cve2024
  metadata:
    max-request: 1

http:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "sensitive_string"
      - type: status
        status:
          - 200
```

## HTTP Request Types

### Basic GET
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/users"
    headers:
      User-Agent: Mozilla/5.0
      Accept: application/json
```

### POST with Body
```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    headers:
      Content-Type: application/json
    body: '{"username":"admin","password":"admin"}'
```

### Raw Request (full control)
```yaml
http:
  - raw:
      - |
        GET /api/v1/users HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}
```

### Multiple Requests (chained)
```yaml
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"admin","password":"admin"}
      - |
        GET /api/admin/users HTTP/1.1
        Host: {{Hostname}}
        Cookie: session={{session_cookie}}

    cookie-reuse: true
    extractors:
      - type: kval
        name: session_cookie
        internal: true
        kval:
          - session
```

## Matcher Types

### 1. Status Code Matcher
```yaml
matchers:
  - type: status
    status:
      - 200
      - 301
      - 302
```

### 2. Word Matcher
```yaml
matchers:
  - type: word
    words:
      - "root:x:0:0"
      - "admin"
    condition: or        # or, and (default: or)
    part: body           # body, header, all, raw (default: body)
    case-insensitive: true
```

### 3. Regex Matcher
```yaml
matchers:
  - type: regex
    regex:
      - "root:[x*]:0:0"
      - "password[\"']?\\s*[:=]\\s*[\"']?[^\\s]+"
    part: body
```

### 4. Binary Matcher
```yaml
matchers:
  - type: binary
    binary:
      - "504b0304"    # ZIP file magic bytes
    part: body
```

### 5. DSL Matcher (most powerful)
```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200"
      - "contains(body, 'admin')"
      - "len(body) > 1000"
      - "contains(all_headers, 'X-Debug')"
      - "!contains(body, 'error')"
      - "status_code >= 200 && status_code < 300"
      - "contains(content_type, 'json')"
```

### 6. XPath Matcher (for XML/HTML)
```yaml
matchers:
  - type: xpath
    xpath:
      - "/html/head/title[contains(text(),'Admin')]"
```

### Matcher Conditions
```yaml
# All matchers must match
matchers-condition: and

# Any matcher can match
matchers-condition: or
```

### Negative Matchers
```yaml
matchers:
  - type: word
    words:
      - "Not Found"
    negative: true       # match when word is NOT present
```

### Matcher Parts
- `body` - Response body (default)
- `header` - Response headers
- `all_headers` - All response headers
- `status_code` - HTTP status code
- `raw` - Full raw response
- `all` - Headers + body
- `interactsh_protocol` - OOB interaction protocol
- `interactsh_request` - OOB interaction request

## Extractor Types

### 1. Regex Extractor
```yaml
extractors:
  - type: regex
    name: version
    regex:
      - "Version: ([0-9.]+)"
    group: 1
    part: body
```

### 2. KVal Extractor (headers/cookies)
```yaml
extractors:
  - type: kval
    kval:
      - content_type
      - server
      - set_cookie
```

### 3. JSON Extractor
```yaml
extractors:
  - type: json
    json:
      - ".data.token"
      - ".users[0].email"
    part: body
```

### 4. XPath Extractor
```yaml
extractors:
  - type: xpath
    xpath:
      - "/html/head/title"
    attribute: text
```

### 5. DSL Extractor
```yaml
extractors:
  - type: dsl
    dsl:
      - "len(body)"
      - "status_code"
```

### Internal Extractors (for chaining)
```yaml
extractors:
  - type: regex
    name: csrf_token
    internal: true       # don't print, use in next request
    regex:
      - 'name="csrf" value="([^"]+)"'
    group: 1
```

## Variables and Payloads

### Built-in Variables
```yaml
# {{BaseURL}} - Full URL with path
# {{RootURL}} - Root URL without path
# {{Hostname}} - Just the hostname
# {{Host}} - Hostname with port
# {{Port}} - Port number
# {{Path}} - URL path
# {{Scheme}} - http or https
# {{interactsh-url}} - Auto-generated interactsh URL
```

### Custom Payloads
```yaml
http:
  - payloads:
      username:
        - admin
        - root
        - test
      password:
        - admin
        - password
        - 123456

    attack: clusterbomb    # sniper, pitchfork, clusterbomb

    raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user={{username}}&pass={{password}}
```

### Payload from File
```yaml
payloads:
  paths: /path/to/wordlist.txt
```

## OOB (Out-of-Band) Detection

```yaml
http:
  - raw:
      - |
        GET /api/fetch?url=http://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"

      - type: word
        part: interactsh_request
        words:
          - "GET /"
```

## DNS Templates

```yaml
id: dns-zone-transfer

info:
  name: DNS Zone Transfer Check
  severity: high

dns:
  - name: "{{FQDN}}"
    type: AXFR
    class: inet
    recursion: true

    matchers:
      - type: word
        words:
          - "IN A"
          - "IN NS"
```

## Network (TCP) Templates

```yaml
id: redis-unauth

info:
  name: Redis Unauthorized Access
  severity: critical

tcp:
  - inputs:
      - data: "INFO\r\n"
    host:
      - "{{Hostname}}"
    port: 6379

    matchers:
      - type: word
        words:
          - "redis_version"
```

## Workflows

### Basic Workflow
```yaml
id: wordpress-workflow

info:
  name: WordPress Audit Workflow
  author: yourname

workflows:
  - template: technologies/wordpress-detect.yaml
    subtemplates:
      - template: vulnerabilities/wordpress/*.yaml
      - template: cves/wordpress/*.yaml
```

### Conditional Workflow
```yaml
workflows:
  - template: technologies/detect-tech.yaml
    matchers:
      - name: wordpress
        subtemplates:
          - template: vulnerabilities/wordpress/*.yaml
      - name: joomla
        subtemplates:
          - template: vulnerabilities/joomla/*.yaml
```

## Practical Template Examples

### Open Redirect Detection
```yaml
id: open-redirect-check

info:
  name: Open Redirect
  severity: medium
  tags: redirect

http:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?url=https://evil.com"
      - "{{BaseURL}}/redir?to=https://evil.com"
      - "{{BaseURL}}/goto?url=https://evil.com"

    matchers:
      - type: regex
        part: header
        regex:
          - '(?m)^(?:Location\s*?:\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\-_\.@]*)evil\.com'
```

### Sensitive File Exposure
```yaml
id: env-file-exposure

info:
  name: .env File Exposure
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/../.env"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "APP_KEY"
          - "SECRET_KEY"
        condition: or
      - type: status
        status:
          - 200
      - type: word
        part: header
        words:
          - "text/html"
        negative: true
```

### IDOR Check
```yaml
id: idor-user-data

info:
  name: IDOR User Data Access
  severity: high

http:
  - payloads:
      user_id:
        - "1"
        - "2"
        - "100"
        - "1000"
    raw:
      - |
        GET /api/users/{{user_id}}/profile HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer LOW_PRIV_TOKEN

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - '"email"'
          - '"name"'
        condition: and
```

## Running Custom Templates

```bash
# Single template
nuclei -u https://target.com -t my-template.yaml

# Template directory
nuclei -u https://target.com -t ./my-templates/

# With debug output
nuclei -u https://target.com -t my-template.yaml -debug

# Validate template
nuclei -t my-template.yaml -validate

# Generate from AI description
nuclei -ai "check for exposed .env files with database credentials"

# List templates by tag
nuclei -tl -tags sqli
```

## DSL Helper Functions

| Function | Description |
|----------|-------------|
| `contains(str, substr)` | String contains check |
| `len(str)` | String length |
| `toUpper(str)` | Uppercase |
| `toLower(str)` | Lowercase |
| `replace(str, old, new)` | String replace |
| `trim(str, cutset)` | Trim characters |
| `sha256(str)` | SHA256 hash |
| `md5(str)` | MD5 hash |
| `base64(str)` | Base64 encode |
| `base64_decode(str)` | Base64 decode |
| `url_encode(str)` | URL encode |
| `url_decode(str)` | URL decode |
| `regex(pattern, str)` | Regex match |
| `rand_int(min, max)` | Random integer |
| `rand_text_alpha(n)` | Random alpha string |

## Pro Tips

- Always use `matchers-condition: and` to reduce false positives
- Use `internal: true` extractors for multi-step request chaining
- `{{interactsh-url}}` auto-generates OOB callback URLs
- Validate templates with `nuclei -t template.yaml -validate`
- Use `-debug` to see full request/response during development
- Tag templates well for organization and selective running
- Use workflows to chain technology detection with vuln scanning
- DSL matchers are the most flexible - use for complex conditions
- Negative matchers help exclude common false positive patterns
