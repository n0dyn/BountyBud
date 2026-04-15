---
id: "dalfox"
title: "Dalfox - XSS Scanner and Parameter Analyzer"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["xss", "dalfox", "scanner", "parameter-analysis", "reflected-xss", "stored-xss", "dom-xss", "waf-evasion"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
source_url: "https://github.com/hahwul/dalfox"
related: ["nuclei-full", "ffuf", "gau", "waybackurls"]
updated: "2026-04-14"
---

## Overview

Dalfox is a powerful open-source XSS scanner written in Go focused on automation. It performs intelligent parameter analysis, static analysis, and BAV (Browser Action Verification) testing. Detects reflected, stored, and DOM-based XSS with WAF evasion capabilities. Designed for pipe-based workflows with other recon tools.

## Installation

```bash
# Go install
go install github.com/hahwul/dalfox/v2@latest

# Homebrew
brew install dalfox

# Snap (Ubuntu)
sudo snap install dalfox

# Docker
docker pull hahwul/dalfox:latest

# NixOS
nix-shell -p dalfox
```

## Scanning Modes

```bash
# Single URL scan
dalfox url "https://target.com/search?q=test"

# Pipe mode (stdin)
cat urls.txt | dalfox pipe

# File mode (batch)
dalfox file urls.txt

# Stored XSS mode
dalfox sxss "https://target.com/comment" -d "body=PAYLOAD" --trigger "https://target.com/view"

# Server mode (REST API)
dalfox server --port 6664

# Payload mode (generate payloads only)
dalfox payload
```

## Command Reference

```bash
# Basic scan
dalfox url "https://target.com/page?param=value"

# With blind XSS callback
dalfox url "https://target.com/page?q=test" -b "https://your-interactsh.oast.pro"

# Custom headers (auth, cookies)
dalfox url "https://target.com/page?q=test" -H "Authorization: Bearer TOKEN"
dalfox url "https://target.com/page?q=test" -H "Cookie: session=abc123"

# Custom payloads
dalfox url "https://target.com/page?q=test" --custom-payload payloads.txt

# Remote wordlist for parameter mining
dalfox url "https://target.com/page" --remote-payloads portswigger,payloadbox

# Mining parameters from wayback/archive
dalfox url "https://target.com/page" --mining-dict-word params.txt
dalfox url "https://target.com/page" --mining-dom   # mine DOM-based params

# Specify HTTP method and data
dalfox url "https://target.com/api" -X POST -d "name=test&email=test"

# Proxy through Burp/Caido
dalfox url "https://target.com/page?q=test" --proxy http://127.0.0.1:8080

# Output formats
dalfox url "https://target.com/page?q=test" -o results.txt
dalfox url "https://target.com/page?q=test" --format json -o results.json

# WAF evasion with encoding
dalfox url "https://target.com/page?q=test" --waf-evasion

# Silence non-vuln output
dalfox url "https://target.com/page?q=test" --silence

# Only show verified vulns
dalfox url "https://target.com/page?q=test" --only-discovery false

# Skip BAV (faster, less accurate)
dalfox url "https://target.com/page?q=test" --skip-bav

# Follow redirects
dalfox url "https://target.com/page?q=test" --follow-redirects

# Timeout and delay
dalfox url "https://target.com/page?q=test" --timeout 10 --delay 100

# Concurrency
dalfox url "https://target.com/page?q=test" -w 50
```

## Key Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-b` | Blind XSS callback URL | - |
| `-H` | Custom header | - |
| `-d` | POST data | - |
| `-X` | HTTP method | GET |
| `--proxy` | Proxy URL | - |
| `-o` | Output file | - |
| `--format` | Output format (plain/json) | plain |
| `-w` | Worker count (concurrency) | 40 |
| `--timeout` | Request timeout (seconds) | 10 |
| `--delay` | Delay between requests (ms) | 0 |
| `--custom-payload` | Custom payload file | - |
| `--remote-payloads` | Remote payload sources | - |
| `--mining-dict-word` | Parameter mining wordlist | - |
| `--waf-evasion` | Enable WAF evasion | false |
| `--skip-bav` | Skip BAV testing | false |
| `--follow-redirects` | Follow redirects | false |
| `--silence` | Silence non-vuln output | false |
| `--only-discovery` | Only parameter discovery | false |

## Pipe Integration with Other Tools

### Full Recon-to-XSS Pipeline
```bash
# subfinder -> httpx -> gau -> dalfox
subfinder -d target.com -silent | httpx -silent | gau --threads 5 | dalfox pipe -b https://callback.oast.pro

# waybackurls -> dalfox
echo "target.com" | waybackurls | grep "=" | dalfox pipe

# katana -> dalfox
katana -u https://target.com -d 3 -f qurl | dalfox pipe

# paramspider -> dalfox
paramspider -d target.com --output params.txt
cat params.txt | dalfox pipe

# gau with qsreplace
echo "target.com" | gau | grep "=" | qsreplace "FUZZ" | dalfox pipe

# gospider -> dalfox
gospider -s "https://target.com" -d 2 --other-source | grep -oP 'https?://[^ ]+' | grep "=" | dalfox pipe

# hakrawler -> dalfox
echo "https://target.com" | hakrawler -d 3 | grep "=" | dalfox pipe

# arjun (find params) then dalfox
arjun -u https://target.com/page -oJ params.json
# use discovered params with dalfox
```

### With Authentication
```bash
# Cookie-based auth
cat urls.txt | dalfox pipe -H "Cookie: session=YOUR_SESSION_COOKIE"

# Bearer token
cat urls.txt | dalfox pipe -H "Authorization: Bearer YOUR_TOKEN"
```

### With Interactsh for Blind XSS
```bash
# Start interactsh-client in background, use URL as callback
cat urls.txt | dalfox pipe -b "https://YOUR_ID.oast.pro"
```

## Analysis Output

Dalfox provides detailed output:
- **POC**: Proof-of-concept URL with working payload
- **Parameter**: Which parameter is vulnerable
- **Type**: Reflected/Stored/DOM-based
- **Payload**: The XSS payload used
- **Evidence**: Response evidence showing injection

## Pro Tips

- Always use `-b` with an interactsh URL for blind XSS detection
- Pipe mode is the primary workflow - chain with recon tools
- Use `--proxy` to send traffic through Burp/Caido for manual verification
- `--remote-payloads portswigger` includes PortSwigger's XSS cheatsheet payloads
- Use `--mining-dom` for DOM-based XSS parameter discovery
- For stored XSS, use `sxss` mode with `--trigger` pointing to the view page
- Filter duplicate URLs before piping: `sort -u` or `anew`
- Use `--waf-evasion` when hitting WAF-protected targets
- Run with `--format json` for programmatic result processing
