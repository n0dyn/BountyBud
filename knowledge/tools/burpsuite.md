---
id: "burpsuite"
title: "Burp Suite - Web Security Testing Platform"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["webapp", "burpsuite", "professional", "proxy-interception", "active-scanning", "vulnerability-research"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://portswigger.net/burp"
related: []
updated: "2026-03-30"
---

## Overview

Industry-standard web application security testing platform with proxy, scanner, and intruder.

## Command Reference

```bash
echo "Burp Suite requires GUI - Launch via: burpsuite"
echo "Configure proxy: 127.0.0.1:8080"
echo "[+] Burp Suite: Configure browser proxy and start testing"
```

## Features

- Proxy interception
- Active scanning
- Vulnerability research

## Documentation

- [Official Documentation](https://portswigger.net/burp)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.95  |
| API         | 0.90  |
| Network     | 0.30  |
| Cloud       | 0.50  |
| CMS         | 0.90  |

## Fallback Alternatives

zaproxy → mitmproxy → caido

## Context-Aware Parameters

N/A (GUI tool). Common CLI integrations and extensions:

```bash
# Headless scan via Burp Suite Enterprise/CLI (if available)
# Use with proxy chains for automation:
curl --proxy http://127.0.0.1:8080 https://{domain}

# Common extensions: Autorize, Logger++, Param Miner, Turbo Intruder, Hackvertor
# Export project via CLI:
# java -jar burpsuite_pro.jar --project-file={domain}.burp
```
