---
id: "nmap-scripts"
title: "Nmap NSE Scripts"
type: "tool"
category: "network"
subcategory: "service-enumeration"
tags: ["service", "nmap-scripts"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Service enumeration using Nmap NSE scripts.

## Command Reference

```bash
nmap -sV --script=default,discovery,safe {domain} -oA {domain}_nse_enum
echo "NSE enumeration results saved to {domain}_nse_enum.*"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.4   |
| API        | 0.2   |
| Network    | 0.9   |
| Cloud      | 0.3   |
| CMS        | 0.3   |

## Fallback Alternatives

- **nmap-full** - Comprehensive scan with all port coverage
- **nuclei-services** - Template-based service vulnerability scanning
- **masscan** - Faster port discovery (use nmap scripts on results)

## Context-Aware Parameters

**Standard NSE enumeration**
```bash
nmap -sV --script=default,discovery,safe {domain} -oA {domain}_nse_enum
```

**Vulnerability-focused NSE scan**
```bash
nmap -sV --script=vuln {domain} -oA {domain}_nse_vuln
```

**HTTP-specific NSE scripts**
```bash
nmap -p 80,443,8080,8443 --script=http-* {domain} -oA {domain}_nse_http
```

**SMB/Windows service enumeration**
```bash
nmap -p 139,445 --script=smb-enum-*,smb-vuln-* {domain} -oA {domain}_nse_smb
```
