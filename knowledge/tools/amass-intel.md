---
id: "amass-intel"
title: "Amass - Intelligence Gathering"
type: "tool"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain", "amass-intel", "intelligence", "osint-collection", "asn-enumeration", "reverse-whois"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/OWASP/Amass"
related: []
updated: "2026-03-30"
---

## Overview

Comprehensive OSINT-based subdomain enumeration with ASN and reverse whois lookups.

## Command Reference

```bash
amass intel -d {domain} -whois -o {domain}_intel.txt
amass enum -passive -d {domain} -o {domain}_amass.txt
echo "[+] Amass: $(wc -l < {domain}_amass.txt) subdomains discovered"
```

## Features

- OSINT collection
- ASN enumeration
- Reverse whois

## Documentation

- [Official Documentation](https://github.com/OWASP/Amass)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.90  |
| API         | 0.85  |
| Network     | 0.75  |
| Cloud       | 0.90  |
| CMS         | 0.90  |

## Fallback Alternatives

subfinder → assetfinder → findomain → chaos

## Context-Aware Parameters

```bash
# Passive enumeration
amass enum -passive -d {domain} -o {domain}_amass_passive.txt

# Active enumeration with brute force
amass enum -active -brute -d {domain} -o {domain}_amass_active.txt

# Intel mode for org discovery
amass intel -org "{org_name}" -o {domain}_amass_intel.txt

# With specific resolvers
amass enum -passive -d {domain} -rf resolvers.txt -o {domain}_amass_resolvers.txt
```
