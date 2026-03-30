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
