---
id: "shodan"
title: "Shodan - Internet Scanner Search"
type: "tool"
category: "reconnaissance"
subcategory: "osint"
tags: ["osint", "shodan", "discovery", "device-discovery", "service-enumeration", "vulnerability-intel"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://www.shodan.io/"
related: []
updated: "2026-03-30"
---

## Overview

Search engine for Internet-connected devices, perfect for discovering exposed services.

## Command Reference

```bash
shodan search hostname:{domain} --fields ip_str,port,org,os,product --separator "," > {domain}_shodan.csv
echo "[+] Shodan: Internet device search completed"
```

## Features

- Device discovery
- Service enumeration
- Vulnerability intel

## Documentation

- [Official Documentation](https://www.shodan.io/)
