---
id: "masscan"
title: "Masscan Fast Port Scan"
type: "tool"
category: "network"
subcategory: "port-scanning"
tags: ["network", "masscan"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Ultra-fast port scanner for large-scale scanning.

## Command Reference

```bash
dig +short {domain} | grep -E '^[0-9.]+' > {domain}_ips.txt
masscan -p1-65535 -iL {domain}_ips.txt --rate=1000 -oX {domain}_masscan.xml
echo "[+] Masscan: High-speed port scan completed"
```
