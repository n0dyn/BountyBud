---
id: "nmap-full"
title: "Nmap Full Port Scan"
type: "tool"
category: "network"
subcategory: "port-scanning"
tags: ["network", "nmap-full"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Comprehensive scan of all 65535 ports.

## Command Reference

```bash
nmap -p- -T4 {domain} -oA {domain}_nmap_full
echo "Nmap full port scan results saved to {domain}_nmap_full.*"
```
