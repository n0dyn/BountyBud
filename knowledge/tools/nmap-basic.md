---
id: "nmap-basic"
title: "Nmap Basic Port Scan"
type: "tool"
category: "network"
subcategory: "port-scanning"
tags: ["network", "nmap-basic"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Basic port scan with service detection and common scripts.

## Command Reference

```bash
nmap -sV -sC -T4 {domain} -oA {domain}_nmap_basic
echo "Nmap basic scan results saved to {domain}_nmap_basic.*"
```
