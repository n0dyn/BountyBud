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
