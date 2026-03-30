---
id: "arjun"
title: "Arjun Parameter Discovery"
type: "tool"
category: "reconnaissance"
subcategory: "parameter-discovery"
tags: ["parameter", "arjun"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

HTTP parameter discovery suite.

## Command Reference

```bash
arjun -u https://{domain} -w /opt/wordlists/parameters.txt -t 20 -o {domain}_parameters.txt
echo "Parameter discovery results saved to {domain}_parameters.txt"
```
