---
id: "nuclei-api"
title: "Nuclei API Templates"
type: "tool"
category: "api-security"
subcategory: "rest"
tags: ["api", "nuclei-api"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

API-specific vulnerability scanning using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t http/misconfiguration/,http/vulnerabilities/ -rate-limit 50 -o {domain}_api_scan.txt
echo "API scan results saved to {domain}_api_scan.txt"
```
