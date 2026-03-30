---
id: "wpscan"
title: "WPScan Vulnerability Scanner"
type: "tool"
category: "cms"
subcategory: "wordpress"
tags: ["wordpress", "wpscan"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

WordPress Security Scanner that identifies vulnerabilities.

## Command Reference

```bash
wpscan --url https://{domain} --enumerate p,t,u --plugins-detection aggressive --api-token YOUR_API_TOKEN -o {domain}_wpscan.json
echo "WPScan results saved to {domain}_wpscan.json"
```
