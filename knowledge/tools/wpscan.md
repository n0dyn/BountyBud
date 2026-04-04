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

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.20  |
| API         | 0.10  |
| Network     | 0.05  |
| Cloud       | 0.10  |
| CMS         | 0.95  |

## Fallback Alternatives

nuclei --tags wordpress → manual WP testing

## Context-Aware Parameters

```bash
# Enumerate plugins
wpscan --url https://{domain} --enumerate p --plugins-detection aggressive -o {domain}_wpscan_plugins.json

# Enumerate themes
wpscan --url https://{domain} --enumerate t -o {domain}_wpscan_themes.json

# Enumerate users
wpscan --url https://{domain} --enumerate u -o {domain}_wpscan_users.json

# With API token for vulnerability data
wpscan --url https://{domain} --enumerate vp,vt,u --api-token {API_TOKEN} -o {domain}_wpscan_full.json

# Aggressive detection mode
wpscan --url https://{domain} --enumerate p,t,u --detection-mode aggressive --plugins-detection aggressive -o {domain}_wpscan_aggressive.json
```
