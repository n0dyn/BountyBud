---
id: "ffuf-api"
title: "FFUF API Endpoint Discovery"
type: "tool"
category: "api-security"
subcategory: "rest"
tags: ["api", "ffuf-api"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

API endpoint discovery using common API patterns.

## Command Reference

```bash
ffuf -u 'https://{domain}/api/FUZZ' -w /opt/wordlists/api_endpoints.txt -t 20 -rate 100 -mc 200,201,204 -o {domain}_api_endpoints.json
echo "API endpoint discovery results saved to {domain}_api_endpoints.json"
```
