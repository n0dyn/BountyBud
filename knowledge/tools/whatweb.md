---
id: "whatweb"
title: "WhatWeb - Web Technology Identifier"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["webapp", "whatweb", "fingerprinting", "technology-detection", "plugin-system", "detailed-analysis"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/urbanadventurer/WhatWeb"
related: []
updated: "2026-03-30"
---

## Overview

Recognizes web technologies including CMS, blogging platforms, analytics packages, and more.

## Command Reference

```bash
whatweb -a 3 --color=never --log-brief={domain}_whatweb.txt https://{domain}
echo "[+] WhatWeb: Technology fingerprinting completed"
```

## Features

- Technology detection
- Plugin system
- Detailed analysis

## Documentation

- [Official Documentation](https://github.com/urbanadventurer/WhatWeb)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.80  |
| API         | 0.70  |
| Network     | 0.30  |
| Cloud       | 0.60  |
| CMS         | 0.85  |

## Fallback Alternatives

httpx -tech-detect → wappalyzer → builtwith

## Context-Aware Parameters

```bash
# Quick scan (aggression level 1)
whatweb -a 1 https://{domain} --log-brief={domain}_whatweb_quick.txt

# Aggressive scan (aggression level 3)
whatweb -a 3 https://{domain} --log-brief={domain}_whatweb_aggressive.txt

# From file
whatweb -i urls.txt --log-brief={domain}_whatweb_batch.txt

# Verbose with plugins
whatweb -a 3 -v https://{domain} --log-verbose={domain}_whatweb_verbose.txt
```
