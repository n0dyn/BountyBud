---
id: "linkfinder"
title: "LinkFinder"
type: "tool"
category: "reconnaissance"
subcategory: "javascript-analysis"
tags: ["javascript", "linkfinder"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Python script to discover endpoints in JavaScript files.

## Command Reference

```bash
python3 /opt/tools/LinkFinder/linkfinder.py -i https://{domain} -d -o {domain}_js_endpoints.html
echo "JavaScript endpoints saved to {domain}_js_endpoints.html"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.8   |
| API        | 0.7   |
| Network    | 0.0   |
| Cloud      | 0.2   |
| CMS        | 0.4   |

## Fallback Alternatives

- **getjs** - Extracts JS file URLs (complementary, use before LinkFinder)
- **katana** - Crawler with built-in JS parsing
- **burpsuite** - Passive JS analysis during proxy use

## Context-Aware Parameters

**Standard endpoint extraction from domain**
```bash
python3 /opt/tools/LinkFinder/linkfinder.py -i https://{domain} -d -o {domain}_js_endpoints.html
```

**Analyze a specific JS file**
```bash
python3 /opt/tools/LinkFinder/linkfinder.py -i https://{domain}/static/app.js -o {domain}_app_endpoints.html
```

**CLI output for pipeline use**
```bash
python3 /opt/tools/LinkFinder/linkfinder.py -i https://{domain} -d -o cli
```

**Analyze local JS files**
```bash
python3 /opt/tools/LinkFinder/linkfinder.py -i /path/to/downloaded.js -o {domain}_local_endpoints.html
```
