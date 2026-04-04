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

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.85  |
| API         | 0.90  |
| Network     | 0.10  |
| Cloud       | 0.40  |
| CMS         | 0.80  |

## Fallback Alternatives

paramspider → x8 → manual parameter fuzzing with ffuf

## Context-Aware Parameters

```bash
# GET parameters
arjun -u https://{domain}/endpoint -m GET -o {domain}_params_get.json

# POST parameters
arjun -u https://{domain}/endpoint -m POST -o {domain}_params_post.json

# JSON parameters
arjun -u https://{domain}/api/endpoint -m JSON -o {domain}_params_json.json

# With custom wordlist
arjun -u https://{domain}/endpoint -w /opt/wordlists/params.txt -o {domain}_params_custom.json

# From URL list
arjun -i urls.txt -o {domain}_params_bulk.json
```
