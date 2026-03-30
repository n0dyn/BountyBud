---
id: "ffuf-params"
title: "FFUF Parameter Fuzzing"
type: "tool"
category: "reconnaissance"
subcategory: "parameter-discovery"
tags: ["parameter", "ffuf-params"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Parameter fuzzing using FFUF with common parameter wordlists.

## Command Reference

```bash
ffuf -u 'https://{domain}/?FUZZ=test' -w /opt/wordlists/parameters.txt -t 20 -rate 100 -mc 200 -o {domain}_param_fuzz.json
echo "Parameter fuzzing results saved to {domain}_param_fuzz.json"
```
