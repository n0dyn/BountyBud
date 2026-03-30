---
id: "gauplus"
title: "GauPlus - Enhanced Archive Mining"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "gauplus", "archive", "enhanced-providers", "content-filtering", "subdomain-support"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/bp0lr/gauplus"
related: []
updated: "2026-03-30"
---

## Overview

Enhanced version of GAU with additional providers and filtering capabilities.

## Command Reference

```bash
gauplus -subs {domain} -b png,jpg,gif,jpeg,swf,woff,svg,pdf -o {domain}_gauplus.txt
echo "[+] GauPlus: $(wc -l < {domain}_gauplus.txt) filtered URLs collected"
```

## Features

- Enhanced providers
- Content filtering
- Subdomain support

## Documentation

- [Official Documentation](https://github.com/bp0lr/gauplus)
