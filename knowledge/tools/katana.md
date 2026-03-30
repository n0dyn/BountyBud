---
id: "katana"
title: "Katana - Next-Gen Web Crawler"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "katana", "modern", "js-rendering", "scope-control", "form-parsing"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/katana"
related: []
updated: "2026-03-30"
---

## Overview

Modern web crawler with JavaScript rendering, form parsing, and scope control.

## Command Reference

```bash
katana -u https://{domain} -d 5 -ps -pss waybackarchive,commoncrawl -f qurl -o {domain}_katana.txt
echo "[+] Katana: $(wc -l < {domain}_katana.txt) URLs discovered"
```

## Features

- JS rendering
- Scope control
- Form parsing

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/katana)
