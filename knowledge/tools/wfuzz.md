---
id: "wfuzz"
title: "Wfuzz - Advanced Web Fuzzer"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "wfuzz", "advanced", "plugin-system", "multiple-injection", "advanced-filtering"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/xmendez/wfuzz"
related: []
updated: "2026-03-30"
---

## Overview

Powerful web application fuzzer with plugins and multiple injection points.

## Command Reference

```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404,403 http://{domain}/FUZZ > {domain}_wfuzz.txt
echo "[+] Wfuzz: Advanced fuzzing completed"
```

## Features

- Plugin system
- Multiple injection
- Advanced filtering

## Documentation

- [Official Documentation](https://github.com/xmendez/wfuzz)
