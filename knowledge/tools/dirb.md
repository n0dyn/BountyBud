---
id: "dirb"
title: "DIRB - Classic Directory Bruteforcer"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "dirb", "classic", "built-in-wordlists", "authentication", "recursive-mode"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "http://dirb.sourceforge.net/"
related: []
updated: "2026-03-30"
---

## Overview

Traditional directory bruteforcer with built-in wordlists and authentication support.

## Command Reference

```bash
dirb https://{domain} /usr/share/dirb/wordlists/big.txt -r -S -w -o {domain}_dirb.txt
echo "[+] DIRB: Classic directory scan completed"
```

## Features

- Built-in wordlists
- Authentication
- Recursive mode

## Documentation

- [Official Documentation](http://dirb.sourceforge.net/)
