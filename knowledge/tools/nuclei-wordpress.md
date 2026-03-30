---
id: "nuclei-wordpress"
title: "Nuclei WordPress Templates"
type: "tool"
category: "cms"
subcategory: "wordpress"
tags: ["wordpress", "nuclei-wordpress"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

WordPress-specific vulnerability scanning using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t wordpress/ -rate-limit 50 -o {domain}_wp_nuclei.txt
echo "WordPress Nuclei scan results saved to {domain}_wp_nuclei.txt"
```
