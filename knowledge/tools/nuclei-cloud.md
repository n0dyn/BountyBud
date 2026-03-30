---
id: "nuclei-cloud"
title: "Nuclei Cloud Templates"
type: "tool"
category: "cloud"
subcategory: "aws"
tags: ["cloud", "nuclei-cloud"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Cloud-specific misconfigurations using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t cloud/ -rate-limit 50 -o {domain}_cloud_scan.txt
echo "Cloud security scan results saved to {domain}_cloud_scan.txt"
```
