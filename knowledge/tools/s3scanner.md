---
id: "s3scanner"
title: "S3 Bucket Scanner"
type: "tool"
category: "cloud"
subcategory: "aws"
tags: ["cloud", "s3scanner"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Scan for misconfigured S3 buckets related to the domain.

## Command Reference

```bash
python3 /opt/tools/S3Scanner/s3scanner.py -d {domain} -o {domain}_s3_buckets.txt
echo "S3 bucket scan results saved to {domain}_s3_buckets.txt"
```
