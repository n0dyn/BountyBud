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

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.1   |
| API        | 0.1   |
| Network    | 0.0   |
| Cloud      | 0.9   |
| CMS        | 0.1   |

## Fallback Alternatives

- **nuclei** - Cloud templates can detect exposed S3 buckets
- **truffleHog** - Can scan S3 buckets for leaked secrets
- **awscli** - Manual bucket enumeration with `aws s3 ls`

## Context-Aware Parameters

**Standard domain-based S3 scan**
```bash
python3 /opt/tools/S3Scanner/s3scanner.py -d {domain} -o {domain}_s3_buckets.txt
```

**Scan from wordlist of bucket names**
```bash
python3 /opt/tools/S3Scanner/s3scanner.py -l {domain}_bucket_names.txt -o {domain}_s3_results.txt
```

**Dump contents of open buckets**
```bash
python3 /opt/tools/S3Scanner/s3scanner.py -d {domain} --dump -o {domain}_s3_dump.txt
```
