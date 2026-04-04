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

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.2   |
| API        | 0.3   |
| Network    | 0.2   |
| Cloud      | 0.9   |
| CMS        | 0.1   |

## Fallback Alternatives

- **s3scanner** - Dedicated S3 bucket misconfiguration scanner
- **nuclei-full** - Full scan includes cloud templates
- **truffleHog** - Finds leaked cloud credentials in repos

## Context-Aware Parameters

**Standard cloud misconfiguration scan**
```bash
nuclei -u https://{domain} -t cloud/ -rate-limit 50 -o {domain}_cloud_scan.txt
```

**AWS-specific cloud scan**
```bash
nuclei -u https://{domain} -t cloud/aws/ -rate-limit 50 -o {domain}_aws_scan.txt
```

**Bulk cloud scan across subdomains**
```bash
nuclei -l {domain}_live_hosts.txt -t cloud/ -rate-limit 30 -c 5 -o {domain}_cloud_bulk.txt
```

**Cloud + exposure combined scan**
```bash
nuclei -u https://{domain} -t cloud/,exposures/ -rate-limit 50 -o {domain}_cloud_exposure.txt
```
