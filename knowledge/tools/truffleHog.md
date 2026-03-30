---
id: "truffleHog"
title: "TruffleHog Secret Scanning"
type: "tool"
category: "reconnaissance"
subcategory: "sensitive-data-discovery"
tags: ["sensitive", "truffleHog", "secrets", "git-scanning", "secret-detection", "verified-results"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/trufflesecurity/trufflehog"
related: []
updated: "2026-03-30"
---

## Overview

Search for secrets accidentally committed to repositories. Note: Requires GitHub repository URL input.

## Command Reference

```bash
echo "Enter GitHub organization/repository URL: "
read repo_url
trufflehog git $repo_url --only-verified > {domain}_secrets.txt
echo "[+] TruffleHog: Secret scan completed for $repo_url"
```

## Features

- Git scanning
- Secret detection
- Verified results

## Documentation

- [Official Documentation](https://github.com/trufflesecurity/trufflehog)
