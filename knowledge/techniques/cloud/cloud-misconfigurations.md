---
id: "cloud-misconfigurations"
title: "Cloud Misconfigurations Playbook - AWS / GCP / Azure (2026)"
type: "technique"
category: "cloud"
subcategory: "aws"
tags: ["cloud", "aws", "gcp", "azure", "s3", "iam", "metadata", "bucket", "misconfiguration", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "dig-deep-asset-classes"]
difficulty: "intermediate"
updated: "2026-03-30"
---

# Cloud Misconfigurations Playbook – AWS / GCP / Azure (2026)

## Discovery Phase
- Subdomain enumeration → bucket names
- JS leaks, error pages, terraform leaks

## Deep Dig Prompts
```
Given company [name] and subdomains [list], generate 30 realistic bucket/storage names for AWS S3, GCP GCS, Azure Blob. Include 2026 patterns (account-specific, region-prefixed, service-linked). Suggest exact test commands for public ACL, policy bypass, signed URL abuse.
```

## Per-Cloud Gold
**AWS**: S3, IAM roles, Metadata v2 bypass, Lambda env vars  
**GCP**: GCS, Cloud Run, Firebase rules, metadata token  
**Azure**: Blob, Key Vault, Managed Identity

## Tools
- S3Scanner, Cloud-Enum, Pacu, ScoutSuite, gcloud/aws-cli
