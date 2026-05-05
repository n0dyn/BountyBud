---
id: "cloud-asset-enumeration"
title: "Cloud Asset Enumeration 2026 - S3, GCS, Azure Blobs, Kubernetes, Serverless & Misconfig Discovery"
type: "technique"
category: "reconnaissance"
subcategory: "cloud-asset-enumeration"
tags: ["cloud", "s3", "gcs", "azure", "kubernetes", "serverless", "lambda", "cloud-enum", "pacu", "2026"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["cloud-misconfigurations", "aws-iam-privesc", "metadata-ssrf", "cloud-penetration-testing"]
updated: "2026-05-04"
---

## Overview
Cloud assets are high-value and often misconfigured. Enumeration beyond subdomain recon finds buckets, functions, clusters, and internal services via public metadata, DNS, and provider APIs.

## Techniques
### 1. Bucket/Storage Discovery
- **S3**: `aws s3 ls s3://target-bucket` or tools (s3scanner, CloudBrute, BucketStream).
- Permutations: `target`, `target-backup`, `target-dev`, `target-logs`.
- **GCS/Azure**: Similar with gcloud / az CLI + wordlists.
- Check permissions: public read, list, write.

### 2. Kubernetes / Container Discovery
- `kubectl` against exposed API servers (from subdomain or ASN).
- Tools: kube-hunter, Kube-bench for misconfigs.
- Look for unauth dashboards, exposed etcd, weak RBAC.

### 3. Serverless / Lambda / Cloud Functions
- Enumerate via DNS (function URLs), API Gateway endpoints.
- Tools: CloudEnum, Pacu, ScoutSuite.
- Test for SSRF to metadata, env var leaks, IAM over-priv.

### 4. Metadata & Instance Enumeration
- SSRF to `169.254.169.254` or `metadata.google.internal`.
- Discover instance roles, user-data, SSH keys.

### 5. Multi-Cloud & Hybrid
- Cross-provider (AWS + GCP peering, Azure AD).

## Workflow
1. Subdomain + ASN recon → potential cloud domains.
2. Bucket/permutation brute.
3. Cloud CLI auth (if creds found) or unauth enum.
4. Pacu/Scout for deeper misconfig.
5. Chain with SSRF/metadata for privesc.

## Deep Dig Prompts
```
For target.com cloud footprint:
1. Generate S3/GCS/Azure bucket wordlist + scan commands.
2. Kubernetes discovery commands and common misconfig checks.
3. Serverless function URL enumeration + metadata SSRF test.
4. Pacu/CloudEnum full run commands.
5. Impact: "Public S3 bucket with PII + Lambda SSRF to IMDS = full AWS account compromise."
Output scripts, tool commands, and chain examples.
```

## Tools
- CloudEnum, Pacu, ScoutSuite, s3scanner, kube-hunter, CloudBrute, BucketStream.

## References
- Hacking the Cloud, 2026 cloud pentest guides, real bug bounty cloud finds.
---
