---
id: "subdomain-takeover"
title: "Subdomain Takeover - Dangling DNS & Cloud Service Hijacking"
type: "technique"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain-takeover", "dns", "cname", "dangling", "s3", "azure", "heroku", "github-pages"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["subfinder", "cloud-misconfigurations"]
updated: "2026-03-30"
---

## Overview

Subdomain takeover occurs when a subdomain's DNS record (usually CNAME) points to an external service that the organization no longer controls. An attacker claims the abandoned resource and serves arbitrary content on the victim's subdomain. Impact: cookie theft (same-origin), phishing, SEO poisoning. Payout: $500-$5k+ depending on impact chain.

## Methodology

```
1. Enumerate all subdomains (subfinder, amass, etc.)
2. Resolve DNS — identify CNAMEs pointing to external services
3. Check if the target resource exists (404, NXDOMAIN, "no such bucket")
4. Claim the resource on the service provider
5. Serve proof-of-concept content
```

## Vulnerable Services & Fingerprints

| Service | CNAME Pattern | Fingerprint (when vulnerable) |
|---------|--------------|-------------------------------|
| AWS S3 | `*.s3.amazonaws.com` | `NoSuchBucket` |
| Azure Blob | `*.blob.core.windows.net` | `The specified container does not exist` |
| Azure Web App | `*.azurewebsites.net` | NXDOMAIN |
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here` |
| Heroku | `*.herokuapp.com` | `No such app` |
| Shopify | `*.myshopify.com` | `Sorry, this shop is currently unavailable` |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain` |
| Ghost | `*.ghost.io` | `The thing you were looking for is no longer here` |
| Pantheon | `*.pantheonsite.io` | `404 unknown site` |
| Cargo | `*.cargocollective.com` | `404 Not Found` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Netlify | `*.netlify.app` | Page not found (but harder to claim) |
| Zendesk | `*.zendesk.com` | `Help Center Closed` |
| WordPress.com | `*.wordpress.com` | `Do you want to register` |
| Tumblr | `*.tumblr.com` | `There's nothing here` |
| Unbounce | `*.unbouncepages.com` | `The requested URL was not found` |
| Fly.io | `*.fly.dev` | NXDOMAIN |

## Detection Tools

```bash
# subjack — automated takeover checking
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl

# nuclei — takeover templates
nuclei -l subdomains.txt -t takeovers/ -o takeover_results.txt

# can-i-take-over-xyz — reference for vulnerable services
# https://github.com/EdOverflow/can-i-take-over-xyz

# Manual CNAME check
dig +short CNAME sub.target.com
host sub.target.com

# Check if CNAME target resolves
dig +short the-cname-target.service.com
# NXDOMAIN or error page = potentially vulnerable
```

## Claiming Resources

### AWS S3
```bash
# If CNAME points to bucket.s3.amazonaws.com and bucket doesn't exist
aws s3 mb s3://bucket-name --region us-east-1
echo "Subdomain takeover PoC" > index.html
aws s3 cp index.html s3://bucket-name/ --acl public-read
aws s3 website s3://bucket-name/ --index-document index.html
```

### GitHub Pages
```
1. Create repo with matching name
2. Enable GitHub Pages
3. Add CNAME file with the target subdomain
4. Push index.html with PoC
```

### Azure
```bash
# Create Azure Web App with the subdomain name
az webapp create --name target-subdomain --resource-group mygroup --plan myplan
```

## Escalation Chains

```
# Cookie theft (if parent domain sets cookies on *.target.com)
# Serve JS that reads document.cookie and exfiltrates

# OAuth token theft
# If OAuth redirect allows *.target.com, redirect to taken-over subdomain

# CSP bypass
# If CSP whitelists *.target.com, serve malicious JS from taken-over subdomain

# Email spoofing
# If MX records are also dangling, claim the mail service
```

## Deep Dig Prompts

```
Given these subdomains and their DNS records [paste]:
1. Identify all CNAMEs pointing to external services.
2. Check each against the known vulnerable services list.
3. For any dangling records, provide exact steps to claim the resource.
4. Assess the impact — can this be chained with cookie theft, OAuth redirect, or CSP bypass?
5. Check for NS delegation takeover (even higher impact than CNAME).
```

## Tools

- **subjack** — Automated subdomain takeover checking
- **nuclei** — Takeover detection templates
- **can-i-take-over-xyz** — Vulnerability reference
- **dnsrecon** — DNS record enumeration
- **dig/host** — Manual DNS queries
