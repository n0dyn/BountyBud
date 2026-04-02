---
id: "bug-bounty-recon-pipeline"
title: "Bug Bounty Recon Pipeline - Complete Automated Workflow"
type: "methodology"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["recon", "pipeline", "automation", "workflow", "subdomain", "url", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["dig-deep-asset-classes", "subfinder", "httpx-probe", "nuclei-full"]
updated: "2026-03-30"
---

## Overview

A complete recon pipeline automates the tedious discovery phase so you can spend time on creative exploitation. This pipeline takes a target domain and produces: live subdomains, URLs, parameters, technologies, JavaScript endpoints, and initial vulnerability scan results.

## Phase 1: Subdomain Discovery

```bash
#!/bin/bash
TARGET=$1
mkdir -p $TARGET/recon

# Passive enumeration (multiple sources)
subfinder -d $TARGET -all -recursive -o $TARGET/recon/subfinder.txt &
amass enum -passive -d $TARGET -o $TARGET/recon/amass.txt &
assetfinder --subs-only $TARGET > $TARGET/recon/assetfinder.txt &
wait

# Merge and deduplicate
cat $TARGET/recon/{subfinder,amass,assetfinder}.txt | sort -u > $TARGET/recon/all_subs.txt
echo "[+] Total unique subdomains: $(wc -l < $TARGET/recon/all_subs.txt)"

# DNS resolution and live host check
httpx -l $TARGET/recon/all_subs.txt -threads 50 -status-code -title -tech-detect \
  -o $TARGET/recon/live_hosts.txt
echo "[+] Live hosts: $(wc -l < $TARGET/recon/live_hosts.txt)"

# Check for subdomain takeover
subjack -w $TARGET/recon/all_subs.txt -t 100 -o $TARGET/recon/takeover.txt
```

## Phase 2: URL & Content Discovery

```bash
# Historical URLs
gau $TARGET --threads 5 --subs | sort -u > $TARGET/recon/gau_urls.txt &
waybackurls $TARGET | sort -u > $TARGET/recon/wayback_urls.txt &
wait

# Active crawling
katana -u $TARGET/recon/live_hosts.txt -d 5 -ps -pss waybackarchive,commoncrawl \
  -f qurl -o $TARGET/recon/katana_urls.txt

# Merge all URLs
cat $TARGET/recon/{gau_urls,wayback_urls,katana_urls}.txt | sort -u > $TARGET/recon/all_urls.txt
echo "[+] Total URLs: $(wc -l < $TARGET/recon/all_urls.txt)"

# Extract interesting endpoints
cat $TARGET/recon/all_urls.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|config|env|bak|sql|log)" \
  > $TARGET/recon/interesting_urls.txt

# Extract JavaScript files
cat $TARGET/recon/all_urls.txt | grep -E "\.js$" | sort -u > $TARGET/recon/js_files.txt
```

## Phase 3: JavaScript Analysis

```bash
# Download all JS files
mkdir -p $TARGET/recon/js
cat $TARGET/recon/js_files.txt | while read url; do
  filename=$(echo $url | md5sum | cut -d' ' -f1)
  curl -s "$url" -o "$TARGET/recon/js/$filename.js" 2>/dev/null
done

# Extract endpoints from JS
cat $TARGET/recon/js/*.js | grep -oE "(https?://[^\"\s']+|/api/[^\"\s']+|/v[0-9]/[^\"\s']+)" \
  | sort -u > $TARGET/recon/js_endpoints.txt

# Search for secrets
grep -rnE "(api_key|apikey|secret|token|password|aws_access|stripe_|sk_live|pk_live)" \
  $TARGET/recon/js/ > $TARGET/recon/js_secrets.txt

# Search for internal/staging URLs
grep -rnE "(internal|staging|dev\.|localhost|192\.168|10\.)" \
  $TARGET/recon/js/ > $TARGET/recon/js_internal.txt
```

## Phase 4: Parameter & Technology Discovery

```bash
# Parameter discovery
arjun -u https://$TARGET -w /opt/wordlists/params.txt -t 20 -o $TARGET/recon/params.json

# Technology fingerprinting
whatweb https://$TARGET -a 3 --log-brief=$TARGET/recon/tech.txt

# WAF detection
wafw00f https://$TARGET -o $TARGET/recon/waf.txt
```

## Phase 5: Vulnerability Scanning

```bash
# Nuclei scan (comprehensive)
nuclei -l $TARGET/recon/live_hosts.txt \
  -t cves/,vulnerabilities/,misconfiguration/,exposures/,takeovers/ \
  -rate-limit 100 -c 50 \
  -o $TARGET/recon/nuclei_results.txt

# Check for CORS misconfigs
python3 corsy.py -i $TARGET/recon/live_hosts.txt -t 20 -o $TARGET/recon/cors.txt

# Check for open redirects
cat $TARGET/recon/all_urls.txt | grep -E "(redirect|url|next|return|goto|dest)=" \
  > $TARGET/recon/redirect_params.txt
```

## Phase 6: Organize & Prioritize

```bash
echo "=== RECON SUMMARY FOR $TARGET ==="
echo "Subdomains: $(wc -l < $TARGET/recon/all_subs.txt)"
echo "Live hosts: $(wc -l < $TARGET/recon/live_hosts.txt)"
echo "URLs: $(wc -l < $TARGET/recon/all_urls.txt)"
echo "JS files: $(wc -l < $TARGET/recon/js_files.txt)"
echo "JS secrets found: $(wc -l < $TARGET/recon/js_secrets.txt)"
echo "Nuclei findings: $(wc -l < $TARGET/recon/nuclei_results.txt)"
echo "Potential takeovers: $(wc -l < $TARGET/recon/takeover.txt)"
```

## Deep Dig Prompt — Post-Recon Analysis

```
Given these recon results [paste summary]:
1. Which subdomains look like staging/dev/internal environments?
2. Which URLs suggest admin panels, API docs, or debug endpoints?
3. What technologies are in use and what are their known vulnerability classes?
4. Which JS secrets need immediate investigation?
5. What attack vectors should I prioritize based on the tech stack and findings?
6. Generate a prioritized testing plan for the next 4 hours.
```
