---
id: "change-detection-monitoring"
title: "Change Detection - Finding Fresh Bugs in New Code"
type: "methodology"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["monitoring", "change-detection", "new-features", "javascript", "subdomain", "api", "methodology", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["bug-bounty-recon-pipeline", "smart-hunting-strategy", "business-logic-hunting"]
updated: "2026-04-04"
---

## Overview

Bugs live in new code. A feature deployed yesterday has 100x more bugs than one that's been live for 3 years. Most hunters blast automated scans at static attack surfaces. The hunters who find bounties are watching for CHANGES — new subdomains, new endpoints, modified JavaScript, new API routes. This guide teaches you how to detect and hunt fresh attack surface.

## Why Change Detection Wins

```
STATIC SCANNING:
  You vs 10,000 other hunters, all running the same tools
  against the same attack surface that's been scanned for years.
  Finding probability: ~0.01%

CHANGE HUNTING:
  New subdomain appears → you're the first to test it
  New JS bundle deployed → new API endpoints nobody's seen
  New feature launched → business logic not yet hardened
  Finding probability: ~5-10%
```

## Subdomain Monitoring

### Initial Baseline

```bash
# Create baseline of all known subdomains
subfinder -d target.com -all -silent | sort -u > ~/targets/target.com/baseline_subs.txt
echo "[+] Baseline: $(wc -l < ~/targets/target.com/baseline_subs.txt) subdomains"
```

### Detect New Subdomains

```bash
#!/bin/bash
# Run this daily/weekly
TARGET="target.com"
BASELINE="$HOME/targets/$TARGET/baseline_subs.txt"
NEW_SCAN="$HOME/targets/$TARGET/subs_$(date +%Y%m%d).txt"

subfinder -d $TARGET -all -silent | sort -u > "$NEW_SCAN"

# Find new subdomains not in baseline
comm -13 "$BASELINE" "$NEW_SCAN" > /tmp/new_subs.txt
NEW_COUNT=$(wc -l < /tmp/new_subs.txt)

if [ "$NEW_COUNT" -gt 0 ]; then
  echo "[!] $NEW_COUNT NEW subdomains found:"
  cat /tmp/new_subs.txt

  # Immediately probe new subdomains
  httpx -l /tmp/new_subs.txt -silent -sc -title -tech-detect

  # Update baseline
  cat "$BASELINE" "$NEW_SCAN" | sort -u > "${BASELINE}.tmp"
  mv "${BASELINE}.tmp" "$BASELINE"
fi
```

### What New Subdomains Mean

```
staging.target.com    → Less hardened, may have debug features
beta.target.com       → New features being tested
api-v3.target.com     → New API version, likely has new endpoints
dashboard.target.com  → New internal tool exposed externally
dev-*.target.com      → Developer environments, default creds
partner.target.com    → Third-party integration, different auth
mobile-api.target.com → Mobile-specific API, often less tested
```

## JavaScript Monitoring

### Detect New/Changed JS Files

```bash
# Crawl and extract JS file URLs
katana -u https://app.target.com -d 2 -jc -silent | grep '\.js$' | sort -u > ~/targets/target.com/js_files.txt

# Download and hash all JS files for comparison
mkdir -p ~/targets/target.com/js_hashes
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1)
  hash=$(curl -s "$url" | md5sum | cut -d' ' -f1)
  echo "$hash $url" >> ~/targets/target.com/js_hashes/current.txt
done < ~/targets/target.com/js_files.txt
```

### Extract New Endpoints from JS

```bash
# When you detect a changed JS file, extract endpoints
# Using linkfinder
python3 linkfinder.py -i "https://app.target.com/static/app.js" -o cli

# Manual grep for API patterns
curl -s "https://app.target.com/static/app.js" | \
  grep -oP '["'"'"'](\/api\/[^"'"'"']+)["'"'"']' | sort -u

# Look for new fetch/axios calls
curl -s "https://app.target.com/static/app.js" | \
  grep -oP '(fetch|axios\.(get|post|put|delete|patch))\s*\(\s*[`"'"'"'][^`"'"'"']+' | sort -u
```

### What JS Changes Reveal

```
New API endpoints      → Test for auth, IDOR, injection
New query parameters   → Test for SQLi, XSS, SSRF
New form fields        → Mass assignment opportunity
New auth logic         → JWT changes, new OAuth flows
New file upload paths  → Test bypass techniques
Hidden admin routes    → BFLA testing
Feature flags          → Enable premium features via client-side toggle
Hardcoded secrets      → API keys, tokens, internal URLs
```

## API Change Detection

### Monitor OpenAPI/Swagger Docs

```bash
# Many apps expose API docs — monitor for changes
SWAGGER_URLS=(
  "https://api.target.com/swagger.json"
  "https://api.target.com/openapi.json"
  "https://api.target.com/v2/api-docs"
  "https://app.target.com/api/docs"
)

for url in "${SWAGGER_URLS[@]}"; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$resp" = "200" ]; then
    echo "[+] API docs found: $url"
    curl -s "$url" | python3 -m json.tool > ~/targets/target.com/api_docs_$(date +%Y%m%d).json
  fi
done

# Diff against previous version
diff ~/targets/target.com/api_docs_prev.json ~/targets/target.com/api_docs_$(date +%Y%m%d).json
```

### Monitor GraphQL Schema

```bash
# Introspection query to get full schema
curl -s -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' \
  | python3 -m json.tool > ~/targets/target.com/graphql_schema_$(date +%Y%m%d).json

# Compare with previous schema to find new types/fields
```

## HTTP Response Monitoring

### Detect New Headers and Features

```bash
# Monitor response headers for changes
curl -sI https://app.target.com | sort > ~/targets/target.com/headers_$(date +%Y%m%d).txt

# Look for new security headers (or removed ones!)
# A removed CSP header = XSS opportunity
# A new X-Powered-By = technology change
# A new API-Version header = new API version
```

### Monitor robots.txt and sitemap

```bash
# New disallowed paths = new features they don't want indexed
curl -s https://target.com/robots.txt > ~/targets/target.com/robots_$(date +%Y%m%d).txt
curl -s https://target.com/sitemap.xml > ~/targets/target.com/sitemap_$(date +%Y%m%d).xml

# Diff
diff ~/targets/target.com/robots_prev.txt ~/targets/target.com/robots_$(date +%Y%m%d).txt
```

## Hunting Fresh Attack Surface

When you detect a change, act fast — you have a window before other hunters notice.

### New Subdomain Playbook

```
1. httpx probe — what's running? (tech, status, title)
2. Is it behind WAF? (wafw00f)
3. whatweb — detailed technology fingerprint
4. If it's a web app:
   - Create an account if possible
   - Map all functionality via mitmproxy
   - Check for default credentials
   - Run nuclei with -tags exposure,misconfig,default-login
   - Test auth boundaries manually
5. If it's an API:
   - Check for docs (/swagger, /api-docs, /graphql)
   - Test authentication (is it even required?)
   - Test each endpoint for IDOR
```

### New API Endpoint Playbook

```
1. What does the endpoint do? (read the JS that calls it)
2. What parameters does it take?
3. Is authentication required? (try without token)
4. Is authorization checked? (try with different user's token)
5. Are IDs in the request? (change them → IDOR)
6. What happens with unexpected input? (SQLi, XSS in stored fields)
7. Is rate limiting applied? (brute-force, race condition)
```

### Changed JavaScript Playbook

```
1. Diff the old and new JS (if you have the old version)
2. Extract new API endpoints
3. Look for new query parameters
4. Check for feature flags or A/B test configs
5. Look for hardcoded secrets (API keys, internal URLs)
6. Test new endpoints for auth and IDOR
```

## Monitoring Schedule

```
DAILY:
  - Subdomain enumeration diff
  - Check for new JS bundles on top 5 targets

WEEKLY:
  - Full JS crawl and endpoint extraction
  - API docs diff (Swagger/GraphQL)
  - robots.txt / sitemap diff
  - Check program changelog/blog for announced features

MONTHLY:
  - Full recon pipeline on all targets
  - Re-evaluate target selection (new programs?)
  - Archive old baselines
```

## Changelog & Release Intelligence

The best hunting edge comes from knowing what changed BEFORE you scan. Developers tell you where the bugs are — you just have to read their changelogs.

### Where to Find Changelogs

```
OFFICIAL SOURCES (check these first):
  https://target.com/changelog
  https://target.com/release-notes
  https://target.com/whats-new
  https://target.com/blog (filter for "release", "update", "new feature")
  https://target.com/docs/changelog
  https://status.target.com (incident history reveals architecture)
  https://community.target.com (forums, feedback — users report bugs before hunters)

DEVELOPER SOURCES:
  GitHub/GitLab public repos — commit history, PRs, issues
  npm/PyPI/Maven packages — version diffs for open-source deps
  Docker Hub — image tags, layer changes
  https://web.archive.org/web/*/target.com/changelog — historical diffs

THIRD-PARTY SOURCES:
  https://builtwith.com/target.com — tech stack changes over time
  https://www.wappalyzer.com — technology detection history
  Google: site:target.com "new feature" OR "release" OR "update"
  Twitter/X: from:target "launched" OR "introducing" OR "now available"
  Product Hunt: search for target — launch announcements
  Crunchbase: funding rounds → new features often follow funding
  LinkedIn: target company hiring posts → reveal tech stack + focus areas
```

### Reading Changelogs Like a Hunter

```
CHANGELOG SAYS                    YOU HEAR
─────────────────────────────────────────────────────────────
"New user roles and permissions"  → Auth boundary changes → test IDOR/BFLA
"Improved file upload handling"   → They had upload bugs → test bypass
"New API v3 endpoints"            → New code, new bugs → map entire v3
"Payment system migration"        → Financial logic changed → test price manip
"SSO/OAuth integration"           → New auth flow → test redirect_uri, state
"New export/import feature"       → File handling → XXE, SSRF, path traversal
"Performance improvements"        → Caching changes → test cache poisoning
"Bug fixes and security updates"  → They found vulns → same class may remain
"New search functionality"        → User input → SQLi, XSS in results
"Webhook support added"           → URL input → SSRF
"New notification system"         → IDOR on notification endpoints
"Multi-tenant workspace"          → Org isolation → cross-tenant access
"Mobile app update"               → API changes → test mobile API endpoints
"Rate limiting improvements"      → Previous rate limit was broken → race condition
"GDPR data export feature"        → PII endpoint → IDOR on export
```

### GitHub Intelligence

```bash
# If the target has public repos, mine them for intel

# Recent commits — what's changing?
gh api repos/{owner}/{repo}/commits --jq '.[].commit.message' | head -30

# Recent PRs — what features are being merged?
gh api repos/{owner}/{repo}/pulls?state=closed\&sort=updated | \
  jq -r '.[] | "\(.merged_at) \(.title)"' | head -20

# Issues — what bugs are they aware of?
gh api repos/{owner}/{repo}/issues?state=all\&sort=updated | \
  jq -r '.[] | "\(.state) \(.title)"' | grep -i "bug\|fix\|vuln\|security\|auth\|xss\|inject" | head -20

# Search code for security-relevant patterns
gh search code "password" --repo {owner}/{repo} --json path -q '.[].path'
gh search code "TODO.*auth\|FIXME.*security\|HACK\|UNSAFE" --repo {owner}/{repo}

# Check for recently added API routes (Node/Express example)
gh api repos/{owner}/{repo}/commits --jq '.[0].sha' | \
  xargs -I{} gh api repos/{owner}/{repo}/compare/{}~10...{} --jq '.files[].filename' | \
  grep -i "route\|controller\|endpoint\|api"
```

### Dependency & CVE Intelligence

```bash
# Check if target uses vulnerable dependencies
# If they have a public package.json, Gemfile, requirements.txt, pom.xml:

# Node.js — check for known vulnerable packages
curl -s https://raw.githubusercontent.com/{owner}/{repo}/main/package.json | \
  jq -r '.dependencies | keys[]' | while read pkg; do
    echo "Checking $pkg..."
    npm audit --json --package-lock-only 2>/dev/null | jq '.vulnerabilities'
  done

# Search for CVEs in their stack
# Use search_cves tool with technology keywords from whatweb/httpx results
# e.g., search_cves("nginx 1.21") or search_cves("wordpress 6.4")
```

### Bug Bounty Program Intelligence

```bash
# Check HackerOne/Bugcrowd for the program's disclosure history

# HackerOne — public disclosed reports (GOLDMINE)
# Browse: https://hackerone.com/{program}/hacktivity
# Filter by: disclosed, severity, bounty amount
# What to look for:
#   - What vuln types have they paid for before? → hunt same class on new features
#   - What was out of scope that's now in scope?
#   - What assets have been added recently?
#   - Are there patterns? (lots of XSS → they probably have more)

# Program changelog (HackerOne/Bugcrowd)
# Check for scope changes — new domains/assets added = fresh attack surface
# Check for bounty table changes — increased payouts = they're struggling with a vuln class
# Check for policy updates — removed restrictions = new testing areas

# Google dork for past disclosures
# site:hackerone.com "target.com" disclosed
# site:bugcrowd.com "target.com"
```

### Status Page Intelligence

```
# Status pages reveal architecture and incidents
# https://status.target.com

WHAT TO LOOK FOR:
  - Component names → reveals internal service architecture
  - Incident history → what broke and how
  - Maintenance windows → what's being updated
  - Third-party integrations listed → additional attack surface
  
  "API Gateway — degraded" → they have a separate API gateway
  "Payment Processing — maintenance" → payment system being updated
  "CDN — resolved" → they use a CDN, check for cache poisoning
  "Authentication Service — incident" → auth service is separate, may have new bugs
```

### Automated Change Intelligence Script

```bash
#!/bin/bash
# Run before each hunting session to gather fresh intel
TARGET="target.com"
INTEL_DIR="$HOME/targets/$TARGET/intel"
mkdir -p "$INTEL_DIR"

echo "[*] Gathering intelligence for $TARGET..."

# 1. Check changelog/blog for updates
for path in changelog release-notes whats-new blog/category/updates; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$path")
  if [ "$code" = "200" ]; then
    echo "[+] Found: https://$TARGET/$path"
    curl -s "https://$TARGET/$path" | html2text | head -100 > "$INTEL_DIR/changelog_$(date +%Y%m%d).txt"
  fi
done

# 2. Check robots.txt for new paths
curl -s "https://$TARGET/robots.txt" > "$INTEL_DIR/robots_$(date +%Y%m%d).txt"

# 3. Check for API docs
for path in swagger.json openapi.json api-docs graphql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$path")
  if [ "$code" = "200" ]; then
    echo "[+] API docs: https://$TARGET/$path"
  fi
done

# 4. Technology fingerprint
whatweb -q "https://$TARGET" > "$INTEL_DIR/tech_$(date +%Y%m%d).txt" 2>/dev/null

# 5. Certificate transparency for new subdomains
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  jq -r '.[].name_value' | sort -u > "$INTEL_DIR/crt_subs_$(date +%Y%m%d).txt"

echo "[+] Intel gathered. Check $INTEL_DIR"
```

## Signals That Indicate Fresh Code

```
HIGH CONFIDENCE (definitely new code):
  - New subdomain resolving to a new IP
  - JS bundle with new hash/version number
  - New API endpoints in Swagger/GraphQL schema
  - Blog post announcing new feature
  - HTTP response with new headers

MEDIUM CONFIDENCE:
  - Changed response size on known endpoint
  - New parameters in existing endpoints
  - Modified error messages
  - New cookies being set

LOW CONFIDENCE (but worth checking):
  - DNS record changes
  - Certificate changes (new SAN entries)
  - CDN changes
```

## Deep Dig Prompts

```
I'm monitoring {target} and detected these changes:
{change_list}

1. Which changes are most likely to have exploitable bugs?
2. What should I test first on the new attack surface?
3. Design a 30-minute focused testing plan for the new features.
4. What business logic assumptions might the new code make?
5. How do I maximize my chances of being first to report?
```
