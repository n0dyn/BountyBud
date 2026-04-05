---
id: "smart-tool-execution"
title: "Smart Tool Execution - Targeted Chunks, Not Blanket Scans"
type: "methodology"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["execution", "timeout", "performance", "chunking", "methodology", "workflow", "deep-dig"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: ["attack-workflow-chains", "tool-selection-guide", "bug-bounty-workflow-engine"]
updated: "2026-04-04"
---

## Overview

Security tools timeout on broad targets. A blanket `gau --subs target.com | nuclei` will hang or timeout on any real-world program. Smart execution means breaking work into small, targeted chunks where each step completes in under 2 minutes and feeds the next step with filtered, relevant data.

## The Core Principle

```
WRONG: Big scope → long timeout → hope it finishes
RIGHT: Small scope → short timeout → filter → repeat on interesting results
```

Every tool call should:
1. Target a SPECIFIC host or small batch (not an entire domain with all subs)
2. Complete in under 120 seconds
3. Filter output before passing to the next tool
4. Produce actionable data, not raw dumps

## Chunked Execution Patterns

### Subdomain Enumeration

```bash
# WRONG — too broad, will timeout or produce unmanageable output
subfinder -d target.com -all -recursive | httpx | nuclei

# RIGHT — step by step with filtering
# Step 1: Fast passive enum (30s)
subfinder -d target.com -silent -o /tmp/subs.txt
wc -l /tmp/subs.txt  # Check size before proceeding

# Step 2: Probe live hosts (60s, batch if needed)
httpx -l /tmp/subs.txt -silent -sc -title -o /tmp/live.txt
wc -l /tmp/live.txt

# Step 3: Identify interesting targets (instant)
# Filter for non-CDN, non-static, app-like hosts
grep -v "cdn\|static\|assets\|media\|images" /tmp/live.txt | head -20

# Step 4: Scan EACH interesting host individually
nuclei -u https://app.target.com -tags exposure,misconfig -timeout 5
```

### URL Collection

```bash
# WRONG — gau on a big domain with subs will timeout
gau --subs target.com --threads 5

# RIGHT — target specific subdomains, limit output
# Step 1: Collect from one subdomain at a time
gau app.target.com --threads 2 2>/dev/null | head -500 > /tmp/urls.txt
wc -l /tmp/urls.txt

# Step 2: Filter for parameterized URLs only
grep "=" /tmp/urls.txt | sort -u > /tmp/params.txt
wc -l /tmp/params.txt

# Step 3: Remove noise (CDN, static, tracking)
grep -v "\.js\|\.css\|\.png\|\.jpg\|\.gif\|\.svg\|\.woff\|analytics\|tracking\|cdn" \
  /tmp/params.txt > /tmp/interesting_params.txt
```

### Vulnerability Scanning

```bash
# WRONG — all templates against all targets
nuclei -l /tmp/all_live_hosts.txt -severity critical,high

# RIGHT — specific templates against specific hosts
# Step 1: Quick exposure check on one host (30s)
nuclei -u https://app.target.com -tags exposure,token,misconfig -timeout 5 -nc

# Step 2: If web app, check for specific vulns (60s)
nuclei -u https://app.target.com -tags xss,sqli,ssrf,ssti -severity high,critical -timeout 5

# Step 3: Tech-specific scan based on what httpx found
nuclei -u https://app.target.com -tags wordpress -timeout 5  # if WordPress detected
nuclei -u https://api.target.com -tags api,graphql -timeout 5  # if API
```

### SQL Injection Testing

```bash
# WRONG — feed hundreds of URLs to sqlmap
sqlmap -m /tmp/all_params.txt --batch --level 5

# RIGHT — pick the most promising params
# Step 1: Filter for injectable-looking params
grep -iE "(id|user|item|product|order|search|query|page|cat|sort|filter)=" \
  /tmp/params.txt | head -20 > /tmp/sqli_candidates.txt

# Step 2: Test one URL at a time with moderate settings
sqlmap -u "https://app.target.com/page?id=1" --batch --level 2 --risk 2 --random-agent --timeout 10

# Step 3: Only escalate level/risk if you see promising behavior
sqlmap -u "https://app.target.com/page?id=1" --batch --level 3 --risk 3 --tamper=space2comment
```

### XSS Testing

```bash
# WRONG — feed all URLs to dalfox
dalfox file /tmp/all_urls.txt

# RIGHT — find reflection points first, then test
# Step 1: Find URLs that reflect input (fast check)
cat /tmp/params.txt | head -30 | while read url; do
  reflected=$(curl -s "${url}CANARY123" | grep -c "CANARY123")
  if [ "$reflected" -gt 0 ]; then echo "$url"; fi
done > /tmp/reflected.txt

# Step 2: Test reflected URLs with dalfox (small batch)
dalfox file /tmp/reflected.txt --silence --timeout 10 -o /tmp/xss_results.txt
```

### Directory Bruteforce

```bash
# WRONG — recursive scan with huge wordlist
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -recursion -recursion-depth 3

# RIGHT — medium wordlist, no recursion first, then drill into interesting dirs
# Step 1: Quick sweep (60s)
ffuf -u https://app.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -t 20 -timeout 5

# Step 2: Drill into interesting directories found
ffuf -u https://app.target.com/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301,302,403 -t 20
```

## Output Size Management

Always check output size before passing to the next tool:

```bash
# Before processing a file
wc -l /tmp/urls.txt
# If > 500 lines, filter before proceeding
head -200 /tmp/urls.txt > /tmp/urls_batch1.txt

# Limit tool output in the command itself
subfinder -d target.com -silent | head -100
gau target.com | head -500
cat urls.txt | shuf | head -50  # Random sample
```

## Timeout Guidelines

```
Tool Category          Recommended Timeout    Max Scope
─────────────────────────────────────────────────────────
Passive recon          60s                    1 domain
DNS resolution         60s                    100 hosts
HTTP probing           90s                    100 hosts  
URL collection         60s                    1 subdomain
Crawling               90s                    1 host, depth 3
Dir bruteforce         90s                    1 host, medium wordlist
Nuclei scan            120s                   1 host, specific tags
SQLMap                 120s                   1 URL
XSS testing            90s                    10 URLs
Port scanning          120s                   1 host or /24
```

## The Filter-Then-Scan Pattern

For every recon phase, follow this pattern:

```
1. COLLECT   — run the tool with tight scope
2. COUNT     — wc -l to know what you're working with
3. FILTER    — remove noise, keep interesting results
4. PRIORITIZE — sort by likelihood of vulnerability
5. SCAN      — test the top 5-10 targets individually
6. ANALYZE   — review results before scanning more
```

## Anti-Patterns to Avoid

```
BAD: Running gau/waybackurls with --subs on large domains
     → Use per-subdomain, pipe through head

BAD: nuclei -l big_list.txt with no -tags filter
     → Always use -tags to target specific vuln classes

BAD: sqlmap -m file_with_200_urls.txt
     → Pick the 5 most promising parameterized URLs

BAD: Setting timeout to 600s hoping a broad scan finishes
     → Reduce scope so it finishes in 60-120s

BAD: ffuf with recursion depth 3+ and large wordlists
     → No recursion first, then drill into findings

BAD: Running 5 tools simultaneously on the same target
     → Run sequentially, use results to inform next tool
```

## Deep Dig Prompts

```
I'm targeting {domain} which has {N} subdomains and {M} live hosts.
1. Break this into execution chunks that will each complete in under 2 minutes.
2. Which 5 hosts should I scan first and why?
3. What specific nuclei tags should I use for each host based on its tech stack?
4. Design a 10-step attack plan where each step builds on the previous.
```
