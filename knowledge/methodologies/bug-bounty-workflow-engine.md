---
id: "bug-bounty-workflow-engine"
title: "Bug Bounty Workflow Engine - 4-Phase Structured Hunting"
type: "methodology"
category: "web-application"
subcategory: "business-logic"
tags: ["workflow", "phases", "structured-hunting", "automation", "methodology", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["attack-workflow-chains", "smart-hunting-strategy", "bug-bounty-recon-pipeline", "tool-selection-guide", "vulnerability-priority-matrix"]
updated: "2026-04-04"
---

## Overview

A disciplined 4-phase workflow that takes you from a blank scope to validated findings. Each phase has defined inputs, tools, outputs, and exit criteria. The AI assistant should guide you through each phase sequentially, executing tools locally and analyzing results before advancing.

## Phase Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   PHASE 1    │───▶│   PHASE 2    │───▶│   PHASE 3    │───▶│   PHASE 4    │
│  Discovery   │    │  Enumeration │    │   Hunting    │    │ Exploitation │
│              │    │              │    │              │    │  & Reporting │
│ Subdomains   │    │ HTTP Probe   │    │ Vuln Scan    │    │ PoC + Report │
│ + DNS        │    │ + Tech ID    │    │ + Manual     │    │ + Escalation │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

---

## Phase 1: Discovery (Attack Surface Mapping)

**Goal:** Find every asset in scope.
**Time budget:** 15-30 minutes per target domain.

### Step 1.1: Subdomain Enumeration

```bash
# Run all sources in parallel
subfinder -d {domain} -all -recursive -o subs_subfinder.txt &
amass enum -passive -d {domain} -o subs_amass.txt &
assetfinder --subs-only {domain} > subs_assetfinder.txt &
wait

# Merge and deduplicate
cat subs_*.txt | sort -u > all_subdomains.txt
echo "[+] Unique subdomains: $(wc -l < all_subdomains.txt)"
```

### Step 1.2: DNS Resolution & Filtering

```bash
# Resolve and filter dead subdomains
cat all_subdomains.txt | dnsx -silent -a -resp -o resolved.txt

# Check for wildcard DNS
echo "random-nonexistent.{domain}" | dnsx -silent
# If resolves → wildcard detected, filter duplicates by IP
```

### Step 1.3: Subdomain Takeover Check

```bash
subjack -w all_subdomains.txt -t 100 -timeout 30 -o takeovers.txt
nuclei -l all_subdomains.txt -tags takeover -o takeover_nuclei.txt
```

### Exit Criteria
- [ ] All passive sources queried
- [ ] Subdomains deduplicated and DNS-resolved
- [ ] Wildcard detection complete
- [ ] Subdomain takeover checked
- [ ] Output: `all_subdomains.txt`, `resolved.txt`

---

## Phase 2: Enumeration (Service & Technology Profiling)

**Goal:** Identify what's running on each host and find the interesting targets.
**Time budget:** 15-30 minutes.

### Step 2.1: HTTP Service Discovery

```bash
httpx -l resolved.txt -sc -cl -title -tech-detect -server \
  -follow-redirects -threads 50 -o live_hosts.txt

# Extract just URLs for downstream tools
cat live_hosts.txt | awk '{print $1}' > live_urls.txt
echo "[+] Live HTTP services: $(wc -l < live_urls.txt)"
```

### Step 2.2: Technology Fingerprinting

```bash
# Detailed tech detection
whatweb -i live_urls.txt --log-brief whatweb_results.txt

# Identify interesting technologies
# Flag: WordPress, Joomla, Drupal → CMS-specific scanning
# Flag: PHP, Java, .NET → language-specific payloads
# Flag: Nginx, Apache, IIS → server-specific bypasses
# Flag: Cloudflare, Akamai → WAF bypass needed
```

### Step 2.3: Content Discovery

```bash
# Historical URLs (passive, fast)
gau {domain} --threads 5 --subs | sort -u > gau_urls.txt &
waybackurls {domain} | sort -u > wayback_urls.txt &
wait

# Active crawling (active, thorough)
katana -list live_urls.txt -d 5 -jc -kf -ps \
  -pss waybackarchive,commoncrawl -o katana_urls.txt

# Merge all URLs
cat gau_urls.txt wayback_urls.txt katana_urls.txt | sort -u > all_urls.txt

# Extract parameterized URLs (high-value targets)
cat all_urls.txt | grep "=" | sort -u > parameterized_urls.txt
echo "[+] Parameterized URLs: $(wc -l < parameterized_urls.txt)"

# Extract JavaScript files
cat all_urls.txt | grep -E '\.js(\?|$)' | sort -u > js_files.txt
```

### Step 2.4: Parameter Discovery

```bash
# Mine for hidden parameters
paramspider -d {domain} -o paramspider_urls.txt
arjun -i live_urls.txt -oT arjun_params.txt -t 10

# Merge with discovered parameterized URLs
cat paramspider_urls.txt >> parameterized_urls.txt
sort -u -o parameterized_urls.txt parameterized_urls.txt
```

### Step 2.5: JavaScript Analysis

```bash
# Extract endpoints from JS files
cat js_files.txt | while read url; do
  python3 linkfinder.py -i "$url" -o cli
done > js_endpoints.txt

# Look for secrets in JS
nuclei -l js_files.txt -tags exposure,token,secret
```

### Exit Criteria
- [ ] All live hosts identified with status codes
- [ ] Technology stack documented per host
- [ ] All URLs (historical + crawled) collected
- [ ] Parameterized URLs extracted
- [ ] JavaScript endpoints analyzed
- [ ] Output: `live_urls.txt`, `all_urls.txt`, `parameterized_urls.txt`, `js_endpoints.txt`

---

## Phase 3: Hunting (Vulnerability Detection)

**Goal:** Find real vulnerabilities using automated + manual testing.
**Time budget:** 1-4 hours depending on scope.

### Step 3.1: Automated Vulnerability Scanning

```bash
# Critical + High severity first
nuclei -l live_urls.txt -severity critical,high \
  -tags rce,sqli,xss,ssrf,lfi,xxe,ssti,auth \
  -rate-limit 150 -bulk-size 25 -o nuclei_critical.txt

# Exposure and misconfiguration checks
nuclei -l live_urls.txt -tags exposure,misconfig,default-login \
  -rate-limit 150 -o nuclei_exposure.txt
```

### Step 3.2: Injection Testing

```bash
# SQL Injection on parameterized URLs
sqlmap -m parameterized_urls.txt --batch \
  --level 2 --risk 2 --random-agent \
  --output-dir sqli_results/

# XSS testing
dalfox file parameterized_urls.txt \
  --mining-dom --deep-domxss \
  --follow-redirects -o xss_results.txt
```

### Step 3.3: SSRF & Redirect Testing

```bash
# Filter URLs with redirect-like parameters
cat parameterized_urls.txt | \
  grep -iE '(url|redirect|next|dest|redir|return|path|continue|window|to|out|view|dir|show|navigation|forward|r_url|page|uri|sp_url|site|html|file|val|validate|domain|callback|feed|host|port|link|go)=' \
  > redirect_candidates.txt

# Test with interactsh callback
nuclei -l redirect_candidates.txt -tags ssrf,redirect,oast
```

### Step 3.4: Manual Testing Priorities

Based on findings from automated scans, manually investigate:

```
1. AUTHENTICATION FLOWS
   - Register → login → password reset → OAuth flows
   - Test: default creds, brute force, token prediction, MFA bypass
   
2. AUTHORIZATION (IDOR/BOLA)
   - Map all endpoints with IDs/UUIDs
   - Test cross-user access with 2 accounts
   - Check vertical escalation (user → admin)

3. BUSINESS LOGIC
   - Price manipulation (change quantity to negative, modify totals)
   - Race conditions on financial operations
   - Workflow bypass (skip steps in multi-step processes)
   - Coupon/promo code abuse

4. FILE UPLOAD
   - Extension bypass (.php → .pHp, .php.jpg, .php%00.jpg)
   - Content-type bypass
   - SVG with XSS payload
   - Polyglot files (GIFAR, PDFXSS)

5. API ABUSE
   - Mass assignment (add admin=true to POST body)
   - GraphQL introspection + query depth attacks
   - Rate limiting bypass (IP rotation, header manipulation)
```

### Step 3.5: Technology-Specific Checks

```
WordPress → wpscan --enumerate ap,at,u,cb,dbe
Drupal    → droopescan scan drupal -u {url}
Joomla    → joomscan -u {url}
Apache    → nuclei -tags apache
Nginx     → Test path traversal: /..;/admin/
IIS       → Test short filename: /ABCDEF~1.ASP
```

### Exit Criteria
- [ ] Nuclei critical/high scan complete
- [ ] SQLi testing on all parameterized URLs
- [ ] XSS testing complete
- [ ] SSRF candidates tested
- [ ] Manual testing on auth/authz/business logic done
- [ ] Technology-specific checks run
- [ ] Output: Findings list with evidence

---

## Phase 4: Exploitation & Reporting

**Goal:** Validate findings, maximize impact, write quality reports.
**Time budget:** 30-60 minutes per finding.

### Step 4.1: Finding Validation (5-Gate Verification)

Every finding must pass all 5 gates:

```
GATE 1 — REPRODUCIBILITY
  Can you reproduce it 3/3 times in a clean browser?
  
GATE 2 — SCOPE CONFIRMATION
  Is the affected asset explicitly in scope?
  
GATE 3 — IMPACT ASSESSMENT
  What's the worst-case scenario if exploited?
  "An attacker could..." must be concrete, not theoretical.
  
GATE 4 — UNIQUENESS
  Has this already been reported? Check disclosed reports.
  Is this a duplicate of another finding in your list?
  
GATE 5 — PROOF OF CONCEPT
  Do you have clear evidence (screenshots, HTTP requests/responses)?
  Can someone else reproduce from your report alone?
```

### Step 4.2: Impact Maximization

Before reporting, try to escalate:

```
XSS → Can it steal admin cookies? → Account takeover?
SQLi → Can you extract PII? → Can you get RCE via INTO OUTFILE?
SSRF → Can you reach cloud metadata? → AWS keys → full compromise?
IDOR → Can you modify data, not just read it? → Can you access admin resources?
LFI → Can you read /etc/shadow? → Can you get RCE via log poisoning?
SSTI → Can you escalate from information disclosure to RCE?
```

### Step 4.3: Report Writing

```markdown
## Title
[Vuln Type] in [Feature] allows [Impact] via [Vector]

## Severity
Critical / High / Medium / Low (with CVSS 3.1 score)

## Description
Brief explanation of the vulnerability and why it matters.

## Steps to Reproduce
1. Navigate to {url}
2. Enter {payload} in {field}
3. Observe {result}

## Impact
An attacker could [specific impact]. This affects [scope of users/data].

## Proof of Concept
[Screenshots, HTTP requests/responses, video]

## Remediation
Specific fix recommendation with code examples if possible.
```

### Step 4.4: Escalation Opportunities

After initial report, continue testing:
- Can you chain this with another finding?
- Does the same pattern exist elsewhere in the application?
- Can you bypass any fix they deploy?

### Exit Criteria
- [ ] All findings pass 5-Gate Verification
- [ ] Impact maximized for each finding
- [ ] Reports written with clear PoC
- [ ] Submitted to platform

---

## Rate Limiting & Stealth Profiles

Adjust tool aggressiveness based on target responsiveness:

```
AGGRESSIVE (lab/CTF/permissive programs)
  - nuclei: rate-limit 300, bulk-size 50
  - ffuf: threads 100, delay 0
  - sqlmap: threads 5, no delay

NORMAL (standard programs)
  - nuclei: rate-limit 150, bulk-size 25
  - ffuf: threads 40, delay 100ms
  - sqlmap: threads 1, delay 1s

CONSERVATIVE (strict rate limiting)
  - nuclei: rate-limit 50, bulk-size 10
  - ffuf: threads 10, delay 500ms
  - sqlmap: threads 1, delay 3s

STEALTH (WAF/IDS detected)
  - nuclei: rate-limit 20, bulk-size 5
  - ffuf: threads 5, delay 2s
  - sqlmap: threads 1, delay 5s, --random-agent, --safe-url
  - Use --tamper scripts for evasion
```

If you receive 429 responses or get blocked, step down one profile level.

---

## Deep Dig Prompts

```
I'm starting Phase {N} for target {domain}.
Here are my results from the previous phase:
{previous_phase_results}

1. Analyze these results and identify the highest-priority targets.
2. What specific tools and parameters should I use next?
3. Are there any red flags or quick wins I should investigate first?
4. What's the recommended time budget for this phase?
5. Execute the first 3 steps of this phase and report findings.
```

```
I found the following potential vulnerabilities:
{findings_list}

For each finding:
1. Does it pass the 5-Gate Verification?
2. What's the maximum impact I can demonstrate?
3. How should I escalate or chain this finding?
4. Draft the report title and severity.
5. What remediation should I recommend?
```
