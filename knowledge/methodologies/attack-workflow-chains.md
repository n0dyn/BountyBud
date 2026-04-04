---
id: "attack-workflow-chains"
title: "Attack Workflow Chains - Structured Tool Sequences for Every Scenario"
type: "methodology"
category: "web-application"
subcategory: "business-logic"
tags: ["workflow", "tool-chain", "automation", "recon", "vulnerability-hunting", "methodology", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["bug-bounty-recon-pipeline", "smart-hunting-strategy", "tool-selection-guide", "vulnerability-priority-matrix"]
updated: "2026-04-04"
---

## Overview

Attack workflow chains are predefined sequences of tools optimized for specific hunting scenarios. Each chain is ordered by priority — run tools in sequence, feed outputs forward, and skip tools you don't have installed. The AI assistant should select the appropriate chain based on your target type and objective, then execute each step locally.

## Bug Bounty Reconnaissance Chain

**Objective:** Map the full attack surface of a target domain before hunting.

```
PHASE 1 — Subdomain Discovery
┌─────────────────────────────────────────────────┐
│ 1. subfinder -d {domain} -all -recursive        │
│ 2. amass enum -passive -d {domain}               │
│ 3. assetfinder --subs-only {domain}              │
│ 4. Merge + deduplicate → all_subs.txt            │
└─────────────────────────────────────────────────┘
         │
         ▼
PHASE 2 — HTTP Probing & Tech Detection
┌─────────────────────────────────────────────────┐
│ 5. httpx -l all_subs.txt -sc -title -tech-detect │
│    -follow-redirects -o live_hosts.txt           │
│ 6. whatweb -i live_hosts.txt (tech fingerprint)  │
└─────────────────────────────────────────────────┘
         │
         ▼
PHASE 3 — URL & Content Discovery
┌─────────────────────────────────────────────────┐
│ 7. katana -list live_hosts.txt -d 5 -jc          │
│    -ps -pss waybackarchive,commoncrawl           │
│ 8. gau {domain} --threads 5 --subs               │
│ 9. waybackurls {domain}                          │
│ 10. Merge + deduplicate → all_urls.txt           │
└─────────────────────────────────────────────────┘
         │
         ▼
PHASE 4 — Parameter Discovery
┌─────────────────────────────────────────────────┐
│ 11. paramspider -d {domain}                      │
│ 12. arjun -i interesting_urls.txt -oT params.txt │
│ 13. x8 -u {url} -w params_wordlist.txt           │
└─────────────────────────────────────────────────┘
```

**Output:** Subdomains, live hosts with tech stacks, all URLs with parameters, JavaScript endpoints.

**Fallback alternatives:**
- subfinder unavailable → use `chaos -d {domain}` or `findomain -t {domain}`
- httpx unavailable → use `httprobe`
- katana unavailable → use `hakrawler -url {domain} -d 3`
- gau unavailable → use `gauplus {domain}`

---

## Vulnerability Hunting Chain

**Objective:** Systematic vulnerability scanning against discovered attack surface.

```
STEP 1 — Broad Vulnerability Scan (Critical + High)
┌─────────────────────────────────────────────────────┐
│ nuclei -l live_hosts.txt -severity critical,high     │
│   -tags rce,sqli,xss,ssrf,lfi,xxe,ssti              │
│   -rate-limit 150 -bulk-size 25 -o nuclei_results.txt│
└─────────────────────────────────────────────────────┘
         │
         ▼
STEP 2 — XSS Deep Scan
┌─────────────────────────────────────────────────────┐
│ dalfox file parameterized_urls.txt --mining-dom      │
│   --deep-domxss --follow-redirects -o xss_results.txt│
│ Fallback: kxss < parameterized_urls.txt              │
└─────────────────────────────────────────────────────┘
         │
         ▼
STEP 3 — SQL Injection
┌─────────────────────────────────────────────────────┐
│ sqlmap -m parameterized_urls.txt --batch             │
│   --level 2 --risk 2 --random-agent                  │
│   --output-dir sqli_results/                         │
│ Fallback: ghauri -m parameterized_urls.txt --batch   │
└─────────────────────────────────────────────────────┘
         │
         ▼
STEP 4 — SSRF & Open Redirect
┌─────────────────────────────────────────────────────┐
│ Filter URLs with redirect/url/path/dest/next params  │
│ Test with Burp Collaborator / interactsh callback    │
│ nuclei -l filtered_urls.txt -tags ssrf,redirect      │
└─────────────────────────────────────────────────────┘
         │
         ▼
STEP 5 — Directory Bruteforce (targeted)
┌─────────────────────────────────────────────────────┐
│ ffuf -u {url}/FUZZ -w wordlist.txt -mc 200,301,302,  │
│   403 -recursion -recursion-depth 2                  │
│ Fallback: feroxbuster → dirsearch → gobuster         │
└─────────────────────────────────────────────────────┘
```

---

## High-Impact Hunting Chain

**Objective:** Focus exclusively on critical/high-payout vulnerabilities.

```
PRIORITY ORDER (by bounty impact):
──────────────────────────────────
  RCE (10) → SQLi (9) → SSRF (8) → IDOR (8)
  → XSS (7) → LFI (7) → XXE (6) → CSRF (5)

STEP 1 — Critical-Only Nuclei Scan
  nuclei -l targets.txt -severity critical
    -tags rce,sqli,ssrf,lfi,xxe -es info,low

STEP 2 — Deep SQLi with Tamper Scripts
  sqlmap -m urls.txt --batch --level 3 --risk 3
    --tamper=space2comment,between,randomcase
    --random-agent --output-dir sqli_deep/

STEP 3 — SSTI Detection
  nuclei -l targets.txt -tags ssti
  Manual: {{7*7}} / ${7*7} / #{7*7} in all input fields

STEP 4 — Blind XSS Campaign
  dalfox file urls.txt --blind {your_callback_url}
    --mining-dom --deep-domxss

STEP 5 — SSRF with Cloud Metadata
  Test all URL-accepting params with:
    http://169.254.169.254/latest/meta-data/
    http://metadata.google.internal/
    http://100.100.100.200/latest/meta-data/
```

---

## API Security Testing Chain

**Objective:** Comprehensive API endpoint testing.

```
STEP 1 — API Discovery
  katana -u {target} -jc -d 3 -f qurl
  Filter: grep -E '\.(json|xml|api|graphql|rest|v[0-9])' urls.txt

STEP 2 — API Fuzzing
  ffuf -u {api_base}/FUZZ -w api_wordlist.txt
    -mc 200,201,204,301,302,401,403,405
  Check: /swagger, /openapi, /api-docs, /graphql

STEP 3 — Authentication Testing
  nuclei -l api_endpoints.txt -tags auth,jwt,oauth,token
  jwt_tool {token} -M at -t {target} -rh "Authorization: Bearer"

STEP 4 — Authorization Testing (IDOR/BOLA)
  For each endpoint with ID parameter:
    Replace ID with another user's ID
    Try sequential IDs, UUIDs from other contexts
    Test horizontal + vertical privilege escalation

STEP 5 — Rate Limiting & Business Logic
  Test rate limits on auth endpoints
  Check for mass assignment (extra POST params)
  Test parameter pollution (?id=1&id=2)
```

---

## Network Penetration Testing Chain

**Objective:** Full network assessment from discovery to exploitation.

```
STEP 1 — Host Discovery
  nmap -sn {subnet} -oG ping_sweep.txt
  Fallback: masscan {subnet} -p0-65535 --rate 1000

STEP 2 — Port Scanning
  nmap -sS -sV -sC -O --top-ports 1000 {target}
    -oA nmap_results
  Fallback: rustscan -a {target} -- -sV -sC

STEP 3 — Service Enumeration
  Based on open ports:
  - 21/FTP: nmap --script ftp-* {target}
  - 22/SSH: nmap --script ssh-* {target}
  - 25/SMTP: nmap --script smtp-* {target}
  - 53/DNS: dnsenum {domain}, fierce --domain {domain}
  - 80,443/HTTP: nikto -h {target}, whatweb {target}
  - 139,445/SMB: enum4linux-ng {target}, smbmap -H {target}
  - 3306/MySQL: nmap --script mysql-* {target}
  - 5432/PostgreSQL: nmap --script pgsql-* {target}

STEP 4 — Vulnerability Assessment
  nuclei -l targets.txt -tags network,service
  nmap --script vuln {target}

STEP 5 — Credential Testing
  hydra -L users.txt -P passwords.txt {target} {service}
  Fallback: medusa, patator
```

---

## Cloud Security Assessment Chain

**Objective:** Identify misconfigurations in cloud infrastructure.

```
AWS Assessment:
  1. prowler -M csv -f {region}
  2. scout-suite --provider aws
  3. pacu (interactive — import prowler results)
  4. s3scanner scan --buckets-file bucket_list.txt

Kubernetes Assessment:
  1. kube-hunter --remote {target}
  2. kube-bench run --targets master,node
  3. trivy k8s --report summary cluster

Container Assessment:
  1. trivy image {image_name}
  2. docker-bench-security (if host access)
  3. falco (runtime monitoring)

IaC Assessment:
  1. checkov -d {terraform_dir}
  2. terrascan scan -d {terraform_dir}
```

---

## Deep Dig Prompts

```
Given target {domain} with the following recon data:
- Subdomains: {subdomain_count} found
- Live hosts: {live_count}
- Technologies detected: {tech_list}

1. Which attack workflow chain is most appropriate?
2. Based on the tech stack, which tools should be prioritized?
3. What custom nuclei templates should I write for this stack?
4. Identify the 3 most likely high-impact vulnerability classes.
5. What parameters/endpoints deserve manual testing?
```

```
I found these results from the vulnerability hunting chain:
{scan_results}

1. Triage these findings by exploitability and impact.
2. Which findings need manual verification vs. are confirmed?
3. For each confirmed finding, draft a PoC and reproduction steps.
4. What chained attacks could amplify the impact?
5. Rate each finding using CVSS 3.1 criteria.
```
