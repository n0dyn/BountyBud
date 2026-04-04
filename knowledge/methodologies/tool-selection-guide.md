---
id: "tool-selection-guide"
title: "Intelligent Tool Selection Guide - Right Tool for Every Target"
type: "methodology"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["tool-selection", "effectiveness", "scoring", "target-analysis", "methodology", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["attack-workflow-chains", "vulnerability-priority-matrix", "smart-hunting-strategy"]
updated: "2026-04-04"
---

## Overview

Not every tool works equally well against every target. This guide provides effectiveness ratings, target-type suitability, and fallback chains so the AI assistant can recommend the optimal toolset for any given target. Scores are 0.0–1.0 based on real-world effectiveness.

## Target Type Detection

Before selecting tools, classify the target:

```
WEB APPLICATION
  Indicators: HTTP/HTTPS ports, HTML responses, web frameworks
  Tech clues: Server headers, X-Powered-By, cookies (PHPSESSID, JSESSIONID, etc.)

API SERVICE
  Indicators: JSON/XML responses, /api/ paths, REST/GraphQL endpoints
  Tech clues: Content-Type headers, CORS headers, API versioning

NETWORK HOST
  Indicators: Non-HTTP ports, raw TCP/UDP services
  Tech clues: Banner grabbing, service fingerprints

CLOUD INFRASTRUCTURE
  Indicators: AWS/GCP/Azure domains, S3 buckets, Lambda URLs
  Tech clues: Cloud-specific headers, metadata endpoints

CMS / KNOWN PLATFORM
  Indicators: WordPress, Drupal, Joomla signatures
  Tech clues: /wp-admin, /wp-content, generator meta tags
```

## Tool Effectiveness Scores by Target Type

### Subdomain Enumeration

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| subfinder | 0.95 | 0.90 | 0.70 | 0.85 | 0.95 |
| amass | 0.90 | 0.85 | 0.75 | 0.90 | 0.90 |
| assetfinder | 0.80 | 0.75 | 0.60 | 0.70 | 0.80 |
| chaos | 0.75 | 0.70 | 0.50 | 0.65 | 0.75 |

**Best pick:** subfinder for speed, amass for thoroughness. Use both when time permits.

### HTTP Probing

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| httpx | 0.95 | 0.95 | 0.60 | 0.85 | 0.95 |
| httprobe | 0.75 | 0.70 | 0.50 | 0.65 | 0.75 |

### Content Discovery / Directory Bruteforce

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| ffuf | 0.95 | 0.90 | 0.30 | 0.70 | 0.90 |
| feroxbuster | 0.90 | 0.85 | 0.25 | 0.65 | 0.85 |
| gobuster | 0.85 | 0.80 | 0.25 | 0.60 | 0.85 |
| dirsearch | 0.80 | 0.75 | 0.20 | 0.55 | 0.80 |
| dirb | 0.65 | 0.60 | 0.20 | 0.45 | 0.65 |

**Fallback chain:** ffuf → feroxbuster → dirsearch → gobuster → dirb

### Crawling & URL Discovery

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| katana | 0.95 | 0.80 | 0.20 | 0.60 | 0.90 |
| hakrawler | 0.80 | 0.70 | 0.15 | 0.50 | 0.75 |
| gospider | 0.80 | 0.65 | 0.15 | 0.50 | 0.75 |
| gau | 0.85 | 0.75 | 0.30 | 0.70 | 0.85 |
| waybackurls | 0.80 | 0.70 | 0.25 | 0.65 | 0.80 |

### Vulnerability Scanning

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| nuclei | 0.95 | 0.90 | 0.80 | 0.85 | 0.95 |
| nikto | 0.70 | 0.50 | 0.30 | 0.40 | 0.75 |
| sqlmap | 0.90 | 0.85 | 0.10 | 0.30 | 0.85 |
| dalfox | 0.90 | 0.70 | 0.05 | 0.20 | 0.80 |
| wpscan | 0.20 | 0.10 | 0.05 | 0.10 | 0.95 |
| zaproxy | 0.85 | 0.80 | 0.30 | 0.50 | 0.80 |

### Port Scanning & Network

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| nmap | 0.70 | 0.65 | 0.95 | 0.80 | 0.70 |
| masscan | 0.50 | 0.45 | 0.90 | 0.70 | 0.50 |
| rustscan | 0.55 | 0.50 | 0.90 | 0.65 | 0.55 |

### OSINT

| Tool | Web App | API | Network | Cloud | CMS |
|------|---------|-----|---------|-------|-----|
| theHarvester | 0.80 | 0.70 | 0.75 | 0.80 | 0.80 |
| shodan | 0.75 | 0.70 | 0.90 | 0.85 | 0.75 |
| spiderfoot | 0.80 | 0.75 | 0.80 | 0.80 | 0.80 |
| sherlock | 0.40 | 0.30 | 0.30 | 0.30 | 0.40 |

---

## Context-Aware Parameter Optimization

### Nmap Parameters by Target Type

```bash
# Web application target
nmap -sV -sC -p 80,443,8080,8443,3000,5000,8000 {target}

# Network host (full assessment)
nmap -sS -sV -sC -O --top-ports 1000 -T4 {target}

# Stealth mode (IDS evasion)
nmap -sS -T2 -f --data-length 24 -D RND:5 {target}

# Quick discovery
nmap -sn -T4 {subnet}
```

### SQLMap Parameters by Context

```bash
# Standard web form
sqlmap -u {url} --batch --level 2 --risk 2 --random-agent

# API endpoint (JSON body)
sqlmap -u {url} --data='{"param":"value"}' --content-type=application/json
  --batch --level 2 --risk 2

# Deep scan (time-intensive)
sqlmap -u {url} --batch --level 5 --risk 3
  --tamper=space2comment,between,randomcase,charencode

# WAF bypass
sqlmap -u {url} --batch --tamper=space2comment,between,randomcase
  --random-agent --delay=2 --safe-url={safe_url} --safe-freq=3

# PHP/MySQL target
sqlmap -u {url} --batch --dbms=mysql --technique=BEUST
  --tamper=space2mysqlblank

# ASP.NET/MSSQL target
sqlmap -u {url} --batch --dbms=mssql --os=windows
  --tamper=space2mssqlblank,between
```

### Nuclei Parameters by Objective

```bash
# Quick critical scan
nuclei -l targets.txt -severity critical,high -rate-limit 150

# Full scan with all templates
nuclei -l targets.txt -rate-limit 100 -bulk-size 25
  -o results.txt -es info

# Technology-specific
nuclei -l targets.txt -tags wordpress  # CMS
nuclei -l targets.txt -tags aws,s3    # Cloud
nuclei -l targets.txt -tags api,graphql  # API

# Custom templates
nuclei -l targets.txt -t ~/nuclei-templates/custom/
```

### FFuf Parameters by Scenario

```bash
# Directory discovery
ffuf -u {url}/FUZZ -w wordlist.txt -mc 200,301,302,403
  -recursion -recursion-depth 2

# Parameter fuzzing
ffuf -u {url}?FUZZ=test -w params.txt -fs {baseline_size}

# Virtual host discovery
ffuf -u {url} -H "Host: FUZZ.{domain}" -w subdomains.txt
  -fs {baseline_size}

# POST data fuzzing
ffuf -u {url} -X POST -d "param=FUZZ" -w payloads.txt
  -mc 200 -fw {baseline_words}

# API endpoint discovery
ffuf -u {url}/api/FUZZ -w api_wordlist.txt
  -mc 200,201,204,301,401,403,405
```

---

## Technology-Specific Tool Recommendations

### PHP Applications
- **Primary:** sqlmap (MySQL injection), nuclei (PHP-specific templates)
- **Recon:** whatweb, wappalyzer
- **Params:** sqlmap with `--dbms=mysql --tamper=space2mysqlblank`
- **Watch for:** Type juggling, deserialization (unserialize), LFI via wrappers

### Node.js / Express
- **Primary:** nuclei, dalfox (DOM XSS common in SPA)
- **Watch for:** Prototype pollution, SSRF via request libraries, NoSQL injection
- **Params:** Use `--content-type=application/json` for all injection tools

### Java / Spring
- **Primary:** nuclei (Java-specific), sqlmap
- **Watch for:** Deserialization (ysoserial), SSTI (Thymeleaf), JNDI injection
- **Params:** sqlmap with `--dbms=oracle` or `--dbms=postgresql`

### Python / Django / Flask
- **Primary:** nuclei, sqlmap
- **Watch for:** SSTI (Jinja2), pickle deserialization, debug mode exposure
- **Params:** Test `{{7*7}}` and `${7*7}` in all inputs

### WordPress
- **Primary:** wpscan (mandatory), nuclei with `--tags wordpress`
- **Recon:** `wpscan --enumerate ap,at,u,cb,dbe`
- **Watch for:** Plugin vulns, XML-RPC abuse, wp-config.php exposure

### Cloud-Hosted (AWS/GCP/Azure)
- **Primary:** nuclei with cloud tags, s3scanner, prowler
- **Watch for:** SSRF to metadata endpoints, S3 bucket misconfig, IAM over-permission

---

## Fallback Chain Reference

When a primary tool fails or isn't installed, use these alternatives:

```
subfinder     → amass → assetfinder → findomain → chaos
httpx         → httprobe → curl scripting
ffuf          → feroxbuster → dirsearch → gobuster → dirb → wfuzz
katana        → hakrawler → gospider → crawley
gau           → gauplus → waybackurls
nuclei        → nikto → zaproxy (active scan)
sqlmap        → ghauri → nosqlmap (for NoSQL)
dalfox        → kxss → xsstrike
nmap          → rustscan → masscan
gobuster      → feroxbuster → dirsearch → ffuf
wpscan        → nuclei --tags wordpress
```

---

## Deep Dig Prompts

```
I'm targeting {domain} which runs {technology_stack}.
Based on the tool effectiveness scores:
1. What's the optimal 5-tool chain for initial assessment?
2. Which tools should I skip based on the target type?
3. What custom parameters should I use for {specific_tool}?
4. If {primary_tool} fails, what's my fallback sequence?
5. What technology-specific vulnerabilities should I prioritize?
```
