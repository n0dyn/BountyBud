---
id: "ffuf-cheatsheet"
title: "FFUF Cheatsheet - Web Fuzzing Quick Reference"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["ffuf", "fuzzing", "cheatsheet", "directory", "parameter", "vhost", "quick-reference"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: ["ffuf", "gobuster", "feroxbuster"]
updated: "2026-03-30"
---

## Basic Usage

```bash
# Directory fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Multiple FUZZ keywords
ffuf -u https://target.com/FUZZ1/FUZZ2 -w wordlist1.txt:FUZZ1 -w wordlist2.txt:FUZZ2
```

## Filtering & Matching

| Flag | Description |
|------|-------------|
| `-mc CODE` | Match HTTP status codes (default: 200,204,301,302,307,401,403,405) |
| `-ml LINES` | Match response line count |
| `-mr REGEX` | Match response regex |
| `-ms SIZE` | Match response size |
| `-mw WORDS` | Match response word count |
| `-fc CODE` | Filter (exclude) HTTP status codes |
| `-fl LINES` | Filter by line count |
| `-fr REGEX` | Filter by regex |
| `-fs SIZE` | Filter by response size |
| `-fw WORDS` | Filter by word count |
| `-ac` | Auto-calibrate filtering |

## Performance

| Flag | Description |
|------|-------------|
| `-t N` | Number of threads (default 40) |
| `-rate N` | Rate limit (requests/sec) |
| `-p SECONDS` | Delay between requests |
| `-timeout N` | HTTP request timeout (default 10s) |
| `-recursion` | Enable recursive fuzzing |
| `-recursion-depth N` | Max recursion depth |

## Output

| Flag | Description |
|------|-------------|
| `-o FILE` | Output file |
| `-of FORMAT` | Output format: json, ejson, html, md, csv, all |
| `-v` | Verbose (show full URL + redirect location) |
| `-s` | Silent mode (no banner) |
| `-c` | Colorize output |

## Common Recipes

```bash
# Directory discovery (filter 404s)
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 404

# File discovery with extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.js,.json,.bak,.old,.conf

# Subdomain/vhost discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs DEFAULT_SIZE

# Parameter fuzzing (GET)
ffuf -u "https://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 404 -fs DEFAULT_SIZE

# Parameter value fuzzing (POST)
ffuf -u https://target.com/login -X POST -d "username=admin&password=FUZZ" -w passwords.txt -fc 401

# POST JSON fuzzing
ffuf -u https://target.com/api/login -X POST -H "Content-Type: application/json" -d '{"user":"admin","pass":"FUZZ"}' -w passwords.txt

# Header fuzzing
ffuf -u https://target.com -H "X-Forwarded-For: FUZZ" -w ips.txt

# Recursive directory scan
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3 -fc 404

# Cookie fuzzing
ffuf -u https://target.com/admin -b "session=FUZZ" -w tokens.txt

# Auto-calibrate (great for WAF evasion)
ffuf -u https://target.com/FUZZ -w wordlist.txt -ac

# Rate-limited scan (polite)
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50 -t 10

# LFI fuzzing
ffuf -u "https://target.com/page?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fc 404 -fs DEFAULT_SIZE

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302
```

## Useful Wordlists (SecLists)

```
# Directories
Discovery/Web-Content/raft-medium-directories.txt
Discovery/Web-Content/raft-large-directories.txt
Discovery/Web-Content/directory-list-2.3-medium.txt

# Files
Discovery/Web-Content/raft-medium-files.txt
Discovery/Web-Content/raft-large-files.txt

# Parameters
Discovery/Web-Content/burp-parameter-names.txt

# Subdomains
Discovery/DNS/subdomains-top1million-5000.txt
Discovery/DNS/subdomains-top1million-20000.txt

# API
Discovery/Web-Content/api/api-endpoints.txt

# LFI
Fuzzing/LFI/LFI-Jhaddix.txt
```
