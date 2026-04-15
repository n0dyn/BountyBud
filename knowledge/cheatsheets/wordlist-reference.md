---
id: "wordlist-reference"
title: "Wordlist Reference Guide"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "wordlists"
tags: ["wordlists", "seclists", "assetnote", "fuzzing", "directory", "subdomain", "parameters"]
platforms: ["linux", "macos", "windows"]
related: ["ffuf-cheatsheet", "bug-bounty-recon-pipeline"]
difficulty: "beginner"
updated: "2026-04-14"
---

# Wordlist Reference Guide

## SecLists (Most Popular)
```
# Install: git clone https://github.com/danielmiessler/SecLists
# Or: apt install seclists → /usr/share/seclists/

# Directory/File Brute Force:
Discovery/Web-Content/raft-large-directories.txt      # 62k dirs
Discovery/Web-Content/raft-large-files.txt             # 37k files
Discovery/Web-Content/directory-list-2.3-medium.txt    # 220k (dirbuster)
Discovery/Web-Content/common.txt                       # 4.7k (quick scan)
Discovery/Web-Content/big.txt                          # 20k

# API Endpoints:
Discovery/Web-Content/api/api-endpoints.txt
Discovery/Web-Content/api/api-seen-in-wild.txt

# Subdomains:
Discovery/DNS/subdomains-top1million-5000.txt          # Quick
Discovery/DNS/subdomains-top1million-20000.txt         # Medium
Discovery/DNS/subdomains-top1million-110000.txt        # Thorough
Discovery/DNS/bitquark-subdomains-top100000.txt

# Parameters:
Discovery/Web-Content/burp-parameter-names.txt         # 6.4k params
Fuzzing/LFI/LFI-Jhaddix.txt                           # LFI paths

# Passwords:
Passwords/Common-Credentials/10k-most-common.txt
Passwords/Common-Credentials/best1050.txt
Passwords/darkweb2017-top10000.txt
Passwords/Leaked-Databases/rockyou-75.txt

# Usernames:
Usernames/top-usernames-shortlist.txt
Usernames/Names/names.txt
```

## Assetnote Wordlists
```
# https://wordlists.assetnote.io/

# Best for modern web apps:
httparchive_directories_1m_2024.txt      # From HTTP Archive
httparchive_subdomains_2024.txt
httparchive_parameters_top_1m_2024.txt
httparchive_js_files_2024.txt

# Technology-specific:
httparchive_aspx_asp_cfm_svc_ashx_asmx.txt  # .NET endpoints
httparchive_php.txt                           # PHP files
httparchive_jsp_jspa_do_action.txt            # Java endpoints
```

## FuzzDB
```
# https://github.com/fuzzdb-project/fuzzdb
attack/lfi/             # LFI payloads
attack/sqli/            # SQL injection
attack/xss/             # XSS payloads
discovery/predictable-filepaths/  # Common paths per technology
web-backdoors/          # Known webshell paths
```

## Specialized Wordlists
```
# Virtual host discovery:
/usr/share/seclists/Discovery/DNS/namelist.txt
# Use with: ffuf -H "Host: FUZZ.target.com" -u http://IP

# Backup files:
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
# Also: .bak, .old, .swp, .orig, ~, .save, .backup extensions

# Git exposure:
.git/HEAD, .git/config, .git/index, .git/refs/heads/main

# GraphQL:
/usr/share/seclists/Discovery/Web-Content/graphql.txt
```

## Quick Reference: Which Wordlist When
```
Subdomain enum → subdomains-top1million-20000.txt
Quick dir scan → common.txt (4.7k)
Thorough dir  → raft-large-directories.txt (62k)
API endpoints → api-endpoints.txt + assetnote
Parameters    → burp-parameter-names.txt
LFI paths     → LFI-Jhaddix.txt
Passwords     → rockyou-75.txt or 10k-most-common.txt
Vhost enum    → namelist.txt
```
