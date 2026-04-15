---
id: "google-dorking-cheatsheet"
title: "Google Dorking for Bug Bounty - Complete Reference"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "osint"
tags: ["google", "dorking", "osint", "recon", "search-operators", "bug-bounty", "passive-recon"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["github-dorking-cheatsheet", "subfinder"]
updated: "2026-04-14"
---

## Core Search Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `site:` | Restrict to domain | `site:target.com` |
| `inurl:` | Match in URL | `inurl:admin` |
| `intitle:` | Match in page title | `intitle:"login"` |
| `intext:` | Match in page body | `intext:"password"` |
| `filetype:` | Filter by file type | `filetype:pdf` |
| `ext:` | Filter by extension | `ext:sql` |
| `cache:` | Show cached version | `cache:target.com` |
| `link:` | Pages linking to URL | `link:target.com` |
| `related:` | Similar sites | `related:target.com` |
| `info:` | Page information | `info:target.com` |
| `define:` | Definition | `define:xss` |
| `allinurl:` | All terms in URL | `allinurl:admin login` |
| `allintitle:` | All terms in title | `allintitle:admin panel` |
| `allintext:` | All terms in body | `allintext:username password` |
| `AROUND(n)` | Words within n of each other | `password AROUND(3) admin` |
| `"..."` | Exact phrase | `"index of /"` |
| `*` | Wildcard | `site:*.target.com` |
| `-` | Exclude | `site:target.com -www` |
| `OR` / `|` | Boolean OR | `inurl:admin OR inurl:login` |
| `AND` | Boolean AND (default) | `site:target.com AND inurl:api` |
| `()` | Group operators | `(inurl:admin | inurl:login) site:target.com` |
| `before:` | Results before date | `site:target.com before:2025-01-01` |
| `after:` | Results after date | `site:target.com after:2025-06-01` |
| `numrange:` | Number range | `numrange:1000-2000` |

## Exposed Files & Configuration

```
# Sensitive config files
site:target.com ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json

# Environment files
site:target.com ext:env | filetype:env
site:target.com inurl:.env intext:DB_PASSWORD

# Database dumps
site:target.com ext:sql | ext:db | ext:sqlite | ext:mdb
site:target.com filetype:sql "INSERT INTO" "VALUES"

# Backup files
site:target.com ext:bak | ext:backup | ext:old | ext:save
site:target.com inurl:backup | inurl:bak | inurl:old

# Git/SVN exposure
site:target.com inurl:.git
site:target.com intitle:"index of" ".git"
site:target.com inurl:.svn

# Documents
site:target.com ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx
site:target.com ext:pdf intext:"confidential" | intext:"internal" | intext:"not for distribution"

# SSH/crypto keys
site:target.com ext:pem | ext:key | ext:ppk
site:target.com filetype:key "BEGIN RSA PRIVATE KEY"
```

## Admin Panels & Login Pages

```
# Admin panels
site:target.com inurl:admin | inurl:administrator | inurl:dashboard | inurl:cpanel | inurl:panel
site:target.com intitle:"admin" | intitle:"administrator" | intitle:"dashboard" | intitle:"control panel"

# Login pages
site:target.com inurl:login | inurl:signin | inurl:auth | inurl:sso
site:target.com intitle:"login" | intitle:"sign in" | intitle:"authentication"

# Registration
site:target.com inurl:register | inurl:signup | inurl:join

# Password reset
site:target.com inurl:reset | inurl:forgot | inurl:recover
```

## API & Development Endpoints

```
# API endpoints
site:target.com inurl:api | inurl:rest | inurl:v1 | inurl:v2 | inurl:v3 | inurl:graphql

# API documentation
site:target.com inurl:swagger | inurl:api-docs | inurl:apidoc | inurl:openapi | inurl:redoc
site:target.com intitle:"Swagger UI" | intitle:"API Documentation"

# Development/staging
site:target.com inurl:dev | inurl:staging | inurl:test | inurl:sandbox | inurl:debug | inurl:uat | inurl:internal | inurl:demo | inurl:beta

# phpinfo / server info
site:target.com inurl:phpinfo | intitle:"phpinfo()" | inurl:server-info | inurl:server-status

# Directory listings
site:target.com intitle:"index of /" | intitle:"directory listing"
```

## Vulnerability-Prone Parameters

```
# SQL Injection
site:target.com inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:&

# XSS
site:target.com inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:&

# Open Redirect
site:target.com inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:page= inurl:& inurl:http

# SSRF
site:target.com inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:&

# LFI
site:target.com inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:&

# RCE
site:target.com inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:&

# File upload
site:target.com intext:"choose file" | intext:"select file" | intext:"upload" | inurl:upload
```

## Error Messages & Debugging

```
# Server errors
site:target.com inurl:"error" | intitle:"exception" | intitle:"failure" | inurl:exception
site:target.com "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace"

# Debug information
site:target.com intext:"debug" | intext:"traceback" | intext:"error in" | intext:"warning:"
site:target.com ext:log intext:"error" | intext:"fatal" | intext:"exception"

# WordPress debug
site:target.com inurl:wp-content/debug.log
```

## Cloud Storage Exposure

```
# AWS S3
site:s3.amazonaws.com "target.com"
site:s3.amazonaws.com "target"
"target.com" site:*.s3.amazonaws.com

# Azure
site:blob.core.windows.net "target"
site:dev.azure.com "target"

# Google Cloud
site:storage.googleapis.com "target"
site:googleapis.com "target"

# DigitalOcean
site:digitaloceanspaces.com "target"
```

## Code & Credential Leaks (Third-Party)

```
# Paste sites
site:pastebin.com "target.com"
site:paste.org "target.com"
site:hastebin.com "target.com"

# Code sharing
site:jsfiddle.net "target.com"
site:codepen.io "target.com"
site:replit.com "target.com"

# Trello boards
site:trello.com "target.com"

# Notion
site:notion.so "target.com"

# Stack Overflow
site:stackoverflow.com "target.com"
```

## CMS-Specific Dorks

```
# WordPress
site:target.com inurl:wp-admin | inurl:wp-login | inurl:wp-content | inurl:wp-includes
site:target.com inurl:wp-json | inurl:xmlrpc.php
site:target.com inurl:/wp-admin/admin-ajax.php

# Drupal
site:target.com inurl:node | intext:"Powered by Drupal"
site:target.com inurl:user/login

# Joomla
site:target.com inurl:administrator | intext:"Powered by Joomla"

# Adobe Experience Manager
site:target.com inurl:/content/dam | inurl:/crx/de | inurl:/libs/granite | inurl:/etc/clientlibs
```

## Subdomain Discovery

```
# Find subdomains indexed by Google
site:*.target.com -www
site:*.*.target.com

# Specific subdomain patterns
site:*.target.com inurl:dev | inurl:staging | inurl:test | inurl:api | inurl:admin
```

## Bug Bounty Program Discovery

```
# Find bug bounty programs
"submit vulnerability report" | "powered by bugcrowd" | "powered by hackerone"
site:*/security.txt "bounty"
site:target.com inurl:security | inurl:responsible-disclosure | inurl:bug-bounty
```

## Automation Tips

```bash
# Use with curl and Google Custom Search API
# Or use tools like:

# googler (CLI)
googler --site target.com ext:sql

# GooFuzz
goofuzz -t target.com -e pdf,xls,doc

# dorkScanner
python3 dorkScanner.py -d target.com

# Combine with nuclei for validation
# 1. Dork for endpoints
# 2. Collect URLs
# 3. Feed to nuclei for scanning
```

## Resources

- **GHDB**: https://www.exploit-db.com/google-hacking-database - Community-driven dork database
- **TakSec dorks**: https://github.com/TakSec/google-dorks-bug-bounty
- **DorkSearch**: https://dorksearch.com - Dork builder tool

## Legal Notes

- Google dorking is passive reconnaissance - no direct interaction with target
- Only use against authorized targets in bug bounty scope
- Respect robots.txt and rate limits
- Accessing exposed data may still require authorization
- Document findings for responsible disclosure
