---
id: "google-dorking"
title: "Google Dorking for Bug Bounty"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "osint"
tags: ["google-dork", "recon", "osint", "information-disclosure", "sensitive-files"]
platforms: ["linux", "macos", "windows"]
related: ["bug-bounty-recon-pipeline", "info-disclosure-checklist"]
difficulty: "beginner"
updated: "2026-04-14"
---

# Google Dorking for Bug Bounty

## Core Operators
```
site:target.com          # Only results from target domain
-site:www.target.com     # Exclude www subdomain
inurl:admin              # URL contains "admin"
intitle:"index of"       # Page title contains string
filetype:pdf             # Specific file type
ext:php                  # Specific extension
intext:"password"        # Page body contains string
cache:target.com         # Google's cached version
link:target.com          # Pages linking to target
```

## Sensitive Files
```
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com filetype:conf
site:target.com filetype:cfg
site:target.com ext:xml | ext:json | ext:yaml | ext:yml
site:target.com ext:key | ext:pem | ext:ppk
site:target.com filetype:xls | filetype:xlsx | filetype:csv
site:target.com filetype:doc | filetype:docx | filetype:pdf
```

## Exposed Panels & Portals
```
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:dashboard
site:target.com inurl:panel
site:target.com intitle:"admin" | intitle:"login" | intitle:"dashboard"
site:target.com inurl:wp-admin | inurl:wp-login
site:target.com inurl:phpmyadmin | inurl:adminer
site:target.com intitle:"Grafana" | intitle:"Kibana" | intitle:"Jenkins"
```

## Information Disclosure
```
site:target.com intitle:"index of" "parent directory"
site:target.com intitle:"index of" ".git"
site:target.com inurl:"/.env"
site:target.com inurl:"/debug" | inurl:"/trace"
site:target.com inurl:"phpinfo.php"
site:target.com "DB_PASSWORD" | "DB_HOST" | "API_KEY" | "SECRET_KEY"
site:target.com "mysql_connect" | "pg_connect"
site:target.com ext:swp | ext:swo | ext:bak | ext:old
```

## API Discovery
```
site:target.com inurl:api
site:target.com inurl:"/api/v1" | inurl:"/api/v2"
site:target.com filetype:json inurl:api
site:target.com inurl:swagger | inurl:openapi
site:target.com inurl:graphql | inurl:graphiql
site:target.com intitle:"API documentation"
```

## Subdomains & Infrastructure
```
site:*.target.com -www
site:*.*.target.com
site:target.com inurl:staging | inurl:dev | inurl:test | inurl:uat
site:target.com inurl:internal | inurl:corp | inurl:vpn
```

## Credentials & Secrets
```
site:target.com "password" | "passwd" | "credentials"
site:target.com "api_key" | "apikey" | "api-key"
site:target.com "access_token" | "auth_token" | "bearer"
site:target.com "AWS_ACCESS_KEY" | "AKIA"
site:target.com "BEGIN RSA PRIVATE KEY"
site:target.com inurl:"/wp-content/debug.log"
```

## Error Pages & Debug
```
site:target.com "stack trace" | "traceback" | "exception"
site:target.com "Warning:" | "Fatal error:" | "Parse error:"
site:target.com "Application Error" | "Server Error"
site:target.com inurl:"error" | inurl:"debug" | inurl:"trace"
```

## Third-Party Leaks
```
"target.com" site:pastebin.com
"target.com" site:github.com
"target.com" site:trello.com
"target.com" site:notion.so
"target.com" site:postman.com
"target.com" site:repl.it
```
