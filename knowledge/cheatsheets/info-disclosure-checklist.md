---
id: "info-disclosure-checklist"
title: "Information Disclosure Checklist"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "sensitive-data-discovery"
tags: ["information-disclosure", "checklist", "recon", "secrets", "metadata", "quick-reference"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["dig-deep-asset-classes", "javascript-analysis"]
updated: "2026-03-30"
---

## Files & Paths to Check

```
# Source control
/.git/HEAD
/.git/config
/.svn/entries
/.hg/hgrc
/.bzr/README

# Environment & config
/.env
/.env.local
/.env.production
/.env.backup
/config.json
/config.yml
/config.php
/wp-config.php
/web.config
/application.properties
/appsettings.json

# Debug & error pages
/debug
/trace
/actuator (Spring Boot)
/actuator/env
/actuator/health
/actuator/configprops
/actuator/mappings
/actuator/heapdump
/elmah.axd (.NET errors)
/phpinfo.php
/info.php
/server-info
/server-status

# API documentation
/swagger.json
/swagger-ui.html
/api-docs
/openapi.json
/v1/api-docs
/v2/api-docs
/graphql (introspection)
/graphiql

# Backup files
/index.php.bak
/index.php~
/index.php.old
/index.php.save
/index.php.swp
/.index.php.swp
/backup.sql
/dump.sql
/database.sql
/db.sql

# Cloud metadata
/latest/meta-data/ (AWS)
/metadata/v1/ (DigitalOcean)

# Package managers
/package.json
/package-lock.json
/composer.json
/composer.lock
/Gemfile
/requirements.txt
/Pipfile
```

## Headers to Inspect

```
Server              # Web server version
X-Powered-By        # Framework/language
X-AspNet-Version    # .NET version
X-Debug-Token       # Symfony debug
X-Request-Id        # Request tracing
X-Runtime           # Processing time (timing attacks)
Via                 # Proxy chain
X-Forwarded-For     # Proxy chain
Set-Cookie          # Session config, flags, domain scope
Content-Security-Policy  # Whitelisted domains (attack surface)
```

## Error Messages

```
# SQL errors → database type, table names, query structure
# Stack traces → file paths, library versions, internal IPs
# Debug mode → full request/response, environment variables
# 404 pages → server technology, default error pages
# API errors → parameter names, valid values, internal structure
# Auth errors → username enumeration ("user not found" vs "wrong password")
```

## JavaScript Sources

```
# Embedded secrets
grep -r "api_key\|secret\|token\|password\|AWS_\|STRIPE_" *.js

# Internal URLs
grep -r "internal\|staging\|dev\.\|localhost\|192\.168\|10\.\|172\." *.js

# Source maps
*.js.map → full original source code
```

## Metadata in Documents/Images

```bash
# Extract metadata from uploaded files
exiftool document.pdf    # Author, software, timestamps
exiftool image.jpg       # GPS location, camera model, software
strings document.docx    # Embedded paths, usernames
```

## Deep Dig Prompts

```
Given this target domain [name]:
1. Check every path in the files/paths list above.
2. Analyze all response headers for version disclosure.
3. Trigger error conditions (invalid input, SQL chars, missing params) and analyze error messages.
4. Find and analyze all JavaScript files for embedded secrets and internal URLs.
5. Check for exposed API documentation (Swagger, GraphQL introspection).
6. Test for source map files (.js.map) on every JavaScript resource.
7. Check common backup file patterns for every discovered page.
```
