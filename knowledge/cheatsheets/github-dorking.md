---
id: "github-dorking"
title: "GitHub Dorking for Bug Bounty"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "osint"
tags: ["github", "secrets", "api-key", "password", "recon", "dorking"]
platforms: ["linux", "macos", "windows"]
related: ["google-dorking", "bug-bounty-recon-pipeline"]
difficulty: "beginner"
updated: "2026-04-14"
---

# GitHub Dorking for Bug Bounty

## Search for Secrets
```
# Search in target org's repos:
org:targetcompany password
org:targetcompany secret
org:targetcompany api_key
org:targetcompany token
org:targetcompany AWS_SECRET_ACCESS_KEY
org:targetcompany AKIA                    # AWS access key prefix
org:targetcompany BEGIN RSA PRIVATE KEY
org:targetcompany jdbc:
org:targetcompany mongodb+srv://

# Search by domain:
"target.com" password
"target.com" api_key
"target.com" secret_key
"target.com" authorization: bearer
```

## Search by File
```
org:targetcompany filename:.env
org:targetcompany filename:.env.production
org:targetcompany filename:credentials
org:targetcompany filename:credentials.json
org:targetcompany filename:config.yml password
org:targetcompany filename:docker-compose.yml
org:targetcompany filename:.htpasswd
org:targetcompany filename:wp-config.php
org:targetcompany filename:id_rsa
org:targetcompany filename:.npmrc _auth
org:targetcompany filename:.dockercfg auth
org:targetcompany filename:settings.py SECRET_KEY
```

## Search by Extension
```
org:targetcompany extension:pem private
org:targetcompany extension:ppk
org:targetcompany extension:key
org:targetcompany extension:sql password
org:targetcompany extension:env
org:targetcompany extension:log password
org:targetcompany extension:cfg password
```

## Specific Secrets Patterns
```
# AWS:
org:targetcompany AKIA
org:targetcompany aws_secret_access_key
org:targetcompany "s3.amazonaws.com"

# Slack:
org:targetcompany xoxb-
org:targetcompany xoxp-
org:targetcompany hooks.slack.com/services

# Stripe:
org:targetcompany sk_live_
org:targetcompany rk_live_

# Database:
org:targetcompany "mysql://"
org:targetcompany "postgres://"
org:targetcompany "mongodb://"
org:targetcompany "redis://"

# OAuth/API:
org:targetcompany client_secret
org:targetcompany consumer_secret
org:targetcompany api_secret
```

## Infrastructure Discovery
```
org:targetcompany filename:Dockerfile
org:targetcompany filename:docker-compose
org:targetcompany filename:Jenkinsfile
org:targetcompany filename:.gitlab-ci.yml
org:targetcompany filename:.github/workflows
org:targetcompany filename:terraform
org:targetcompany filename:ansible
org:targetcompany filename:Vagrantfile
```

## Tools
```bash
# GitDorker:
python3 GitDorker.py -t TOKEN -org targetcompany

# truffleHog:
trufflehog github --org=targetcompany

# gitleaks:
gitleaks detect --source /path/to/repo

# gh CLI search:
gh search code "password" --owner targetcompany
```
