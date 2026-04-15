---
id: "github-dorking-cheatsheet"
title: "GitHub Dorking for Bug Bounty - Complete Reference"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "osint"
tags: ["github", "dorking", "osint", "secrets", "api-keys", "credentials", "code-search", "recon"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["google-dorking-cheatsheet", "truffleHog"]
updated: "2026-04-14"
---

## GitHub Search Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `org:` | Search within organization | `org:target-corp password` |
| `user:` | Search user's repos | `user:devname api_key` |
| `repo:` | Search specific repo | `repo:org/repo secret` |
| `filename:` | Search by filename | `filename:.env DB_PASSWORD` |
| `extension:` | Search by file extension | `extension:yml password` |
| `path:` | Search in file path | `path:config password` |
| `language:` | Filter by language | `language:python secret` |
| `size:` | Filter by file size | `size:>1000 password` |
| `in:file` | Search in file content | `api_key in:file` |
| `in:path` | Search in file path | `config in:path` |
| `in:name` | Search in repo name | `internal in:name` |
| `fork:true` | Include forks | `password fork:true` |
| `created:` | Filter by creation date | `created:>2025-01-01` |
| `pushed:` | Filter by push date | `pushed:>2025-01-01` |
| `stars:` | Filter by stars | `password stars:<5` |

## API Keys & Tokens

```
# AWS
org:target "AKIA"
org:target "AWS_ACCESS_KEY_ID"
org:target "AWS_SECRET_ACCESS_KEY"
org:target "aws_access_key_id"
org:target filename:.env AWS

# Google Cloud
org:target "AIza"
org:target "GOOGLE_API_KEY"
org:target "GOOGLE_CLOUD_PROJECT"
org:target filename:service_account.json

# Azure
org:target "AZURE_CLIENT_SECRET"
org:target "AZURE_SUBSCRIPTION_ID"

# Stripe
org:target "sk_live_"
org:target "rk_live_"
org:target "pk_live_"

# Twilio
org:target "TWILIO_ACCOUNT_SID"
org:target "TWILIO_AUTH_TOKEN"

# SendGrid
org:target "SG."
org:target "SENDGRID_API_KEY"

# Slack
org:target "xoxb-"
org:target "xoxp-"
org:target "xoxo-"
org:target "xoxa-"

# GitHub tokens
org:target "ghp_"
org:target "gho_"
org:target "ghu_"
org:target "ghs_"

# Mailgun
org:target "key-" filename:.env
org:target "MAILGUN_API_KEY"

# Firebase
org:target "firebase" filename:.json
org:target "firebaseConfig"

# Heroku
org:target "HEROKU_API_KEY"

# DigitalOcean
org:target "DO_API_TOKEN"
org:target "DIGITALOCEAN_ACCESS_TOKEN"

# Generic
org:target "api_key"
org:target "apikey"
org:target "api_secret"
org:target "access_token"
org:target "client_secret"
org:target "private_key"
org:target "bearer"
```

## Passwords & Credentials

```
# Direct password strings
org:target "password ="
org:target "password:"
org:target "passwd"
org:target "pwd ="
org:target "secret ="

# Database credentials
org:target "DB_PASSWORD"
org:target "DATABASE_URL"
org:target "MYSQL_PASSWORD"
org:target "POSTGRES_PASSWORD"
org:target "MONGO_URI"
org:target "REDIS_URL"
org:target "connection_string"

# SMTP
org:target "SMTP_PASSWORD"
org:target "MAIL_PASSWORD"
org:target "EMAIL_PASSWORD"

# LDAP
org:target "LDAP_PASSWORD"
org:target "ldap_bind_password"

# SSH keys
org:target filename:id_rsa
org:target filename:id_dsa
org:target "BEGIN RSA PRIVATE KEY"
org:target "BEGIN DSA PRIVATE KEY"
org:target "BEGIN EC PRIVATE KEY"
org:target "BEGIN OPENSSH PRIVATE KEY"

# SSL/TLS keys
org:target filename:.pem "PRIVATE KEY"
org:target filename:.key "PRIVATE KEY"
org:target filename:.p12
org:target filename:.pfx
```

## Configuration Files

```
# Environment files
org:target filename:.env
org:target filename:.env.production
org:target filename:.env.staging
org:target filename:.env.local
org:target filename:.env.development

# Config files
org:target filename:config.json password
org:target filename:config.yml password
org:target filename:config.yaml secret
org:target filename:settings.py SECRET_KEY
org:target filename:settings.json
org:target filename:application.properties password
org:target filename:application.yml password
org:target filename:wp-config.php
org:target filename:web.config password
org:target filename:appsettings.json

# Docker
org:target filename:docker-compose.yml password
org:target filename:Dockerfile password
org:target filename:.dockerenv

# Kubernetes
org:target filename:kubeconfig
org:target filename:kube_config
org:target filename:values.yaml password

# CI/CD
org:target filename:.travis.yml password
org:target filename:Jenkinsfile password
org:target filename:.gitlab-ci.yml password
org:target path:.github/workflows password
org:target path:.circleci password

# Terraform
org:target filename:.tfvars password
org:target filename:terraform.tfstate

# NPM
org:target filename:.npmrc _auth
org:target filename:.npmrc authToken
```

## Internal Information

```
# Internal tools
org:target "internal" | "intranet" | "confluence" | "jira"
org:target "staging" | "production" | "dev-" | "test-"

# IP addresses & internal URLs
org:target "10.0." | "172.16." | "192.168."
org:target "internal.target.com" | "staging.target.com" | "dev.target.com"

# VPN configs
org:target filename:.ovpn
org:target filename:vpn extension:conf

# Infrastructure
org:target filename:ansible password
org:target filename:inventory password
org:target filename:hosts.yml
```

## GitHub-Specific Recon

```
# GitHub Actions secrets
org:target path:.github/workflows secrets
org:target path:.github/workflows env:

# GitHub Pages
org:target filename:CNAME
org:target filename:_config.yml

# GitHub Issues & PRs (search code comments)
org:target "TODO" | "FIXME" | "HACK" | "XXX" password

# Git history artifacts
org:target filename:.gitignore .env
org:target filename:.gitignore credentials
```

## Advanced Techniques

### Cross-Fork Object Reference (CFOR)
```
# Deleted fork commits may still be accessible via original repo
# If you know a commit hash from a deleted fork:
https://github.com/org/repo/commit/COMMIT_HASH

# Commits from deleted forks persist in the original repo's object database
```

### GitHub API Search
```bash
# Search code via API (more results than web UI)
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=org:target+password+filename:.env"

# Search repos
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  "https://api.github.com/search/repositories?q=org:target+internal"

# Search commits
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  "https://api.github.com/search/commits?q=org:target+password+removal"
```

### Google + GitHub
```
# Use Google to search GitHub raw content
site:raw.githubusercontent.com "target.com" password
site:gist.github.com "target.com" api_key
site:github.com "target.com" filename:.env
```

## Automation Tools

```bash
# TruffleHog - find secrets in git history
trufflehog github --org=target-org
trufflehog github --repo=https://github.com/org/repo

# GitLeaks
gitleaks detect --source /path/to/repo --report-path report.json
gitleaks detect --source https://github.com/org/repo

# github-dorks (Python tool)
pip3 install github-dorks
github-dorks -o target-org

# git-secrets
git secrets --scan -r /path/to/repo

# shhgit (real-time GitHub monitoring)
shhgit --search-query "org:target password"

# gh CLI
gh search code "org:target-corp password" --limit 100
gh search code "org:target-corp AKIA" --limit 100
```

## High-Value Bug Bounty Dorks

```
# Top dorks that have produced bounties
org:target "password" filename:.env
org:target "AWS_ACCESS_KEY_ID" filename:.env
org:target "sk_live_"
org:target "AKIA"
org:target filename:id_rsa
org:target "client_secret"
org:target "BEGIN RSA PRIVATE KEY"
org:target "authorization: bearer"
org:target filename:credentials
org:target "jdbc:" password
org:target "mongodb+srv://"
org:target "postgres://" password
org:target "mysql://" password
```

## Workflow

1. **Identify org**: Find all GitHub orgs associated with target
2. **Broad search**: Start with `org:target password`, `org:target secret`
3. **File search**: Target `.env`, config files, credential files
4. **Key patterns**: Search for known API key patterns (AKIA, sk_live, etc.)
5. **History search**: Use TruffleHog/GitLeaks for git commit history
6. **Employee repos**: Find developer personal repos with company code
7. **Validate**: Test found credentials (carefully, in-scope only)
8. **Report**: Document the exposure path and impact

## Pro Tips

- Employee personal repos often contain leaked company credentials
- Deleted commits are NOT truly deleted - they persist in git objects
- GitHub Actions workflow files frequently contain hardcoded secrets
- Search for the target's domain name across ALL of GitHub, not just their org
- Use `pushed:>2025-01-01` to find recent (potentially active) leaks
- Check `.gitignore` files to understand what SHOULD have been excluded
- Low-star repos from new accounts are often the leakiest
- CI/CD configs (.travis.yml, Jenkinsfile) are goldmine for secrets
- Docker Compose files frequently contain database passwords
- Terraform state files may contain cloud provider credentials in plaintext
