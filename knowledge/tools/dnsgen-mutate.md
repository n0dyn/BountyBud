---
id: "dnsgen-mutate"
title: "DNSGen - Subdomain Mutation"
type: "tool"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain", "dnsgen-mutate", "active", "subdomain-mutation", "pattern-generation", "wordlist-expansion"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/ProjectAnte/dnsgen"
related: []
updated: "2026-03-30"
---

## Overview

Generates potential subdomains using permutation patterns and wordlist-based mutations.

## Command Reference

```bash
cat {domain}_subfinder.txt | dnsgen - | head -20000 > {domain}_mutations.txt
puredns resolve {domain}_mutations.txt -r /opt/resolvers.txt > {domain}_resolved_mutations.txt
echo "[+] DNSGen: $(wc -l < {domain}_resolved_mutations.txt) new subdomains resolved via mutation"
```

## Features

- Subdomain mutation
- Pattern generation
- Wordlist expansion

## Documentation

- [Official Documentation](https://github.com/ProjectAnte/dnsgen)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.3   |
| API        | 0.2   |
| Network    | 0.4   |
| Cloud      | 0.3   |
| CMS        | 0.2   |

## Fallback Alternatives

- **altdns** - Alternative subdomain permutation tool
- **gotator** - Fast subdomain permutation generator in Go
- **subfinder** - Passive enumeration without mutation (different approach)

## Context-Aware Parameters

**Standard mutation with resolution**
```bash
cat {domain}_subfinder.txt | dnsgen - | head -20000 > {domain}_mutations.txt
puredns resolve {domain}_mutations.txt -r /opt/resolvers.txt > {domain}_resolved_mutations.txt
```

**Custom wordlist mutation**
```bash
cat {domain}_subfinder.txt | dnsgen -w /opt/wordlists/dns_permutations.txt - > {domain}_custom_mutations.txt
```

**Targeted mutation with limited output**
```bash
cat {domain}_subfinder.txt | dnsgen - | head -5000 | puredns resolve -r /opt/resolvers.txt > {domain}_quick_mutations.txt
```
