---
id: "ffuf-api"
title: "FFUF API Endpoint Discovery"
type: "tool"
category: "api-security"
subcategory: "rest"
tags: ["api", "ffuf-api"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

API endpoint discovery using common API patterns.

## Command Reference

```bash
ffuf -u 'https://{domain}/api/FUZZ' -w /opt/wordlists/api_endpoints.txt -t 20 -rate 100 -mc 200,201,204 -o {domain}_api_endpoints.json
echo "API endpoint discovery results saved to {domain}_api_endpoints.json"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.5   |
| API        | 0.9   |
| Network    | 0.0   |
| Cloud      | 0.2   |
| CMS        | 0.3   |

## Fallback Alternatives

- **arjun** - Specialized parameter discovery for APIs
- **gobuster** - Directory/vhost mode for API path enumeration
- **wfuzz** - Multi-point fuzzing for API endpoints

## Context-Aware Parameters

**Standard API endpoint discovery**
```bash
ffuf -u 'https://{domain}/api/FUZZ' -w /opt/wordlists/api_endpoints.txt -t 20 -rate 100 -mc 200,201,204 -o {domain}_api_endpoints.json
```

**Versioned API path enumeration**
```bash
ffuf -u 'https://{domain}/api/v1/FUZZ' -w /opt/wordlists/api_endpoints.txt -t 20 -rate 100 -mc 200,201,204,301 -o {domain}_api_v1.json
```

**API endpoint discovery with authentication**
```bash
ffuf -u 'https://{domain}/api/FUZZ' -w /opt/wordlists/api_endpoints.txt -H "Authorization: Bearer TOKEN" -t 10 -rate 50 -mc 200,201,204 -o {domain}_api_auth.json
```

**GraphQL endpoint discovery**
```bash
ffuf -u 'https://{domain}/FUZZ' -w /opt/wordlists/graphql_paths.txt -t 10 -rate 50 -mc 200,405 -o {domain}_graphql.json
```
