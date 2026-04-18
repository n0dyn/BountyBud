---
id: "javascript-analysis"
title: "JavaScript Analysis Masterclass for Bug Bounty & Red Teaming"
type: "technique"
category: "web-application"
subcategory: "xss"
tags: ["javascript", "js-analysis", "secrets", "endpoints", "dom-xss", "prototype-pollution", "feature-flags", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques", "dig-deep-asset-classes", "ctf-web-playbook"]
difficulty: "intermediate"
updated: "2026-03-30"
---

# JavaScript Analysis Masterclass for Bug Bounty Hunting, Red Teaming & CTF

## Why JS Analysis Matters
Client-side bundles are the #1 source of hidden endpoints, secrets, and logic flaws that automated scanners miss.

## Collection Phase
- Burp spider + HAR export  
- `waybackurls | grep "\.js$"` + historical JS  
- Tools: `gau`, `katana`, `hakrawler`

## Analysis Techniques
1. Beautify & chunk large files  
2. Secret & comment grep: `api_key|secret|token|aws_access|stripe|debug|admin|staging|TODO|FIXME`  
3. **Hydration Mining:** Scan HTML source for hydration blocks (e.g., `<script id="__NEXT_DATA__" type="application/json">`). These contain:
   - Initial application state
   - Environment variables (leaked `PREVIEW` or `PREVIEW_ACCESS` tokens)
   - Internal `baseUrl` or backend API routing logic.
4. **Static Logic Tracing:** Trace data from a dangerous `Source` (like `postMessage` or `localStorage`) to a `Sink` (like `eval()` or `innerHTML`).
   - Use byte-offsets to find handler logic in minified files.
   - Look for origin validation short-circuits.
5. Endpoint mapping: every `fetch`, `axios`, `WebSocket`  
6. Vulnerability hunting: DOM sinks (innerHTML, eval) + controllable sources → DOM-XSS / prototype pollution  
7. Feature flags & client-side auth checks

## Deep Dig Prompts
```
Analyze this beautified JavaScript [paste chunk]: 
- Extract all unique API endpoints, feature flags, hardcoded credentials  
- Flag staging/internal URLs  
- List any client-side validations that scream “server bypass possible”
```

```
Check for DOM-based vulnerabilities: List sources and sinks that could lead to XSS or prototype pollution.
```

## Tools & Automation
- LinkFinder / jsleak  
- `ripgrep` + custom regex  
- Nuclei JS secret templates  

## Common High-Impact Findings
- Staging admin APIs  
- Hardcoded test creds  
- Premium feature flags toggleable by users  
- Internal service discovery via JS
