---
id: "ctf-web-playbook"
title: "CTF Web Playbook - Flag Hunting Edition"
type: "methodology"
category: "web-application"
subcategory: "xss"
tags: ["ctf", "web", "git-exposure", "prototype-pollution", "graphql", "source-maps", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["javascript-analysis", "dig-deep-asset-classes"]
difficulty: "intermediate"
updated: "2026-03-30"
---

# CTF Web Playbook – Flag Hunting Edition

## Quick-Win Checklist
- JS source maps = flag 90% of the time
- Hidden admin endpoints via naming convention
- GraphQL introspection = instant win

## Deep Dig Prompts
```
You are in a CTF. This is the only JS file [paste]: Extract the flag or the next internal endpoint. Think like a CTF author.
```

## CTF-Specific Vectors
- .git exposure
- Backup files
- Debug endpoints with flags
- Prototype pollution → RCE
