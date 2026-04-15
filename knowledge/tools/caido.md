---
id: "caido"
title: "Caido - Modern Web Security Proxy"
type: "tool"
category: "web-application"
subcategory: "proxy"
tags: ["proxy", "caido", "interceptor", "web-testing", "replay", "automate", "httpql", "burp-alternative"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
source_url: "https://caido.io"
related: ["burpsuite", "zaproxy"]
updated: "2026-04-14"
---

## Overview

Caido is a modern, lightweight web security proxy built in Rust. Alternative to Burp Suite with significantly better performance and lower memory usage. Features include HTTPQL query language, visual workflow automation, match & replace, replay, automate (intruder equivalent), multi-project support, and a growing plugin ecosystem. Free tier includes multi-project support.

## Installation

```bash
# Download from https://caido.io/download
# Available as desktop app or CLI

# Linux
curl -L https://caido.io/download/linux -o caido
chmod +x caido

# Docker
docker run --rm -p 8080:8080 caido/caido

# Start
./caido
# Access at http://localhost:8080 (default)
```

## Core Features

### Intercept Proxy
- Intercept and modify HTTP/HTTPS requests in real-time
- Conditional intercept using HTTPQL filters
- TLS termination with auto-generated CA certificate
- WebSocket support

### HTTPQL Query Language
```
# Filter by host
req.host eq "target.com"

# Filter by path
req.path cont "/api/"

# Filter by method
req.method eq "POST"

# Filter by status code
resp.code eq 200
resp.code gt 399

# Filter by body content
resp.body cont "admin"
req.body cont "password"

# Filter by header
req.header cont "Authorization"

# Complex queries with AND/OR
req.host eq "target.com" AND req.path cont "/api/" AND resp.code eq 200
req.method eq "POST" OR req.method eq "PUT"

# Negation
NOT req.path cont "/static/"

# Nested queries
(req.host eq "api.target.com" OR req.host eq "target.com") AND resp.code eq 200
```

### Replay (like Burp Repeater)
- Send individual requests and inspect responses
- Modify any part of the request
- Tab-based interface for multiple requests
- Request history within replay

### Automate (like Burp Intruder)
- Position-based payload insertion
- Multiple payload types
- HTTPQL filtering on results
- Concurrent request handling
- Rate limiting controls

### Match & Replace
- Modify requests/responses automatically
- HTTPQL-based conditions for targeted replacements
- Works in proxy mode and Automate mode
- Supports regex replacements

### Workflows (Visual Automation)
- Visual node-based workflow editor
- Custom JavaScript or bash scripts
- Conditional logic nodes
- Marketplace for community workflows
- Event-driven (trigger on request, response, etc.)

### Sitemap / Scope
- Automatic sitemap building from captured traffic
- Scope management for focusing on target domains
- Tree view of discovered endpoints

## Key Advantages Over Burp Suite

| Feature | Caido | Burp Suite |
|---------|-------|-----------|
| Performance | Rust-based, very fast | Java, high memory |
| Multi-project (free) | Yes | Pro only |
| Query language | HTTPQL (powerful) | Basic filters |
| Workflow automation | Visual editor | Extensions/macros |
| Price | Free tier available | Community limited |
| Startup time | Seconds | Minutes |
| Memory usage | Low (~100MB) | High (1GB+) |

## Workflow with Other Tools

### Proxy Chain
```bash
# Send tool traffic through Caido
# Set Caido as upstream proxy

# curl through Caido
curl -x http://127.0.0.1:8080 https://target.com

# dalfox through Caido
dalfox url "https://target.com/page?q=test" --proxy http://127.0.0.1:8080

# sqlmap through Caido
sqlmap -u "https://target.com/page?id=1" --proxy http://127.0.0.1:8080

# nuclei through Caido
nuclei -u https://target.com -proxy http://127.0.0.1:8080

# ffuf through Caido
ffuf -u https://target.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080
```

### MCP Integration
Caido has an MCP server plugin enabling AI assistant integration for traffic analysis.

### Interactsh Integration
The quickssrf Caido plugin integrates interactsh for OOB testing.

### Export
- Export requests as curl commands
- Export to various formats for scripting
- Share projects between team members

## Bug Bounty Workflow

1. **Setup**: Install CA cert, configure browser proxy to 127.0.0.1:8080
2. **Scope**: Set scope to target domain(s) in project settings
3. **Browse**: Navigate target application, build sitemap
4. **Filter**: Use HTTPQL to find interesting endpoints: `req.path cont "/api/" AND resp.code eq 200`
5. **Test**: Use Replay for manual testing of interesting requests
6. **Automate**: Use Automate for fuzzing parameters, IDOR testing
7. **Match & Replace**: Set up rules for session token rotation, header injection
8. **Workflows**: Create custom automation for repetitive testing patterns

## Plugin SDK

```javascript
// Caido Plugin SDK capabilities
getWorkflows()
onCreatedWorkflow()
onUpdatedWorkflow()
onDeletedWorkflow()
// Custom request/response modification
// Custom UI panels
```

## Pro Tips

- HTTPQL autocomplete remembers your previous queries
- Use workflows for repetitive tasks like session token refresh
- Multi-project support lets you context-switch between targets instantly
- Match & Replace can now run inside Automate for combined fuzzing
- Export requests as curl for scripting and automation
- The plugin marketplace has community-contributed tools
- Lower memory footprint makes it ideal for running alongside other tools
- Use conditional intercept to only pause on interesting requests
