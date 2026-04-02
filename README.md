# BountyBud

A comprehensive security testing toolkit and RAG-ready knowledge base for bug bounty hunters, penetration testers, and red teamers.

## Features

### Command Generation
Generate ready-to-use commands for 49+ security tools across 15 categories — subdomain enumeration, directory brute-forcing, vulnerability scanning, OSINT, cloud testing, and more. Enter a target domain and get optimized, rate-limited commands.

### XSS Payload Generator
Context-aware XSS payload generation with encoding options (URL, HTML, Unicode, hex), filter bypass techniques, and a blind XSS callback listener that logs execution details.

### Knowledge Base (RAG-Ready)
87 structured documents with 397 pre-chunked sections covering:

| Category | Topics |
|----------|--------|
| **Web Application** | XSS, SQLi, SSRF, IDOR/BOLA, SSTI, race conditions, business logic, auth bypass |
| **Network** | Port scanning methodology, service exploitation, wireless attacks |
| **Privilege Escalation** | Linux, Windows, Active Directory |
| **Cloud** | AWS, GCP, Azure misconfigurations |
| **API Security** | GraphQL, gRPC, REST |
| **Mobile** | Frida, APK analysis, runtime hooking |
| **Social Engineering** | Phishing, pretexting, vishing |
| **Post-Exploitation** | Persistence, lateral movement, credential harvesting, C2 |
| **Payloads** | XSS, SQLi, SSRF, SSTI, command injection libraries |
| **Cheatsheets** | Nmap, FFUF, Burp Suite, reverse shells |

Every document includes **Deep Dig Prompts** — LLM-ready templates you can feed to AI with target-specific data for guided vulnerability discovery.

### REST API for AI Agents
All knowledge is accessible via `/api/kb/` endpoints with CORS headers, designed for RAG system consumption:

```
GET /api/kb/search?q=ssrf+bypass&category=web-application
GET /api/kb/chunks?type=technique&limit=50
GET /api/kb/document/ad-attacks
GET /api/kb/manifest
GET /api/kb/taxonomy
GET /api/kb/stats
GET /api/kb/related/ssrf-techniques
POST /api/kb/reindex
```

The `/api/kb/chunks` endpoint returns pre-chunked content with metadata and token counts — ready to embed into any vector store.

### MCP Server (Model Context Protocol)

BountyBud exposes an MCP-compatible SSE endpoint so AI tools like Claude Desktop, Claude Code, Gemini, etc. can connect directly to the knowledge base.

**Endpoint:** `GET /mcp/sse` (requires API key)

**Tools available to AI clients:**
| Tool | Description |
|------|-------------|
| `search_knowledge` | Full-text search with category/type/difficulty filters |
| `get_document` | Retrieve a full document by ID |
| `list_documents` | Browse all documents with optional filters |
| `get_related` | Find related documents |
| `get_stats` | Knowledge base statistics |

**Connect from Claude Code:**
```bash
claude mcp add --transport sse bountybud https://bb.nxit.cc/mcp/sse?api_key=YOUR_KEY
```

**Connect from Claude Desktop** (via `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "bountybud": {
      "command": "npx",
      "args": ["mcp-remote", "https://bb.nxit.cc/mcp/sse?api_key=YOUR_KEY"]
    }
  }
}
```

**Security:** API key required (set `MCP_API_KEY` env var). Rate limited to 60 req/min per IP, max 20 concurrent sessions, 8KB request size cap, strict method allowlist.

### Security Tools Catalog
Curated collection of tools with descriptions, installation instructions, and documentation links.

### Browser Extensions
Recommended browser extensions for security testing workflows.

## Tech Stack

- **Backend**: Python 3.11+, Flask
- **Frontend**: Bootstrap 5, vanilla JavaScript
- **Search**: SQLite FTS5 (zero-dependency full-text search)
- **Content**: Markdown with YAML frontmatter
- **Server**: Gunicorn

## Quick Start

```bash
# Clone
git clone https://github.com/n0dyn/BountyBud.git
cd BountyBud

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# or: pip install flask gunicorn python-frontmatter markdown pygments

# Set MCP API key (required for MCP access)
export MCP_API_KEY="your-secret-key-here"

# Run
python3 app.py
```

Open `http://localhost:5000` in your browser.

## Project Structure

```
BountyBud/
├── app.py                     # Flask application
├── kb/                        # Knowledge base engine
│   ├── loader.py              # Markdown + frontmatter parser & chunker
│   ├── indexer.py             # SQLite FTS5 index builder
│   ├── search.py              # Search & query logic
│   └── routes.py              # /api/kb/* REST endpoints
├── knowledge/                 # 87 markdown knowledge files
│   ├── tools/                 # 49 security tool docs
│   ├── techniques/            # Attack technique guides
│   │   ├── web/               # SSRF, IDOR, race conditions, etc.
│   │   ├── network/           # Port scanning, service exploitation
│   │   ├── cloud/             # AWS/GCP/Azure misconfigs
│   │   ├── mobile/            # Frida, APK testing
│   │   ├── api/               # GraphQL, gRPC
│   │   ├── privilege-escalation/  # Linux, Windows, AD
│   │   ├── post-exploitation/ # Persistence, lateral movement
│   │   └── social-engineering/
│   ├── methodologies/         # End-to-end workflows
│   ├── payloads/              # XSS, SQLi, SSRF, SSTI, cmd injection
│   ├── cheatsheets/           # Nmap, FFUF, Burp, reverse shells
│   └── reporting/             # Report templates
├── templates/                 # Jinja2 HTML templates
├── static/                    # CSS, JS, images, JSON data
├── scripts/                   # Migration & maintenance scripts
└── data/                      # Auto-generated search index
```

## Adding Knowledge

Create a markdown file in the appropriate `knowledge/` subdirectory with YAML frontmatter:

```yaml
---
id: "unique-slug"
title: "Document Title"
type: "technique"
category: "web-application"
subcategory: "ssrf"
tags: ["ssrf", "bypass", "cloud"]
difficulty: "advanced"
platforms: ["linux", "macos"]
related: ["other-doc-id"]
updated: "2026-03-30"
---

## Overview
Content here...

## Deep Dig Prompts
LLM-ready prompts here...
```

Then rebuild the index:
```bash
python3 scripts/reindex.py
# or POST /api/kb/reindex
```

## Disclaimer

This toolkit is for **educational purposes and authorized security testing only**. Always ensure you have proper written authorization before testing any target. Unauthorized security testing is illegal and unethical.

## License

MIT
