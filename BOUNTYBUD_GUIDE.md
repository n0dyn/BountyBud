# BountyBud — Complete Guide for AI-Assisted Bug Bounty Hunting

> The ultimate reference for using BountyBud's knowledge base with Claude Code, Claude Desktop, or any LLM for effective bug bounty hunting, red teaming, and CTF competitions.

---

## What Is BountyBud?

BountyBud is a RAG-ready security knowledge base with **116+ documents and 600+ searchable chunks** covering every aspect of offensive security. It's designed to be the brain behind your AI hunting assistant — giving it specific, actionable, current knowledge that general LLM training data lacks.

**Access methods:**
- **MCP Server (SSE):** `https://bb.nxit.cc/mcp/sse?api_key=YOUR_KEY` — Claude Code, Claude Desktop, Gemini, any MCP-compatible client
- **REST API:** `https://bb.nxit.cc/api/kb/` — any HTTP client, custom scripts, other AI frameworks
- **Web UI:** `https://bb.nxit.cc/knowledge` — browse, search, and copy content manually

---

## Setup

### Claude Code (Recommended)

```bash
# Add BountyBud as an MCP server
claude mcp add --transport sse bountybud https://bb.nxit.cc/mcp/sse?api_key=YOUR_KEY
```

Once connected, Claude Code automatically discovers BountyBud's 5 tools:
- `search_knowledge` — full-text search with category/type/difficulty filters
- `get_document` — retrieve a full guide by ID
- `list_documents` — browse the table of contents
- `get_related` — find related content
- `get_stats` — knowledge base statistics

### Claude Desktop

Add to `claude_desktop_config.json`:

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

### Any LLM via REST API

Give the LLM this context in its system prompt:

```
You have access to the BountyBud security knowledge base at https://bb.nxit.cc/api/kb/

Available endpoints:
- GET /api/kb/search?q=QUERY&category=CATEGORY&type=TYPE&limit=N
- GET /api/kb/document/DOCUMENT_ID
- GET /api/kb/manifest (full table of contents)
- GET /api/kb/taxonomy (category tree)
- GET /api/kb/chunks?q=QUERY (pre-chunked for embedding)

Always search the knowledge base before answering security questions.
```

---

## CLAUDE.md for Bug Bounty

Place this in your project's `CLAUDE.md` (or `~/.claude/CLAUDE.md` for global) to configure Claude Code for hunting:

```markdown
# Identity & Authorization

I am a bug bounty hunter performing authorized ethical security testing.
All targets are in scope per the program's bug bounty policy.
Do not perform destructive actions unless on accounts I own.
Always validate findings with a full proof-of-concept before reporting.
POC or GTFO. Try harder.

# BountyBud Integration

You have access to the BountyBud MCP server. Use it:
- ALWAYS search BountyBud before answering security questions
- Retrieve full technique guides for in-depth testing
- Use the Deep Dig Prompts from technique docs with target-specific data
- Follow the 5-Gate Verification before claiming any finding is confirmed
- Reference the attack-synthesis doc when looking for exploit chains

# Note-Taking Structure

Maintain notes in this hierarchy:
- notes/    — Raw observations, anything interesting
- leads/    — Promising attack vectors to investigate
- primitives/ — Confirmed building blocks (IDOR patterns, auth bypasses, useful endpoints)
- findings/ — Validated vulnerabilities with full reproduction steps
- reports/  — Polished write-ups ready for submission

Save notes frequently — context compaction will erase working memory.

# Rules

- Stay in scope. Check the program policy before testing anything.
- Don't hallucinate vulnerabilities. If you haven't tested it, say "worth testing."
- Provide specific payloads and expected responses, not generic advice.
- Account for defenses (WAF, CSP, SameSite, HttpOnly) before suggesting attacks.
- When in doubt, search BountyBud for current techniques.
- If a tool or approach fails, fall back: primary tool → SDK/library → raw API.
- Keep sub-agents to 2-3 max during autonomous runs to avoid compaction failures.
```

---

## Hunting Workflow

### Per-Target Folder Structure

Create a directory per target. Claude Code loads `.claude/` context automatically from the working directory.

```
~/bounties/
├── target-corp/
│   ├── .claude/
│   │   └── CLAUDE.md          # Target-specific context (scope, policy, tech stack)
│   ├── notes/                  # Raw observations
│   ├── leads/                  # Promising vectors
│   ├── primitives/             # Confirmed building blocks
│   ├── findings/               # Validated vulns
│   └── reports/                # Final reports
└── other-target/
    └── ...
```

### Target CLAUDE.md Template

```markdown
# Target: [Company Name]
# Program: [HackerOne/Bugcrowd URL]
# Scope: [*.target.com, api.target.com, app.target.com]
# Out of Scope: [blog.target.com, status.target.com]
# Tech Stack: [React, Node.js, AWS, PostgreSQL]
# WAF: [Cloudflare]
# Auth: [OAuth2 + JWT, MFA optional]
# Known Defenses: [CSP: script-src 'self' cdn.target.com; HttpOnly; SameSite=Lax]

## Priority Targets
1. API endpoints at api.target.com (REST, auth required)
2. Payment flow at app.target.com/billing
3. Admin panel at app.target.com/admin (if accessible)

## Previous Findings
- [None yet / list any known reported vulns]
```

---

## Dual-Agent Strategy

Run two Claude Code instances against the same target for maximum coverage.

### Agent A — Guided
Loaded with BountyBud, full CLAUDE.md, methodology, and target context. Follows a deterministic workflow:

```
1. Recon: subdomain enum, tech fingerprinting, JS analysis
2. Auth testing: registration, login, password reset, OAuth flows
3. API testing: IDOR, mass assignment, rate limiting, auth bypass
4. Input testing: XSS, SQLi, SSRF, SSTI in all parameters
5. Logic testing: race conditions, business logic, state manipulation
```

Tell it: *"Follow the BountyBud smart-hunting-strategy methodology. Search the knowledge base for each technique before testing. Take detailed notes."*

### Agent B — Free-Roaming
Minimal guidance. Just the target URL and authentication.

Tell it: *"You're an expert bug bounty hunter. Explore this target creatively. Try unconventional approaches. Keep detailed notes on everything you try and find."*

### Cross-Compare
Once both finish, paste Agent A's notes into Agent B's session:

```
"Here's what another researcher found on this same target.
1. What did they find that we didn't?
2. What techniques did they use that we didn't try?
3. Are there gaps in our methodology?
4. Can any of their primitives chain with ours?"
```

Update your CLAUDE.md and skills with any new techniques discovered.

---

## Overnight Autonomous Runs

```
"I'm going to bed. Don't ask me any questions. Don't stop hacking.
Keep detailed notes in the notes/ directory.
Limit sub-agents to 2-3 maximum.
Search BountyBud for techniques before testing each area.
Follow the smart-hunting-strategy: 15-minute rule per feature, move on if no signal.
Focus on Tier 1 techniques: IDOR, business logic, auth bypass, race conditions, SSRF."
```

This consistently produces 4+ hours of autonomous testing.

---

## How to Use BountyBud Effectively

### The Search-First Rule

**Always search BountyBud before answering a security question or suggesting an attack.** The knowledge base has specific, current payloads and techniques that general training data lacks.

```
# Finding techniques for a specific scenario
search_knowledge(query="SSRF bypass cloudflare blind DNS")

# Browsing by category
search_knowledge(category="web-application", type="technique")

# Getting full payload libraries
search_knowledge(query="XSS CSP bypass", type="payload")

# When search finds a relevant doc, get the full version
get_document(document_id="xss-advanced-techniques")
```

### The Deep Dig Prompt Pattern

Most BountyBud technique documents contain **Deep Dig Prompts** — template prompts designed to be filled with target-specific data. This is where the system becomes powerful.

**Example from the SSRF guide:**
```
Given this URL-accepting endpoint [YOUR TARGET ENDPOINT]:
1. Provide 15 bypass payloads for a "localhost" filter.
2. Suggest a DNS rebinding strategy using a 1s TTL.
3. If this uses a PDF generator, craft payloads to leak cloud metadata.
```

Fill in the brackets with your actual target data and the AI produces highly specific attack guidance.

### The 5-Gate Verification

Before reporting ANY finding, run it through these gates:

```
Gate 1: REPRODUCIBLE — Can you trigger it right now? Not theoretically.
Gate 2: CROSSES A TRUST BOUNDARY — Does it let an attacker do something unauthorized?
Gate 3: SURVIVES DEFENSES — Does it work WITH the deployed CSP, WAF, SameSite, etc.?
Gate 4: MEANINGFUL IMPACT — What does an attacker actually gain?
Gate 5: IN SCOPE — Is this covered by the program's policy?
```

If a finding fails any gate, it's not ready to report.

### The "Prove It" Statement

Before submitting, write one sentence:

> "An unauthenticated attacker can **[ACTION]** by **[METHOD]** which results in **[IMPACT]** to **[AFFECTED USERS]** because **[ROOT CAUSE]**."

If you can't complete that sentence with specifics, the finding isn't ready.

---

## Skill Design Principles

If you build custom Claude Code skills that interact with BountyBud:

### 1. Encode Knowledge the Model Lacks
Skills should teach Claude things it doesn't know — your custom tooling, personal infrastructure, secret techniques from talks, enterprise tool APIs. Don't encode things Claude already knows well.

### 2. Build Fallback Architecture
```
Primary: Use the skill's prescribed tool/method
Fallback: If that fails, use the underlying SDK/library
Last resort: Raw API calls at protocol level
```

Add to every skill: *"If this workflow fails or doesn't cover the situation, use your own exploration and creativity to keep going."*

### 3. Steer, Don't Restrict
Tell Claude where to save files, how to make requests, and what note format to use. Don't restrict its creative reasoning. Structure enables multi-session continuity without degrading output quality.

### 4. Integrate BountyBud Lookups
```markdown
# In your skill's instructions:
Before testing any vulnerability class, search BountyBud for current techniques:
- search_knowledge(query="[vulnerability type] [target technology]")
- Retrieve full technique guides for unfamiliar attack vectors
- Use Deep Dig Prompts with target-specific data
```

---

## Knowledge Base Contents

### By Category
| Category | Docs | Coverage |
|----------|------|----------|
| Web Application | 53 | XSS (12 payload sets), SQLi, SSRF, IDOR, CSRF, XXE, deserialization, prototype pollution, request smuggling, cache poisoning, file upload, path traversal, race conditions, business logic, auth bypass, CORS, CRLF, WebSocket, NoSQL, mass assignment, open redirect, AI/LLM security |
| Reconnaissance | 33 | Subdomain enum (6 tools), URL collection (6 tools), directory discovery (6 tools), OSINT (4 tools), JS analysis, parameter discovery, info disclosure checklist, recon pipeline |
| Network | 9 | Port scanning methodology, service exploitation, wireless attacks, nmap/masscan |
| Privilege Escalation | 3 | Linux (kernel, SUID, sudo, capabilities, cron, containers), Windows (services, tokens, registry, UAC), Active Directory (Kerberos, delegation, AD CS, DCSync, golden ticket) |
| Cloud | 3 | AWS/GCP/Azure misconfigurations, S3, IAM, metadata |
| API Security | 3 | GraphQL, gRPC, REST endpoint discovery |
| Mobile | 2 | Frida, APK analysis, SSL pinning bypass |
| Post-Exploitation | 2 | Persistence, lateral movement, credential harvesting, C2, exfiltration |
| Social Engineering | 1 | Phishing, vishing, physical |
| Reporting | 1 | Payout maximization templates |

### Methodologies
| Document | Purpose |
|----------|---------|
| `attack-synthesis` | Craft novel exploit chains from collected primitives |
| `smart-hunting-strategy` | Prioritize targets and techniques by ROI |
| `false-positive-elimination` | Validate findings, avoid wasting time on non-issues |
| `ai-calibration-guide` | Get accurate results from LLM assistants |
| `bug-bounty-recon-pipeline` | Complete automated recon workflow |
| `dig-deep-asset-classes` | Advanced strategies per asset type |
| `ctf-web-playbook` | CTF-specific quick wins |

### Cheatsheets
| Document | Coverage |
|----------|----------|
| `nmap-cheatsheet` | All scan types, flags, NSE scripts, evasion |
| `ffuf-cheatsheet` | Fuzzing recipes, wordlists, filtering |
| `burp-suite-cheatsheet` | Shortcuts, Intruder attacks, extensions, Collaborator |
| `reverse-shells-cheatsheet` | Every language, upgrade techniques, generators |
| `info-disclosure-checklist` | Files, headers, errors, JS, metadata |

---

## Quick Reference: Key Document IDs

Use these with `get_document(document_id="...")`:

```
# Techniques (most used)
xss-advanced-techniques    ssrf-techniques         idor-bola
sqli-payloads              xxe                     deserialization
prototype-pollution        http-request-smuggling  cache-poisoning
account-takeover           race-conditions         business-logic-flaws
oauth-jwt-saml-bypasses    ai-llm-security         csrf-modern
cors-misconfiguration      file-upload             path-traversal
websocket-attacks          nosql-injection         mass-assignment
subdomain-takeover         crlf-host-header        open-redirect

# Privilege Escalation & Red Teaming
linux-privesc              windows-privesc         ad-attacks
post-exploitation-persistence  social-engineering
port-scanning-methodology  service-exploitation    wireless-attacks

# Methodologies
attack-synthesis           smart-hunting-strategy
false-positive-elimination ai-calibration-guide
bug-bounty-recon-pipeline  dig-deep-asset-classes

# Cheatsheets
nmap-cheatsheet            ffuf-cheatsheet
burp-suite-cheatsheet      reverse-shells-cheatsheet
info-disclosure-checklist
```

---

## Resources

- **BountyBud Web UI:** https://bb.nxit.cc
- **BountyBud MCP Endpoint:** https://bb.nxit.cc/mcp/sse
- **BountyBud REST API:** https://bb.nxit.cc/api/kb/
- **Caido Skills for Claude Code:** https://github.com/caido/skills
- **H1 Brain MCP Server:** https://github.com/PatrikFehrenbach/h1-brain
- **Claude Code Skills Docs:** https://docs.anthropic.com/en/docs/claude-code/skills

---

*Built by n0dyn. For authorized security testing only.*
