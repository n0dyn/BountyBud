#!/usr/bin/env python3
"""BountyBud MCP Server — local stdio bridge to the remote REST API.

Run with Claude Code:
  claude mcp add bountybud -- python3 /path/to/mcp_server.py

Environment variables:
  BOUNTYBUD_URL  — API base URL (default: https://bb.nxit.cc/api/kb)
  BOUNTYBUD_KEY  — API key for authentication
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API_BASE = os.getenv("BOUNTYBUD_URL", "https://bb.nxit.cc/api/kb").rstrip("/")
API_KEY = os.getenv("BOUNTYBUD_KEY", "")

PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {"name": "BountyBud", "version": "1.0.0"}

CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"subscribe": False, "listChanged": False},
}

INSTRUCTIONS = (
    "BountyBud is a comprehensive bug bounty and red teaming knowledge base with 120+ documents "
    "and 700+ searchable chunks covering tools, techniques, payloads, and methodologies. Key workflow: "
    "1) search_knowledge to find relevant techniques, payloads, and tool guidance, "
    "2) get_document for full guides with context-aware parameters and effectiveness scores, "
    "3) search_cves / get_cve for live CVE intelligence from the NVD, "
    "4) Follow the 4-phase workflow: Discovery → Enumeration → Hunting → Exploitation, "
    "5) Use the vulnerability priority matrix to focus on high-impact findings first, "
    "6) Validate all findings with the 5-Gate Verification before reporting. "
    "Tool docs include effectiveness scores by target type and fallback alternatives. "
    "Use deep dig prompts from technique docs with target-specific data."
)

TOOLS = [
    {
        "name": "search_knowledge",
        "description": (
            "Search the BountyBud security knowledge base. Returns relevant chunks "
            "about bug bounty techniques, XSS/SQLi/SSRF payloads, tools, methodologies, "
            "privilege escalation, Active Directory attacks, cloud security, and more."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g., 'SSRF bypass', 'linux privesc', 'blind XSS')",
                },
                "category": {
                    "type": "string",
                    "description": "Filter by category",
                    "enum": [
                        "reconnaissance", "web-application", "network", "cloud",
                        "mobile", "api-security", "privilege-escalation",
                        "post-exploitation", "social-engineering", "reporting", "cms",
                    ],
                },
                "type": {
                    "type": "string",
                    "description": "Filter by content type",
                    "enum": ["tool", "technique", "methodology", "payload", "cheatsheet", "report-template"],
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10, max 50)",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_document",
        "description": (
            "Get a full document by ID. Returns complete markdown with metadata. "
            "Use list_documents to find IDs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Document ID (e.g., 'ad-attacks', 'ssrf-techniques')",
                },
            },
            "required": ["document_id"],
        },
    },
    {
        "name": "list_documents",
        "description": "List all documents with metadata. Use to discover content before get_document.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Filter by category"},
                "type": {"type": "string", "description": "Filter by content type"},
            },
        },
    },
    {
        "name": "get_related",
        "description": "Find documents related to a given document by tag similarity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string", "description": "Document ID"},
            },
            "required": ["document_id"],
        },
    },
    {
        "name": "get_stats",
        "description": "Get KB stats: total documents, chunks, counts by category/type/difficulty.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "search_cves",
        "description": (
            "Search the NVD (National Vulnerability Database) for recent CVEs. "
            "Use to find vulnerabilities affecting specific technologies during hunting. "
            "Returns CVE IDs, descriptions, CVSS scores, and references."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search term (e.g., 'apache log4j', 'wordpress plugin', 'nginx')",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by CVSS v3 severity",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "days": {
                    "type": "integer",
                    "description": "CVEs published in the last N days (default 30, max 120)",
                    "default": 30,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 20, max 50)",
                    "default": 20,
                },
            },
            "required": ["keyword"],
        },
    },
    {
        "name": "get_cve",
        "description": (
            "Get full details for a specific CVE by ID. Returns description, CVSS score, "
            "affected products, CWE weaknesses, and references."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier (e.g., 'CVE-2024-12345')",
                },
            },
            "required": ["cve_id"],
        },
    },
]

RESOURCES = [
    {
        "uri": "bountybud://taxonomy",
        "name": "Knowledge Base Taxonomy",
        "description": "Full category tree with document counts",
        "mimeType": "application/json",
    },
    {
        "uri": "bountybud://manifest",
        "name": "Document Manifest",
        "description": "Complete index of all documents with metadata",
        "mimeType": "application/json",
    },
]


# ── REST API Client ─────────────────────────────────────────


def _api_get(path: str, params: dict | None = None) -> dict:
    """GET request to BountyBud REST API."""
    url = f"{API_BASE}{path}"
    if params:
        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None and v != ""})
        if qs:
            url += "?" + qs
    req = urllib.request.Request(url)
    if API_KEY:
        req.add_header("Authorization", f"Bearer {API_KEY}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        raise RuntimeError(f"API error {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection error: {e.reason}") from e


# ── Tool Execution ──────────────────────────────────────────


def _execute_tool(name: str, arguments: dict) -> list[dict]:
    """Execute a tool via the REST API and return MCP content blocks."""

    if name == "search_knowledge":
        query = arguments.get("query", "")
        if not query:
            return [{"type": "text", "text": "A search query is required."}]
        params = {
            "q": query,
            "category": arguments.get("category"),
            "type": arguments.get("type"),
            "limit": str(min(int(arguments.get("limit", 10)), 50)),
        }
        resp = _api_get("/search", params)
        results = resp.get("data", {}).get("results", [])
        if not results:
            return [{"type": "text", "text": f"No results for '{query}'."}]

        lines = [f"Found {resp['data'].get('total', len(results))} results for '{query}':\n"]
        for r in results:
            tags = ", ".join(r.get("metadata", {}).get("tags", [])[:4])
            lines.append(
                f"### {r.get('title', '')} — {r.get('section', '')}\n"
                f"**Type:** {r.get('metadata', {}).get('type', '')} | "
                f"**Category:** {r.get('metadata', {}).get('category', '')} | "
                f"**Tags:** {tags}\n\n"
                f"{r.get('content', '')}\n\n---\n"
            )
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_document":
        doc_id = arguments.get("document_id", "")
        if not doc_id:
            return [{"type": "text", "text": "A document_id is required."}]
        resp = _api_get(f"/document/{urllib.parse.quote(doc_id, safe='')}")
        doc = resp.get("data")
        if not doc:
            return [{"type": "text", "text": f"Document '{doc_id}' not found."}]

        meta = doc.get("metadata", {})
        header = (
            f"# {meta.get('title', doc.get('id', doc_id))}\n\n"
            f"**Type:** {meta.get('type', '')} | "
            f"**Category:** {meta.get('category', '')} | "
            f"**Difficulty:** {meta.get('difficulty', '')} | "
            f"**Tags:** {', '.join(meta.get('tags', []))}\n\n---\n\n"
        )
        return [{"type": "text", "text": header + doc.get("body_markdown", "")}]

    elif name == "list_documents":
        resp = _api_get("/manifest")
        manifest = resp.get("data", {}).get("documents", [])

        cat_filter = arguments.get("category")
        type_filter = arguments.get("type")
        if cat_filter:
            manifest = [d for d in manifest if d.get("category") == cat_filter]
        if type_filter:
            manifest = [d for d in manifest if d.get("type") == type_filter]

        if not manifest:
            return [{"type": "text", "text": "No documents match the given filters."}]

        lines = [f"**{len(manifest)} documents found:**\n"]
        for d in manifest:
            tags = ", ".join(d.get("tags", [])[:3])
            lines.append(f"- **{d['id']}** — {d.get('title', '')} [{d.get('type', '')}/{d.get('category', '')}] ({tags})")
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_related":
        doc_id = arguments.get("document_id", "")
        if not doc_id:
            return [{"type": "text", "text": "A document_id is required."}]
        resp = _api_get(f"/related/{urllib.parse.quote(doc_id, safe='')}")
        related = resp.get("data", [])
        if not related:
            return [{"type": "text", "text": f"No related documents for '{doc_id}'."}]

        lines = [f"**Documents related to '{doc_id}':**\n"]
        for r in related:
            lines.append(f"- **{r['id']}** — {r.get('title', '')} [{r.get('type', '')}/{r.get('category', '')}]")
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_stats":
        resp = _api_get("/stats")
        stats = resp.get("data", {})
        text = (
            f"**BountyBud Knowledge Base Stats:**\n\n"
            f"- **Total Documents:** {stats.get('total_documents', '?')}\n"
            f"- **Total RAG Chunks:** {stats.get('total_chunks', '?')}\n\n"
        )
        for section, key in [("By Type", "by_type"), ("By Category", "by_category"), ("By Difficulty", "by_difficulty")]:
            text += f"**{section}:**\n"
            for k, v in sorted(stats.get(key, {}).items()):
                text += f"  - {k}: {v}\n"
            text += "\n"
        return [{"type": "text", "text": text}]

    elif name == "search_cves":
        keyword = arguments.get("keyword", "")
        if not keyword:
            return [{"type": "text", "text": "A keyword is required."}]
        params = {
            "keyword": keyword,
            "severity": arguments.get("severity", ""),
            "days": str(arguments.get("days", 30)),
            "limit": str(arguments.get("limit", 20)),
        }
        # Use the CVE endpoint on the BountyBud API
        cve_base = API_BASE.replace("/api/kb", "/api/cve")
        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        url = f"{cve_base}/search?{qs}"
        req = urllib.request.Request(url)
        if API_KEY:
            req.add_header("Authorization", f"Bearer {API_KEY}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            return [{"type": "text", "text": f"CVE search error: {e}"}]

        vulns = data.get("data", {}).get("vulnerabilities", [])
        total = data.get("data", {}).get("total_results", 0)
        if not vulns:
            return [{"type": "text", "text": f"No CVEs found for '{keyword}'."}]

        lines = [f"**{total} CVEs found for '{keyword}'** (showing {len(vulns)}):\n"]
        for v in vulns:
            score = v.get("cvss_score", "N/A")
            severity = v.get("cvss_severity", "N/A")
            lines.append(
                f"### {v['id']} — CVSS {score} ({severity})\n"
                f"**Published:** {v.get('published', '')[:10]}\n\n"
                f"{v.get('description', '')[:300]}\n\n"
                f"**References:** {', '.join(v.get('references', [])[:3])}\n\n---\n"
            )
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_cve":
        cve_id = arguments.get("cve_id", "")
        if not cve_id:
            return [{"type": "text", "text": "A cve_id is required."}]
        cve_base = API_BASE.replace("/api/kb", "/api/cve")
        url = f"{cve_base}/{urllib.parse.quote(cve_id, safe='')}"
        req = urllib.request.Request(url)
        if API_KEY:
            req.add_header("Authorization", f"Bearer {API_KEY}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            return [{"type": "text", "text": f"CVE lookup error: {e}"}]

        cve = data.get("data", {})
        if not cve:
            return [{"type": "text", "text": f"CVE {cve_id} not found."}]

        score = cve.get("cvss_score", "N/A")
        severity = cve.get("cvss_severity", "N/A")
        cwes = ", ".join(cve.get("weaknesses", [])) or "N/A"
        refs = "\n".join(f"- {r.get('url', '')}" for r in cve.get("references", [])[:10])
        affected = "\n".join(f"- `{a}`" for a in cve.get("affected_products", [])[:10])

        text = (
            f"# {cve.get('id', cve_id)}\n\n"
            f"**CVSS Score:** {score} ({severity})\n"
            f"**Published:** {cve.get('published', '')[:10]}\n"
            f"**Last Modified:** {cve.get('lastModified', '')[:10]}\n"
            f"**CWE:** {cwes}\n"
            f"**Vector:** {cve.get('cvss_vector', 'N/A')}\n\n"
            f"## Description\n\n{cve.get('description', '')}\n\n"
            f"## Affected Products\n\n{affected or 'N/A'}\n\n"
            f"## References\n\n{refs or 'N/A'}\n"
        )
        return [{"type": "text", "text": text}]

    return [{"type": "text", "text": f"Unknown tool: {name}"}]


def _read_resource(uri: str) -> list[dict]:
    """Read a resource via the REST API."""
    if uri == "bountybud://taxonomy":
        resp = _api_get("/taxonomy")
        return [{"uri": uri, "mimeType": "application/json", "text": json.dumps(resp.get("data", {}), indent=2)}]
    elif uri == "bountybud://manifest":
        resp = _api_get("/manifest")
        return [{"uri": uri, "mimeType": "application/json", "text": json.dumps(resp.get("data", {}), indent=2)}]
    return []


# ── JSON-RPC Handler ────────────────────────────────────────


def _handle_message(msg: dict) -> dict | None:
    """Handle a JSON-RPC message. Returns response or None for notifications."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    if msg_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": CAPABILITIES,
                "serverInfo": SERVER_INFO,
                "instructions": INSTRUCTIONS,
            },
        }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        try:
            content = _execute_tool(tool_name, arguments)
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"content": content}}
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True},
            }

    elif method == "resources/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": RESOURCES}}

    elif method == "resources/read":
        uri = params.get("uri", "")
        try:
            contents = _read_resource(uri)
        except Exception as e:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": str(e)}}
        if not contents:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32602, "message": f"Unknown resource: {uri}"}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"contents": contents}}

    elif method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

    else:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


# ── Stdio Transport ─────────────────────────────────────────


def main():
    """Main loop — read JSON-RPC from stdin, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
            continue

        response = _handle_message(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
