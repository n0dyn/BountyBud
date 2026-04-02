"""MCP (Model Context Protocol) SSE server integrated into Flask.

Exposes the BountyBud knowledge base via MCP so AI tools like Claude Desktop,
Claude Code, Gemini, etc. can connect and query the KB.

Endpoints:
  GET  /mcp/sse              — SSE stream (client connects here)
  POST /mcp/messages/<session> — JSON-RPC message endpoint
"""

import json
import os
import queue
import threading
import time
import uuid
from collections import defaultdict
from flask import Blueprint, Response, request, stream_with_context

from kb.indexer import ensure_index
from kb.search import (
    get_document,
    get_manifest,
    get_related,
    get_stats,
    get_taxonomy,
    search_chunks,
)

mcp_bp = Blueprint('mcp', __name__)

# ── Security: Rate Limiting & Session Limits ─────────────────

MAX_SESSIONS = 20              # Max concurrent SSE connections
MAX_REQUESTS_PER_MIN = 60      # Per-IP rate limit
MAX_REQUEST_SIZE = 8192        # Max JSON-RPC message size in bytes
SESSION_TIMEOUT = 600          # SSE session timeout (10 min idle)

# API key — set via MCP_API_KEY env var. If set, all MCP requests must include it.
MCP_API_KEY = os.getenv('MCP_API_KEY', '')

# Active SSE sessions: session_id -> queue
_sessions: dict[str, queue.Queue] = {}
_sessions_lock = threading.Lock()

# Rate limiting: ip -> list of timestamps
_rate_limits: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()


def _check_rate_limit(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.time()
    with _rate_lock:
        # Prune old entries
        _rate_limits[ip] = [t for t in _rate_limits[ip] if now - t < 60]
        if len(_rate_limits[ip]) >= MAX_REQUESTS_PER_MIN:
            return False
        _rate_limits[ip].append(now)
    return True


def _check_api_key() -> str | None:
    """Validate the API key. Returns None if valid, error message if not."""
    if not MCP_API_KEY:
        return None  # No key configured = MCP disabled
    # Accept key via Authorization header or query param
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:].strip()
        if token == MCP_API_KEY:
            return None
    # Also check query param (for SSE connections where headers can be tricky)
    if request.args.get('api_key') == MCP_API_KEY:
        return None
    return "Invalid or missing API key"


def _sanitize_input(text: str, max_len: int = 500) -> str:
    """Sanitize user input — strip dangerous chars, enforce length."""
    if not isinstance(text, str):
        return ""
    # Remove null bytes and control chars (keep newlines/tabs for payloads)
    cleaned = text.replace('\x00', '')
    return cleaned[:max_len]

# ── Server Info ──────────────────────────────────────────────

SERVER_INFO = {
    "name": "BountyBud",
    "version": "1.0.0",
}

CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"subscribe": False, "listChanged": False},
}

PROTOCOL_VERSION = "2024-11-05"

INSTRUCTIONS = (
    "BountyBud is a comprehensive bug bounty and red teaming knowledge base with 115+ documents "
    "and 600+ searchable chunks. IMPORTANT: Read the 'bountybud://instructions' resource FIRST — "
    "it explains exactly how to use this system effectively. Key workflow: "
    "1) search_knowledge to find relevant content, "
    "2) get_document for full guides, "
    "3) Always validate findings with the 5-Gate Verification before claiming vulnerabilities. "
    "4) Use deep dig prompts from technique docs with target-specific data. "
    "Never claim a finding is confirmed without testing evidence from the user."
)

# ── Tool Definitions ─────────────────────────────────────────

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
                    "description": "Search query (e.g., 'SSRF bypass cloudflare', 'linux privilege escalation', 'blind XSS callback')",
                },
                "category": {
                    "type": "string",
                    "description": "Filter by category: reconnaissance, web-application, network, cloud, mobile, api-security, privilege-escalation, post-exploitation, social-engineering, reporting, cms",
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
                "difficulty": {
                    "type": "string",
                    "description": "Filter by difficulty level",
                    "enum": ["beginner", "intermediate", "advanced", "expert"],
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default 10, max 50)",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_document",
        "description": (
            "Get a full document from the knowledge base by its ID. "
            "Returns the complete markdown content with metadata. "
            "Use list_documents first to find document IDs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Document ID (e.g., 'ad-attacks', 'linux-privesc', 'ssrf-techniques', 'nmap-cheatsheet')",
                },
            },
            "required": ["document_id"],
        },
    },
    {
        "name": "list_documents",
        "description": (
            "List all documents in the knowledge base with their metadata. "
            "Returns document IDs, titles, types, categories, and tags. "
            "Use this to discover available content before calling get_document."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category (optional)",
                },
                "type": {
                    "type": "string",
                    "description": "Filter by content type (optional)",
                },
            },
        },
    },
    {
        "name": "get_related",
        "description": "Find documents related to a given document by ID and tag similarity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Document ID to find related content for",
                },
            },
            "required": ["document_id"],
        },
    },
    {
        "name": "get_stats",
        "description": "Get knowledge base statistics: total documents, chunks, counts by category/type/difficulty.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]

# ── Resource Definitions ─────────────────────────────────────

RESOURCES = [
    {
        "uri": "bountybud://instructions",
        "name": "BountyBud Usage Instructions",
        "description": "How to effectively use this knowledge base — read this FIRST before any other interaction",
        "mimeType": "text/markdown",
    },
    {
        "uri": "bountybud://taxonomy",
        "name": "Knowledge Base Taxonomy",
        "description": "Full category tree with document counts — the structure of the knowledge base",
        "mimeType": "application/json",
    },
    {
        "uri": "bountybud://manifest",
        "name": "Document Manifest",
        "description": "Complete index of all documents with metadata (no body content)",
        "mimeType": "application/json",
    },
]

# ── Tool Execution ───────────────────────────────────────────

def _execute_tool(name: str, arguments: dict) -> list[dict]:
    """Execute a tool and return MCP content blocks."""
    ensure_index()

    if name == "search_knowledge":
        query = _sanitize_input(arguments.get("query", ""), 200)
        if not query:
            return [{"type": "text", "text": "A search query is required."}]
        result = search_chunks(
            query=query,
            doc_type=_sanitize_input(arguments.get("type", ""), 50) or None,
            category=_sanitize_input(arguments.get("category", ""), 50) or None,
            difficulty=_sanitize_input(arguments.get("difficulty", ""), 20) or None,
            limit=min(int(arguments.get("limit", 10)), 50),
        )
        if not result["results"]:
            return [{"type": "text", "text": f"No results found for '{arguments.get('query')}'."}]

        lines = [f"Found {result['total']} results for '{arguments.get('query')}':\n"]
        for r in result["results"]:
            tags = ", ".join(r["metadata"].get("tags", [])[:4])
            lines.append(
                f"### {r['title']} — {r['section']}\n"
                f"**Type:** {r['metadata']['type']} | "
                f"**Category:** {r['metadata']['category']} | "
                f"**Tags:** {tags}\n\n"
                f"{r['content']}\n\n---\n"
            )
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_document":
        doc_id = _sanitize_input(arguments.get("document_id", ""), 100)
        if not doc_id:
            return [{"type": "text", "text": "A document_id is required."}]
        doc = get_document(doc_id)
        if not doc:
            return [{"type": "text", "text": f"Document '{doc_id}' not found."}]

        meta = doc["metadata"]
        header = (
            f"# {meta.get('title', doc['id'])}\n\n"
            f"**Type:** {meta.get('type', '')} | "
            f"**Category:** {meta.get('category', '')} | "
            f"**Difficulty:** {meta.get('difficulty', '')} | "
            f"**Tags:** {', '.join(meta.get('tags', []))}\n\n---\n\n"
        )
        return [{"type": "text", "text": header + doc["body_markdown"]}]

    elif name == "list_documents":
        manifest = get_manifest()
        cat_filter = _sanitize_input(arguments.get("category", ""), 50) or None
        type_filter = _sanitize_input(arguments.get("type", ""), 50) or None

        if cat_filter:
            manifest = [d for d in manifest if d["category"] == cat_filter]
        if type_filter:
            manifest = [d for d in manifest if d["type"] == type_filter]

        if not manifest:
            return [{"type": "text", "text": "No documents match the given filters."}]

        lines = [f"**{len(manifest)} documents found:**\n"]
        for d in manifest:
            tags = ", ".join(d.get("tags", [])[:3])
            lines.append(
                f"- **{d['id']}** — {d['title']} "
                f"[{d['type']}/{d['category']}] ({tags})"
            )
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_related":
        doc_id = _sanitize_input(arguments.get("document_id", ""), 100)
        if not doc_id:
            return [{"type": "text", "text": "A document_id is required."}]
        related = get_related(doc_id)
        if not related:
            return [{"type": "text", "text": f"No related documents found for '{doc_id}'."}]

        lines = [f"**Documents related to '{doc_id}':**\n"]
        for r in related:
            lines.append(
                f"- **{r['id']}** — {r['title']} [{r['type']}/{r['category']}] "
                f"(relation: {r.get('relation', 'unknown')})"
            )
        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "get_stats":
        stats = get_stats()
        text = (
            f"**BountyBud Knowledge Base Stats:**\n\n"
            f"- **Total Documents:** {stats['total_documents']}\n"
            f"- **Total RAG Chunks:** {stats['total_chunks']}\n\n"
            f"**By Type:**\n"
        )
        for t, c in sorted(stats["by_type"].items()):
            text += f"  - {t}: {c}\n"
        text += "\n**By Category:**\n"
        for cat, c in sorted(stats["by_category"].items()):
            text += f"  - {cat}: {c}\n"
        text += "\n**By Difficulty:**\n"
        for d, c in sorted(stats["by_difficulty"].items()):
            text += f"  - {d}: {c}\n"
        return [{"type": "text", "text": text}]

    return [{"type": "text", "text": f"Unknown tool: {name}"}]


def _read_resource(uri: str) -> list[dict]:
    """Read a resource by URI."""
    ensure_index()

    if uri == "bountybud://instructions":
        doc = get_document("system-prompt")
        if doc:
            return [{"uri": uri, "mimeType": "text/markdown", "text": doc["body_markdown"]}]
        return [{"uri": uri, "mimeType": "text/markdown", "text": "System prompt document not found. Run reindex."}]

    elif uri == "bountybud://taxonomy":
        taxonomy = get_taxonomy()
        return [{"uri": uri, "mimeType": "application/json", "text": json.dumps(taxonomy, indent=2)}]

    elif uri == "bountybud://manifest":
        manifest = get_manifest()
        return [{"uri": uri, "mimeType": "application/json", "text": json.dumps(manifest, indent=2)}]

    return []


# ── JSON-RPC Handler ─────────────────────────────────────────

def _handle_jsonrpc(msg: dict) -> dict | None:
    """Handle a single JSON-RPC message. Returns response dict or None for notifications."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    # Notifications (no id) — no response
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
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": content},
            }
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
        contents = _read_resource(uri)
        if not contents:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"Resource not found: {uri}"},
            }
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"contents": contents}}

    elif method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

    else:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


# ── SSE Endpoint ─────────────────────────────────────────────

@mcp_bp.route('/sse')
def mcp_sse():
    """SSE endpoint — client connects here to receive JSON-RPC responses."""
    # API key check
    if MCP_API_KEY:
        err = _check_api_key()
        if err:
            return {"error": err}, 401

    client_ip = request.remote_addr or "unknown"

    # Rate limit SSE connections
    if not _check_rate_limit(client_ip):
        return {"error": "Rate limit exceeded"}, 429

    # Enforce max session limit
    with _sessions_lock:
        if len(_sessions) >= MAX_SESSIONS:
            return {"error": "Too many active sessions"}, 503

    session_id = uuid.uuid4().hex
    q = queue.Queue()

    with _sessions_lock:
        _sessions[session_id] = q

    def generate():
        # Send the endpoint event first
        messages_url = f"/mcp/messages/{session_id}"
        yield f"event: endpoint\ndata: {messages_url}\n\n"

        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    if msg is None:
                        break
                    yield f"event: message\ndata: {json.dumps(msg)}\n\n"
                except queue.Empty:
                    # Send keepalive comment
                    yield ": keepalive\n\n"
        finally:
            with _sessions_lock:
                _sessions.pop(session_id, None)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*',
        },
    )


@mcp_bp.route('/messages/<session_id>', methods=['POST', 'OPTIONS'])
def mcp_messages(session_id):
    """Message endpoint — client sends JSON-RPC requests here."""
    if request.method == 'OPTIONS':
        return Response('', 204, headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        })

    # API key check
    if MCP_API_KEY:
        err = _check_api_key()
        if err:
            return {"error": err}, 401

    client_ip = request.remote_addr or "unknown"

    # Rate limit
    if not _check_rate_limit(client_ip):
        return {"error": "Rate limit exceeded"}, 429

    # Validate session ID format (hex UUID only)
    if not session_id or len(session_id) != 32 or not all(c in '0123456789abcdef' for c in session_id):
        return {"error": "Invalid session ID"}, 400

    # Enforce max request size
    if request.content_length and request.content_length > MAX_REQUEST_SIZE:
        return {"error": "Request too large"}, 413

    with _sessions_lock:
        q = _sessions.get(session_id)

    if q is None:
        return {"error": "Invalid or expired session"}, 404

    try:
        msg = request.get_json(force=False, silent=False)
        if not isinstance(msg, dict):
            return {"error": "Invalid JSON-RPC message"}, 400
    except Exception:
        return {"error": "Invalid JSON"}, 400

    # Validate JSON-RPC structure
    if msg.get("jsonrpc") != "2.0":
        return {"error": "Invalid JSON-RPC version"}, 400

    method = msg.get("method", "")
    if not isinstance(method, str) or len(method) > 100:
        return {"error": "Invalid method"}, 400

    # Only allow known methods
    allowed_methods = {
        "initialize", "notifications/initialized", "initialized",
        "ping", "tools/list", "tools/call",
        "resources/list", "resources/read",
        "prompts/list", "prompts/get",
        "notifications/cancelled",
    }
    if method not in allowed_methods:
        response = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
        if msg.get("id") is not None:
            q.put(response)
        return '', 202, {'Access-Control-Allow-Origin': '*'}

    response = _handle_jsonrpc(msg)

    if response is not None:
        q.put(response)

    return '', 202, {
        'Access-Control-Allow-Origin': '*',
    }
