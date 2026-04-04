#!/usr/bin/env python3
"""BountyBud MCP Server — local stdio bridge with tool execution.

Connects to the BountyBud REST API for knowledge base access and provides
local security tool execution. The KB informs tool selection, parameters,
and methodology — execute_tool runs them on the local machine.

Run with Claude Code:
  claude mcp add bountybud -- python3 /path/to/mcp_server.py

Environment variables:
  BOUNTYBUD_URL  — API base URL (default: https://bb.nxit.cc/api/kb)
  BOUNTYBUD_KEY  — API key for authentication
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = os.getenv("BOUNTYBUD_URL", "https://bb.nxit.cc/api/kb").rstrip("/")
API_KEY = os.getenv("BOUNTYBUD_KEY", "")

# ── Local Tool Execution ───────────────────────────────────────

# Track running/completed processes
_processes: dict[str, dict] = {}
_proc_lock = threading.Lock()
_proc_counter = 0


# Complete toolbelt — every security tool BountyBud knows about, with binary
# names for install detection and one-line descriptions for the LLM.
TOOLBELT = {
    # ── Subdomain Enumeration ──
    "subfinder":      {"bin": "subfinder",      "cat": "recon",    "desc": "Fast passive subdomain discovery from multiple sources"},
    "amass":          {"bin": "amass",           "cat": "recon",    "desc": "In-depth subdomain enumeration (passive + active + brute)"},
    "assetfinder":    {"bin": "assetfinder",     "cat": "recon",    "desc": "Quick subdomain finder using cert transparency + APIs"},
    "chaos":          {"bin": "chaos",           "cat": "recon",    "desc": "ProjectDiscovery's subdomain dataset API"},
    "findomain":      {"bin": "findomain",       "cat": "recon",    "desc": "Cross-platform subdomain enumerator"},
    # ── DNS & Resolution ──
    "dnsx":           {"bin": "dnsx",            "cat": "recon",    "desc": "Fast DNS resolver and query tool"},
    "dnsgen":         {"bin": "dnsgen",          "cat": "recon",    "desc": "DNS wordlist generator from subdomains (permutation)"},
    "fierce":         {"bin": "fierce",          "cat": "recon",    "desc": "DNS reconnaissance and zone transfer testing"},
    "dnsenum":        {"bin": "dnsenum",         "cat": "recon",    "desc": "DNS enumeration with zone transfers and brute force"},
    "subjack":        {"bin": "subjack",         "cat": "recon",    "desc": "Subdomain takeover detection"},
    # ── HTTP Probing ──
    "httpx":          {"bin": "httpx",           "cat": "recon",    "desc": "HTTP probe with tech detection, status codes, titles"},
    "httprobe":       {"bin": "httprobe",        "cat": "recon",    "desc": "Simple live HTTP host prober"},
    # ── URL & Content Discovery ──
    "katana":         {"bin": "katana",          "cat": "recon",    "desc": "Modern web crawler with JS rendering and form parsing"},
    "hakrawler":      {"bin": "hakrawler",       "cat": "recon",    "desc": "Fast web crawler for URL and endpoint discovery"},
    "gospider":       {"bin": "gospider",        "cat": "recon",    "desc": "Fast web spider with link/form/JS extraction"},
    "gau":            {"bin": "gau",             "cat": "recon",    "desc": "Historical URL fetcher (Wayback, Common Crawl, OTX)"},
    "gauplus":        {"bin": "gauplus",         "cat": "recon",    "desc": "Enhanced gau with extra sources"},
    "waybackurls":    {"bin": "waybackurls",     "cat": "recon",    "desc": "Fetch URLs from Wayback Machine archives"},
    "waymore":        {"bin": "waymore",         "cat": "recon",    "desc": "Wayback Machine URL + response fetcher"},
    # ── Directory & Content Bruteforce ──
    "ffuf":           {"bin": "ffuf",            "cat": "recon",    "desc": "Fast web fuzzer — dirs, params, vhosts, POST data"},
    "feroxbuster":    {"bin": "feroxbuster",     "cat": "recon",    "desc": "Recursive content discovery with auto-filtering"},
    "gobuster":       {"bin": "gobuster",        "cat": "recon",    "desc": "Directory/DNS/vhost brute-forcer"},
    "dirsearch":      {"bin": "dirsearch",       "cat": "recon",    "desc": "Web path scanner with extension support"},
    "dirb":           {"bin": "dirb",            "cat": "recon",    "desc": "Classic URL bruteforcer"},
    "wfuzz":          {"bin": "wfuzz",           "cat": "recon",    "desc": "Web fuzzer for parameters, dirs, headers"},
    # ── Parameter Discovery ──
    "arjun":          {"bin": "arjun",           "cat": "recon",    "desc": "Hidden HTTP parameter discovery (GET/POST/JSON)"},
    "paramspider":    {"bin": "paramspider",     "cat": "recon",    "desc": "Mine parameters from web archives"},
    "x8":             {"bin": "x8",              "cat": "recon",    "desc": "Hidden parameter discovery with smart detection"},
    # ── JavaScript Analysis ──
    "linkfinder":     {"bin": "linkfinder",      "cat": "recon",    "desc": "Extract endpoints from JavaScript files"},
    "getjs":          {"bin": "getjs",           "cat": "recon",    "desc": "Fetch and extract JavaScript file URLs"},
    # ── Technology Fingerprinting ──
    "whatweb":        {"bin": "whatweb",          "cat": "recon",    "desc": "Web technology fingerprinter (CMS, framework, server)"},
    "wafw00f":        {"bin": "wafw00f",          "cat": "recon",    "desc": "WAF detection and fingerprinting"},
    # ── Port Scanning ──
    "nmap":           {"bin": "nmap",            "cat": "network",  "desc": "Network scanner — ports, services, OS, scripts, vulns"},
    "masscan":        {"bin": "masscan",         "cat": "network",  "desc": "Fastest port scanner (async SYN, millions of hosts)"},
    "rustscan":       {"bin": "rustscan",        "cat": "network",  "desc": "Fast port scanner that pipes to nmap for service detection"},
    # ── Vulnerability Scanning ──
    "nuclei":         {"bin": "nuclei",          "cat": "vuln",     "desc": "Template-based vuln scanner — 7000+ CVE/misconfig/exposure checks"},
    "nikto":          {"bin": "nikto",           "cat": "vuln",     "desc": "Web server scanner for dangerous files and outdated software"},
    "zaproxy":        {"bin": "zap-cli",         "cat": "vuln",     "desc": "OWASP ZAP — web app security scanner (spider + active scan)"},
    # ── SQL Injection ──
    "sqlmap":         {"bin": "sqlmap",          "cat": "vuln",     "desc": "Automated SQL injection detection and exploitation"},
    "ghauri":         {"bin": "ghauri",          "cat": "vuln",     "desc": "Advanced SQL injection detection (sqlmap alternative)"},
    "nosqlmap":       {"bin": "nosqlmap",        "cat": "vuln",     "desc": "NoSQL injection and exploitation tool"},
    # ── XSS ──
    "dalfox":         {"bin": "dalfox",          "cat": "vuln",     "desc": "Parameter analysis and XSS scanner with DOM mining"},
    "kxss":           {"bin": "kxss",            "cat": "vuln",     "desc": "Reflected parameter finder for XSS testing"},
    # ── SSTI ──
    "tplmap":         {"bin": "tplmap",          "cat": "vuln",     "desc": "Server-Side Template Injection detection and exploitation"},
    # ── CMS ──
    "wpscan":         {"bin": "wpscan",          "cat": "cms",      "desc": "WordPress vulnerability scanner (plugins, themes, users)"},
    "droopescan":     {"bin": "droopescan",      "cat": "cms",      "desc": "Drupal/Joomla/SilverStripe scanner"},
    "joomscan":       {"bin": "joomscan",        "cat": "cms",      "desc": "Joomla vulnerability scanner"},
    # ── OSINT ──
    "theharvester":   {"bin": "theHarvester",    "cat": "osint",    "desc": "Email, subdomain, and name harvester from public sources"},
    "shodan":         {"bin": "shodan",          "cat": "osint",    "desc": "Shodan CLI — search internet-connected devices"},
    "spiderfoot":     {"bin": "spiderfoot",      "cat": "osint",    "desc": "OSINT automation with 200+ data sources"},
    "sherlock":       {"bin": "sherlock",        "cat": "osint",    "desc": "Find social media accounts by username"},
    "recon-ng":       {"bin": "recon-ng",        "cat": "osint",    "desc": "Full-featured OSINT framework with modules"},
    # ── Cloud ──
    "s3scanner":      {"bin": "s3scanner",       "cat": "cloud",    "desc": "S3 bucket permission scanner"},
    "prowler":        {"bin": "prowler",         "cat": "cloud",    "desc": "AWS/Azure/GCP security assessment"},
    "scout-suite":    {"bin": "scout",           "cat": "cloud",    "desc": "Multi-cloud security auditing"},
    "trivy":          {"bin": "trivy",           "cat": "cloud",    "desc": "Container/IaC/filesystem vulnerability scanner"},
    "kube-hunter":    {"bin": "kube-hunter",     "cat": "cloud",    "desc": "Kubernetes penetration testing"},
    "kube-bench":     {"bin": "kube-bench",      "cat": "cloud",    "desc": "Kubernetes CIS benchmark checker"},
    "checkov":        {"bin": "checkov",         "cat": "cloud",    "desc": "IaC static analysis (Terraform, CloudFormation, K8s)"},
    # ── Secrets ──
    "trufflehog":     {"bin": "trufflehog",      "cat": "recon",    "desc": "Find leaked credentials in git repos and filesystems"},
    # ── Auth & Crypto ──
    "jwt-tool":       {"bin": "jwt_tool",        "cat": "vuln",     "desc": "JWT testing — none alg, key confusion, claim tampering"},
    "hashcat":        {"bin": "hashcat",         "cat": "auth",     "desc": "GPU-accelerated password/hash cracker"},
    "john":           {"bin": "john",            "cat": "auth",     "desc": "John the Ripper — password hash cracker"},
    "hydra":          {"bin": "hydra",           "cat": "auth",     "desc": "Online password brute-forcer (SSH, FTP, HTTP, etc.)"},
    "medusa":         {"bin": "medusa",          "cat": "auth",     "desc": "Parallel login brute-forcer"},
    # ── Network Services ──
    "enum4linux-ng":  {"bin": "enum4linux-ng",   "cat": "network",  "desc": "SMB/NetBIOS enumeration (users, shares, policies)"},
    "smbmap":         {"bin": "smbmap",          "cat": "network",  "desc": "SMB share enumeration and access testing"},
    "netexec":        {"bin": "netexec",         "cat": "network",  "desc": "Network service exploitation (SMB, LDAP, WinRM, etc.)"},
    "rpcclient":      {"bin": "rpcclient",       "cat": "network",  "desc": "Windows RPC client for domain enumeration"},
    "evil-winrm":     {"bin": "evil-winrm",      "cat": "network",  "desc": "WinRM shell for Windows post-exploitation"},
    # ── Proxy & Interception ──
    "mitmproxy":      {"bin": "mitmproxy",       "cat": "proxy",    "desc": "Interactive HTTPS proxy for traffic interception"},
    "burpsuite":      {"bin": "burpsuite",       "cat": "proxy",    "desc": "Web security testing platform (GUI)"},
    # ── Binary / RE ──
    "binwalk":        {"bin": "binwalk",         "cat": "binary",   "desc": "Firmware analysis and extraction"},
    "checksec":       {"bin": "checksec",        "cat": "binary",   "desc": "Check binary security properties (NX, PIE, RELRO, etc.)"},
    "strings":        {"bin": "strings",         "cat": "binary",   "desc": "Extract printable strings from binary files"},
    "objdump":        {"bin": "objdump",         "cat": "binary",   "desc": "Disassemble and inspect binary object files"},
    # ── Forensics ──
    "exiftool":       {"bin": "exiftool",        "cat": "forensics","desc": "Read/write metadata in files (images, PDFs, etc.)"},
    "steghide":       {"bin": "steghide",        "cat": "forensics","desc": "Steganography — hide/extract data in images/audio"},
    "foremost":       {"bin": "foremost",        "cat": "forensics","desc": "File carving and recovery from disk images"},
    # ── Utility ──
    "interactsh":     {"bin": "interactsh-client","cat": "util",     "desc": "OOB interaction server for SSRF/XXE/blind testing"},
    "anew":           {"bin": "anew",            "cat": "util",     "desc": "Append lines to file only if they don't already exist"},
    "qsreplace":      {"bin": "qsreplace",       "cat": "util",     "desc": "Replace query string parameter values in URLs"},
    "uro":            {"bin": "uro",             "cat": "util",     "desc": "Deduplicate URLs by removing similar/useless ones"},
    "unfurl":         {"bin": "unfurl",          "cat": "util",     "desc": "Parse and extract components from URLs"},
    "jq":             {"bin": "jq",              "cat": "util",     "desc": "Command-line JSON processor"},
    "curl":           {"bin": "curl",            "cat": "util",     "desc": "Transfer data with URLs (HTTP, FTP, etc.)"},
}


def _check_installed(binary: str) -> bool:
    """Check if a binary is available on PATH."""
    return shutil.which(binary) is not None


def _get_toolbelt_status() -> str:
    """Return the full toolbelt with install status."""
    categories: dict[str, list[str]] = {}
    for name, info in sorted(TOOLBELT.items()):
        cat = info["cat"]
        if cat not in categories:
            categories[cat] = []
        installed = "Y" if _check_installed(info["bin"]) else "-"
        categories[cat].append(f"  [{installed}] {name:18s} {info['desc']}")

    lines = ["# BountyBud Toolbelt\n"]
    lines.append(f"[Y] = installed, [-] = not found on PATH\n")

    cat_order = ["recon", "network", "vuln", "cms", "osint", "cloud", "auth",
                 "proxy", "binary", "forensics", "util"]
    cat_names = {
        "recon": "Reconnaissance", "network": "Network", "vuln": "Vulnerability Scanning",
        "cms": "CMS", "osint": "OSINT", "cloud": "Cloud Security", "auth": "Auth & Cracking",
        "proxy": "Proxy & Interception", "binary": "Binary / RE", "forensics": "Forensics",
        "util": "Utility",
    }

    for cat in cat_order:
        if cat in categories:
            lines.append(f"\n## {cat_names.get(cat, cat)}\n")
            lines.extend(categories[cat])

    installed = sum(1 for t in TOOLBELT.values() if _check_installed(t["bin"]))
    lines.append(f"\n**{installed}/{len(TOOLBELT)} tools available**")
    lines.append("\nUse `search_knowledge` for detailed usage, parameters, and effectiveness scores.")
    lines.append("Use `execute_tool` to run any installed tool.")
    return "\n".join(lines)


def _run_command(command: str, timeout: int = 300, workdir: str | None = None) -> dict:
    """Execute a shell command locally and return results."""
    global _proc_counter
    with _proc_lock:
        _proc_counter += 1
        proc_id = f"proc_{_proc_counter}"

    cwd = workdir or os.getcwd()

    _processes[proc_id] = {
        "id": proc_id,
        "command": command,
        "status": "running",
        "started": time.time(),
        "pid": None,
    }

    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            preexec_fn=os.setsid if sys.platform != "win32" else None,
        )
        _processes[proc_id]["pid"] = proc.pid

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=5)
            _processes[proc_id]["status"] = "timeout"
            return {
                "id": proc_id,
                "exit_code": -1,
                "stdout": stdout.decode(errors="replace")[-10000:],
                "stderr": stderr.decode(errors="replace")[-5000:],
                "status": "timeout",
                "duration": round(time.time() - _processes[proc_id]["started"], 1),
            }

        _processes[proc_id]["status"] = "completed"
        return {
            "id": proc_id,
            "exit_code": proc.returncode,
            "stdout": stdout.decode(errors="replace")[-10000:],
            "stderr": stderr.decode(errors="replace")[-5000:],
            "status": "completed",
            "duration": round(time.time() - _processes[proc_id]["started"], 1),
        }

    except Exception as e:
        _processes[proc_id]["status"] = "error"
        return {"id": proc_id, "exit_code": -1, "stdout": "", "stderr": str(e), "status": "error", "duration": 0}

PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {"name": "BountyBud", "version": "1.0.0"}

CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"subscribe": False, "listChanged": False},
}

INSTRUCTIONS = (
    "BountyBud is a bug bounty and red teaming assistant with a 125-document knowledge base "
    "AND local tool execution. You can both research and act.\n\n"
    "WORKFLOW:\n"
    "1) get_toolbelt — see what's installed locally (call once at start)\n"
    "2) search_knowledge — find techniques, payloads, tool parameters, and methodology\n"
    "3) execute_tool — run security tools locally, informed by KB guidance\n"
    "4) search_cves / get_cve — live CVE intelligence from the NVD\n\n"
    "METHODOLOGY: Follow the 4-phase workflow: Discovery → Enumeration → Hunting → Exploitation.\n"
    "Use the vulnerability priority matrix (RCE > SQLi > SSRF > IDOR > XSS).\n"
    "Tool docs include effectiveness scores by target type, context-aware parameters, "
    "and fallback alternatives. Always validate findings with 5-Gate Verification before reporting."
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
    # ── Local Tool Execution ──
    {
        "name": "get_toolbelt",
        "description": (
            "List ALL available security tools with install status. Call this first to know "
            "what's available on the local machine. Returns tool names, categories, descriptions, "
            "and whether each is installed. Use search_knowledge for detailed parameters and "
            "effectiveness scores per tool."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "execute_tool",
        "description": (
            "Execute a security tool command on the local machine. Use search_knowledge first "
            "to find the right tool, parameters, and methodology for your target. Returns "
            "stdout, stderr, exit code, and duration. Commands run with a timeout (default 5 min). "
            "For long scans, increase the timeout."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The full shell command to execute (e.g., 'subfinder -d example.com -all -silent')",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max execution time in seconds (default 300, max 3600)",
                    "default": 300,
                },
                "workdir": {
                    "type": "string",
                    "description": "Working directory for the command (default: current directory)",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "list_processes",
        "description": "List running and recently completed tool processes with status and duration.",
        "inputSchema": {"type": "object", "properties": {}},
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

    elif name == "get_toolbelt":
        text = _get_toolbelt_status()
        return [{"type": "text", "text": text}]

    elif name == "execute_tool":
        command = arguments.get("command", "").strip()
        if not command:
            return [{"type": "text", "text": "A command is required."}]
        timeout = min(int(arguments.get("timeout", 300)), 3600)
        workdir = arguments.get("workdir")

        result = _run_command(command, timeout=timeout, workdir=workdir)

        parts = [f"**Command:** `{command}`"]
        parts.append(f"**Status:** {result['status']} | **Exit code:** {result['exit_code']} | **Duration:** {result['duration']}s")

        if result["stdout"]:
            stdout = result["stdout"]
            if len(stdout) > 8000:
                stdout = stdout[:4000] + "\n\n... [truncated] ...\n\n" + stdout[-4000:]
            parts.append(f"\n**stdout:**\n```\n{stdout}\n```")
        if result["stderr"]:
            stderr = result["stderr"]
            if len(stderr) > 4000:
                stderr = stderr[-4000:]
            parts.append(f"\n**stderr:**\n```\n{stderr}\n```")

        if not result["stdout"] and not result["stderr"]:
            parts.append("\n(no output)")

        return [{"type": "text", "text": "\n".join(parts)}]

    elif name == "list_processes":
        if not _processes:
            return [{"type": "text", "text": "No processes tracked yet."}]

        lines = ["**Tracked Processes:**\n"]
        for pid, info in sorted(_processes.items(), key=lambda x: x[1].get("started", 0), reverse=True):
            elapsed = round(time.time() - info.get("started", 0), 1)
            status = info.get("status", "unknown")
            cmd = info.get("command", "")[:80]
            lines.append(f"- **{pid}** [{status}] {elapsed}s — `{cmd}`")

        return [{"type": "text", "text": "\n".join(lines)}]

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
