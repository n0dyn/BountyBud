#!/usr/bin/env python3
"""BountyBud MCP Server — verification-driven bug bounty AI agent.

Local stdio bridge with tool execution, target profiling, finding verification,
primitive chaining, smart output parsing, and scope management.

Connects to the BountyBud REST API for knowledge base access and provides
local security tool execution with intelligent feedback loops.

Run with Claude Code:
  claude mcp add bountybud -- python3 /path/to/mcp_server.py

Environment variables:
  BOUNTYBUD_URL  — API base URL (default: https://bb.nxit.cc/api/kb)
  BOUNTYBUD_KEY  — API key for authentication
"""

import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from notifications import send_telegram_msg

API_BASE = os.getenv("BOUNTYBUD_URL", "https://bb.nxit.cc/api/kb").rstrip("/")
API_KEY = os.getenv("BOUNTYBUD_KEY", "")

# ── Mitmproxy Integration ─────────────────────────────────────
MITMPROXY_API = os.getenv("MITMPROXY_API", "http://localhost:8081")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))
_proxy_started = False

# Ensure common tool directories are on PATH
_extra_paths = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/.cargo/bin"),
    os.path.expanduser("~/.bountybud-tools/bin"),
]
_current_path = os.environ.get("PATH", "")
for _p in _extra_paths:
    if _p not in _current_path:
        _current_path = f"{_p}:{_current_path}"
os.environ["PATH"] = _current_path

# ── Persistent Data Directory ─────────────────────────────────
DATA_DIR = os.path.expanduser("~/.bountybud")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "primitives"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "findings"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "sessions"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "targets"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "huntlogs"), exist_ok=True)

# Learning database — single JSONL file that accumulates across all targets
LEARNING_DB = os.path.join(DATA_DIR, "learning.jsonl")

# ── KB Query Expansion ────────────────────────────────────────
# Security synonym map: maps common search terms to related KB terms.
# This bridges the gap between what hunters type and what docs contain.
# Each key is a trigger pattern; value is a list of additional search terms.
_SECURITY_SYNONYMS = {
    # Intent → technique mappings
    "steal cookie": ["xss", "session hijack", "cookie theft"],
    "cookie theft": ["xss", "session hijack", "cookie stealing"],
    "session hijack": ["xss", "cookie", "session fixation"],
    "bypass login": ["auth bypass", "authentication bypass", "default credentials"],
    "bypass auth": ["authentication bypass", "auth bypass", "session", "jwt"],
    "privilege escalation": ["privesc", "vertical privilege", "horizontal privilege"],
    "privesc": ["privilege escalation", "linux privesc", "windows privesc"],
    "remote code execution": ["rce", "command injection", "deserialization"],
    "rce": ["remote code execution", "command injection", "deserialization", "file upload"],
    "data exfiltration": ["data leak", "information disclosure", "exfil"],
    "steal data": ["data exfiltration", "information disclosure", "sqli"],
    "password": ["credential", "brute force", "default credentials", "auth bypass"],
    "credential": ["password", "api key", "secret", "token", "auth"],
    "redirect": ["open redirect", "url redirect", "ssrf"],
    "file inclusion": ["lfi", "rfi", "path traversal", "file read"],
    "lfi": ["local file inclusion", "path traversal", "file read", "directory traversal"],
    "upload": ["file upload", "unrestricted upload", "webshell"],
    "injection": ["sqli", "command injection", "ssti", "xss", "nosql injection"],
    "template injection": ["ssti", "server-side template injection", "jinja2", "twig"],
    "ssti": ["template injection", "server-side template injection", "jinja2"],
    "race condition": ["race", "toctou", "concurrent", "parallel requests"],
    "idor": ["insecure direct object reference", "bola", "broken object level authorization", "access control"],
    "bola": ["idor", "broken object level authorization", "access control"],
    "ssrf": ["server-side request forgery", "internal service", "metadata endpoint"],
    "cors": ["cross-origin", "origin reflection", "cors misconfiguration"],
    "csrf": ["cross-site request forgery", "state-changing", "anti-csrf"],
    "xxe": ["xml external entity", "xml injection", "dtd"],
    "smuggling": ["http request smuggling", "cl-te", "te-cl", "desync"],
    "cache poisoning": ["web cache", "cache key", "cache deception"],
    "prototype pollution": ["__proto__", "constructor pollution", "javascript prototype"],
    "subdomain takeover": ["dangling cname", "unclaimed subdomain"],
    "oauth": ["oauth bypass", "jwt", "saml", "token", "authorization code"],
    "jwt": ["json web token", "jwt bypass", "none algorithm", "key confusion"],
    "api": ["api security", "rest api", "graphql", "api endpoint"],
    "graphql": ["graphql introspection", "batching attack", "nested query"],
    "websocket": ["websocket attack", "ws hijack", "cross-site websocket"],
    "mass assignment": ["parameter binding", "auto-bind", "object injection"],
    "waf bypass": ["waf evasion", "encoding bypass", "filter bypass", "obfuscation"],
    "cloud": ["cloud misconfiguration", "s3 bucket", "azure blob", "metadata"],
    "deserialization": ["insecure deserialization", "pickle", "ysoserial", "unserialize"],
    "crlf": ["crlf injection", "header injection", "http response splitting"],
    "business logic": ["logic flaw", "workflow bypass", "price manipulation", "race condition"],
}

# Tech stack → relevant KB categories/tags for context-aware boosting
_TECH_KB_MAPPING = {
    "php": ["php", "lfi", "file-upload", "deserialization", "type-juggling"],
    "wordpress": ["wordpress", "wpscan", "php", "cms", "plugin"],
    "laravel": ["php", "laravel", "deserialization", "ssti", "mass-assignment"],
    "drupal": ["php", "drupal", "cms", "deserialization"],
    "node": ["javascript", "prototype-pollution", "ssrf", "xss", "npm"],
    "express": ["javascript", "express", "ssrf", "prototype-pollution"],
    "next": ["javascript", "next", "ssrf", "ssr", "react"],
    "react": ["javascript", "react", "dom-xss", "client-side"],
    "angular": ["javascript", "angular", "dom-xss", "csp", "template-injection"],
    "vue": ["javascript", "vue", "dom-xss", "client-side"],
    "python": ["python", "ssti", "pickle", "deserialization", "ssrf"],
    "django": ["python", "django", "ssti", "csrf", "mass-assignment"],
    "flask": ["python", "flask", "ssti", "jinja2", "debug"],
    "fastapi": ["python", "fastapi", "api", "ssrf"],
    "java": ["java", "deserialization", "jndi", "spring", "el-injection"],
    "spring": ["java", "spring", "actuator", "deserialization", "el-injection"],
    "tomcat": ["java", "tomcat", "manager", "deserialization"],
    "ruby": ["ruby", "rails", "ssti", "erb", "deserialization", "mass-assignment"],
    "rails": ["ruby", "rails", "mass-assignment", "ssti", "csrf"],
    "graphql": ["graphql", "introspection", "batching", "authorization"],
    "mongodb": ["nosql", "nosql-injection", "mongodb"],
    "mysql": ["sql", "sqli", "mysql"],
    "postgresql": ["sql", "sqli", "postgresql"],
    "nginx": ["nginx", "path-traversal", "alias-traversal", "off-by-slash"],
    "apache": ["apache", "htaccess", "mod-rewrite", "path-traversal"],
    "cloudflare": ["waf", "waf-bypass", "cloudflare", "origin-ip"],
    "aws": ["cloud", "aws", "s3", "metadata", "ssrf"],
    "azure": ["cloud", "azure", "blob", "metadata"],
    "gcp": ["cloud", "gcp", "metadata", "ssrf"],
    "docker": ["container", "docker", "escape", "mount"],
    "kubernetes": ["container", "kubernetes", "rbac", "service-account"],
}


def _expand_query(query: str) -> list[str]:
    """Expand a search query with security synonyms.
    Returns list of additional search terms to try."""
    query_lower = query.lower().strip()
    expansions = set()

    for trigger, synonyms in _SECURITY_SYNONYMS.items():
        if trigger in query_lower or query_lower in trigger:
            expansions.update(synonyms)

    # Also check individual words
    words = query_lower.split()
    for word in words:
        for trigger, synonyms in _SECURITY_SYNONYMS.items():
            if word == trigger or (len(word) > 3 and word in trigger):
                expansions.update(synonyms)

    # Remove terms already in the original query
    expansions -= set(words)
    return list(expansions)[:8]  # Cap at 8 expansion terms


def _tech_boost_tags(target: str) -> list[str]:
    """Get KB tags relevant to a target's tech stack for result boosting."""
    if not target:
        return []
    ctx = _load_target(target)
    if not ctx:
        return []

    boost_tags = set()
    techs = [t.lower() for t in ctx.get("technologies", [])]
    waf = ctx.get("waf", "").lower()

    for tech in techs:
        for key, tags in _TECH_KB_MAPPING.items():
            if key in tech or tech in key:
                boost_tags.update(tags)

    if waf:
        for key, tags in _TECH_KB_MAPPING.items():
            if key in waf:
                boost_tags.update(tags)

    return list(boost_tags)

# ── Local Tool Execution ───────────────────────────────────────

# Track running/completed processes
_processes: dict[str, dict] = {}
_proc_lock = threading.Lock()
_proc_counter = 0

# ── Target Context (in-memory + persisted) ─────────────────────
_target_contexts: dict[str, dict] = {}

# ── Active Engagement Session ──────────────────────────────────
_active_session: dict | None = None


# ── WAF / Error Signature Detection ───────────────────────────

WAF_SIGNATURES = {
    # Pattern → (WAF name, advice)
    r"cloudflare": ("Cloudflare", "Target is behind Cloudflare. Try: origin IP hunting (censys/shodan), header injection (X-Forwarded-For), or encoding payloads (double URL encode, unicode)."),
    r"akamai.*ghost": ("Akamai", "Akamai Ghost detected. Use slow, distributed requests. Try parameter pollution and chunk transfer encoding."),
    r"aws.*waf|awselb|x-amzn": ("AWS WAF/ALB", "AWS WAF detected. Try: unicode normalization bypass, case variation, chunked encoding. Check for API Gateway endpoints that may bypass WAF."),
    r"sucuri": ("Sucuri", "Sucuri WAF detected. Try: HPP (HTTP Parameter Pollution), multipart form encoding, null byte injection in parameters."),
    r"imperva|incapsula": ("Imperva/Incapsula", "Imperva detected. Rate limit your requests. Try encoding chains: URL encode → base64 → URL encode. Check for origin IP via DNS history."),
    r"f5.*big-?ip|bigipserver": ("F5 BIG-IP", "F5 BIG-IP detected. Check for TMUI (CVE-2020-5902 class). Try cookie decoding to reveal internal IPs."),
    r"mod_security|modsec": ("ModSecurity", "ModSecurity WAF rules active. Try: comment injection (/*!*/), alternative syntax, WAF rule bypass via content-type manipulation."),
    r"wordfence": ("Wordfence", "Wordfence (WordPress WAF). Rate limit and try parameter-based bypasses. Check for REST API endpoints not covered by Wordfence rules."),
    r"ddos-guard": ("DDoS-Guard", "DDoS-Guard detected. Requires browser-like headers (User-Agent, Accept, Referer). Try headless browser for initial cookie."),
    r"barracuda": ("Barracuda", "Barracuda WAF. Try chunked transfer encoding and multipart form manipulation."),
}

NEGATIVE_SIGNAL_PATTERNS = {
    # Pattern → advisory message
    r"403 forbidden": "BLOCKED: 403 Forbidden. This could be WAF, ACL, or auth-required. Try: different User-Agent, add cookies/tokens, check for path traversal bypass (/..;/path).",
    r"401 unauthorized": "AUTH REQUIRED: 401 response. You need valid credentials. Check for: default creds, token leakage in JS, OAuth misconfig, or try registration.",
    r"429 too many": "RATE LIMITED: 429 response. Slow down requests. Try: rotate User-Agent, add delays, use different IP, or target less-monitored endpoints.",
    r"connection refused|connection reset": "CONNECTION FAILED: Target refused/reset connection. Port may be filtered, service may be down, or IP may be blocked. Try from different source or check alternate ports.",
    r"ssl.*error|certificate.*error": "SSL ERROR: Certificate issue. Try: --insecure/-k flag, check for cert transparency logs, or use HTTP instead if testing allows.",
    r"captcha|recaptcha|hcaptcha|challenge": "CAPTCHA DETECTED: Automated testing blocked by CAPTCHA. Switch to manual testing with browser + proxy. Consider testing API endpoints directly which often skip CAPTCHA.",
    r"request blocked|access denied|security violation": "SECURITY BLOCK: Request actively blocked. Try: encoding payload, changing HTTP method, different content-type, or test from authorized session.",
    r"invalid.*token|token.*expired|jwt.*invalid": "TOKEN ISSUE: Auth token invalid/expired. Refresh the token, check for token rotation, or test for JWT vulnerabilities (none algorithm, key confusion).",
    r"not found.*api|api.*not found|no route": "API 404: Endpoint doesn't exist. Check for: API versioning (/v1/ vs /v2/), typos, alternative paths. Use JS analysis to find valid endpoints.",
    r"timeout|timed? ?out|deadline exceeded": "TIMEOUT: Request/command timed out. Reduce scope, target single host, or increase timeout. Consider if the target is performing heavy processing (potential DoS vector).",
}

POSITIVE_SIGNAL_PATTERNS = {
    # Patterns that indicate something interesting was found
    r"sql syntax|you have an error in your sql|mysql_|pg_query|sqlite3?\.": "POTENTIAL SQLi: SQL error message detected in response! Verify with time-based blind SQLi. This is HIGH PRIORITY.",
    r"stack trace|traceback|exception in thread|at .+\(.+\.java:\d+\)": "INFO LEAK: Stack trace detected. Extract technology versions, internal paths, class names. Check for debug mode.",
    r"root:x:0|/etc/passwd|/etc/shadow": "CRITICAL: /etc/passwd or shadow content in response! Verify LFI/RFI. Test for RCE escalation.",
    r"<script>alert|javascript:alert|onerror=|onload=": "POTENTIAL XSS: Script/event handler reflected. Verify execution in browser (use verify_finding with headless check).",
    r"internal server error|500 error": "500 ERROR: Server crashed. This might indicate: input validation failure, injection point, or deserialization issue. Try fuzzing this parameter.",
    r"phpinfo\(\)|server_software|document_root": "INFO LEAK: phpinfo() or server config exposed. Extract: PHP version, loaded modules, document root, temp dirs.",
    r"aws_access_key|AKIA[A-Z0-9]|sk-[a-zA-Z0-9]": "CRITICAL: Potential cloud credential or API key in output! Verify and check scope for secret exposure.",
    r"BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY": "CRITICAL: Private key exposed! Verify ownership and test for authentication.",
    r"mongodb://|postgres://|mysql://|redis://": "INFO LEAK: Database connection string found. Extract credentials, host, database name. Test for direct DB access.",
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+": "JWT TOKEN found in output. Decode it (base64), check claims, test for none algorithm and key confusion.",
}


def _analyze_output(stdout: str, stderr: str, command: str = "", target: str = "") -> list[str]:
    """Analyze tool output with full heuristic chain:
    1. Signal detection (WAF, errors, interesting findings)
    2. Context correlation (match against target profile)
    3. Learning integration (check historical outcomes for similar signals)
    4. Decision routing (recommend specific next action)
    """
    advisories = []
    combined = (stdout + " " + stderr).lower()
    raw = stdout + " " + stderr

    # ── Stage 1: Signal Detection ──
    detected_waf = None
    for pattern, (waf_name, advice) in WAF_SIGNATURES.items():
        if re.search(pattern, combined, re.IGNORECASE):
            detected_waf = waf_name
            advisories.append(f"⚠️ WAF DETECTED [{waf_name}]: {advice}")
            break

    negative_hits = []
    for pattern, advice in NEGATIVE_SIGNAL_PATTERNS.items():
        if re.search(pattern, combined, re.IGNORECASE):
            negative_hits.append(pattern)
            advisories.append(f"⚠️ {advice}")

    positive_hits = []
    for pattern, note in POSITIVE_SIGNAL_PATTERNS.items():
        if re.search(pattern, raw, re.IGNORECASE):
            positive_hits.append(pattern)
            advisories.append(f"🔥 {note}")

    # ── Stage 2: Context Correlation ──
    # If we have a target context, correlate findings against known tech stack
    ctx = _load_target(target) if target else {}
    if ctx:
        known_waf = ctx.get("waf", "")
        techs = [t.lower() for t in ctx.get("technologies", [])]

        # Auto-update target context if we detected a new WAF
        if detected_waf and not known_waf:
            ctx["waf"] = detected_waf
            _save_target(target, ctx)
            advisories.append(f"TARGET CONTEXT UPDATED: WAF set to {detected_waf}")

        # Tech-aware false positive filtering
        if positive_hits:
            # Don't flag PHP-specific patterns on non-PHP stacks
            if "phpinfo" in str(positive_hits) and not any(t in techs for t in ["php", "wordpress", "laravel"]):
                advisories = [a for a in advisories if "phpinfo" not in a]
                advisories.append("NOTE: phpinfo pattern matched but target is not PHP — likely false positive.")

    # ── Stage 3: Learning Integration ──
    # Check if we have historical data about this technique+context combo
    if command and target:
        all_learnings = _load_all_learnings()
        if all_learnings:
            # Extract tool name from command
            cmd_tool = command.split()[0].split("/")[-1] if command else ""

            # Find outcomes for same tool + same WAF
            relevant = [
                e for e in all_learnings
                if e.get("technique", "").startswith(cmd_tool)
                and (not detected_waf or e.get("waf", "").lower() == detected_waf.lower())
            ]

            if relevant:
                successes = sum(1 for e in relevant if e.get("outcome") == "success")
                blocked = sum(1 for e in relevant if e.get("outcome") == "blocked")
                total = len(relevant)

                if blocked > successes and total >= 3:
                    advisories.append(
                        f"LEARNING: {cmd_tool} has been blocked {blocked}/{total} times "
                        f"in similar contexts. Consider switching technique."
                    )
                    # Suggest bypasses that worked before
                    bypasses = [e.get("bypass_used") for e in relevant if e.get("bypass_used") and e.get("outcome") == "success"]
                    if bypasses:
                        advisories.append(f"KNOWN BYPASSES: {', '.join(set(bypasses))}")
                elif successes > 0:
                    best = [e.get("details") for e in relevant if e.get("outcome") == "success" and e.get("details")]
                    if best:
                        advisories.append(f"LEARNING: {cmd_tool} succeeded before in similar context: {best[0][:100]}")

    # ── Stage 4: Decision Routing ──
    if positive_hits and not negative_hits:
        # Found something interesting, no blockers
        advisories.append("NEXT: Verify this finding. Use verify_finding with a reproduction curl command.")
        advisories.append("NEXT: Store as primitive with store_primitive if not directly exploitable.")
    elif detected_waf and negative_hits:
        # Blocked by WAF
        advisories.append("DECISION: WAF is blocking. Three options:")
        advisories.append("  1. Try encoding bypass (double URL encode, unicode, chunked transfer)")
        advisories.append("  2. Hunt origin IP to bypass WAF entirely (use censys/shodan)")
        advisories.append("  3. Switch to business logic testing (WAF can't block logical flaws)")
    elif negative_hits and not positive_hits:
        # Something failed but not WAF-related
        if any("rate limit" in h for h in negative_hits):
            advisories.append("DECISION: Rate limited. Slow down and target different endpoints.")
        elif any("403" in h or "401" in h for h in negative_hits):
            advisories.append("DECISION: Auth/access blocked. Try: auth_bypass_test, or get valid session first.")
    elif not advisories:
        # Clean output, nothing detected
        # Check if the output is empty or minimal (tool might have failed silently)
        if len(stdout.strip()) < 10 and len(stderr.strip()) < 10:
            advisories.append("NOTE: Very little output. Tool may have failed silently. Check command syntax.")

    return advisories


# ── Pre-execution Heuristics ──────────────────────────────────

def _pre_execution_check(command: str, target: str = "") -> str | None:
    """Run heuristic checks BEFORE executing a command.
    Returns advisory string if there's a concern, None if clear to proceed."""
    cmd_parts = command.split()
    if not cmd_parts:
        return None

    cmd_tool = cmd_parts[0].split("/")[-1]

    # Check target context for tech-aware filtering
    ctx = _load_target(target) if target else {}
    techs = [t.lower() for t in ctx.get("technologies", [])]
    waf = ctx.get("waf", "").lower()

    advisories = []

    # ── Scope check ──
    if ctx.get("out_of_scope"):
        for oos in ctx["out_of_scope"]:
            if oos.lower() in command.lower():
                return f"BLOCKED: '{oos}' is OUT OF SCOPE for this target. Remove it from your command."

    # ── Tech-stack mismatch detection ──
    if techs:
        # PHP tools on non-PHP targets
        if cmd_tool in ("wpscan", "droopescan", "joomscan") and not any(t in techs for t in ["php", "wordpress", "drupal", "joomla"]):
            advisories.append(f"MISMATCH: {cmd_tool} is a CMS scanner but target stack is {', '.join(ctx.get('technologies', []))}. This is likely a waste of time.")

        # NoSQL tools on SQL targets
        if cmd_tool == "nosqlmap" and any(t in techs for t in ["mysql", "postgresql", "mssql"]):
            advisories.append(f"MISMATCH: nosqlmap targets NoSQL but this target uses {', '.join(t for t in techs if t in ('mysql', 'postgresql', 'mssql'))}. Use sqlmap instead.")

        # SQL tools on NoSQL targets
        if cmd_tool in ("sqlmap", "ghauri") and any(t in techs for t in ["mongodb", "dynamodb", "couchdb"]):
            advisories.append(f"MISMATCH: {cmd_tool} targets SQL but this target uses NoSQL ({', '.join(t for t in techs if t in ('mongodb', 'dynamodb', 'couchdb'))}). Use nosqlmap instead.")

    # ── WAF-aware scanning ──
    if waf and waf != "none":
        # Broad scans against WAF-protected targets are usually pointless
        if cmd_tool == "nuclei" and "-tags" not in command and "-t " not in command:
            advisories.append(f"WARNING: Running nuclei without -tags against WAF-protected target ({waf}). Most templates will be blocked. Use -tags to target specific vuln classes.")

        if cmd_tool in ("sqlmap", "ghauri") and "--tamper" not in command:
            advisories.append(f"WARNING: Running {cmd_tool} against {waf} without --tamper. Payloads will likely be blocked. Add --tamper=between,randomcase,space2comment or try manual testing.")

        if cmd_tool == "dalfox" and "--waf-evasion" not in command.lower():
            advisories.append(f"WARNING: Running dalfox against {waf} without evasion. Consider manual XSS testing or encoding payloads.")

    # ── Scope explosion detection ──
    if cmd_tool in ("gau", "waybackurls", "katana", "gospider") and "--subs" in command:
        advisories.append("SCOPE WARNING: Using --subs will crawl ALL subdomains. This will likely timeout or produce too much output. Remove --subs and target specific domains.")

    if cmd_tool == "nuclei" and "-l " in command:
        # Check if the list might be too big
        advisories.append("TIP: If the target list is large, use -rl (rate limit) and -tags to narrow scope.")

    # ── Historical failure check ──
    if target:
        all_learnings = _load_all_learnings()
        if all_learnings:
            same_tool = [e for e in all_learnings if e.get("technique", "").startswith(cmd_tool) and e.get("target") == target]
            if same_tool:
                last = sorted(same_tool, key=lambda e: e.get("timestamp", ""))[-1]
                if last.get("outcome") == "blocked":
                    advisories.append(
                        f"HISTORY: {cmd_tool} was blocked on this exact target last time"
                        f" ({last.get('timestamp', '')[:10]}). "
                        f"Consider a different approach or add bypass technique."
                    )
                elif last.get("outcome") == "success":
                    advisories.append(
                        f"HISTORY: {cmd_tool} succeeded on this target before: {last.get('details', '')[:80]}"
                    )

    return "\n".join(advisories) if advisories else None


# Complete toolbelt — every security tool BountyBud knows about
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
    "exiftool":       {"bin": "exiftool",        "cat": "forensics", "desc": "Read/write metadata in files (images, PDFs, etc.)"},
    "steghide":       {"bin": "steghide",        "cat": "forensics", "desc": "Steganography — hide/extract data in images/audio"},
    "foremost":       {"bin": "foremost",        "cat": "forensics", "desc": "File carving and recovery from disk images"},
    # ── Exploitation Frameworks ──
    "msfconsole":     {"bin": "msfconsole",      "cat": "exploit",  "desc": "Metasploit Framework console — exploit, payload, and post modules"},
    "msfvenom":       {"bin": "msfvenom",        "cat": "exploit",  "desc": "Metasploit payload generator (shellcode, exe, scripts)"},
    "msfrpcd":        {"bin": "msfrpcd",         "cat": "exploit",  "desc": "Metasploit RPC daemon for remote/scripted access"},
    # ── Utility ──
    "interactsh":     {"bin": "interactsh-client", "cat": "util",    "desc": "OOB interaction server for SSRF/XXE/blind testing"},
    "anew":           {"bin": "anew",            "cat": "util",     "desc": "Append lines to file only if they don't already exist"},
    "qsreplace":      {"bin": "qsreplace",       "cat": "util",     "desc": "Replace query string parameter values in URLs"},
    "uro":            {"bin": "uro",             "cat": "util",     "desc": "Deduplicate URLs by removing similar/useless ones"},
    "unfurl":         {"bin": "unfurl",          "cat": "util",     "desc": "Parse and extract components from URLs"},
    "jq":             {"bin": "jq",              "cat": "util",     "desc": "Command-line JSON processor"},
    "curl":           {"bin": "curl",            "cat": "util",     "desc": "Transfer data with URLs (HTTP, FTP, etc.)"},
}


def _check_installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def _get_toolbelt_status() -> str:
    """Compact toolbelt status — shows installed tools grouped by category."""
    cat_order = ["recon", "network", "vuln", "exploit", "cms", "osint", "cloud",
                 "auth", "proxy", "binary", "forensics", "util"]
    cat_names = {
        "recon": "Recon", "network": "Network", "vuln": "Vuln Scan",
        "exploit": "Exploit", "cms": "CMS", "osint": "OSINT",
        "cloud": "Cloud", "auth": "Auth/Crack",
        "proxy": "Proxy", "binary": "Binary", "forensics": "Forensics",
        "util": "Utility",
    }

    installed_by_cat: dict[str, list[str]] = {}
    missing_by_cat: dict[str, list[str]] = {}
    total_installed = 0

    for name, info in sorted(TOOLBELT.items()):
        cat = info["cat"]
        if _check_installed(info["bin"]):
            installed_by_cat.setdefault(cat, []).append(name)
            total_installed += 1
        else:
            missing_by_cat.setdefault(cat, []).append(name)

    lines = [f"**{total_installed}/{len(TOOLBELT)} tools installed**\n"]

    for cat in cat_order:
        installed = installed_by_cat.get(cat, [])
        missing = missing_by_cat.get(cat, [])
        if installed or missing:
            inst_str = ", ".join(installed) if installed else "none"
            line = f"**{cat_names.get(cat, cat)}:** {inst_str}"
            if missing:
                line += f" | missing: {', '.join(missing)}"
            lines.append(line)

    lines.append("\nRun tools with `execute_tool`. Use `search_knowledge` for technique details.")
    lines.append("Load more tools: `get_tools('proxy')` for interception, `get_tools('hunting')` for findings/chains.")
    return "\n".join(lines)


def _run_command(command: str, timeout: int = 300, workdir: str | None = None, background: bool = False) -> dict:
    """Execute a shell command locally with smart output analysis."""
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

        if background:
            return {
                "id": proc_id,
                "status": "background",
                "message": f"Command started in background. Use check_proc {proc_id} to see progress.",
                "duration": 0,
            }

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if sys.platform != "win32":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.kill()
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
        return {
            "id": proc_id,
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "status": "error",
            "duration": round(time.time() - _processes[proc_id]["started"], 1),
        }


# ── Target Context Management ─────────────────────────────────

def _target_file(target: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', target)
    return os.path.join(DATA_DIR, "targets", f"{safe}.json")


def _load_target(target: str) -> dict:
    if target in _target_contexts:
        return _target_contexts[target]
    fpath = _target_file(target)
    if os.path.exists(fpath):
        with open(fpath) as f:
            ctx = json.load(f)
        _target_contexts[target] = ctx
        return ctx
    return {}


def _save_target(target: str, ctx: dict):
    _target_contexts[target] = ctx
    fpath = _target_file(target)
    with open(fpath, "w") as f:
        json.dump(ctx, f, indent=2, default=str)


# ── Primitive / Finding Storage ────────────────────────────────

def _primitives_file(target: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', target)
    return os.path.join(DATA_DIR, "primitives", f"{safe}.json")


def _load_primitives(target: str) -> list[dict]:
    fpath = _primitives_file(target)
    if os.path.exists(fpath):
        with open(fpath) as f:
            return json.load(f)
    return []


def _save_primitives(target: str, primitives: list[dict]):
    fpath = _primitives_file(target)
    with open(fpath, "w") as f:
        json.dump(primitives, f, indent=2, default=str)


def _findings_file(target: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', target)
    return os.path.join(DATA_DIR, "findings", f"{safe}.json")


def _load_findings(target: str) -> list[dict]:
    fpath = _findings_file(target)
    if os.path.exists(fpath):
        with open(fpath) as f:
            return json.load(f)
    return []


def _save_findings(target: str, findings: list[dict]):
    fpath = _findings_file(target)
    with open(fpath, "w") as f:
        json.dump(findings, f, indent=2, default=str)


# ── Hunt Log (survives context compression) ───────────────────

def _huntlog_file(target: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', target)
    return os.path.join(DATA_DIR, "huntlogs", f"{safe}.jsonl")


def _append_huntlog(target: str, entry: dict):
    entry["timestamp"] = datetime.datetime.now().isoformat()
    fpath = _huntlog_file(target)
    with open(fpath, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def _read_huntlog(target: str, last_n: int = 50) -> list[dict]:
    fpath = _huntlog_file(target)
    if not os.path.exists(fpath):
        return []
    with open(fpath) as f:
        lines = f.readlines()
    entries = []
    for line in lines[-(last_n):]:
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def _format_huntlog(entries: list[dict]) -> str:
    """Format hunt log entries into a readable state reconstruction."""
    if not entries:
        return "No hunt log entries."

    lines = []
    # Group by phase for clearer reconstruction
    current_phase = None
    for e in entries:
        phase = e.get("phase", "")
        if phase and phase != current_phase:
            current_phase = phase
            lines.append(f"\n## Phase: {phase}")

        entry_type = e.get("type", "note")
        ts = e.get("timestamp", "")[:16]
        msg = e.get("message", "")

        if entry_type == "status":
            lines.append(f"[{ts}] **STATUS:** {msg}")
        elif entry_type == "finding":
            sev = e.get("severity", "?")
            lines.append(f"[{ts}] **FINDING [{sev.upper()}]:** {msg}")
        elif entry_type == "tested":
            result = e.get("result", "")
            lines.append(f"[{ts}] TESTED: {msg} → {result}")
        elif entry_type == "todo":
            lines.append(f"[{ts}] TODO: {msg}")
        elif entry_type == "blocked":
            lines.append(f"[{ts}] BLOCKED: {msg}")
        elif entry_type == "plan":
            lines.append(f"[{ts}] **PLAN:** {msg}")
        else:
            lines.append(f"[{ts}] {msg}")

        # Include data if present
        data = e.get("data")
        if data and isinstance(data, dict):
            for k, v in data.items():
                lines.append(f"  {k}: {v}")

    return "\n".join(lines)


# ── Learning Engine ───────────────────────────────────────────

def _record_learning(entry: dict):
    """Append a learning outcome to the database."""
    entry["timestamp"] = datetime.datetime.now().isoformat()
    with open(LEARNING_DB, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def _load_all_learnings() -> list[dict]:
    """Load all learning outcomes."""
    if not os.path.exists(LEARNING_DB):
        return []
    entries = []
    with open(LEARNING_DB) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def _temporal_decay(timestamp_str: str, half_life_days: float = 30.0) -> float:
    """Calculate temporal decay weight. Recent outcomes matter more."""
    try:
        ts = datetime.datetime.fromisoformat(timestamp_str)
        age_days = (datetime.datetime.now() - ts).total_seconds() / 86400
        import math
        return math.pow(0.5, age_days / half_life_days)
    except (ValueError, TypeError):
        return 0.5  # Unknown age gets medium weight


def _confidence_score(successes: int, total: int) -> tuple[float, str]:
    """Wilson score interval lower bound — better than raw percentage for small samples.
    Returns (score, confidence_level)."""
    if total == 0:
        return (0.0, "none")
    import math
    z = 1.96  # 95% confidence
    p = successes / total
    denominator = 1 + z * z / total
    centre = p + z * z / (2 * total)
    spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)
    lower_bound = (centre - spread) / denominator

    if total >= 20:
        level = "high"
    elif total >= 5:
        level = "medium"
    else:
        level = "low"

    return (max(0, lower_bound), level)


def _detect_cross_target_patterns(all_data: list[dict]) -> list[dict]:
    """Detect patterns that recur across multiple targets."""
    from collections import defaultdict
    patterns = []

    # Group by (vuln_type, target_type) to find recurring vuln classes
    vuln_by_target_type = defaultdict(lambda: {"targets": set(), "successes": 0, "total": 0})
    for entry in all_data:
        vuln = entry.get("vuln_type", "")
        ttype = entry.get("target_type", "")
        target = entry.get("target", "")
        if vuln and ttype:
            key = (vuln, ttype)
            vuln_by_target_type[key]["total"] += 1
            if target:
                vuln_by_target_type[key]["targets"].add(target)
            if entry.get("outcome") == "success":
                vuln_by_target_type[key]["successes"] += 1

    for (vuln, ttype), stats in vuln_by_target_type.items():
        if len(stats["targets"]) >= 2 and stats["successes"] >= 2:
            rate = stats["successes"] / stats["total"]
            patterns.append({
                "type": "recurring_vuln",
                "vuln_type": vuln,
                "target_type": ttype,
                "targets_affected": len(stats["targets"]),
                "success_rate": rate,
                "total_tests": stats["total"],
                "insight": f"{vuln} found on {len(stats['targets'])} different {ttype} targets ({rate:.0%} success rate)",
            })

    # Group by (technique, waf) to find WAF-specific effectiveness
    tech_by_waf = defaultdict(lambda: {"successes": 0, "blocked": 0, "total": 0, "bypasses": []})
    for entry in all_data:
        technique = entry.get("technique", "")
        waf = entry.get("waf", "")
        if technique and waf and waf.lower() != "none":
            key = (technique, waf)
            tech_by_waf[key]["total"] += 1
            if entry.get("outcome") == "success":
                tech_by_waf[key]["successes"] += 1
                if entry.get("bypass_used"):
                    tech_by_waf[key]["bypasses"].append(entry["bypass_used"])
            elif entry.get("outcome") == "blocked":
                tech_by_waf[key]["blocked"] += 1

    for (technique, waf), stats in tech_by_waf.items():
        if stats["total"] >= 3 and stats["blocked"] >= 2:
            patterns.append({
                "type": "waf_blocker",
                "technique": technique,
                "waf": waf,
                "block_rate": stats["blocked"] / stats["total"],
                "insight": f"{technique} blocked {stats['blocked']}/{stats['total']} times by {waf}",
                "bypasses": stats["bypasses"],
            })
        elif stats["total"] >= 2 and stats["successes"] >= 2:
            patterns.append({
                "type": "waf_effective",
                "technique": technique,
                "waf": waf,
                "success_rate": stats["successes"] / stats["total"],
                "insight": f"{technique} works against {waf} ({stats['successes']}/{stats['total']})",
                "bypasses": stats["bypasses"],
            })

    # Detect technique evolution (same technique improving or degrading over time)
    tech_timeline = defaultdict(list)
    for entry in all_data:
        technique = entry.get("technique", "")
        if technique:
            tech_timeline[technique].append(entry)

    for technique, entries in tech_timeline.items():
        if len(entries) >= 4:
            # Split into halves and compare success rates
            sorted_entries = sorted(entries, key=lambda e: e.get("timestamp", ""))
            mid = len(sorted_entries) // 2
            early = sorted_entries[:mid]
            recent = sorted_entries[mid:]
            early_rate = sum(1 for e in early if e.get("outcome") == "success") / len(early) if early else 0
            recent_rate = sum(1 for e in recent if e.get("outcome") == "success") / len(recent) if recent else 0
            delta = recent_rate - early_rate

            if abs(delta) >= 0.25:  # Significant change
                direction = "improving" if delta > 0 else "degrading"
                patterns.append({
                    "type": "trend",
                    "technique": technique,
                    "direction": direction,
                    "early_rate": early_rate,
                    "recent_rate": recent_rate,
                    "insight": f"{technique} is {direction}: {early_rate:.0%} early → {recent_rate:.0%} recent",
                })

    return sorted(patterns, key=lambda p: p.get("targets_affected", 0) + p.get("success_rate", 0), reverse=True)


def _generate_playbook(tech_stack: list[str], waf: str = "", target_type: str = "") -> str:
    """Generate an advanced adaptive playbook with temporal decay, confidence scoring, and pattern detection."""
    all_data = _load_all_learnings()

    if not all_data:
        return (
            "No learning data yet. BountyBud learns from outcomes you record with `record_outcome`.\n"
            "After a few hunts, this will return personalized recommendations ranked by success rate.\n\n"
            "**Bootstrap recommendations for this context:**\n"
            + _bootstrap_recommendations(tech_stack, waf, target_type)
        )

    tech_lower = set(t.lower() for t in tech_stack)
    waf_lower = waf.lower() if waf else ""

    # Score relevance with temporal decay
    technique_stats: dict[str, dict] = {}
    waf_bypass_stats: dict[str, list[tuple[str, float]]] = {}

    for entry in all_data:
        decay = _temporal_decay(entry.get("timestamp", ""))
        entry_techs = set(t.lower() for t in entry.get("tech_stack", []))
        entry_waf = entry.get("waf", "").lower()
        entry_type = entry.get("target_type", "").lower()

        # Contextual relevance score
        relevance = 1.0  # Base relevance
        overlap = tech_lower & entry_techs
        relevance += len(overlap) * 2.0
        if waf_lower and entry_waf and waf_lower in entry_waf:
            relevance += 3.0
        if target_type and entry_type and target_type.lower() == entry_type:
            relevance += 1.5

        # Combined weight = relevance * recency
        weight = relevance * decay

        technique = entry.get("technique", "unknown")
        outcome = entry.get("outcome", "unknown")
        vuln_type = entry.get("vuln_type", "")
        key = f"{technique}:{vuln_type}" if vuln_type else technique

        if key not in technique_stats:
            technique_stats[key] = {
                "technique": technique, "vuln_type": vuln_type,
                "weighted_success": 0, "weighted_total": 0,
                "raw_success": 0, "raw_fail": 0, "raw_blocked": 0, "raw_partial": 0, "raw_total": 0,
                "max_relevance": 0, "details": [], "recent_outcomes": [],
            }

        stats = technique_stats[key]
        stats["weighted_total"] += weight
        stats["raw_total"] += 1
        stats["max_relevance"] = max(stats["max_relevance"], relevance)

        if outcome == "success":
            stats["weighted_success"] += weight
            stats["raw_success"] += 1
            detail = entry.get("details", "")
            if detail:
                stats["details"].append(detail[:120])
        elif outcome == "blocked":
            stats["raw_blocked"] += 1
        elif outcome == "partial":
            stats["raw_partial"] += 1
        else:
            stats["raw_fail"] += 1

        # Track last 5 outcomes for trend display
        stats["recent_outcomes"].append(outcome[0].upper())
        stats["recent_outcomes"] = stats["recent_outcomes"][-5:]

        # Track WAF bypasses with recency weight
        if outcome == "success" and entry.get("bypass_used") and entry.get("waf"):
            waf_name = entry["waf"]
            if waf_name not in waf_bypass_stats:
                waf_bypass_stats[waf_name] = []
            waf_bypass_stats[waf_name].append((entry["bypass_used"], decay))

    # Rank by weighted success rate with confidence
    ranked = []
    for key, stats in technique_stats.items():
        w_total = stats["weighted_total"]
        w_success = stats["weighted_success"]
        w_rate = w_success / w_total if w_total > 0 else 0

        # Wilson confidence on raw counts
        conf_score, conf_level = _confidence_score(stats["raw_success"], stats["raw_total"])

        # Final score: weighted_rate * confidence * relevance
        final_score = w_rate * (0.5 + conf_score) * min(stats["max_relevance"], 10)

        ranked.append((final_score, w_rate, conf_score, conf_level, stats))

    ranked.sort(key=lambda x: x[0], reverse=True)

    # Cross-target pattern detection
    patterns = _detect_cross_target_patterns(all_data)

    # Build playbook
    lines = [f"# Adaptive Playbook\n"]
    lines.append(f"**Context:** tech={', '.join(tech_stack) or 'any'}, waf={waf or 'unknown'}, type={target_type or 'any'}")
    lines.append(f"**Learning base:** {len(all_data)} outcomes across {len(set(e.get('target','') for e in all_data if e.get('target')))} targets\n")

    # Cross-target patterns first (highest value intel)
    if patterns:
        lines.append("## Cross-Target Intelligence\n")
        for p in patterns[:6]:
            if p["type"] == "recurring_vuln":
                lines.append(f"  PATTERN: {p['insight']}")
            elif p["type"] == "waf_blocker":
                lines.append(f"  AVOID: {p['insight']}")
                if p.get("bypasses"):
                    lines.append(f"    Bypasses that worked: {', '.join(set(p['bypasses']))}")
            elif p["type"] == "waf_effective":
                lines.append(f"  WORKS: {p['insight']}")
            elif p["type"] == "trend":
                icon = "^" if p["direction"] == "improving" else "v"
                lines.append(f"  TREND {icon}: {p['insight']}")
        lines.append("")

    # Top recommendations with confidence
    lines.append("## Recommended Techniques\n")
    conf_icons = {"high": "***", "medium": "**", "low": "*", "none": ""}

    for i, (fscore, wrate, cscore, clevel, stats) in enumerate(ranked[:15], 1):
        technique = stats["technique"]
        vuln = stats["vuln_type"]
        total = stats["raw_total"]
        success = stats["raw_success"]
        trend = "".join(stats["recent_outcomes"][-5:])

        label = f"{technique}" + (f" ({vuln})" if vuln else "")
        conf_star = conf_icons.get(clevel, "")
        lines.append(
            f"  {i:2d}. {conf_star}**{label}**{conf_star} — "
            f"{success}/{total} ({wrate:.0%} weighted) "
            f"confidence={clevel} trend=[{trend}]"
        )

        if stats["details"]:
            for d in stats["details"][:2]:
                lines.append(f"      Worked: {d}")

    # WAF bypass intelligence with recency
    if waf_lower and waf_bypass_stats:
        lines.append(f"\n## WAF Bypass Intelligence\n")
        for waf_name, bypass_list in waf_bypass_stats.items():
            if waf_lower in waf_name.lower():
                lines.append(f"**{waf_name}** — bypasses (sorted by recency):")
                from collections import Counter
                # Weight by recency
                weighted_bypasses: dict[str, float] = {}
                for bypass, decay_w in bypass_list:
                    weighted_bypasses[bypass] = weighted_bypasses.get(bypass, 0) + decay_w
                for bypass, score in sorted(weighted_bypasses.items(), key=lambda x: x[1], reverse=True)[:7]:
                    count = sum(1 for b, _ in bypass_list if b == bypass)
                    lines.append(f"  - {bypass} ({count}x, recency_score={score:.2f})")

    # Anti-patterns
    lines.append("\n## Anti-Patterns (avoid these)\n")
    anti = [(wrate, stats) for _, wrate, _, _, stats in ranked if stats["raw_total"] >= 2 and wrate < 0.15]
    anti.sort(key=lambda x: x[0])
    if anti:
        for wrate, stats in anti[:5]:
            label = f"{stats['technique']}" + (f" ({stats['vuln_type']})" if stats['vuln_type'] else "")
            lines.append(f"  - **{label}** — {stats['raw_success']}/{stats['raw_total']} ({wrate:.0%}) — low ROI in this context")
    else:
        lines.append("  (not enough data yet)")

    # Knowledge gaps
    lines.append("\n## Knowledge Gaps\n")
    common_techniques = {
        "idor_test", "cors_test", "auth_bypass", "sqli", "xss_reflected",
        "xss_stored", "ssrf", "ssti", "lfi", "xxe", "race_condition",
        "mass_assignment", "workflow_bypass", "price_manipulation",
        "jwt_attack", "graphql_introspection", "subdomain_takeover",
        "open_redirect", "header_injection", "cache_poisoning",
    }
    tested = {stats["technique"] for _, _, _, _, stats in ranked}
    untested = common_techniques - tested
    if untested:
        lines.append("Never tested (consider trying):")
        for t in sorted(untested):
            lines.append(f"  - {t}")

    # Adaptive strategy suggestion
    lines.append("\n## Adaptive Strategy\n")
    if waf_lower:
        blocked_count = sum(s["raw_blocked"] for _, _, _, _, s in ranked)
        total_count = sum(s["raw_total"] for _, _, _, _, s in ranked)
        if total_count and blocked_count / total_count > 0.3:
            lines.append(f"HIGH BLOCK RATE ({blocked_count}/{total_count}). Recommendations:")
            lines.append("  1. Hunt for origin IP to bypass WAF entirely")
            lines.append("  2. Focus on business logic bugs (WAF can't block logical flaws)")
            lines.append("  3. Test API endpoints which often have different WAF rules")
            lines.append("  4. Use the working bypasses listed above")

    top_success = [(wrate, stats) for _, wrate, _, _, stats in ranked if wrate > 0.5 and stats["raw_total"] >= 2]
    if top_success:
        lines.append(f"\nHIGH-VALUE FOCUS: These techniques work well on this context:")
        for wrate, stats in top_success[:3]:
            lines.append(f"  - {stats['technique']} ({wrate:.0%}) — double down on this")

    return "\n".join(lines)


def _bootstrap_recommendations(tech_stack: list[str], waf: str, target_type: str) -> str:
    """Provide default recommendations when no learning data exists yet."""
    lines = []
    tech_lower = [t.lower() for t in tech_stack]

    if target_type in ("saas", "web_app"):
        lines.append("- IDOR testing on all endpoints with IDs (highest ROI for SaaS)")
        lines.append("- CORS misconfiguration on API endpoints")
        lines.append("- Auth bypass (method switch, header mangle)")
        lines.append("- Business logic: workflow bypass, price manipulation")
    elif target_type == "api":
        lines.append("- BFLA: access admin endpoints with regular user token")
        lines.append("- Mass assignment: add extra fields to POST/PUT requests")
        lines.append("- Rate limiting: race conditions on stateful operations")
        lines.append("- GraphQL introspection and batching attacks")
    elif target_type == "ecommerce":
        lines.append("- Price manipulation in checkout flow")
        lines.append("- Coupon race conditions (concurrent redemption)")
        lines.append("- IDOR on order/invoice endpoints")
        lines.append("- Workflow bypass: skip payment step")

    if any(t in tech_lower for t in ["react", "angular", "vue", "next"]):
        lines.append("- DOM XSS in client-side routing")
        lines.append("- Hidden API endpoints in JavaScript bundles")
    if any(t in tech_lower for t in ["express", "node", "fastify"]):
        lines.append("- Prototype pollution")
        lines.append("- SSRF in server-side rendering")
    if any(t in tech_lower for t in ["graphql"]):
        lines.append("- Introspection query for full schema")
        lines.append("- Nested query DoS")
        lines.append("- Batching attacks to bypass rate limits")
    if waf:
        lines.append(f"- WAF ({waf}): start with business logic bugs that WAF can't block")
        lines.append(f"- Search for origin IP via DNS history, censys, or shodan")

    if not lines:
        lines.append("- Start with fingerprinting, then IDOR + auth bypass + CORS")
        lines.append("- Record outcomes with record_outcome to build the learning database")

    return "\n".join(lines)


# ── Finding Intelligence — False Positive / True Positive Heuristics ──

# Known false positive patterns per vuln type.
# Each entry: (pattern_in_response, reason_its_FP, deduction_points)
# Finding starts at 100 confidence. Each FP match deducts points.
# Below 40 = likely false positive. Above 70 = likely real.
FALSE_POSITIVE_PATTERNS = {
    "xss": [
        (r"content-security-policy.*script-src", "CSP blocks inline scripts — XSS likely mitigated even if reflected", 40),
        (r"content-security-policy.*default-src\s+'none'", "Strict CSP (default-src 'none') — XSS extremely unlikely to execute", 50),
        (r"x-xss-protection:\s*1;\s*mode=block", "X-XSS-Protection header may block reflected XSS in older browsers", 10),
        (r"<!--.*(<script|onerror|onload).*-->", "Payload reflected inside HTML comment — not executable", 45),
        (r"<input[^>]*value=['\"].*(<script|onerror)", "Payload in input value attribute — may be encoded on render", 15),
        (r"\\u003c|\\u003e|&lt;|&gt;", "Payload is HTML/unicode encoded in response — not executable as-is", 35),
        (r"%3c|%3e|%22", "Payload URL-encoded in response — browser won't interpret as HTML", 30),
    ],
    "sqli": [
        (r"(custom|friendly|generic)\s*(error|page|message)", "Generic/custom error page — SQL error text may be hardcoded, not dynamic", 35),
        (r"<title>.*(404|not found|error).*</title>", "SQL-like error on a 404/error page — likely static error template", 40),
        (r"(example|sample|documentation|placeholder).*sql", "SQL keyword in docs/example content, not actual error", 45),
        (r"no results|0 results|nothing found", "Empty results ≠ SQL injection — query may just have no matches", 30),
    ],
    "ssrf": [
        (r"(timeout|timed out|connection refused)", "Target couldn't reach internal host — confirms filtering, not SSRF", 25),
        (r"(invalid url|malformed|bad request).*4[0-9]{2}", "Input validation caught the SSRF attempt", 35),
        (r"(localhost|127\.0\.0\.1|0\.0\.0\.0).*blocked", "SSRF protection is actively blocking internal IPs", 40),
    ],
    "idor": [
        (r'"id":\s*\d+.*"id":\s*\d+', "Multiple IDs in response — may be a list/index endpoint, not IDOR", 15),
        (r"(public|shared|published)", "Resource may be intentionally public/shared — not access control failure", 20),
    ],
    "lfi": [
        (r"(open_basedir|allow_url_include\s*=\s*off)", "PHP restrictions active — LFI likely mitigated", 30),
        (r"(no such file|file not found|cannot open)", "File doesn't exist — path traversal blocked or path wrong", 25),
    ],
    "open_redirect": [
        (r"(warning|redirect).*leaving", "Interstitial warning page before redirect — intentional UX, not vuln", 40),
        (r"(allowlist|whitelist|allowed_domains)", "Redirect uses domain allowlist — likely properly validated", 45),
    ],
    "info_disclosure": [
        (r"(example\.com|test@test|john\.doe|jane@)", "Dummy/placeholder data, not real PII", 50),
        (r"(documentation|api-docs|swagger)", "Info is in public API documentation — intentionally exposed", 40),
    ],
}

# Evidence quality tiers — how strong is the proof?
EVIDENCE_QUALITY = {
    "xss": {
        "definitive": [  # Auto-verified, report immediately
            "alert fired in headless browser",
            "javascript executed in DOM",
            "cookie exfiltrated to external server",
        ],
        "strong": [  # Very likely real, verify in browser
            "payload rendered unencoded in HTML body",
            "payload in script context without encoding",
            "event handler attribute injected and rendered",
        ],
        "weak": [  # Might be FP, needs more investigation
            "payload reflected in response body",
            "payload in HTML attribute value",
            "payload in JSON response",
        ],
        "insufficient": [  # Almost certainly FP
            "payload reflected but encoded",
            "payload in HTML comment",
            "payload in non-rendered context",
        ],
    },
    "sqli": {
        "definitive": [
            "UNION SELECT returned extra data from DB",
            "time-based blind confirmed with measurable delay",
            "database version/name extracted",
            "data exfiltrated from non-public table",
        ],
        "strong": [
            "SQL error with table/column names",
            "different response for true/false boolean conditions",
            "error contains database-specific syntax",
        ],
        "weak": [
            "generic SQL error message",
            "response size difference with quotes",
            "500 error on special characters",
        ],
        "insufficient": [
            "error page mentions SQL",
            "WAF block message on SQL keywords",
            "generic 500 error",
        ],
    },
    "ssrf": {
        "definitive": [
            "received callback on attacker-controlled server",
            "internal service response returned to client",
            "cloud metadata (169.254.169.254) content returned",
        ],
        "strong": [
            "different response time for internal vs external IPs",
            "error message reveals internal hostname/IP",
            "DNS lookup to attacker domain confirmed",
        ],
        "weak": [
            "different HTTP status for internal IPs",
            "generic error on internal IP attempt",
        ],
        "insufficient": [
            "same error for all inputs",
            "SSRF protection message returned",
        ],
    },
    "idor": {
        "definitive": [
            "accessed another user's private data with changed ID",
            "modified another user's resource",
            "deleted another user's resource",
        ],
        "strong": [
            "different user's data returned with sequential ID",
            "accessed resource outside own organization/tenant",
        ],
        "weak": [
            "different response for different IDs",
            "found valid IDs by enumeration",
        ],
        "insufficient": [
            "resource is publicly accessible to all users",
            "ID change returns same data",
        ],
    },
}

# Historical false positive tracking (persisted)
FP_TRACKING_FILE = os.path.join(DATA_DIR, "false_positives.jsonl")


def _load_fp_history() -> list[dict]:
    if not os.path.exists(FP_TRACKING_FILE):
        return []
    entries = []
    with open(FP_TRACKING_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def _record_fp(entry: dict):
    entry["timestamp"] = datetime.datetime.now().isoformat()
    with open(FP_TRACKING_FILE, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def _assess_finding_confidence(
    vuln_type: str,
    response_body: str,
    response_headers: str,
    evidence_description: str = "",
    target: str = "",
) -> dict:
    """Multi-factor confidence assessment for a potential finding.

    Returns:
        {
            "confidence": 0-100,
            "level": "definitive" | "strong" | "weak" | "likely_fp",
            "factors": [{"factor": str, "impact": int, "detail": str}],
            "recommendation": str,
            "evidence_quality": str,
            "fp_patterns_matched": [str],
        }
    """
    confidence = 75  # Start at 75, adjust up/down
    factors = []
    fp_matched = []
    combined = (response_body + " " + response_headers).lower()

    # ── Factor 1: False positive pattern matching ──
    fp_patterns = FALSE_POSITIVE_PATTERNS.get(vuln_type, [])
    for pattern, reason, deduction in fp_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            confidence -= deduction
            fp_matched.append(reason)
            factors.append({"factor": "fp_pattern", "impact": -deduction, "detail": reason})

    # ── Factor 2: Evidence quality assessment ──
    evidence_lower = evidence_description.lower()
    quality_tiers = EVIDENCE_QUALITY.get(vuln_type, {})
    evidence_quality = "unknown"

    for tier in ["definitive", "strong", "weak", "insufficient"]:
        examples = quality_tiers.get(tier, [])
        for example in examples:
            if any(word in evidence_lower for word in example.lower().split()[:3]):
                evidence_quality = tier
                break
        if evidence_quality != "unknown":
            break

    quality_adjustments = {"definitive": +25, "strong": +15, "weak": -10, "insufficient": -30, "unknown": 0}
    adj = quality_adjustments.get(evidence_quality, 0)
    confidence += adj
    if adj != 0:
        factors.append({"factor": "evidence_quality", "impact": adj, "detail": f"Evidence quality: {evidence_quality}"})

    # ── Factor 3: Security headers context ──
    if vuln_type == "xss":
        if "content-security-policy" not in combined:
            confidence += 10
            factors.append({"factor": "no_csp", "impact": +10, "detail": "No CSP header — XSS more likely exploitable"})
        if "httponly" not in combined and "set-cookie" in combined:
            confidence += 5
            factors.append({"factor": "no_httponly", "impact": +5, "detail": "Cookies without HttpOnly — XSS can steal session"})

    if vuln_type == "csrf":
        if "samesite=strict" in combined or "samesite=lax" in combined:
            confidence -= 25
            factors.append({"factor": "samesite", "impact": -25, "detail": "SameSite cookie attribute mitigates CSRF"})

    # ── Factor 4: Historical FP check ──
    fp_history = _load_fp_history()
    similar_fps = [
        fp for fp in fp_history
        if fp.get("vuln_type") == vuln_type
        and fp.get("target") == target
    ]
    if similar_fps:
        confidence -= 15
        factors.append({
            "factor": "historical_fp",
            "impact": -15,
            "detail": f"Similar finding was marked FP on this target {len(similar_fps)} time(s) before",
        })

    # Also check across all targets for same vuln_type pattern
    similar_all = [fp for fp in fp_history if fp.get("vuln_type") == vuln_type]
    if len(similar_all) >= 3:
        confidence -= 10
        factors.append({
            "factor": "recurring_fp_type",
            "impact": -10,
            "detail": f"{vuln_type} has been a false positive {len(similar_all)} times across targets",
        })

    # ── Factor 5: Target context ──
    ctx = _load_target(target) if target else {}
    if ctx:
        waf = ctx.get("waf", "")
        if waf and waf.lower() != "none":
            # WAFs can inject misleading content (block pages that look like errors)
            confidence -= 5
            factors.append({"factor": "waf_present", "impact": -5, "detail": f"WAF ({waf}) may produce misleading responses"})

    # ── Clamp and classify ──
    confidence = max(0, min(100, confidence))

    if confidence >= 80:
        level = "definitive"
        recommendation = "HIGH CONFIDENCE. Verify reproduction is consistent, then report."
    elif confidence >= 60:
        level = "strong"
        recommendation = "LIKELY REAL. Verify in browser/manually, ensure impact is clear, then report."
    elif confidence >= 40:
        level = "weak"
        recommendation = "UNCERTAIN. Needs more investigation — try different payloads, check encoding, verify in browser."
    else:
        level = "likely_fp"
        recommendation = "LIKELY FALSE POSITIVE. Review the FP factors below. Store as primitive if partially interesting."

    return {
        "confidence": confidence,
        "level": level,
        "factors": factors,
        "recommendation": recommendation,
        "evidence_quality": evidence_quality,
        "fp_patterns_matched": fp_matched,
    }


# ── Headless Browser Verification ─────────────────────────────

def _verify_xss_headless(url: str, expected_alert: str = "") -> dict:
    """Use Playwright to verify XSS fires in a real browser."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"verified": False, "method": "headless", "error": "playwright not installed"}

    result = {"verified": False, "method": "headless", "url": url, "alerts": []}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            alerts = []

            def handle_dialog(dialog):
                alerts.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", handle_dialog)
            page.goto(url, timeout=15000, wait_until="networkidle")
            time.sleep(2)  # Wait for delayed JS execution
            browser.close()

            result["alerts"] = alerts
            if alerts:
                result["verified"] = True
                result["evidence"] = f"Alert fired with message: {alerts[0]}"
            elif expected_alert:
                result["note"] = f"No alert fired. Expected: {expected_alert}"
    except Exception as e:
        result["error"] = str(e)

    return result


def _verify_curl(curl_command: str) -> dict:
    """Execute a curl command and analyze the response for exploit evidence."""
    result = _run_command(curl_command, timeout=30)
    return {
        "verified": result["exit_code"] == 0,
        "method": "curl",
        "status": result["status"],
        "stdout": result["stdout"][:5000],
        "stderr": result["stderr"][:2000],
        "advisories": _analyze_output(result["stdout"], result["stderr"]),
    }


# ── Mitmproxy Helpers ─────────────────────────────────────────

def _start_mitmproxy(port: int) -> bool:
    """Start mitmproxy in background if not running."""
    global _proxy_started
    if _proxy_started:
        return True
    try:
        subprocess.Popen(
            ["mitmproxy", "-p", str(port), "--mode", "regular", "-q"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        _proxy_started = True
        return True
    except Exception as e:
        raise RuntimeError(f"Failed to start mitmproxy: {e}")


def _mitm_api_get(path: str) -> dict:
    """GET request to mitmproxy API."""
    url = f"{MITMPROXY_API}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"mitmproxy API error: {e}")


def _http_request(method: str, url: str, headers: dict | None = None, body: str = "") -> dict:
    """Make an HTTP request and return response with status, headers, body."""
    req = urllib.request.Request(url, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if body:
        req.data = body.encode()

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_headers = dict(resp.headers)
            resp_body = resp.read().decode(errors="ignore")
            return {"status": resp.status, "headers": resp_headers, "body": resp_body[:3000]}
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "body": e.read().decode(errors="ignore")[:3000],
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": f"Error: {e}"}


# ── MCP Protocol ──────────────────────────────────────────────

PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {"name": "BountyBud", "version": "2.0.0"}

CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"subscribe": False, "listChanged": False},
}

INSTRUCTIONS = (
    "BountyBud — AI bug bounty agent with 130+ doc KB, local tool execution, and self-learning.\n\n"

    "FIRST: If resuming a hunt, call get_hunt_log(target) IMMEDIATELY to reload your state.\n\n"

    "YOU ARE A HACKER, NOT A SCANNER OPERATOR.\n"
    "Scanners find 5% of bugs. You find the other 95% by THINKING.\n"
    "- Ask: 'What does this app assume? How do I break that assumption?'\n"
    "- Ask: 'What happens if I change this ID? Skip this step? Replay as another user?'\n"
    "- Ask: 'What would be BAD if an attacker could do this?'\n"
    "- Scan found nothing? GOOD. That's where the REAL hunting starts.\n"
    "- Every feature is an attack surface. Payments, invites, exports, settings, sharing.\n"
    "- Don't spray tools. Pick an endpoint, understand it deeply, break it.\n"
    "- Chain low-severity findings into high-impact exploits.\n"
    "- search_knowledge for techniques, payloads, and methodology when you need depth.\n\n"

    "WORKFLOW: Setup → Intel → Discovery → Hunt → Verify → Learn\n"
    "- Setup: get_toolbelt, start_session, fingerprint (whatweb/httpx/wafw00f), set_target_context\n"
    "- Intel: Changelogs, HackerOne hacktivity, search_cves. Hunt NEW code, not old.\n"
    "- Discovery: Subdomain enum → probe → JS crawl. Small scope, 60-120s timeouts.\n"
    "- Hunt: Understand the app. Test IDOR, auth bypass, business logic, race conditions.\n"
    "  get_tools('proxy') for interception. get_tools('hunting') for primitives/chains.\n"
    "- Verify: verify_finding scores confidence and detects false positives. POC required.\n"
    "- Learn: record_outcome after every test. get_playbook ranks what works.\n\n"

    "PERSISTENCE: You WILL lose context. Protect yourself:\n"
    "- hunt_log after every phase, finding, decision, and TODO.\n"
    "- store_primitive for every interesting observation, even if not exploitable alone.\n"
    "- After context loss: get_hunt_log shows TODOs, target context, primitive count, full history.\n"
    "- The hunt log, primitives, findings, target context, and learning DB all persist to disk.\n"
    "- get_tools(category) loads additional tools on demand: kb, proxy, hunting, learning, session.\n"
)

_ALL_TOOLS = [
    {
        "name": "search_knowledge",
        "description": (
            "Search the BountyBud security knowledge base. Returns relevant chunks "
            "about techniques, payloads, tools, methodologies, and more. "
            "The KB has 130+ docs covering reconnaissance, exploitation, post-exploitation, "
            "business logic, change detection, tool selection, and vulnerability prioritization."
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
        "description": "Get a full document by ID. Use list_documents to find IDs.",
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
        "name": "search_cves",
        "description": (
            "Search the NVD for recent CVEs affecting specific technologies. "
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
        "description": "Get full details for a specific CVE by ID.",
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
            "List ALL available security tools with install status. Call ONCE at session start."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "execute_tool",
        "description": (
            "Execute a security tool command locally. Output is auto-analyzed for WAF signatures, "
            "error patterns, and interesting findings — read the advisories section. "
            "Use search_knowledge first to find the right tool and parameters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Full shell command (e.g., 'subfinder -d example.com -all -silent')",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Max seconds (default 1800, max 3600). Long-running tools like amass or feroxbuster should use high timeouts.",
                    "default": 1800,
                },
                "background": {
                    "type": "boolean",
                    "description": "If true, starts the command in the background and returns a proc_id. Useful for extremely long-running scans.",
                    "default": False,
                },
                "workdir": {
                    "type": "string",
                    "description": "Working directory (default: current)",
                },
            },
            "required": ["command"],
        },
    },
    # ── Target Context ──
    {
        "name": "set_target_context",
        "description": "Store target tech profile after fingerprinting. Persists across sessions. Guides tool selection and heuristics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "technologies": {"type": "array", "items": {"type": "string"}, "description": "Tech stack list"},
                "waf": {"type": "string", "description": "WAF name or 'none'"},
                "server": {"type": "string", "description": "Web server"},
                "cms": {"type": "string", "description": "CMS if detected"},
                "api_type": {"type": "string", "description": "REST, GraphQL, SOAP, etc."},
                "auth_type": {"type": "string", "description": "JWT, cookies, OAuth2, API key, etc."},
                "notes": {"type": "string", "description": "Additional observations"},
                "scope": {"type": "array", "items": {"type": "string"}, "description": "In-scope assets"},
                "out_of_scope": {"type": "array", "items": {"type": "string"}, "description": "Out-of-scope assets"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "get_target_context",
        "description": (
            "Retrieve the stored technology profile for a target. Returns tech stack, WAF, "
            "scope, and all stored context. Use this to inform tool and technique selection."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain or URL",
                },
            },
            "required": ["target"],
        },
    },
    # ── Primitive Chaining ──
    {
        "name": "store_primitive",
        "description": (
            "Store an observed primitive — any interesting observation about the target, "
            "even if not directly exploitable. Primitives are the building blocks of exploit chains. "
            "Examples: 'sequential user IDs', 'no CSRF token on settings', 'debug headers in response', "
            "'endpoint reflects input without encoding'. Store EVERYTHING interesting."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
                "primitive_type": {
                    "type": "string",
                    "description": "Category of primitive",
                    "enum": [
                        "info_disclosure", "idor_indicator", "auth_weakness",
                        "input_reflection", "misconfig", "logic_flaw",
                        "rate_limit_absence", "endpoint_discovery",
                        "header_anomaly", "error_leak", "secret_exposure",
                        "access_control_gap", "state_issue", "crypto_weakness",
                        "other",
                    ],
                },
                "description": {
                    "type": "string",
                    "description": "What you observed (be specific — include endpoint, parameter, behavior)",
                },
                "evidence": {
                    "type": "string",
                    "description": "The actual evidence (HTTP request/response snippet, URL, parameter values)",
                },
                "severity_estimate": {
                    "type": "string",
                    "description": "How impactful could this be if chained?",
                    "enum": ["low", "medium", "high", "critical"],
                },
            },
            "required": ["target", "primitive_type", "description"],
        },
    },
    {
        "name": "analyze_chains",
        "description": (
            "Analyze all stored primitives for a target and suggest exploit chains. "
            "Looks for combinations of primitives that could chain into higher-impact exploits. "
            "Example: info_disclosure (user IDs) + idor_indicator (no authz check) = account takeover. "
            "Call this periodically during a hunt to find non-obvious combinations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    # ── Finding Verification ──
    {
        "name": "verify_finding",
        "description": (
            "MANDATORY before reporting any vulnerability. Verifies a finding is real, not a false positive. "
            "Requires a reproduction method (curl command, URL, or script). "
            "For XSS: can use headless browser to verify alert fires. "
            "For other vulns: executes the curl/command and checks response for exploit evidence. "
            "A finding without verification is WORTHLESS. POC or GTFO."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability class",
                    "enum": [
                        "xss", "sqli", "ssrf", "idor", "rce", "lfi", "xxe",
                        "auth_bypass", "csrf", "open_redirect", "ssti",
                        "race_condition", "business_logic", "info_disclosure",
                        "subdomain_takeover", "cors_misconfig", "other",
                    ],
                },
                "title": {
                    "type": "string",
                    "description": "Short title (e.g., 'Stored XSS in profile bio field')",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability",
                },
                "reproduction_curl": {
                    "type": "string",
                    "description": "curl command that reproduces the vulnerability",
                },
                "reproduction_url": {
                    "type": "string",
                    "description": "URL that demonstrates the vulnerability (for XSS headless verification)",
                },
                "expected_evidence": {
                    "type": "string",
                    "description": "What should appear in the response to prove exploitation (e.g., 'alert fires', 'SQL error', 'etc/passwd content')",
                },
                "severity": {
                    "type": "string",
                    "description": "CVSS-based severity",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
                "impact": {
                    "type": "string",
                    "description": "Business impact description",
                },
            },
            "required": ["target", "vuln_type", "title", "description"],
        },
    },
    {
        "name": "list_findings",
        "description": "List all verified findings for a target with verification status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "mark_false_positive",
        "description": (
            "Mark a finding as a false positive. Records WHY it was FP so the system learns — "
            "future similar findings will receive lower confidence scores. Also records as a "
            "failed learning outcome. Always explain the reason clearly."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "finding_id": {"type": "string", "description": "Finding ID to mark (from list_findings)"},
                "vuln_type": {"type": "string", "description": "Vulnerability type of the FP"},
                "reason": {"type": "string", "description": "Why this is a false positive (be specific — this trains the system)"},
            },
            "required": ["reason"],
        },
    },
    # ── Session Management ──
    {
        "name": "start_session",
        "description": (
            "Start a hunting session for a target. Tracks time, tools used, findings, and progress. "
            "Call at the beginning of each hunting session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Primary target domain",
                },
                "program": {
                    "type": "string",
                    "description": "Bug bounty program name (e.g., 'HackerOne - Acme Corp')",
                },
                "objective": {
                    "type": "string",
                    "description": "What are you hunting for this session?",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "session_status",
        "description": "Get current session status including time elapsed, primitives found, and verified findings.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ── Hunt Log (context survival) ──
    {
        "name": "hunt_log",
        "description": "Write to persistent hunt log. Survives context loss. Log progress, findings, TODOs. Use get_hunt_log to resume.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "type": {"type": "string", "enum": ["status", "finding", "tested", "todo", "blocked", "plan", "note"]},
                "phase": {"type": "string", "enum": ["setup", "intel", "discovery", "hunting", "verification", "reporting"]},
                "message": {"type": "string", "description": "What happened or what to do next. Be specific."},
                "data": {"type": "object", "description": "Optional structured data"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "result": {"type": "string", "description": "For tested entries: outcome"},
            },
            "required": ["target", "type", "message"],
        },
    },
    {
        "name": "get_hunt_log",
        "description": (
            "Read the hunt log to reconstruct state after context compression. "
            "Returns timestamped entries showing what was done, found, tested, and planned. "
            "CALL THIS FIRST after context loss to understand where you left off. "
            "Also useful to review progress mid-hunt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "last_n": {
                    "type": "integer",
                    "description": "Number of recent entries to return (default 50, max 200)",
                    "default": 50,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "run_autonomous_hunt",
        "description": (
            "Kicks off the 5-model Autonomous Orchestration Engine (The Archivist -> Researcher -> Brain -> Hand -> Strategist). "
            "This tool utilizes your 4x GPU + 256GB RAM hardware rig to ingest logs, identify hot zones, reason through vulnerabilities, "
            "and verify them with a final 'Strategist' check. Use this for deep, end-to-end vulnerability discovery."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain to hunt on (e.g., 'target.corp')",
                },
                "log_file": {
                    "type": "string",
                    "description": "Optional: Path to a specific log file to ingest. Defaults to active proxy logs.",
                },
                "profile": {
                    "type": "string",
                    "description": "Hunting profile: STEALTH (5-10s delay), CONSERVATIVE (1-3s delay), or AGGRESSIVE (0s delay). Defaults to STEALTH.",
                    "enum": ["STEALTH", "CONSERVATIVE", "AGGRESSIVE"],
                    "default": "STEALTH",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_scope_updates",
        "description": (
            "Manually triggers a scope check across all tracked HackerOne and Bugcrowd programs. "
            "Detects newly added in-scope assets and provides a summary. "
            "Note: This tool uses private API keys (H1_TOKEN, BUGCROWD_TOKEN) stored on the Workhorse."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ── Learning Engine ──
    {
        "name": "record_outcome",
        "description": (
            "Record the outcome of a technique/test. This is how BountyBud LEARNS. "
            "After every test — whether it succeeds, fails, or gets blocked — record it. "
            "Over time, BountyBud builds up knowledge of what works on which tech stacks, "
            "which WAF bypasses succeed, and which techniques are waste of time. "
            "This data feeds into get_playbook for adaptive recommendations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique": {
                    "type": "string",
                    "description": "What technique/tool was used (e.g., 'cors_test', 'sqlmap', 'idor_test', 'auth_bypass_header_mangle', 'nuclei_cve_scan')",
                },
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability class tested",
                    "enum": [
                        "xss_reflected", "xss_stored", "sqli", "ssrf", "idor",
                        "cors_misconfig", "auth_bypass", "rce", "lfi", "xxe",
                        "ssti", "csrf", "open_redirect", "race_condition",
                        "mass_assignment", "workflow_bypass", "price_manipulation",
                        "jwt_attack", "subdomain_takeover", "info_disclosure",
                        "graphql_introspection", "header_injection", "other",
                    ],
                },
                "outcome": {
                    "type": "string",
                    "description": "What happened",
                    "enum": ["success", "fail", "blocked", "partial"],
                },
                "tech_stack": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target's tech stack (e.g., ['React', 'Express', 'MongoDB'])",
                },
                "waf": {
                    "type": "string",
                    "description": "WAF if any (e.g., 'Cloudflare', 'AWS WAF', 'none')",
                },
                "target_type": {
                    "type": "string",
                    "description": "Type of target",
                    "enum": ["web_app", "api", "mobile_api", "saas", "ecommerce", "cms", "network", "cloud", "other"],
                },
                "target": {
                    "type": "string",
                    "description": "Target domain (for reference)",
                },
                "details": {
                    "type": "string",
                    "description": "What specifically worked or failed (be specific — this is what future playbooks show)",
                },
                "bypass_used": {
                    "type": "string",
                    "description": "If WAF was bypassed, what encoding/technique worked (e.g., 'double URL encode', 'unicode normalization', 'chunked transfer')",
                },
            },
            "required": ["technique", "outcome"],
        },
    },
    {
        "name": "get_playbook",
        "description": (
            "Get an adaptive playbook based on accumulated learning data. "
            "Returns techniques ranked by historical success rate for the given tech stack and WAF. "
            "Also shows WAF bypass intelligence, anti-patterns to avoid, and untested techniques. "
            "Call this at the START of a hunt to plan your approach based on what has worked before."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tech_stack": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target tech stack (e.g., ['React', 'Express', 'MongoDB'])",
                },
                "waf": {
                    "type": "string",
                    "description": "Target WAF if known",
                },
                "target_type": {
                    "type": "string",
                    "description": "Type of target",
                    "enum": ["web_app", "api", "mobile_api", "saas", "ecommerce", "cms", "network", "cloud", "other"],
                },
            },
        },
    },
    {
        "name": "export_training_data",
        "description": (
            "Export all learning data as structured training data (JSONL format). "
            "This can be used to fine-tune future models or analyze hunting patterns. "
            "Each record includes technique, outcome, tech stack, WAF, details, and context. "
            "Export formats: 'raw' (full JSONL), 'training' (instruction/response pairs for fine-tuning), "
            "'summary' (aggregated statistics as JSON)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "description": "Export format",
                    "enum": ["raw", "training", "summary"],
                    "default": "raw",
                },
                "output_file": {
                    "type": "string",
                    "description": "File path to write to (default: ~/.bountybud/exports/training_<timestamp>.jsonl)",
                },
            },
        },
    },
    {
        "name": "web_research",
        "description": (
            "Fetch a URL and extract useful content for hunting intelligence. "
            "Use for: checking target changelogs, reading HackerOne disclosed reports, "
            "fetching robots.txt/sitemap, reading API docs, checking status pages. "
            "Returns extracted text content (HTML stripped)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch (e.g., 'https://target.com/changelog', 'https://hackerone.com/target/hacktivity')",
                },
                "extract_mode": {
                    "type": "string",
                    "description": "What to extract from the response",
                    "enum": ["text", "links", "headers", "full"],
                    "default": "text",
                },
                "max_length": {
                    "type": "integer",
                    "description": "Max response length in chars (default 5000)",
                    "default": 5000,
                },
            },
            "required": ["url"],
        },
    },
    # ── Mitmproxy / Interception ──
    {
        "name": "start_proxy",
        "description": (
            "Start mitmproxy in background for HTTP/HTTPS interception. "
            "This is your Burp Suite equivalent — capture, modify, and replay requests. "
            "Configure browser/tool to use localhost:8080 as proxy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Proxy port (default 8080)",
                    "default": 8080,
                },
            },
        },
    },
    {
        "name": "capture_requests",
        "description": "Get all captured HTTP requests from mitmproxy. Returns method, URL, status, size for each flow.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "replay_request",
        "description": (
            "Replay an HTTP request with optional modifications. Use to test IDOR (change IDs), "
            "auth bypass (swap/remove cookies), CORS, parameter manipulation. "
            "This is the core manual testing tool — capture a request, then replay with modifications."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)"},
                "url": {"type": "string", "description": "Target URL"},
                "headers": {"type": "object", "description": "HTTP headers dict (e.g., {\"Cookie\": \"session=abc\", \"Origin\": \"https://evil.com\"})"},
                "body": {"type": "string", "description": "Request body for POST/PUT/PATCH"},
                "follow_redirects": {"type": "boolean", "description": "Follow redirects (default true)", "default": True},
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "cors_test",
        "description": (
            "Test CORS misconfiguration on a URL. Simulates browser request with attacker Origin. "
            "Checks Access-Control-Allow-Origin reflection, wildcard, null origin, and credential headers. "
            "A CORS misconfig with credentials = account takeover via malicious page."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to test"},
                "origin": {"type": "string", "description": "Attacker origin (default: https://attacker.example.com)", "default": "https://attacker.example.com"},
                "credentials": {"type": "boolean", "description": "Include credentials (default true)", "default": True},
            },
            "required": ["url"],
        },
    },
    {
        "name": "header_injection_test",
        "description": (
            "Test header-based vulnerabilities. Injects custom headers (X-Forwarded-For, X-Original-URL, "
            "Host override, etc.) and checks for behavior changes. Useful for WAF bypass, SSRF, "
            "internal access, and cache poisoning."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "header": {"type": "string", "description": "Header name to inject (e.g., X-Forwarded-For, X-Original-URL, Host)"},
                "value": {"type": "string", "description": "Header value to inject"},
            },
            "required": ["url", "header", "value"],
        },
    },
    {
        "name": "auth_bypass_test",
        "description": (
            "Test authentication bypass techniques on a URL. Techniques: "
            "no-auth (strip all auth headers), method-switch (try all HTTP methods), "
            "param-inject (add admin params), header-mangle (X-Original-URL, X-Forwarded-For, etc.)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (should be an authenticated endpoint)"},
                "technique": {
                    "type": "string",
                    "enum": ["no-auth", "method-switch", "param-inject", "header-mangle"],
                    "description": "Bypass technique to test",
                },
            },
            "required": ["url", "technique"],
        },
    },
]

# ── Lazy Tool Loading ─────────────────────────────────────────
# Core tools are always returned on tools/list. Extended tools load on demand
# via get_tools(category). This keeps the initial handshake small (~5KB)
# so any LLM client works regardless of context window or timeout settings.

# Which tools are always visible
_CORE_TOOL_NAMES = {
    "search_knowledge", "execute_tool", "get_toolbelt",
    "set_target_context", "get_target_context",
    "hunt_log", "get_hunt_log", "start_session",
}

# Categorize extended tools for on-demand loading
_TOOL_CATEGORIES = {
    "kb": {
        "description": "Knowledge base deep-dive tools",
        "when": "When you need detailed techniques, payloads, or methodology. Use search_knowledge first (core tool), then get_document for full docs.",
        "tools": {"get_document", "list_documents", "search_cves", "get_cve"},
    },
    "proxy": {
        "description": "HTTP interception, replay, and active testing",
        "when": (
            "Phase 3 (Hunting). After discovery, when you're manually testing the app. "
            "Flow: start_proxy → browse target → capture_requests → pick interesting request → "
            "replay_request with modified IDs/cookies/params. "
            "Use cors_test on every API endpoint. Use auth_bypass_test on every authenticated endpoint. "
            "Use header_injection_test when you suspect WAF bypass or internal routing."
        ),
        "tools": {"start_proxy", "capture_requests", "replay_request", "cors_test", "header_injection_test", "auth_bypass_test"},
    },
    "hunting": {
        "description": "Observation tracking, chain analysis, finding verification",
        "when": (
            "Throughout the hunt. "
            "store_primitive: call EVERY TIME you notice something interesting (even if not exploitable). "
            "analyze_chains: call after storing 3+ primitives to find exploit combinations. "
            "verify_finding: call BEFORE reporting ANY vulnerability — it scores confidence and catches false positives. "
            "mark_false_positive: call when verify_finding says likely FP — teaches the system for next time. "
            "web_research: call to fetch changelogs, HackerOne reports, robots.txt, API docs."
        ),
        "tools": {"store_primitive", "analyze_chains", "verify_finding", "list_findings", "mark_false_positive", "web_research"},
    },
    "learning": {
        "description": "Self-learning engine",
        "when": (
            "record_outcome: call after EVERY technique you test — success, fail, blocked, or partial. "
            "This is how BountyBud learns what works on which tech stacks. "
            "get_playbook: call at the START of a new hunt to get ranked recommendations based on history. "
            "export_training_data: call to export learning data for model fine-tuning."
        ),
        "tools": {"record_outcome", "get_playbook", "export_training_data"},
    },
    "session": {
        "description": "Session tracking",
        "when": "session_status shows elapsed time, commands run, primitives stored, and findings count.",
        "tools": {"session_status"},
    },
}

# Build lookup: tool name → full tool definition
_TOOL_BY_NAME = {t["name"]: t for t in _ALL_TOOLS}

# Build the core tools list that's returned on tools/list
_GET_TOOLS_META = {
    "name": "get_tools",
    "description": (
        "Load additional tools by category. BountyBud has 33 tools — only core tools are loaded initially. "
        "Call get_tools() with no args to see all categories. "
        "Call get_tools(category='proxy') to load proxy/interception tools. "
        "Categories: kb, proxy, hunting, learning, session."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "description": "Tool category to load. Omit to see all categories.",
                "enum": ["kb", "proxy", "hunting", "learning", "session", "all"],
            },
        },
    },
}

# Build two tool sets:
# - CORE_TOOLS: compact schemas for all tools (used by tools/list for constrained clients)
# - _GET_TOOLS_META remains for deep-dive parameter docs via get_tools()
def _compact_tool(tool: dict) -> dict:
    """Create a compact version of a tool schema for tools/list."""
    compact = {"name": tool["name"], "description": tool.get("description", "")[:120]}
    schema = tool.get("inputSchema", {})
    # Keep only required params in compact mode
    if schema.get("properties"):
        required = set(schema.get("required", []))
        compact_props = {}
        for k, v in schema["properties"].items():
            if k in required:
                compact_props[k] = {"type": v.get("type", "string"), "description": v.get("description", "")[:60]}
                if v.get("enum"):
                    compact_props[k]["enum"] = v["enum"]
        compact["inputSchema"] = {"type": "object", "properties": compact_props, "required": list(required)}
    else:
        compact["inputSchema"] = {"type": "object", "properties": {}}
    return compact

CORE_TOOLS = [_compact_tool(t) for t in _ALL_TOOLS] + [_GET_TOOLS_META]

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


# ── Chain Analysis Engine ─────────────────────────────────────

# Known primitive combinations that form exploit chains
CHAIN_PATTERNS = [
    {
        "requires": ["info_disclosure", "idor_indicator"],
        "name": "Information Disclosure → IDOR → Data Access",
        "description": "Leaked identifiers (user IDs, UUIDs) combined with missing authorization checks enable accessing other users' data.",
        "severity": "high",
        "steps": [
            "1. Use the disclosed identifiers from the info_disclosure primitive",
            "2. Substitute them into the IDOR-vulnerable endpoint",
            "3. Verify you can access another user's data",
            "4. Escalate: can you MODIFY data too? (GET → PUT/DELETE)",
        ],
    },
    {
        "requires": ["input_reflection", "misconfig"],
        "name": "Input Reflection + Security Misconfig → XSS/Injection",
        "description": "Reflected input combined with missing security headers (CSP, X-Frame-Options) enables XSS or clickjacking.",
        "severity": "high",
        "steps": [
            "1. Confirm input is reflected without sanitization",
            "2. Check if CSP blocks inline scripts (if no CSP → direct XSS)",
            "3. If CSP exists, try CSP bypass via allowed domains",
            "4. Test stored XSS (input persisted in DB and rendered to other users)",
        ],
    },
    {
        "requires": ["auth_weakness", "endpoint_discovery"],
        "name": "Auth Weakness + Hidden Endpoint → Privilege Escalation",
        "description": "Weak authentication combined with discovered admin/internal endpoints enables unauthorized access to privileged functionality.",
        "severity": "critical",
        "steps": [
            "1. Access the discovered endpoint with a low-privilege session",
            "2. If auth is cookie-based, try removing/modifying the cookie",
            "3. If JWT, test for none algorithm and claim manipulation",
            "4. Try accessing the endpoint with no authentication at all",
        ],
    },
    {
        "requires": ["rate_limit_absence", "auth_weakness"],
        "name": "No Rate Limit + Auth Weakness → Brute Force / Account Takeover",
        "description": "Missing rate limiting on authentication endpoints enables credential stuffing or token brute-forcing.",
        "severity": "high",
        "steps": [
            "1. Confirm no rate limit on login/reset/OTP endpoint",
            "2. Brute-force the weak auth mechanism (short tokens, predictable values)",
            "3. Test for account lockout bypass",
            "4. Chain with credential stuffing if email enumeration is possible",
        ],
    },
    {
        "requires": ["state_issue", "logic_flaw"],
        "name": "State Manipulation + Logic Flaw → Business Logic Bypass",
        "description": "Manipulable state combined with logic flaws enables workflow bypass (skip payment, reuse tokens, etc.).",
        "severity": "high",
        "steps": [
            "1. Map the full state machine (what states exist, what transitions are valid)",
            "2. Try invalid transitions (completed → draft, paid → unpaid)",
            "3. Race condition: submit multiple state changes simultaneously",
            "4. Check if reverting state preserves side effects (refund + keep product)",
        ],
    },
    {
        "requires": ["info_disclosure", "access_control_gap"],
        "name": "Info Leak + Broken Access Control → Data Exfiltration",
        "description": "Leaked internal identifiers combined with missing access controls enable mass data extraction.",
        "severity": "critical",
        "steps": [
            "1. Enumerate IDs using the leaked identifier pattern",
            "2. Automate requests to the access-control-gap endpoint with enumerated IDs",
            "3. Assess scope: how much data is accessible? PII? Financial?",
            "4. Check for bulk export endpoints that bypass pagination",
        ],
    },
    {
        "requires": ["endpoint_discovery", "misconfig"],
        "name": "Hidden Endpoint + Misconfig → Sensitive Data Exposure",
        "description": "Undocumented endpoints with security misconfigurations expose debug info, source code, or credentials.",
        "severity": "high",
        "steps": [
            "1. Access the endpoint — is authentication required?",
            "2. Check for debug modes (verbose errors, stack traces)",
            "3. Look for credential leakage in response headers or body",
            "4. Test for directory traversal from the misconfigured endpoint",
        ],
    },
    {
        "requires": ["header_anomaly", "input_reflection"],
        "name": "Header Injection + Input Reflection → Request Smuggling/CRLF",
        "description": "Custom header acceptance combined with input reflection enables CRLF injection or request smuggling.",
        "severity": "high",
        "steps": [
            "1. Test CRLF injection: %0d%0a in header values",
            "2. Try injecting Set-Cookie headers (session fixation)",
            "3. Test for HTTP request smuggling (CL.TE / TE.CL)",
            "4. Check if reflected headers appear in cached responses (cache poisoning)",
        ],
    },
    {
        "requires": ["secret_exposure"],
        "name": "Exposed Secret → Direct Compromise",
        "description": "Any exposed secret (API key, token, password, private key) is immediately exploitable.",
        "severity": "critical",
        "steps": [
            "1. Identify the secret type and associated service",
            "2. Test if the secret is still valid/active",
            "3. Determine the scope of access the secret provides",
            "4. Check for additional secrets accessible with this access",
        ],
    },
    {
        "requires": ["crypto_weakness"],
        "name": "Cryptographic Weakness → Token Forgery/Data Decryption",
        "description": "Weak cryptography enables forging tokens, decrypting data, or bypassing integrity checks.",
        "severity": "high",
        "steps": [
            "1. Identify the weak algorithm/implementation",
            "2. For JWT: test none algorithm, HMAC/RSA confusion, weak secrets",
            "3. For encrypted data: test known-plaintext, padding oracle, ECB mode",
            "4. For signatures: test length extension, timing attacks",
        ],
    },
    {
        "requires": ["rate_limit_absence", "state_issue"],
        "name": "No Rate Limit + State Issue → Race Condition Exploit",
        "description": "Missing rate limiting on stateful operations enables TOCTOU race conditions.",
        "severity": "high",
        "steps": [
            "1. Identify the stateful operation (transfer, redeem, vote, claim)",
            "2. Send 20-50 concurrent requests using threading/turbo intruder",
            "3. Check if the operation executed multiple times (balance went negative, extra coupons)",
            "4. Test with different timing windows",
        ],
    },
    {
        "requires": ["error_leak", "endpoint_discovery"],
        "name": "Error Leak + Endpoint → Technology-Specific Exploitation",
        "description": "Error messages revealing technology details combined with endpoints enable targeted exploitation.",
        "severity": "medium",
        "steps": [
            "1. Extract exact version numbers from error messages",
            "2. search_cves for those specific versions",
            "3. Check if known exploits work on the discovered endpoints",
            "4. Use error messages to map internal architecture",
        ],
    },
]


def _analyze_primitive_chains(target: str) -> str:
    """Analyze stored primitives and suggest exploit chains."""
    primitives = _load_primitives(target)
    if not primitives:
        return f"No primitives stored for {target}. Use store_primitive to record observations first."

    # Group primitives by type
    by_type: dict[str, list[dict]] = {}
    for p in primitives:
        ptype = p.get("type", "other")
        if ptype not in by_type:
            by_type[ptype] = []
        by_type[ptype].append(p)

    available_types = set(by_type.keys())

    lines = [f"# Chain Analysis for {target}\n"]
    lines.append(f"**{len(primitives)} primitives stored** across {len(available_types)} categories:\n")
    for ptype, items in sorted(by_type.items()):
        lines.append(f"- **{ptype}**: {len(items)} observation(s)")
    lines.append("")

    # Find matching chain patterns
    chains_found = []
    for chain in CHAIN_PATTERNS:
        required = set(chain["requires"])
        if required.issubset(available_types):
            chains_found.append(chain)

    if chains_found:
        lines.append(f"## 🔥 {len(chains_found)} Potential Exploit Chain(s) Detected\n")
        for i, chain in enumerate(chains_found, 1):
            lines.append(f"### Chain {i}: {chain['name']}")
            lines.append(f"**Severity:** {chain['severity'].upper()}")
            lines.append(f"**Description:** {chain['description']}\n")

            # Show which primitives feed into this chain
            lines.append("**Your primitives that feed this chain:**")
            for req_type in chain["requires"]:
                for p in by_type.get(req_type, []):
                    lines.append(f"  - [{req_type}] {p.get('description', '')[:100]}")
            lines.append("")

            lines.append("**Exploitation steps:**")
            for step in chain["steps"]:
                lines.append(f"  {step}")
            lines.append("")
    else:
        lines.append("## No complete chains detected yet.\n")
        lines.append("Keep hunting and storing primitives. Chains form when you have complementary observations.")
        lines.append("\n**Primitive types that would unlock chains:**")
        for chain in CHAIN_PATTERNS:
            missing = set(chain["requires"]) - available_types
            if missing and len(missing) <= 2:
                lines.append(f"  - Need **{', '.join(missing)}** to unlock: {chain['name']}")

    # Always suggest manual investigation for single primitives
    lines.append("\n## Individual Primitive Analysis\n")
    for p in primitives:
        ptype = p.get("type", "other")
        desc = p.get("description", "")
        sev = p.get("severity_estimate", "unknown")
        lines.append(f"- **[{sev.upper()}] [{ptype}]** {desc[:120]}")

    return "\n".join(lines)


# ── REST API Client ─────────────────────────────────────────

def _api_get(path: str, params: dict | None = None) -> dict:
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
    """Execute a tool via the REST API or locally and return MCP content blocks."""
    global _active_session

    if name == "search_knowledge":
        query = arguments.get("query", "")
        if not query:
            return [{"type": "text", "text": "A search query is required."}]

        limit = min(int(arguments.get("limit", 10)), 50)
        params = {
            "q": query,
            "category": arguments.get("category"),
            "type": arguments.get("type"),
            "limit": str(limit),
        }

        # ── Primary search ──
        resp = _api_get("/search", params)
        results = resp.get("data", {}).get("results", [])

        # ── Query expansion: if few results, expand with synonyms ──
        expansions_used = []
        if len(results) < 3:
            expanded_terms = _expand_query(query)
            if expanded_terms:
                # Try expanded queries and merge unique results
                seen_ids = {r.get("chunk_id") for r in results}
                for term in expanded_terms[:4]:  # Limit expansion queries
                    exp_params = dict(params)
                    exp_params["q"] = term
                    exp_params["limit"] = "5"
                    try:
                        exp_resp = _api_get("/search", exp_params)
                        for r in exp_resp.get("data", {}).get("results", []):
                            cid = r.get("chunk_id")
                            if cid and cid not in seen_ids:
                                r["_expanded"] = True  # Mark as expansion result
                                results.append(r)
                                seen_ids.add(cid)
                                expansions_used.append(term)
                    except Exception:
                        pass
                expansions_used = list(set(expansions_used))

        # ── Fallback: OR query if AND returned nothing ──
        if not results and " " in query:
            words = query.strip().split()
            for word in words:
                if len(word) > 2:  # Skip tiny words
                    try:
                        or_params = dict(params)
                        or_params["q"] = word
                        or_params["limit"] = "5"
                        or_resp = _api_get("/search", or_params)
                        for r in or_resp.get("data", {}).get("results", []):
                            r["_partial"] = True
                            results.append(r)
                    except Exception:
                        pass
            # Deduplicate
            seen_ids = set()
            deduped = []
            for r in results:
                cid = r.get("chunk_id")
                if cid not in seen_ids:
                    deduped.append(r)
                    seen_ids.add(cid)
            results = deduped

        if not results:
            return [{"type": "text", "text": f"No results for '{query}'. Try broader terms or `list_documents` to browse by category."}]

        # ── Context-aware reranking ──
        # Detect target from active session or arguments
        target = ""
        if _active_session:
            target = _active_session.get("target", "")

        boost_tags = _tech_boost_tags(target) if target else []
        if boost_tags:
            # Score boost: results matching target tech stack rank higher
            for r in results:
                r_tags = set(t.lower() for t in r.get("metadata", {}).get("tags", []))
                r_cat = r.get("metadata", {}).get("category", "").lower()
                r_subcat = r.get("metadata", {}).get("subcategory", "").lower()
                boost = sum(1 for bt in boost_tags if bt in r_tags or bt in r_cat or bt in r_subcat)
                # Store original score, apply boost
                orig_score = r.get("relevance_score", 0)
                r["_boosted"] = boost > 0
                r["relevance_score"] = orig_score + (boost * 0.5)

            # Re-sort by boosted relevance (higher is better after boost)
            results.sort(key=lambda r: r.get("relevance_score", 0), reverse=True)

        # ── Format results ──
        total = resp.get("data", {}).get("total", len(results))
        header = f"Found {total} results for '{query}'"
        if expansions_used:
            header += f" (also searched: {', '.join(expansions_used[:3])})"
        if boost_tags and target:
            header += f" [ranked for {target}]"
        header += ":\n"
        lines = [header]

        for r in results[:limit]:
            tags = ", ".join(r.get("metadata", {}).get("tags", [])[:4])
            prefix = ""
            if r.get("_boosted"):
                prefix = "⚡ "  # Tech-relevant marker
            elif r.get("_expanded"):
                prefix = "↗ "  # Expansion result marker
            elif r.get("_partial"):
                prefix = "~ "  # Partial match marker

            lines.append(
                f"### {prefix}{r.get('title', '')} — {r.get('section', '')}\n"
                f"**Type:** {r.get('metadata', {}).get('type', '')} | "
                f"**Category:** {r.get('metadata', {}).get('category', '')} | "
                f"**Tags:** {tags}\n\n"
                f"{r.get('content', '')}\n\n---\n"
            )

        # ── Hunt-state-informed suggestions ──
        suggestions = []
        if target:
            ctx = _load_target(target)
            techs = [t.lower() for t in ctx.get("technologies", [])]
            waf = ctx.get("waf", "").lower()

            # Suggest related docs based on query + tech stack
            query_lower = query.lower()
            if "xss" in query_lower and any(t in techs for t in ["react", "angular", "vue"]):
                suggestions.append("TIP: JS framework detected — check `get_document('xss-advanced-techniques')` for framework-specific bypass")
            if "sqli" in query_lower and any(t in techs for t in ["mongodb", "nosql"]):
                suggestions.append("TIP: NoSQL DB detected — also try `search_knowledge('nosql injection')` for MongoDB-specific payloads")
            if waf and "bypass" not in query_lower:
                suggestions.append(f"TIP: {waf} WAF active — add 'bypass' or 'evasion' to your search for WAF-aware payloads")
            if "api" in query_lower and any(t in techs for t in ["graphql"]):
                suggestions.append("TIP: GraphQL detected — try `get_document('graphql-grpc')` for introspection and batching attacks")

            # Check if primitives exist that relate to this search
            primitives_dir = os.path.join(DATA_DIR, "primitives")
            target_slug = re.sub(r'[^\w.-]', '_', target)
            prim_files = [f for f in os.listdir(primitives_dir) if f.startswith(target_slug)] if os.path.isdir(primitives_dir) else []
            if prim_files and len(prim_files) >= 2:
                suggestions.append(f"NOTE: You have {len(prim_files)} stored primitives for {target}. Run `analyze_chains` to check for exploit chains.")

        if suggestions:
            lines.append("\n**━━━ HUNT INTELLIGENCE ━━━**")
            for s in suggestions:
                lines.append(f"  {s}")

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

    elif name == "get_tools":
        category = arguments.get("category", "")

        if not category:
            # List all categories with tool counts
            lines = ["# BountyBud Tool Categories\n"]
            lines.append(f"**{len(_ALL_TOOLS)} total tools** — {len(_CORE_TOOL_NAMES)} core (always loaded) + {len(_ALL_TOOLS) - len(_CORE_TOOL_NAMES)} extended\n")
            lines.append("Call `get_tools(category='...')` to load a category's tools.\n")

            for cat_name, cat_info in _TOOL_CATEGORIES.items():
                tool_names = sorted(cat_info["tools"])
                lines.append(f"## `{cat_name}` — {cat_info['description']}")
                lines.append(f"  Tools: {', '.join(tool_names)}")
                if cat_info.get("when"):
                    lines.append(f"  When: {cat_info['when']}")
                lines.append("")

            lines.append("## `all` — Load every tool definition")
            return [{"type": "text", "text": "\n".join(lines)}]

        if category == "all":
            # Return compact summary of all tools (not full JSON schemas)
            lines = [f"**All {len(_ALL_TOOLS)} tools:**\n"]
            for t in _ALL_TOOLS:
                req = t.get("inputSchema", {}).get("required", [])
                params = list(t.get("inputSchema", {}).get("properties", {}).keys())
                req_str = ", ".join(req) if req else "none"
                lines.append(f"- **{t['name']}**({req_str}) — {t.get('description', '')[:80]}")
            lines.append("\nUse `get_tools(category)` for full parameter details.")
            return [{"type": "text", "text": "\n".join(lines)}]

        cat_info = _TOOL_CATEGORIES.get(category)
        if not cat_info:
            return [{"type": "text", "text": f"Unknown category '{category}'. Valid: {', '.join(_TOOL_CATEGORIES.keys())}, all"}]

        # Return the full tool definitions for this category
        cat_tools = [_TOOL_BY_NAME[name] for name in sorted(cat_info["tools"]) if name in _TOOL_BY_NAME]
        if not cat_tools:
            return [{"type": "text", "text": f"No tools found in category '{category}'."}]

        import json as _json
        lines = [f"# {category} tools — {cat_info['description']}\n"]
        if cat_info.get("when"):
            lines.append(f"**When to use:** {cat_info['when']}\n")
        lines.append(f"**{len(cat_tools)} tools available:**\n")

        for tool in cat_tools:
            lines.append(f"### `{tool['name']}`")
            lines.append(f"{tool.get('description', '')}\n")

            # Show parameters
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            required = schema.get("required", [])
            if props:
                lines.append("**Parameters:**")
                for param_name, param_info in props.items():
                    req_mark = " (required)" if param_name in required else ""
                    param_type = param_info.get("type", "string")
                    param_desc = param_info.get("description", "")
                    enum_vals = param_info.get("enum")
                    line = f"  - `{param_name}` ({param_type}){req_mark}: {param_desc}"
                    if enum_vals:
                        line += f" — options: {', '.join(str(v) for v in enum_vals)}"
                    lines.append(line)
            lines.append("")

        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "execute_tool":
        command = arguments.get("command", "").strip()
        if not command:
            return [{"type": "text", "text": "A command is required."}]
        timeout = min(int(arguments.get("timeout", 1800)), 3600)
        background = arguments.get("background", False)
        workdir = arguments.get("workdir")

        # Infer target from command or active session
        inferred_target = ""
        if _active_session:
            inferred_target = _active_session.get("target", "")

        # ── Pre-execution heuristics ──
        pre_check = _pre_execution_check(command, inferred_target)

        parts = []
        if pre_check:
            parts.append(f"**━━━ PRE-EXECUTION CHECK ━━━**\n{pre_check}\n**━━━━━━━━━━━━━━━━━━━━━━━━━**\n")

        result = _run_command(command, timeout=timeout, workdir=workdir, background=background)

        parts.append(f"**Command:** `{command}`")
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

        # ── Post-execution heuristics (with context) ──
        advisories = _analyze_output(
            result.get("stdout", ""), result.get("stderr", ""),
            command=command, target=inferred_target,
        )
        if advisories:
            parts.append("\n**━━━ BOUNTYBUD ANALYSIS ━━━**")
            for adv in advisories:
                parts.append(adv)
            # Nudge LLM toward the right extended tools based on what was found
            has_positive = any("🔥" in a for a in advisories)
            has_negative = any("⚠️" in a for a in advisories)
            if has_positive:
                parts.append("TIP: Use `store_primitive` to record this observation. Use `verify_finding` to confirm exploitability. (Load with `get_tools('hunting')`)")
            if has_negative and not has_positive:
                parts.append("TIP: Use `record_outcome` to log this blocked/failed attempt so future playbooks adapt. (Load with `get_tools('learning')`)")
            parts.append("**━━━━━━━━━━━━━━━━━━━━━━━━━**")

        # Log to active session
        if _active_session:
            _active_session.setdefault("commands_run", []).append({
                "command": command[:200],
                "status": result["status"],
                "duration": result["duration"],
                "advisories": len(advisories),
                "timestamp": datetime.datetime.now().isoformat(),
            })

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

    # ── Target Context ──

    elif name == "set_target_context":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        ctx = _load_target(target)
        ctx["target"] = target
        ctx["updated"] = datetime.datetime.now().isoformat()

        # Merge provided fields
        for field in ["technologies", "waf", "server", "cms", "api_type", "auth_type", "notes", "scope", "out_of_scope"]:
            val = arguments.get(field)
            if val is not None:
                if field in ("technologies", "scope", "out_of_scope") and isinstance(val, list):
                    existing = ctx.get(field, [])
                    ctx[field] = list(set(existing + val))
                else:
                    ctx[field] = val

        _save_target(target, ctx)

        # Generate tech-aware recommendations
        techs = ctx.get("technologies", [])
        waf = ctx.get("waf", "")
        recommendations = []

        tech_lower = [t.lower() for t in techs]
        if any(t in tech_lower for t in ["php", "wordpress", "laravel", "drupal"]):
            recommendations.append("PHP stack detected: test for LFI (../ traversal), RCE via file upload, PHP type juggling, deserialization")
        if any(t in tech_lower for t in ["node", "express", "next", "react", "angular", "vue"]):
            recommendations.append("Node/JS stack: test for prototype pollution, SSRF in SSR, DOM XSS, JWT vulnerabilities")
        if any(t in tech_lower for t in ["python", "django", "flask", "fastapi"]):
            recommendations.append("Python stack: test for SSTI (Jinja2/Mako), pickle deserialization, debug mode, SSRF")
        if any(t in tech_lower for t in ["java", "spring", "tomcat", "struts"]):
            recommendations.append("Java stack: test for deserialization (ysoserial), JNDI injection, Spring actuators, EL injection")
        if any(t in tech_lower for t in ["ruby", "rails"]):
            recommendations.append("Ruby/Rails stack: test for mass assignment, SSTI (ERB), deserialization, CVE-rich history")
        if any(t in tech_lower for t in ["graphql"]):
            recommendations.append("GraphQL: run introspection query, test for batching attacks, nested query DoS, authorization on mutations")
        if any(t in tech_lower for t in ["mongodb", "nosql"]):
            recommendations.append("NoSQL: test for NoSQL injection ({$gt:\"\"}, $regex), authentication bypass, data exposure")
        if any(t in tech_lower for t in ["mysql", "postgresql", "mssql", "oracle"]):
            recommendations.append("SQL DB detected: test for SQLi (time-based blind, error-based, UNION), especially on search/filter params")
        if waf and waf.lower() != "none":
            recommendations.append(f"WAF ({waf}): encode payloads, try bypass techniques, hunt for origin IP, test API endpoints that may skip WAF")

        text = f"**Target context saved for {target}.**\n\n"
        text += f"**Tech Stack:** {', '.join(techs) if techs else 'not set'}\n"
        text += f"**WAF:** {waf or 'not set'}\n"
        text += f"**Server:** {ctx.get('server', 'not set')}\n"
        text += f"**CMS:** {ctx.get('cms', 'not set')}\n"
        text += f"**API Type:** {ctx.get('api_type', 'not set')}\n"
        text += f"**Auth:** {ctx.get('auth_type', 'not set')}\n"
        if ctx.get("scope"):
            text += f"**In Scope:** {', '.join(ctx['scope'])}\n"
        if ctx.get("out_of_scope"):
            text += f"**Out of Scope:** {', '.join(ctx['out_of_scope'])}\n"
        if recommendations:
            text += f"\n**Tech-Specific Recommendations:**\n"
            for rec in recommendations:
                text += f"  - {rec}\n"

        # Auto-suggest relevant KB searches for the tech stack
        kb_searches = []
        for tech in techs:
            tech_l = tech.lower()
            if tech_l in _TECH_KB_MAPPING:
                kb_searches.extend(_TECH_KB_MAPPING[tech_l][:2])
        if waf:
            kb_searches.append("waf bypass")
        kb_searches = list(dict.fromkeys(kb_searches))[:5]  # Dedupe, cap at 5

        if kb_searches:
            text += f"\n**Suggested KB searches for this stack:**\n"
            for ks in kb_searches:
                text += f"  - `search_knowledge('{ks}')`\n"

        text += "\n**Next:** `search_knowledge` for detailed techniques. `get_tools('proxy')` when ready to test. `get_tools('hunting')` to track findings."

        return [{"type": "text", "text": text}]

    elif name == "get_target_context":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        ctx = _load_target(target)
        if not ctx:
            return [{"type": "text", "text": f"No context stored for {target}. Run fingerprinting tools first, then call set_target_context."}]

        primitives = _load_primitives(target)
        findings = _load_findings(target)

        text = f"# Target Profile: {target}\n\n"
        text += f"**Last Updated:** {ctx.get('updated', 'unknown')}\n"
        text += f"**Technologies:** {', '.join(ctx.get('technologies', [])) or 'unknown'}\n"
        text += f"**WAF:** {ctx.get('waf', 'unknown')}\n"
        text += f"**Server:** {ctx.get('server', 'unknown')}\n"
        text += f"**CMS:** {ctx.get('cms', 'none')}\n"
        text += f"**API Type:** {ctx.get('api_type', 'unknown')}\n"
        text += f"**Auth:** {ctx.get('auth_type', 'unknown')}\n"
        if ctx.get("scope"):
            text += f"**In Scope:** {', '.join(ctx['scope'])}\n"
        if ctx.get("out_of_scope"):
            text += f"**Out of Scope:** {', '.join(ctx['out_of_scope'])}\n"
        if ctx.get("notes"):
            text += f"**Notes:** {ctx['notes']}\n"
        text += f"\n**Primitives Stored:** {len(primitives)}\n"
        text += f"**Verified Findings:** {len(findings)}\n"

        return [{"type": "text", "text": text}]

    # ── Primitive Chaining ──

    elif name == "store_primitive":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        primitive = {
            "id": hashlib.md5(f"{time.time()}{arguments.get('description', '')}".encode()).hexdigest()[:12],
            "type": arguments.get("primitive_type", "other"),
            "description": arguments.get("description", ""),
            "evidence": arguments.get("evidence", ""),
            "severity_estimate": arguments.get("severity_estimate", "low"),
            "timestamp": datetime.datetime.now().isoformat(),
        }

        primitives = _load_primitives(target)
        primitives.append(primitive)
        _save_primitives(target, primitives)

        # Update session
        if _active_session:
            _active_session["primitives_count"] = _active_session.get("primitives_count", 0) + 1

        # Auto-log to hunt log
        _append_huntlog(target, {
            "type": "note",
            "phase": "hunting",
            "message": f"Primitive [{primitive['type']}]: {primitive['description'][:120]}",
        })

        text = f"**Primitive stored** [{primitive['type']}] for {target}.\n"
        text += f"Total primitives: {len(primitives)}. "
        text += f"Run `analyze_chains` to check for exploit combinations."

        return [{"type": "text", "text": text}]

    elif name == "list_primitives":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        primitives = _load_primitives(target)
        if not primitives:
            return [{"type": "text", "text": f"No primitives stored for {target}. Start hunting and use store_primitive to record observations."}]

        lines = [f"**{len(primitives)} primitives for {target}:**\n"]
        for p in primitives:
            sev = p.get("severity_estimate", "?")
            ptype = p.get("type", "?")
            desc = p.get("description", "")[:150]
            ts = p.get("timestamp", "")[:16]
            lines.append(f"- **[{sev.upper()}] [{ptype}]** {desc} _{ts}_")
            if p.get("evidence"):
                lines.append(f"  Evidence: `{p['evidence'][:100]}`")

        return [{"type": "text", "text": "\n".join(lines)}]

    elif name == "analyze_chains":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        analysis = _analyze_primitive_chains(target)
        return [{"type": "text", "text": analysis}]

    # ── Finding Verification ──

    elif name == "verify_finding":
        target = arguments.get("target", "")
        vuln_type = arguments.get("vuln_type", "other")
        title = arguments.get("title", "")
        description = arguments.get("description", "")
        curl_cmd = arguments.get("reproduction_curl", "")
        repro_url = arguments.get("reproduction_url", "")
        expected = arguments.get("expected_evidence", "")
        severity = arguments.get("severity", "medium")
        impact = arguments.get("impact", "")

        if not target or not title:
            return [{"type": "text", "text": "target and title are required."}]

        finding = {
            "id": hashlib.md5(f"{target}{title}{time.time()}".encode()).hexdigest()[:12],
            "target": target,
            "vuln_type": vuln_type,
            "title": title,
            "description": description,
            "severity": severity,
            "impact": impact,
            "timestamp": datetime.datetime.now().isoformat(),
            "verification": {"status": "pending", "results": []},
        }

        verification_results = []
        verified = False
        response_body = ""
        response_headers = ""

        # Attempt curl verification
        # ── Resilient Parsing Fallback ──
        if not curl_cmd and description:
            # Look for curl commands in description if not explicitly provided
            curl_match = re.search(r'(curl\s+-X\s+[A-Z]+\s+["\'].*?["\'])', description, re.IGNORECASE | re.DOTALL)
            if not curl_match:
                curl_match = re.search(r'reproduction_curl:\s*(.*)', description, re.IGNORECASE)
            
            if curl_match:
                curl_cmd = curl_match.group(1).strip()

        if curl_cmd:
            curl_result = _verify_curl(curl_cmd)
            verification_results.append({"method": "curl", "result": curl_result})
            response_body = curl_result.get("stdout", "")
            response_headers = curl_result.get("stderr", "")  # curl -v puts headers in stderr

            if expected and response_body:
                if re.search(re.escape(expected), response_body, re.IGNORECASE):
                    verified = True
                    curl_result["evidence_found"] = True
            elif curl_result.get("verified"):
                if curl_result.get("advisories"):
                    for adv in curl_result["advisories"]:
                        if "CRITICAL" in adv or "POTENTIAL" in adv:
                            verified = True

        # Attempt headless XSS verification
        if vuln_type == "xss" and repro_url:
            headless_result = _verify_xss_headless(repro_url, expected)
            verification_results.append({"method": "headless_browser", "result": headless_result})
            if headless_result.get("verified"):
                verified = True

        # If no reproduction method provided
        if not curl_cmd and not repro_url:
            verification_results.append({
                "method": "none",
                "result": {
                    "verified": False,
                    "error": "NO REPRODUCTION METHOD PROVIDED. You MUST provide reproduction_curl or reproduction_url.",
                },
            })

        # ── Confidence Assessment (the intelligence layer) ──
        assessment = _assess_finding_confidence(
            vuln_type=vuln_type,
            response_body=response_body,
            response_headers=response_headers,
            evidence_description=expected or description,
            target=target,
        )

        # Headless XSS verification overrides confidence
        if vuln_type == "xss" and any(
            vr.get("result", {}).get("verified") for vr in verification_results
            if vr.get("method") == "headless_browser"
        ):
            assessment["confidence"] = 95
            assessment["level"] = "definitive"
            assessment["recommendation"] = "XSS confirmed by headless browser. Report immediately."

        # ── Signal Guard Validation (Staleness & Collision Check) ──
        signal_guard_warning = ""
        desc_lower = description.lower() + " " + title.lower()
        if re.search(r'cve-\d{4}-\d{4,}', desc_lower) or any(k in desc_lower for k in ["bypass", "techdocs", "backstage/plugin"]):
            assessment["confidence"] = max(0, assessment["confidence"] - 15)
            signal_guard_warning = "⚠️ SIGNAL GUARD: This is a high-collision area or targets a known CVE/bypass. Verify if this logic is already being discussed in public PRs before submitting."
            if "fp_patterns_matched" not in assessment:
                assessment["fp_patterns_matched"] = []
            assessment["fp_patterns_matched"].append("Signal Guard: High-Collision Area")

        # Determine final status
        if verified and assessment["confidence"] >= 60:
            status = "verified"
        elif verified and assessment["confidence"] < 60:
            status = "needs_review"  # Curl matched but FP signals present
        elif assessment["confidence"] >= 80:
            status = "high_confidence"
        elif assessment["confidence"] >= 40:
            status = "needs_investigation"
        else:
            status = "likely_false_positive"

        finding["verification"] = {
            "status": status,
            "results": verification_results,
            "confidence": assessment["confidence"],
            "confidence_level": assessment["level"],
            "evidence_quality": assessment["evidence_quality"],
            "fp_patterns_matched": assessment["fp_patterns_matched"],
            "verified_at": datetime.datetime.now().isoformat() if verified else None,
        }

        # Save finding
        findings = _load_findings(target)
        findings.append(finding)
        _save_findings(target, findings)

        # Update session
        if _active_session:
            if status in ("verified", "high_confidence"):
                _active_session["verified_findings"] = _active_session.get("verified_findings", 0) + 1
            _active_session["total_findings"] = _active_session.get("total_findings", 0) + 1

        # ── Build response ──
        conf = assessment["confidence"]
        level = assessment["level"]
        conf_bar = "#" * (conf // 5) + "-" * (20 - conf // 5)

        text = f"**Finding Assessment: {title}**\n"
        text += f"**Type:** {vuln_type} | **Severity:** {severity} | **Target:** {target}\n\n"

        text += f"## Confidence: {conf}/100 [{level.upper()}]\n"
        text += f"[{conf_bar}] {conf}%\n\n"
        text += f"**Status:** {status.replace('_', ' ').upper()}\n"
        text += f"**Evidence Quality:** {assessment['evidence_quality']}\n"
        text += f"**Recommendation:** {assessment['recommendation']}\n\n"

        # Show confidence factors
        if assessment["factors"]:
            text += "## Confidence Factors\n"
            for factor in assessment["factors"]:
                sign = "+" if factor["impact"] > 0 else ""
                text += f"  [{sign}{factor['impact']:+d}] {factor['detail']}\n"
            text += "\n"

        # Show FP patterns matched
        if assessment["fp_patterns_matched"]:
            text += "## False Positive Indicators\n"
            for fp in assessment["fp_patterns_matched"]:
                text += f"  - {fp}\n"
            text += "\n"

        if signal_guard_warning:
            text += f"{signal_guard_warning}\n\n"

        # Show verification results
        for vr in verification_results:
            method = vr.get("method", "unknown")
            result = vr.get("result", {})
            text += f"## Verification [{method}]\n"
            if result.get("verified") or result.get("evidence_found"):
                text += f"  CONFIRMED"
                if result.get("evidence"):
                    text += f": {result['evidence'][:300]}"
                if result.get("alerts"):
                    text += f"\n  Alerts: {result['alerts']}"
            else:
                text += f"  NOT CONFIRMED"
                if result.get("error"):
                    text += f": {result['error'][:200]}"
            text += "\n\n"

        # Status-specific guidance
        if status == "verified":
            text += "**NEXT:** Write the report. Include reproduction steps, impact, and remediation advice.\n"
            
            # Send Telegram Alert
            alert_msg = f"🔥 *VULNERABILITY VERIFIED* 🔥\n\n"
            alert_msg += f"*Target:* `{target}`\n"
            alert_msg += f"*Type:* `{vuln_type.upper()}`\n"
            alert_msg += f"*Severity:* `{severity.upper()}`\n"
            alert_msg += f"*Title:* {title}\n"
            alert_msg += f"\n*Confidence:* {conf}%\n"
            alert_msg += f"*Impact:* {impact[:200]}..."
            send_telegram_msg(alert_msg)
        elif status == "high_confidence":
            text += "**NEXT:** Manually verify in browser, then report if confirmed.\n"
        elif status == "needs_review":
            text += "**NEXT:** POC matched but FP signals detected. Verify manually — is the impact real?\n"
        elif status == "needs_investigation":
            text += "**NEXT:** More testing needed. Try different payloads, check encoding, test in browser.\n"
        elif status == "likely_false_positive":
            text += "**NEXT:** Likely FP. Use mark_false_positive to record, or investigate further if you disagree.\n"
            text += "If partially interesting, use store_primitive instead.\n"

        # ── Auto-record learning outcome ──
        outcome_map = {
            "verified": "success", "high_confidence": "success",
            "needs_review": "partial", "needs_investigation": "partial",
            "likely_false_positive": "fail",
        }
        ctx = _load_target(target) if target else {}
        _record_learning({
            "technique": f"verify_{vuln_type}",
            "vuln_type": vuln_type,
            "outcome": outcome_map.get(status, "partial"),
            "target": target,
            "details": f"{title} — confidence {conf}/100 ({level})",
            "tech_stack": list(ctx.get("technologies", [])),
            "waf": ctx.get("waf", ""),
            "target_type": ctx.get("target_type", ""),
        })

        # ── Auto-log to hunt log ──
        if target:
            log_type = "finding" if status in ("verified", "high_confidence") else "tested"
            _append_huntlog(target, {
                "type": log_type,
                "phase": "verification",
                "message": f"[{status}] {vuln_type}: {title} (confidence: {conf}/100)",
                "severity": severity,
                "result": status,
            })

        return [{"type": "text", "text": text}]

    elif name == "mark_false_positive":
        target = arguments.get("target", "")
        finding_id = arguments.get("finding_id", "")
        vuln_type = arguments.get("vuln_type", "")
        reason = arguments.get("reason", "")

        if not reason:
            return [{"type": "text", "text": "reason is required — explain why this is a false positive."}]

        _record_fp({
            "target": target,
            "finding_id": finding_id,
            "vuln_type": vuln_type,
            "reason": reason,
        })

        # Update the finding if we can find it
        if target and finding_id:
            findings = _load_findings(target)
            for f in findings:
                if f.get("id") == finding_id:
                    f["verification"]["status"] = "false_positive"
                    f["verification"]["fp_reason"] = reason
                    break
            _save_findings(target, findings)

        # Also record as a learning outcome
        _record_learning({
            "technique": f"verify_{vuln_type}",
            "vuln_type": vuln_type,
            "outcome": "fail",
            "target": target,
            "details": f"FALSE POSITIVE: {reason}",
            "tech_stack": list(_load_target(target).get("technologies", [])) if target else [],
            "waf": _load_target(target).get("waf", "") if target else "",
        })

        fp_count = len(_load_fp_history())
        text = f"**Marked as false positive.** Reason: {reason}\n"
        text += f"Recorded in learning DB and FP history ({fp_count} total FPs tracked).\n"
        text += "Future findings of this type on this target will receive lower confidence scores."

        return [{"type": "text", "text": text}]

    elif name == "list_findings":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        findings = _load_findings(target)
        if not findings:
            return [{"type": "text", "text": f"No findings recorded for {target}."}]

        lines = [f"**{len(findings)} findings for {target}:**\n"]
        for f in findings:
            status = f.get("verification", {}).get("status", "unknown")
            icon = "+" if status == "verified" else "-"
            sev = f.get("severity", "?")
            lines.append(f"- **[{icon}] [{sev.upper()}] {f.get('vuln_type', '?')}** — {f.get('title', '')}")
            lines.append(f"  Verification: {status} | {f.get('timestamp', '')[:16]}")

        verified_count = sum(1 for f in findings if f.get("verification", {}).get("status") == "verified")
        lines.append(f"\n**{verified_count}/{len(findings)} verified**")

        return [{"type": "text", "text": "\n".join(lines)}]

    # ── Session Management ──

    elif name == "start_session":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        _active_session = {
            "target": target,
            "program": arguments.get("program", ""),
            "objective": arguments.get("objective", ""),
            "started": datetime.datetime.now().isoformat(),
            "started_ts": time.time(),
            "commands_run": [],
            "primitives_count": 0,
            "verified_findings": 0,
            "total_findings": 0,
        }

        # Save session to disk
        session_file = os.path.join(DATA_DIR, "sessions", f"session_{int(time.time())}.json")
        with open(session_file, "w") as sf:
            json.dump(_active_session, sf, indent=2)

        # Load existing context for this target
        ctx = _load_target(target)
        primitives = _load_primitives(target)
        findings = _load_findings(target)

        text = f"**Hunting session started for {target}.**\n\n"
        if arguments.get("program"):
            text += f"**Program:** {arguments['program']}\n"
        if arguments.get("objective"):
            text += f"**Objective:** {arguments['objective']}\n"
        # Check for existing hunt log (resumable hunt)
        hunt_entries = _read_huntlog(target, last_n=5)
        if hunt_entries:
            text += f"\n**RESUMING PREVIOUS HUNT** — {len(_read_huntlog(target, last_n=9999))} log entries found.\n"
            text += "Call `get_hunt_log` to see full state, TODOs, and where you left off.\n"
            # Show last plan/todo
            last_actionable = [e for e in hunt_entries if e.get("type") in ("todo", "plan")]
            if last_actionable:
                text += f"Last action item: {last_actionable[-1].get('message', '')}\n"

        text += f"\n**Target state:**\n"
        text += f"  - Context: {'loaded' if ctx else 'not set — fingerprint first'}\n"
        if ctx:
            text += f"    Tech: {', '.join(ctx.get('technologies', []))}, WAF: {ctx.get('waf', 'unknown')}\n"
        text += f"  - Primitives: {len(primitives)} stored\n"
        text += f"  - Findings: {len(findings)} recorded\n"

        if not ctx:
            text += f"\n**First steps:**\n"
            text += "  1. Fingerprint: whatweb, httpx -tech-detect, wafw00f\n"
            text += "  2. set_target_context with results\n"
            text += "  3. Intel: changelogs, hacktivity, scope changes\n"
        elif not hunt_entries:
            text += f"\n**First steps:**\n"
            text += "  1. Check what's NEW since last hunt (changelog, new features, scope changes)\n"
            text += "  2. search_cves for the tech stack\n"
            text += "  3. Start hunting — think like an attacker, not a scanner\n"

        learnings = _load_all_learnings()
        if learnings:
            text += f"\n**{len(learnings)} learning outcomes** available. Call get_playbook for adaptive strategy.\n"

        text += "\nRemember: you're a hacker, not a scanner. Understand the app, break assumptions, chain findings."

        return [{"type": "text", "text": text}]

    elif name == "session_status":
        if not _active_session:
            return [{"type": "text", "text": "No active session. Use start_session to begin."}]

        elapsed = time.time() - _active_session.get("started_ts", time.time())
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        text = f"**Session Status — {_active_session.get('target', '?')}**\n\n"
        text += f"**Duration:** {mins}m {secs}s\n"
        if _active_session.get("program"):
            text += f"**Program:** {_active_session['program']}\n"
        if _active_session.get("objective"):
            text += f"**Objective:** {_active_session['objective']}\n"
        text += f"**Commands run:** {len(_active_session.get('commands_run', []))}\n"
        text += f"**Primitives stored:** {_active_session.get('primitives_count', 0)}\n"
        text += f"**Findings:** {_active_session.get('total_findings', 0)} total, "
        text += f"{_active_session.get('verified_findings', 0)} verified\n"

        cmds = _active_session.get("commands_run", [])
        if cmds:
            text += f"\n**Recent commands:**\n"
            for cmd in cmds[-5:]:
                text += f"  - [{cmd.get('status', '?')}] `{cmd.get('command', '')[:60]}` ({cmd.get('duration', 0)}s)\n"

        # Advisory count
        total_advisories = sum(c.get("advisories", 0) for c in cmds)
        if total_advisories:
            text += f"\n**{total_advisories} smart advisories** generated during this session."

        return [{"type": "text", "text": text}]

    # ── Hunt Log ──

    elif name == "hunt_log":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        entry = {
            "type": arguments.get("type", "note"),
            "phase": arguments.get("phase", ""),
            "message": arguments.get("message", ""),
        }
        if arguments.get("data"):
            entry["data"] = arguments["data"]
        if arguments.get("severity"):
            entry["severity"] = arguments["severity"]
        if arguments.get("result"):
            entry["result"] = arguments["result"]

        _append_huntlog(target, entry)

        count = len(_read_huntlog(target, last_n=9999))
        return [{"type": "text", "text": f"Logged [{entry['type']}] for {target}. Total entries: {count}."}]

    elif name == "get_hunt_log":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        last_n = min(int(arguments.get("last_n", 50)), 200)
        entries = _read_huntlog(target, last_n=last_n)

        if not entries:
            return [{"type": "text", "text": f"No hunt log for {target}. Start logging with hunt_log."}]

        # Build full state reconstruction
        header = f"# Hunt Log — {target}\n"
        header += f"**{len(entries)} entries** (showing last {last_n})\n"

        # Also pull in target context and primitive/finding counts for full picture
        ctx = _load_target(target)
        primitives = _load_primitives(target)
        findings = _load_findings(target)

        header += f"\n**Target Context:** {'loaded' if ctx else 'not set'}"
        if ctx:
            header += f" — tech: {', '.join(ctx.get('technologies', []))}, waf: {ctx.get('waf', 'unknown')}"
        header += f"\n**Primitives:** {len(primitives)} stored"
        header += f"\n**Findings:** {len(findings)} recorded"

        # Show uncompleted TODOs
        todos = [e for e in entries if e.get("type") == "todo"]
        if todos:
            header += f"\n\n**Outstanding TODOs:**"
            for t in todos[-10:]:
                header += f"\n  - {t.get('message', '')}"

        header += "\n\n---\n"

        formatted = _format_huntlog(entries)
        return [{"type": "text", "text": header + formatted}]

    elif name == "clear_hunt_log":
        target = arguments.get("target", "")
        if not target:
            return [{"type": "text", "text": "A target is required."}]

        fpath = _huntlog_file(target)
        if os.path.exists(fpath):
            os.remove(fpath)
            return [{"type": "text", "text": f"Hunt log cleared for {target}."}]
        return [{"type": "text", "text": f"No hunt log found for {target}."}]

    # ── Learning Engine ──

    elif name == "record_outcome":
        technique = arguments.get("technique", "")
        outcome = arguments.get("outcome", "")
        if not technique or not outcome:
            return [{"type": "text", "text": "technique and outcome are required."}]

        entry = {
            "technique": technique,
            "vuln_type": arguments.get("vuln_type", ""),
            "outcome": outcome,
            "tech_stack": arguments.get("tech_stack", []),
            "waf": arguments.get("waf", ""),
            "target_type": arguments.get("target_type", ""),
            "target": arguments.get("target", ""),
            "details": arguments.get("details", ""),
            "bypass_used": arguments.get("bypass_used", ""),
        }

        _record_learning(entry)

        all_data = _load_all_learnings()
        total = len(all_data)
        successes = sum(1 for d in all_data if d.get("outcome") == "success")

        icon = {"success": "+", "fail": "-", "blocked": "x", "partial": "~"}.get(outcome, "?")
        text = f"**[{icon}] Outcome recorded:** {technique} → {outcome}\n"
        if arguments.get("details"):
            text += f"Details: {arguments['details']}\n"
        if arguments.get("bypass_used"):
            text += f"Bypass: {arguments['bypass_used']}\n"
        text += f"\nLearning DB: {total} total outcomes, {successes} successes ({successes/total:.0%} overall rate)"

        return [{"type": "text", "text": text}]

    elif name == "get_playbook":
        tech_stack = arguments.get("tech_stack", [])
        waf = arguments.get("waf", "")
        target_type = arguments.get("target_type", "")

        playbook = _generate_playbook(tech_stack, waf, target_type)
        return [{"type": "text", "text": playbook}]

    elif name == "learning_stats":
        all_data = _load_all_learnings()
        if not all_data:
            return [{"type": "text", "text": "No learning data yet. Use record_outcome after each test."}]

        total = len(all_data)
        by_outcome = {}
        by_technique = {}
        by_vuln = {}
        by_waf = {}
        targets_seen = set()

        for entry in all_data:
            outcome = entry.get("outcome", "unknown")
            technique = entry.get("technique", "unknown")
            vuln = entry.get("vuln_type", "") or "unspecified"
            waf = entry.get("waf", "") or "none"
            target = entry.get("target", "")

            by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

            if technique not in by_technique:
                by_technique[technique] = {"success": 0, "fail": 0, "blocked": 0, "partial": 0, "total": 0}
            by_technique[technique][outcome] = by_technique[technique].get(outcome, 0) + 1
            by_technique[technique]["total"] += 1

            if vuln != "unspecified":
                if vuln not in by_vuln:
                    by_vuln[vuln] = {"success": 0, "total": 0}
                by_vuln[vuln]["total"] += 1
                if outcome == "success":
                    by_vuln[vuln]["success"] += 1

            if waf != "none":
                if waf not in by_waf:
                    by_waf[waf] = {"success": 0, "blocked": 0, "total": 0}
                by_waf[waf]["total"] += 1
                if outcome == "success":
                    by_waf[waf]["success"] += 1
                elif outcome == "blocked":
                    by_waf[waf]["blocked"] += 1

            if target:
                targets_seen.add(target)

        text = f"# BountyBud Learning Stats\n\n"
        text += f"**Total outcomes:** {total}\n"
        text += f"**Targets tested:** {len(targets_seen)}\n"
        text += f"**Outcomes:** " + ", ".join(f"{k}: {v}" for k, v in sorted(by_outcome.items())) + "\n"

        # Top techniques by success rate (min 2 attempts)
        text += f"\n## Technique Effectiveness\n"
        ranked_tech = []
        for tech, stats in by_technique.items():
            if stats["total"] >= 1:
                rate = stats["success"] / stats["total"]
                ranked_tech.append((rate, stats["total"], tech, stats))
        ranked_tech.sort(key=lambda x: (-x[0], -x[1]))

        for rate, total_t, tech, stats in ranked_tech[:20]:
            bar = "+" * stats["success"] + "-" * stats["fail"] + "x" * stats.get("blocked", 0) + "~" * stats.get("partial", 0)
            text += f"  {tech:30s} {stats['success']}/{total_t} ({rate:.0%}) [{bar}]\n"

        # Vuln type success rates
        if by_vuln:
            text += f"\n## Vulnerability Class Success Rates\n"
            ranked_vuln = [(v["success"] / v["total"], v["total"], k, v) for k, v in by_vuln.items()]
            ranked_vuln.sort(key=lambda x: (-x[0], -x[1]))
            for rate, total_v, vuln, stats in ranked_vuln:
                text += f"  {vuln:25s} {stats['success']}/{total_v} ({rate:.0%})\n"

        # WAF encounter stats
        if by_waf:
            text += f"\n## WAF Encounters\n"
            for waf_name, stats in sorted(by_waf.items()):
                block_rate = stats["blocked"] / stats["total"] if stats["total"] else 0
                text += f"  {waf_name:20s} {stats['total']} encounters, {stats['blocked']} blocked ({block_rate:.0%}), {stats['success']} successful\n"

        return [{"type": "text", "text": text}]

    elif name == "export_training_data":
        fmt = arguments.get("format", "raw")
        all_data = _load_all_learnings()

        if not all_data:
            return [{"type": "text", "text": "No learning data to export."}]

        os.makedirs(os.path.join(DATA_DIR, "exports"), exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_file = os.path.join(DATA_DIR, "exports", f"training_{timestamp}.jsonl")
        output_file = arguments.get("output_file", default_file)

        if fmt == "raw":
            with open(output_file, "w") as f:
                for entry in all_data:
                    f.write(json.dumps(entry, default=str) + "\n")

        elif fmt == "training":
            # Generate instruction/response pairs for fine-tuning
            training_pairs = []
            for entry in all_data:
                tech = ", ".join(entry.get("tech_stack", [])) or "unknown"
                waf = entry.get("waf", "") or "none"
                vuln = entry.get("vuln_type", "") or "general"
                technique = entry.get("technique", "")
                outcome = entry.get("outcome", "")
                details = entry.get("details", "")
                bypass = entry.get("bypass_used", "")

                instruction = (
                    f"You are testing a {entry.get('target_type', 'web')} application "
                    f"with tech stack: {tech}. WAF: {waf}. "
                    f"You want to test for {vuln} using {technique}."
                )

                if outcome == "success":
                    response = f"This technique was SUCCESSFUL. {details}"
                    if bypass:
                        response += f" WAF bypass used: {bypass}."
                    response += " Record this as a verified finding and continue testing related endpoints."
                elif outcome == "blocked":
                    response = (
                        f"This technique was BLOCKED by {waf}. {details} "
                        f"Adapt by: trying encoding bypasses, switching to business logic testing, "
                        f"or hunting for origin IP to bypass WAF."
                    )
                elif outcome == "partial":
                    response = (
                        f"PARTIAL result — interesting but not fully exploitable yet. {details} "
                        f"Store this as a primitive and look for chaining opportunities."
                    )
                else:
                    response = (
                        f"This technique FAILED against this target. {details} "
                        f"Move to the next technique in the playbook."
                    )

                training_pairs.append({
                    "instruction": instruction,
                    "response": response,
                    "metadata": {
                        "technique": technique,
                        "vuln_type": vuln,
                        "outcome": outcome,
                        "tech_stack": entry.get("tech_stack", []),
                        "waf": waf,
                    },
                })

            with open(output_file, "w") as f:
                for pair in training_pairs:
                    f.write(json.dumps(pair) + "\n")

        elif fmt == "summary":
            # Aggregated summary as JSON
            from collections import Counter, defaultdict
            summary = {
                "total_outcomes": len(all_data),
                "date_range": {
                    "earliest": min((e.get("timestamp", "") for e in all_data), default=""),
                    "latest": max((e.get("timestamp", "") for e in all_data), default=""),
                },
                "outcomes": dict(Counter(e.get("outcome", "unknown") for e in all_data)),
                "targets_tested": len(set(e.get("target", "") for e in all_data if e.get("target"))),
                "techniques_used": dict(Counter(e.get("technique", "") for e in all_data)),
                "vuln_types_tested": dict(Counter(e.get("vuln_type", "") for e in all_data if e.get("vuln_type"))),
                "waf_encounters": dict(Counter(e.get("waf", "") for e in all_data if e.get("waf"))),
                "tech_stacks_seen": dict(Counter(t for e in all_data for t in e.get("tech_stack", []))),
                "success_by_technique": {},
                "patterns": _detect_cross_target_patterns(all_data),
            }

            # Success rates per technique
            tech_outcomes = defaultdict(lambda: {"success": 0, "total": 0})
            for e in all_data:
                t = e.get("technique", "")
                if t:
                    tech_outcomes[t]["total"] += 1
                    if e.get("outcome") == "success":
                        tech_outcomes[t]["success"] += 1
            summary["success_by_technique"] = {
                t: {"success": s["success"], "total": s["total"], "rate": round(s["success"]/s["total"], 3)}
                for t, s in tech_outcomes.items()
            }

            output_file = output_file.replace(".jsonl", ".json")
            with open(output_file, "w") as f:
                json.dump(summary, f, indent=2, default=str)

        file_size = os.path.getsize(output_file)
        return [{"type": "text", "text": (
            f"**Exported {len(all_data)} records** in '{fmt}' format.\n"
            f"**File:** {output_file}\n"
            f"**Size:** {file_size:,} bytes\n\n"
            f"This data can be used for:\n"
            f"- Fine-tuning models on real hunting outcomes (use 'training' format)\n"
            f"- Analyzing patterns and improving methodology (use 'summary' format)\n"
            f"- Importing into other systems or sharing with team (use 'raw' format)"
        )}]

    elif name == "web_research":
        url = arguments.get("url", "")
        if not url:
            return [{"type": "text", "text": "URL is required."}]

        extract_mode = arguments.get("extract_mode", "text")
        max_length = min(int(arguments.get("max_length", 5000)), 15000)

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            req.add_header("Accept", "text/html,application/json,*/*")
            with urllib.request.urlopen(req, timeout=15) as resp:
                content_type = resp.headers.get("Content-Type", "")
                raw = resp.read().decode(errors="ignore")
                resp_headers = dict(resp.headers)
                status = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="ignore") if e.fp else ""
            resp_headers = dict(e.headers)
            status = e.code
            content_type = e.headers.get("Content-Type", "")
        except Exception as e:
            return [{"type": "text", "text": f"Fetch error: {e}"}]

        parts = [f"**{status}** — {url}\n"]

        if extract_mode == "headers" or extract_mode == "full":
            parts.append("**Response Headers:**\n```")
            for k, v in resp_headers.items():
                parts.append(f"{k}: {v}")
            parts.append("```\n")

        if extract_mode in ("text", "full"):
            # Strip HTML tags for readability
            if "html" in content_type.lower():
                # Simple HTML stripping
                text = re.sub(r'<script[^>]*>.*?</script>', '', raw, flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r'<[^>]+>', ' ', text)
                text = re.sub(r'\s+', ' ', text).strip()
            else:
                text = raw

            if len(text) > max_length:
                text = text[:max_length] + f"\n\n... [truncated at {max_length} chars]"
            parts.append(f"**Content:**\n```\n{text}\n```")

        if extract_mode == "links" or extract_mode == "full":
            # Extract all links
            links = re.findall(r'href=["\']([^"\']+)["\']', raw)
            if links:
                unique_links = list(dict.fromkeys(links))[:50]  # Dedupe, limit
                parts.append(f"\n**Links ({len(unique_links)}):**")
                for link in unique_links:
                    parts.append(f"  - {link}")

        # Smart analysis
        advisories = _analyze_output(raw, "")
        if advisories:
            parts.append("\n**━━━ BOUNTYBUD ANALYSIS ━━━**")
            for adv in advisories:
                parts.append(adv)

        return [{"type": "text", "text": "\n".join(parts)}]

    # ── CVE Tools ──

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

    # ── Mitmproxy Tools ──

    elif name == "start_proxy":
        port = int(arguments.get("port", PROXY_PORT))
        try:
            _start_mitmproxy(port)
            return [{"type": "text", "text": (
                f"**mitmproxy started on localhost:{port}**\n\n"
                f"Configure browser/tools to use this proxy:\n"
                f"- HTTP/HTTPS Proxy: localhost:{port}\n"
                f"- CA cert: http://mitm.it (visit through proxy)\n\n"
                f"Use `capture_requests` to see intercepted traffic.\n"
                f"Use `replay_request` to modify and resend requests."
            )}]
        except Exception as e:
            return [{"type": "text", "text": f"Error starting proxy: {e}"}]

    elif name == "capture_requests":
        try:
            flows = _mitm_api_get("/flows")
            if not flows:
                return [{"type": "text", "text": "No requests captured yet. Browse the target through the proxy."}]

            lines = [f"**{len(flows)} requests captured:**\n"]
            for flow in flows[-30:]:  # Last 30
                req = flow.get("request", {})
                resp = flow.get("response", {})
                method = req.get("method", "?")
                url = req.get("pretty_url", "?")
                status = resp.get("status_code", "?")
                content_type = resp.get("headers", {}).get("content-type", "")[:30] if resp.get("headers") else ""
                lines.append(f"- `{method} {url}` → {status} {content_type}")
            return [{"type": "text", "text": "\n".join(lines)}]
        except Exception as e:
            return [{"type": "text", "text": f"Error (is mitmproxy running?): {e}"}]

    elif name == "replay_request":
        method = arguments.get("method", "GET")
        url = arguments.get("url", "")
        headers = arguments.get("headers", {})
        body = arguments.get("body", "")

        if not url:
            return [{"type": "text", "text": "URL is required."}]

        inferred_target = _active_session.get("target", "") if _active_session else ""
        resp = _http_request(method, url, headers, body)
        resp_headers_str = "\n".join(f"{k}: {v}" for k, v in resp.get("headers", {}).items())

        advisories = _analyze_output(
            resp.get("body", ""), resp_headers_str,
            command=f"replay {method} {url}", target=inferred_target,
        )

        parts = [
            f"**{method} {url}**\n",
            f"**Status:** {resp['status']}\n",
            f"**Response Headers:**\n```\n{resp_headers_str}\n```\n",
            f"**Body (first 3000 chars):**\n```\n{resp.get('body', '')}\n```",
        ]

        if advisories:
            parts.append("\n**━━━ BOUNTYBUD ANALYSIS ━━━**")
            for adv in advisories:
                parts.append(adv)
            parts.append("**━━━━━━━━━━━━━━━━━━━━━━━━━**")

        # Track in session
        if _active_session:
            _active_session.setdefault("commands_run", []).append({
                "command": f"replay {method} {url}"[:200],
                "status": "completed",
                "duration": 0,
                "advisories": len(advisories),
                "timestamp": datetime.datetime.now().isoformat(),
            })

        return [{"type": "text", "text": "\n".join(parts)}]

    elif name == "cors_test":
        url = arguments.get("url", "")
        origin = arguments.get("origin", "https://attacker.example.com")
        creds = arguments.get("credentials", True)

        if not url:
            return [{"type": "text", "text": "URL is required."}]

        headers = {"Origin": origin, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        if creds:
            headers["Cookie"] = "placeholder=value"

        # GET request
        resp = _http_request("GET", url, headers)

        # Also test preflight OPTIONS
        options_headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        }
        preflight = _http_request("OPTIONS", url, options_headers)

        # Analyze CORS headers (case-insensitive lookup)
        resp_h = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        pre_h = {k.lower(): v for k, v in preflight.get("headers", {}).items()}

        acao = resp_h.get("access-control-allow-origin", "")
        acac = resp_h.get("access-control-allow-credentials", "")
        pre_acao = pre_h.get("access-control-allow-origin", "")
        pre_methods = pre_h.get("access-control-allow-methods", "")
        pre_headers = pre_h.get("access-control-allow-headers", "")

        # Vulnerability assessment
        findings = []
        if acao == origin:
            findings.append("CRITICAL: Origin is reflected in ACAO! Attacker-controlled origin accepted.")
            if acac.lower() == "true":
                findings.append("CRITICAL: Credentials allowed with reflected origin = FULL ACCOUNT TAKEOVER via malicious page.")
        elif acao == "*":
            findings.append("WARNING: Wildcard ACAO (*). Cross-origin reads possible (but not with credentials).")
        elif acao == "null":
            findings.append("WARNING: null origin accepted. Exploitable via sandboxed iframe (data: URI, file://).")
        else:
            findings.append("OK: CORS properly restricted for this origin.")

        if pre_acao:
            findings.append(f"Preflight allows origin: {pre_acao}")
        if pre_methods:
            findings.append(f"Preflight allows methods: {pre_methods}")

        text = f"**CORS Test: {url}**\n"
        text += f"**Tested Origin:** {origin}\n\n"
        text += f"**GET Response:**\n"
        text += f"  - Access-Control-Allow-Origin: `{acao or '(not set)'}`\n"
        text += f"  - Access-Control-Allow-Credentials: `{acac or '(not set)'}`\n"
        text += f"  - Status: {resp['status']}\n\n"
        text += f"**OPTIONS Preflight:**\n"
        text += f"  - Allow-Origin: `{pre_acao or '(not set)'}`\n"
        text += f"  - Allow-Methods: `{pre_methods or '(not set)'}`\n"
        text += f"  - Allow-Headers: `{pre_headers or '(not set)'}`\n"
        text += f"  - Status: {preflight['status']}\n\n"
        text += f"**Assessment:**\n"
        for f in findings:
            text += f"  - {f}\n"

        # Session tracking
        if _active_session:
            _active_session.setdefault("commands_run", []).append({
                "command": f"cors_test {url}"[:200],
                "status": "completed", "duration": 0,
                "advisories": len(findings),
                "timestamp": datetime.datetime.now().isoformat(),
            })

        # Auto-log significant findings to hunt log
        inferred_target = _active_session.get("target", "") if _active_session else ""
        if any("CRITICAL" in f for f in findings) and inferred_target:
            _append_huntlog(inferred_target, {
                "type": "finding", "phase": "hunting",
                "message": f"CORS misconfig on {url}: origin reflection with credentials",
                "severity": "high",
            })

        return [{"type": "text", "text": text}]

    elif name == "header_injection_test":
        url = arguments.get("url", "")
        header = arguments.get("header", "")
        value = arguments.get("value", "")

        if not all([url, header, value]):
            return [{"type": "text", "text": "URL, header, and value are required."}]

        # Make baseline request (no injection)
        baseline = _http_request("GET", url, {"User-Agent": "Mozilla/5.0"})

        # Make injected request
        injected = _http_request("GET", url, {header: value, "User-Agent": "Mozilla/5.0"})

        # Compare
        status_changed = baseline["status"] != injected["status"]
        body_changed = baseline["body"][:500] != injected["body"][:500]
        size_diff = len(injected["body"]) - len(baseline["body"])

        text = f"**Header Injection Test: `{header}: {value}`**\n"
        text += f"**Target:** {url}\n\n"
        text += f"**Baseline:** status={baseline['status']}, body_size={len(baseline['body'])}\n"
        text += f"**Injected:** status={injected['status']}, body_size={len(injected['body'])}\n\n"

        if status_changed:
            text += f"**STATUS CHANGED:** {baseline['status']} → {injected['status']} — behavior differs with injected header!\n"
        if body_changed:
            text += f"**BODY CHANGED:** Response differs by {size_diff} bytes — header is influencing response!\n"
        if not status_changed and not body_changed:
            text += "**No change detected** — header appears to be ignored.\n"

        text += f"\n**Injected Response Body (first 1500 chars):**\n```\n{injected['body'][:1500]}\n```\n"

        # Check for common indicators — with full context
        inferred_target = _active_session.get("target", "") if _active_session else ""
        advisories = _analyze_output(
            injected["body"], "", command=f"header_inject {header}:{value} {url}", target=inferred_target,
        )
        if advisories:
            text += "\n**━━━ BOUNTYBUD ANALYSIS ━━━**\n"
            for adv in advisories:
                text += adv + "\n"

        # Session tracking
        if _active_session:
            _active_session.setdefault("commands_run", []).append({
                "command": f"header_injection_test {header}:{value} {url}"[:200],
                "status": "completed", "duration": 0,
                "advisories": len(advisories),
                "timestamp": datetime.datetime.now().isoformat(),
            })
            # Auto-log if behavior changed
            if (status_changed or body_changed) and inferred_target:
                _append_huntlog(inferred_target, {
                    "type": "finding", "phase": "hunting",
                    "message": f"Header {header}:{value} changes behavior on {url} (status: {baseline['status']}→{injected['status']})",
                    "severity": "medium",
                })

        return [{"type": "text", "text": text}]

    elif name == "check_scope_updates":
        try:
            import os
            from scope_monitor import ScopeMonitor
            
            monitor = ScopeMonitor()
            h1_handles = os.getenv("H1_HANDLES", "").split(",")
            bc_codes = os.getenv("BC_CODES", "").split(",")
            
            # Clean lists
            h1_handles = [h.strip() for h in h1_handles if h.strip()]
            bc_codes = [c.strip() for c in bc_codes if c.strip()]
            
            if not h1_handles and not bc_codes:
                return [{"type": "text", "text": "No H1_HANDLES or BC_CODES configured in environment."}]
                
            new_assets = monitor.check_for_updates(h1_handles, bc_codes)
            
            if not new_assets:
                return [{"type": "text", "text": "Scope check complete. No new assets detected."}]
                
            lines = [f"**🔥 {len(new_assets)} NEW ASSETS DETECTED 🔥**\n"]
            for item in new_assets:
                lines.append(f"- **{item['platform'].upper()}**: `{item['program']}` -> `{item['asset']}`")
            
            lines.append("\nBountyBud has automatically triggered the Discovery phase for these assets.")
            
            # Trigger auto-discovery thread for each (if domain-like)
            # Since this is the MCP server, we can't easily spawn threads that call back into tools,
            # but the scope_monitor logic here is for the user report.
            # The background thread in api_worker.py handles the actual auto-triggering.
            
            return [{"type": "text", "text": "\n".join(lines)}]
            
        except Exception as e:
            return [{"type": "text", "text": f"Error checking scope updates: {e}"}]

    elif name == "run_autonomous_hunt":
        target = arguments.get("target", "")
        log_file = arguments.get("log_file", "")
        profile = arguments.get("profile", "STEALTH")

        if not target:
            return [{"type": "text", "text": "Target domain is required."}]

        try:
            from orchestrator import BountyBudPipeline
            pipeline = BountyBudPipeline(target, profile=profile)

            # Fetch logs
            raw_logs = ""
            if log_file and os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    raw_logs = f.read(10_000_000)
            else:
                # Fallback to mitmproxy logs if they exist
                mitm_log = os.path.expanduser("~/.bountybud/proxy_logs.json")
                if os.path.exists(mitm_log):
                    with open(mitm_log, 'r') as f:
                        raw_logs = f.read(10_000_000)
                else:
                    return [{"type": "text", "text": "No traffic logs found. Please browse the target with mitmproxy first or provide a log_file."}]

            # Run the autonomous pipeline
            findings = pipeline.run_autonomous_funnel(raw_logs)

            if not findings:
                return [{"type": "text", "text": "Autonomous pipeline completed. No vulnerabilities confirmed by the Strategist."}]

            lines = [f"**🔥 {len(findings)} VULNERABILITIES CONFIRMED BY THE STRATEGIST 🔥**\n"]
            for f in findings:
                hyp = f["hypothesis"]
                ass = f["assessment"]
                lines.append(f"### Finding in Zone {f['zone']}")
                lines.append(f"**Hypothesis:** {hyp.get('hypothesis')}")
                lines.append(f"**Confidence:** {ass.get('confidence') * 100:.1f}%")
                lines.append(f"**Reasoning:** {ass.get('reasoning')}")
                lines.append(f"**False Positive Check:** {ass.get('false_positive_check')}")
                lines.append("---")

            # Log success to hunt log
            _append_huntlog(target, {
                "type": "status", "phase": "verification",
                "message": f"Autonomous pipeline completed. Found {len(findings)} confirmed vulnerabilities.",
            })

            return [{"type": "text", "text": "\n".join(lines)}]

        except Exception as e:
            return [{"type": "text", "text": f"Error running autonomous pipeline: {e}"}]

    elif name == "auth_bypass_test":
        url = arguments.get("url", "")
        technique = arguments.get("technique", "no-auth")

        if not url:
            return [{"type": "text", "text": "URL is required."}]

        results = []

        if technique == "no-auth":
            resp = _http_request("GET", url, {"User-Agent": "Mozilla/5.0"})
            if resp["status"] == 200:
                results.append(f"**NO AUTH → 200 OK** — Endpoint accessible without authentication!")
                results.append("This may be a valid finding if the endpoint should require auth.")
            elif resp["status"] in (401, 403):
                results.append(f"**NO AUTH → {resp['status']}** — Auth is enforced (expected).")
            else:
                results.append(f"**NO AUTH → {resp['status']}** — Unexpected status. Investigate.")
            results.append(f"Body preview: `{resp['body'][:200]}`")

        elif technique == "method-switch":
            results.append("**HTTP Method Switch Test:**")
            for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
                resp = _http_request(m, url, {"User-Agent": "Mozilla/5.0"})
                marker = "***" if resp["status"] == 200 else ""
                results.append(f"  {m:8s} → {resp['status']} {marker}")
            results.append("\n*** = potential bypass (200 on unexpected method)")

        elif technique == "param-inject":
            results.append("**Parameter Injection Test:**")
            for param_url in [
                f"{url}{'&' if '?' in url else '?'}admin=true",
                f"{url}{'&' if '?' in url else '?'}role=admin",
                f"{url}{'&' if '?' in url else '?'}debug=1",
                f"{url}{'&' if '?' in url else '?'}internal=true",
                f"{url}{'&' if '?' in url else '?'}bypass=1",
            ]:
                resp = _http_request("GET", param_url, {"User-Agent": "Mozilla/5.0"})
                marker = "***" if resp["status"] == 200 else ""
                param = param_url.split("?")[-1].split("&")[-1]
                results.append(f"  ?{param:20s} → {resp['status']} {marker}")

        elif technique == "header-mangle":
            results.append("**Header Manipulation Test:**")
            mangles = [
                ("X-Original-URL", "/admin"),
                ("X-Rewrite-URL", "/admin"),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Forwarded-Host", "localhost"),
                ("X-Custom-IP-Authorization", "127.0.0.1"),
                ("X-Real-IP", "127.0.0.1"),
                ("Referer", url.replace("://", "://admin.")),
            ]
            baseline = _http_request("GET", url, {"User-Agent": "Mozilla/5.0"})
            for h, v in mangles:
                resp = _http_request("GET", url, {h: v, "User-Agent": "Mozilla/5.0"})
                changed = "CHANGED" if resp["status"] != baseline["status"] else ""
                results.append(f"  {h}: {v} → {resp['status']} {changed}")

        # Session tracking + auto-log significant findings
        if _active_session:
            _active_session.setdefault("commands_run", []).append({
                "command": f"auth_bypass_test {technique} {url}"[:200],
                "status": "completed", "duration": 0,
                "advisories": sum(1 for r in results if "***" in r or "200 OK" in r),
                "timestamp": datetime.datetime.now().isoformat(),
            })
            inferred_target = _active_session.get("target", "")
            if any("200 OK" in r or "***" in r or "CHANGED" in r for r in results) and inferred_target:
                _append_huntlog(inferred_target, {
                    "type": "finding", "phase": "hunting",
                    "message": f"Auth bypass ({technique}) potential on {url}",
                    "severity": "high",
                })

        return [{"type": "text", "text": "\n".join(results)}]

    return [{"type": "text", "text": f"Unknown tool: {name}"}]


def _read_resource(uri: str) -> list[dict]:
    if uri == "bountybud://taxonomy":
        resp = _api_get("/taxonomy")
        return [{"uri": uri, "mimeType": "application/json", "text": json.dumps(resp.get("data", {}), indent=2)}]
    elif uri == "bountybud://manifest":
        resp = _api_get("/manifest")
        return [{"uri": uri, "mimeType": "application/json", "text": json.dumps(resp.get("data", {}), indent=2)}]
    return []


# ── JSON-RPC Handler ────────────────────────────────────────

def _handle_message(msg: dict) -> dict | None:
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
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": CORE_TOOLS}}

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
