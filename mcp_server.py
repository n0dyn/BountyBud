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

API_BASE = os.getenv("BOUNTYBUD_URL", "https://bb.nxit.cc/api/kb").rstrip("/")
API_KEY = os.getenv("BOUNTYBUD_KEY", "")

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


def _analyze_output(stdout: str, stderr: str) -> list[str]:
    """Analyze tool output for WAF signatures, errors, and interesting findings."""
    advisories = []
    combined = (stdout + " " + stderr).lower()

    # Check WAF signatures
    for pattern, (waf_name, advice) in WAF_SIGNATURES.items():
        if re.search(pattern, combined, re.IGNORECASE):
            advisories.append(f"⚠️ WAF DETECTED [{waf_name}]: {advice}")
            break  # Only report first WAF match

    # Check negative signals
    for pattern, advice in NEGATIVE_SIGNAL_PATTERNS.items():
        if re.search(pattern, combined, re.IGNORECASE):
            advisories.append(f"⚠️ {advice}")

    # Check positive signals (interesting findings)
    for pattern, note in POSITIVE_SIGNAL_PATTERNS.items():
        if re.search(pattern, stdout + " " + stderr, re.IGNORECASE):
            advisories.append(f"🔥 {note}")

    return advisories


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
    categories: dict[str, list[str]] = {}
    for name, info in sorted(TOOLBELT.items()):
        cat = info["cat"]
        if cat not in categories:
            categories[cat] = []
        installed = "Y" if _check_installed(info["bin"]) else "-"
        categories[cat].append(f"  [{installed}] {name:18s} {info['desc']}")

    lines = ["# BountyBud Toolbelt\n"]
    lines.append("[Y] = installed, [-] = not found on PATH\n")

    cat_order = ["recon", "network", "vuln", "exploit", "cms", "osint", "cloud",
                 "auth", "proxy", "binary", "forensics", "util"]
    cat_names = {
        "recon": "Reconnaissance", "network": "Network", "vuln": "Vulnerability Scanning",
        "exploit": "Exploitation Frameworks", "cms": "CMS", "osint": "OSINT",
        "cloud": "Cloud Security", "auth": "Auth & Cracking",
        "proxy": "Proxy & Interception", "binary": "Binary / RE", "forensics": "Forensics",
        "util": "Utility",
    }

    for cat in cat_order:
        if cat in categories:
            lines.append(f"\n## {cat_names.get(cat, cat)}\n")
            lines.extend(categories[cat])

    installed = sum(1 for t in TOOLBELT.values() if _check_installed(t["bin"]))
    lines.append(f"\n**{installed}/{len(TOOLBELT)} tools available**")
    lines.append("\nUse `search_knowledge` for detailed usage and `execute_tool` to run.")
    return "\n".join(lines)


def _run_command(command: str, timeout: int = 300, workdir: str | None = None) -> dict:
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


# ── MCP Protocol ──────────────────────────────────────────────

PROTOCOL_VERSION = "2024-11-05"

SERVER_INFO = {"name": "BountyBud", "version": "2.0.0"}

CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"subscribe": False, "listChanged": False},
}

INSTRUCTIONS = (
    "BountyBud v2 — Verification-driven bug bounty AI agent with 130+ doc knowledge base, "
    "local tool execution, target profiling, finding verification, and primitive chaining.\n\n"

    "═══ WORKFLOW — FOLLOW THIS ORDER ═══\n\n"

    "PHASE 0 — SETUP:\n"
    "  1) get_toolbelt → see installed tools (call ONCE at session start)\n"
    "  2) start_session → initialize a hunting session for the target\n"
    "  3) set_target_context → fingerprint target BEFORE any active scanning\n"
    "     Run: whatweb, httpx -tech-detect, wafw00f FIRST\n"
    "     Store results with set_target_context so all future tool selection is informed\n\n"

    "PHASE 1 — INTEL (before touching the target):\n"
    "  - Check changelog/release notes for recent features\n"
    "  - Check HackerOne/Bugcrowd hacktivity for past disclosed bugs\n"
    "  - Check scope changes in program policy\n"
    "  - search_cves for the fingerprinted tech stack\n"
    "  - Search BB knowledge: 'change-detection-monitoring'\n\n"

    "PHASE 2 — DISCOVERY (automated, light touch):\n"
    "  - Subdomain enum → HTTP probe → tech fingerprint\n"
    "  - JS crawl → endpoint extraction\n"
    "  - Use get_target_context to CHECK what tech stack you found\n"
    "  - ONLY run scanners relevant to the detected stack\n"
    "  - Store interesting observations with store_primitive\n\n"

    "PHASE 3 — HUNTING (manual, proxy-driven):\n"
    "  - Use the app as a real user, capture flows in mitmproxy\n"
    "  - Test business logic: IDOR, auth bypass, workflow skip, price manipulation\n"
    "  - Every interesting observation → store_primitive\n"
    "  - Periodically: analyze_chains to find multi-primitive exploits\n\n"

    "PHASE 4 — VERIFICATION (mandatory before reporting):\n"
    "  - EVERY finding MUST go through verify_finding before reporting\n"
    "  - verify_finding requires a reproducible curl/script + evidence\n"
    "  - For XSS: headless browser verification available (fires real alert?)\n"
    "  - NO finding is valid without POC. 'POC or GTFO.'\n\n"

    "═══ CRITICAL RULES ═══\n\n"

    "TOOL EXECUTION — SMALL SCOPE, SHORT TIMEOUT:\n"
    "- NEVER broad-scope a root domain. Break into individual subdomains/batches of 5-10.\n"
    "- Timeouts: recon 60-120s, vuln scan 120s, single-host scan 180s max.\n"
    "- FILTER before processing: pipe through grep/awk/head.\n"
    "- CHAIN small steps: discover → filter → scan filtered → analyze.\n"
    "- BAD: gau --subs target.com | nuclei (will timeout)\n"
    "- GOOD: subfinder -d target.com -silent | head -50 | httpx -silent > live.txt\n"
    "        nuclei -u https://app.target.com -tags exposure,misconfig -timeout 5\n\n"

    "SMART OUTPUT — BountyBud auto-analyzes tool output:\n"
    "- WAF detection: if a WAF is detected, the output will include bypass advice.\n"
    "- Negative signals: 403/401/429/timeouts get actionable advice appended.\n"
    "- Positive signals: SQLi errors, stack traces, secrets, JWTs are flagged.\n"
    "- READ the advisories in tool output. They tell you what to do next.\n\n"

    "TARGET CONTEXT — TECH-AWARE HUNTING:\n"
    "- After fingerprinting, call set_target_context with the tech stack.\n"
    "- get_target_context returns the profile — use it to select relevant techniques.\n"
    "- Don't test PHP vulns on a Node.js app. Don't try XXE on a JSON-only API.\n"
    "- The target context persists across sessions for the same target.\n\n"

    "PRIMITIVE CHAINING — FIND COMBOS:\n"
    "- store_primitive for EVERY interesting observation, even if not exploitable alone.\n"
    "- Examples: 'user IDs are sequential', 'endpoint reflects input', 'no CSRF token on /settings'\n"
    "- analyze_chains reviews all primitives and suggests exploit chains.\n"
    "- Real bounties come from chains: info disclosure + IDOR = account takeover.\n\n"

    "HUNTER MENTALITY:\n"
    "- Automated scan found nothing? GOOD. Now hunt manually.\n"
    "- Use mitmproxy to capture traffic. Break assumptions. Change IDs, skip steps, modify prices.\n"
    "- NEVER say 'target appears well-hardened'. Say 'switching to manual testing'.\n"
    "- Bugs live in NEW code. Hunt what changed, not what's been scanned for years.\n"
    "- Search BB: 'business-logic-hunting' for manual testing methodology.\n"
)

TOOLS = [
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
                    "description": "Max seconds (default 300, max 3600). Keep short for recon (60-120s).",
                    "default": 300,
                },
                "workdir": {
                    "type": "string",
                    "description": "Working directory (default: current)",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "list_processes",
        "description": "List running and recently completed tool processes.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ── Target Context ──
    {
        "name": "set_target_context",
        "description": (
            "Store technology profile for a target. Call AFTER fingerprinting (whatweb, httpx, wafw00f). "
            "This context persists across sessions and guides tool/technique selection. "
            "You MUST fingerprint the target before running active scanners."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain or URL (e.g., 'app.target.com')",
                },
                "technologies": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Detected technologies (e.g., ['React', 'Express', 'MongoDB', 'nginx'])",
                },
                "waf": {
                    "type": "string",
                    "description": "Detected WAF if any (e.g., 'Cloudflare', 'AWS WAF', 'none')",
                },
                "server": {
                    "type": "string",
                    "description": "Web server (e.g., 'nginx/1.25.3', 'Apache/2.4.58')",
                },
                "cms": {
                    "type": "string",
                    "description": "CMS if detected (e.g., 'WordPress 6.4', 'Drupal 10')",
                },
                "api_type": {
                    "type": "string",
                    "description": "API style (e.g., 'REST', 'GraphQL', 'SOAP', 'gRPC')",
                },
                "auth_type": {
                    "type": "string",
                    "description": "Auth mechanism (e.g., 'JWT', 'session cookies', 'OAuth2', 'API key')",
                },
                "notes": {
                    "type": "string",
                    "description": "Any additional observations about the target",
                },
                "scope": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "In-scope domains/IPs for this target",
                },
                "out_of_scope": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicitly out-of-scope assets",
                },
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
        "name": "list_primitives",
        "description": "List all stored primitives for a target. Review before analyze_chains.",
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
        params = {
            "q": query,
            "category": arguments.get("category"),
            "type": arguments.get("type"),
            "limit": str(min(int(arguments.get("limit", 10)), 50)),
        }
        # If we have target context, add tech-aware hints
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

        # Smart output analysis
        advisories = _analyze_output(result.get("stdout", ""), result.get("stderr", ""))
        if advisories:
            parts.append("\n**━━━ BOUNTYBUD ANALYSIS ━━━**")
            for adv in advisories:
                parts.append(adv)
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

        # Attempt curl verification
        if curl_cmd:
            curl_result = _verify_curl(curl_cmd)
            verification_results.append({"method": "curl", "result": curl_result})

            # Check if expected evidence is in the response
            if expected and curl_result.get("stdout"):
                if re.search(re.escape(expected), curl_result["stdout"], re.IGNORECASE):
                    verified = True
                    curl_result["evidence_found"] = True
            elif curl_result.get("verified"):
                # Check for positive signals
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
                    "error": "NO REPRODUCTION METHOD PROVIDED. You MUST provide either reproduction_curl or reproduction_url. A finding without a POC is worthless.",
                },
            })

        finding["verification"] = {
            "status": "verified" if verified else "unverified",
            "results": verification_results,
            "verified_at": datetime.datetime.now().isoformat() if verified else None,
        }

        # Save finding
        findings = _load_findings(target)
        findings.append(finding)
        _save_findings(target, findings)

        # Update session
        if _active_session:
            if verified:
                _active_session["verified_findings"] = _active_session.get("verified_findings", 0) + 1
            _active_session["total_findings"] = _active_session.get("total_findings", 0) + 1

        # Build response
        if verified:
            text = f"**VERIFIED** — Finding confirmed exploitable.\n\n"
        else:
            text = f"**UNVERIFIED** — Could not confirm exploitation. Review results below.\n\n"

        text += f"**Finding:** {title}\n"
        text += f"**Type:** {vuln_type} | **Severity:** {severity}\n"
        text += f"**Target:** {target}\n\n"

        for vr in verification_results:
            method = vr.get("method", "unknown")
            result = vr.get("result", {})
            text += f"**Verification [{method}]:**\n"
            if result.get("verified"):
                text += f"  Status: CONFIRMED\n"
                if result.get("evidence"):
                    text += f"  Evidence: {result['evidence'][:500]}\n"
                if result.get("alerts"):
                    text += f"  Alerts fired: {result['alerts']}\n"
            else:
                text += f"  Status: NOT CONFIRMED\n"
                if result.get("error"):
                    text += f"  Issue: {result['error']}\n"
                if result.get("note"):
                    text += f"  Note: {result['note']}\n"
            if result.get("advisories"):
                text += f"  Advisories:\n"
                for adv in result["advisories"]:
                    text += f"    {adv}\n"
            text += "\n"

        if not verified:
            text += "**NEXT STEPS:** Refine your POC. Try:\n"
            text += "  1. Different payload encoding\n"
            text += "  2. Different injection point\n"
            text += "  3. Check if the vulnerability requires authentication\n"
            text += "  4. Verify in browser manually\n"
            text += "  5. Use store_primitive if this is an interesting observation but not yet exploitable\n"

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
        text += f"\n**Existing data for this target:**\n"
        text += f"  - Target context: {'loaded' if ctx else 'none — run fingerprinting first'}\n"
        text += f"  - Primitives: {len(primitives)} stored\n"
        text += f"  - Past findings: {len(findings)} recorded\n"
        text += f"\n**Recommended first steps:**\n"

        if not ctx:
            text += "  1. Fingerprint: `whatweb <target>`, `httpx -u <target> -tech-detect`, `wafw00f <target>`\n"
            text += "  2. Store results: `set_target_context`\n"
            text += "  3. Gather intel: check changelogs, HackerOne hacktivity, scope changes\n"
        else:
            text += f"  1. Review target context: tech={', '.join(ctx.get('technologies', []))}, waf={ctx.get('waf', 'unknown')}\n"
            text += "  2. Check for NEW changes since last hunt (changelog, new subdomains, JS changes)\n"
            text += "  3. Review existing primitives with `list_primitives` and `analyze_chains`\n"

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
