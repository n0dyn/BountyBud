---
id: "advanced-infrastructure-logic-hunting"
title: "Advanced Infrastructure & Logic Hunting"
type: "methodology"
category: "hunting"
tags: ["infrastructure", "business-logic", "2026", "advanced"]
difficulty: "expert"
updated: "2026-04-18"
---

## Overview
This methodology documents the procedures for identifying high-impact architectural flaws and logic errors, distilled from successful 2026 hunts on major infrastructure (Netflix/Spotify).

## Phase 1: Environment & Context Setup
- **Procedure:** Audit the execution environment for tool-specific dependencies.
- **Method:** Verify that sub-agents and local security tools are executing within dedicated virtual environments (venvs) to ensure consistent behavior of complex libraries (e.g., gRPC, specialized HTTP clients).

## Phase 2: Multidimensional Reconnaissance
- **Procedure:** Reconcile static scope definitions with dynamic discovery.
- **Method:**
  1. Parse program-provided scope files (CSV/JSON) for high-value keywords (Core, Bounty-Eligible).
  2. Research "silent" acquisitions to identify overlooked subdomains.
  3. Filter massive subdomain lists using regex to exclude infrastructure noise and prioritize user-facing or internal-tool patterns.

## Phase 3: Historical Data & Leak Mining
- **Procedure:** Extract secrets and internal configurations from frontend state.
- **Method:**
  1. **Hydration Mining:** Scan hydration blocks (e.g., `__NEXT_DATA__`) for runtime configuration, internal `baseUrl` definitions, and leaked API/Preview tokens.
  2. **Wayback Mining:** Mine web archives specifically for endpoints containing strings like `unauth`, `config`, `v1/license`, or `recovery`.

## Phase 4: Differentiator Probing
- **Procedure:** Distinguish real API endpoints from SPA routing "fake positives."
- **Method:** Use `Content-Length` and `Content-Type` auditing. If every sub-path returns the same byte count and `text/html`, the target is a frontend mask. Hunt for `405 Method Not Allowed` or `401/403` responses as indicators of actual backend logic.

## Phase 5: Infrastructure Header Analysis
- **Procedure:** Test for the reflection of untrusted "Forwarded" headers.
- **Method:** Inject standard and non-standard proxy headers (e.g., `X-Forwarded-Host`) and audit the *entire* response header set. Target the `domain` attribute of `Set-Cookie` and redirect locations to identify Session Hijacking or Cache Poisoning vectors.

## Phase 6: Static Logic Tracing
- **Procedure:** Map data flow from untrusted inputs to dangerous sinks in minified bundles.
- **Method:**
  1. Identify cross-origin listeners (e.g., `postMessage`).
  2. Use byte-offset searching to locate specific handler logic in large JS files.
  3. Trace variables from the listener (Source) to the final execution point (Sink), checking for the presence or absence of origin validation functions.

## Phase 7: Verification & Signal Protection
- **Procedure:** Pre-triage findings against a security logic engine.
- **Method:**
  1. Run findings through an AI verification engine to score "Confidence" and "Evidence Quality."
  2. Explicitly search for "Triager Refutations" (e.g., CSP blocks, reachability issues) before finalizing the report.
  3. Generate a "Proven Impact" summary that prioritizes financial or business risk over theoretical technical possibilities.
