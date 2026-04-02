---
id: "false-positive-elimination"
title: "False Positive Elimination & Validation Methodology"
type: "methodology"
category: "reporting"
subcategory: "vulnerability-reports"
tags: ["false-positives", "validation", "triage", "poc", "exploitability", "quality", "reporting", "methodology"]
platforms: ["linux", "macos", "windows"]
related: ["payout-maximization", "ctf-web-playbook", "attack-synthesis"]
difficulty: "intermediate"
updated: "2026-03-30"
---

# False Positive Elimination & Validation Methodology

> "You can find a legitimate critical vulnerability and still earn nothing from it" by submitting
> an incomprehensible report that analysts cannot reproduce. This guide ensures every finding
> you report is real, exploitable, and convincing.

---

## 1. Common False Positives LLMs/AI Generate

AI-assisted bug hunting is growing fast (HackerOne saw a 210% increase in valid AI-related
vulnerability reports in 2025), but LLMs produce specific, predictable failure modes.

### What LLMs Get Wrong Most Often

| Failure Mode | Example | Why It Happens |
|---|---|---|
| **Hallucinated vulnerabilities** | LLM fabricates a CVE number or invents a code path that doesn't exist | LLMs generate plausible-sounding text without verifying against the actual codebase |
| **Hallucinated command output** | Claims RCE by showing fake shell output that was never actually executed | LLM predicts what output "would look like" instead of running the command |
| **Pattern-matching without context** | Flags every `eval()` call as RCE, even when input is hardcoded | No data-flow analysis; matches syntax, not semantics |
| **Overstated severity** | Calls a self-XSS "Critical" or an open redirect with no token leak "High" | LLMs default to worst-case framing without impact analysis |
| **Copy-paste template reports** | Generic report structure with placeholder-quality details | Trained on report templates; fills them in plausibly but inaccurately |
| **Ignoring mitigations** | Reports CSRF without checking for anti-CSRF tokens already in place | Checks for vulnerability class, not deployed defenses |
| **Theoretical-only chains** | "If an attacker could also do X, Y, and Z, then..." | Describes attack trees without proving any individual link |
| **Misreading error messages** | SQL error message in response = "confirmed SQLi" | Confuses information disclosure with exploitable injection |

### Detection: How to Spot AI-Generated Garbage

The curl project shut down its bug bounty after 20% of reports were AI-generated slop. Common tells:

- **Fabricated CVEs** - look up every CVE reference; LLMs invent them
- **Unreproducible steps** - if you can't reproduce it yourself, don't submit it
- **Generic impact statements** - "could allow an attacker to compromise the system" with no specifics
- **Sleep test for RCE claims** - if the LLM "shows" command output, verify with `sleep(20)` or time-based confirmation; hallucinated output won't actually delay the response
- **No actual HTTP requests/responses shown** - just narrative description of what "would happen"

### Rule: Validate Every AI Finding Manually

Before submitting any AI-assisted finding:
1. Reproduce the vulnerability yourself in a browser/Burp/curl
2. Capture actual HTTP request and response proving the behavior
3. Confirm the vulnerable code path exists (not hallucinated)
4. Verify no mitigations are already in place (CSP, CSRF tokens, encoding)
5. Test the actual impact, not the theoretical impact

---

## 2. Validation Methodology — Confirming a Finding Is Real

### The 5-Gate Validation Process

Every finding must pass all five gates before you write a report:

**Gate 1: Scope Check**
- Is the asset explicitly in scope for this program?
- Is the vulnerability class eligible? (Check exclusions list)
- 25-30% of rejections are out-of-scope submissions

**Gate 2: Reproducibility**
- Can you reproduce it 3 times in a row?
- Can you reproduce it from a clean browser/session?
- Can you reproduce it on the latest version of the target?
- Document exact reproduction steps as you go

**Gate 3: Root Cause Confirmation**
- Do you understand WHY the vulnerability exists?
- Can you identify the specific parameter, endpoint, or code path?
- Is this a real flaw or intended behavior?

**Gate 4: Impact Verification**
- What can an attacker actually DO with this?
- Can you demonstrate data access, privilege escalation, or code execution?
- Would a real attacker invest time exploiting this?

**Gate 5: Mitigation Check**
- Are there existing protections that limit exploitation?
- CSP headers, WAF rules, rate limiting, authentication requirements?
- Does the attack require unrealistic preconditions (physical access, MITM, etc.)?

### Pre-Report Checklist

```
[ ] Vulnerability is in scope (checked program policy)
[ ] Reproduced 3+ times independently
[ ] Root cause identified and understood
[ ] Actual impact demonstrated (not theoretical)
[ ] No existing mitigations that prevent exploitation
[ ] Proof captured: HTTP requests, responses, screenshots, video
[ ] Steps are clear enough for a junior analyst to follow
[ ] Checked for duplicates in disclosed reports
```

---

## 3. Impact Verification — Proving Actual Exploitability

### The "So What?" Test

For every finding, answer: "What is the worst thing an attacker can actually do with this,
and can I prove it?"

### Impact Demonstration by Severity

| Severity | What You Must Prove | Insufficient |
|---|---|---|
| **Critical** | RCE demonstrated, full database dump, admin account takeover | "Could potentially lead to..." |
| **High** | Sensitive data accessed, privilege escalation shown, stored XSS executing on other users | Self-XSS, reflected XSS on logout page |
| **Medium** | CSRF changing account settings, IDOR accessing other users' non-sensitive data | CSRF on logout, IDOR on public data |
| **Low** | Information disclosure of internal paths, verbose errors with version info | Missing headers with no exploit path |
| **Informational** | Best practice violation, no direct exploit | This is NOT a vulnerability report |

### Proving Impact Concretely

**Data Exfiltration**: Actually read another user's data. Show the request and response
containing the data.

**Account Takeover**: Take over a test account. Show before (attacker's session) and
after (victim's session/data).

**Code Execution**: Execute a command that produces observable output (e.g., `id`, `whoami`,
DNS lookup to your controlled server). Never use destructive commands.

**Privilege Escalation**: Show a low-privilege user performing a high-privilege action.
Show both the normal restricted response and the bypassed response.

---

## 4. Triage Frameworks — How Programs Evaluate Reports

### How HackerOne/Bugcrowd Triage Works

Programs classify reports into these outcomes:

| Status | Meaning | Your Action |
|---|---|---|
| **Triaged** | Valid, confirmed, being fixed | Wait for fix and bounty |
| **Duplicate** | Someone reported it first | Check disclosed reports before submitting |
| **Informational** | Real observation, but not actionable | Your impact case was too weak |
| **Not Applicable (N/A)** | Not a valid vulnerability | Fundamental misunderstanding of the issue |
| **Spam** | No legitimate security content | Reputation damage; avoid at all costs |

### CVSS Severity Mapping (How Programs Score)

Programs use CVSS or custom frameworks. The key vectors:

- **Attack Vector**: Network (remote) > Adjacent > Local > Physical
- **Attack Complexity**: Low (easy to exploit) > High (requires preconditions)
- **Privileges Required**: None > Low > High
- **User Interaction**: None > Required
- **Impact on CIA**: High > Low > None for each of Confidentiality, Integrity, Availability

### What Triggers Immediate Rejection

1. No demonstrated security impact
2. Out-of-scope asset or vulnerability class
3. Requires victim to perform unrealistic actions
4. Already publicly known or previously reported
5. Theoretical-only (no PoC)
6. Scanner output pasted without manual verification

---

## 5. Most Common Rejected Report Types

### The Rejection Hall of Shame

Based on analysis of 9,942 HackerOne reports (1,400 invalid, ~14.1% rejection rate):

**1. Missing Security Headers (No Impact)**
```
REJECTED: "X-Frame-Options header is missing"
WHY: No clickjacking PoC on a sensitive page. Header alone is informational.
FIX: Only report if you can demonstrate clickjacking on a page with
     sensitive actions (e.g., framing a bank transfer page).
```

**2. Self-XSS**
```
REJECTED: "XSS in user's own profile name field visible only to themselves"
WHY: Attacker can only attack themselves. No cross-user impact.
FIX: Only report if you can chain it (e.g., stored XSS visible to admins,
     or via login CSRF to force victim into attacker's session).
```

**3. CSRF on Logout / Non-Sensitive Actions**
```
REJECTED: "CSRF allows attacker to log victim out"
WHY: Minimal impact. Logging someone out is an annoyance, not a vulnerability.
FIX: Focus CSRF on state-changing actions: password change, email change,
     fund transfer, permission modification.
```

**4. Open Redirect Without Token Theft**
```
REJECTED: "Open redirect on login page"
WHY: No demonstrated theft of OAuth tokens, session tokens, or credentials.
FIX: Show the redirect leaking an auth token in the Referer header, or
     use it in an OAuth flow to steal the authorization code.
```

**5. Version/Path Disclosure**
```
REJECTED: "Server header reveals Apache 2.4.51"
WHY: Version number alone is not exploitable. No CVE demonstrated.
FIX: Only report if the disclosed version has a known, exploitable CVE
     and you can demonstrate exploitation.
```

**6. SPF/DKIM/DMARC Misconfiguration**
```
REJECTED: "Missing DMARC record"
WHY: Requires attacker to set up phishing infrastructure; most programs
     consider email config out of scope.
FIX: Usually not worth reporting. If you must, send a spoofed email
     that lands in inbox (not spam) as proof.
```

**7. Theoretical Vulnerability Chains**
```
REJECTED: "If combined with XSS on another subdomain, this CORS
          misconfiguration could lead to data theft"
WHY: You haven't found the XSS. The chain is incomplete.
FIX: Complete the chain or don't report it. Report individual
     links only if each has independent impact.
```

**8. Rate Limiting Absence**
```
REJECTED: "No rate limiting on login endpoint"
WHY: Most programs consider this a best practice, not a vulnerability.
FIX: Only report if you can demonstrate actual account takeover via
     brute force within a reasonable timeframe, or OTP bypass.
```

**9. Clickjacking on Non-Sensitive Pages**
```
REJECTED: "Clickjacking on the marketing homepage"
WHY: No sensitive action can be triggered. Clicking a marketing page
     does nothing harmful.
FIX: Target pages with one-click sensitive actions: delete account,
     change permissions, approve transactions.
```

**10. Scanner Output Dumps**
```
REJECTED: [Nessus/Nuclei output pasted directly]
WHY: No manual verification, no demonstrated impact, no reproduction steps.
FIX: Use scanners for lead generation only. Manually verify and write
     a proper report for every finding.
```

---

## 6. Proof-of-Concept Standards

### What Makes a PoC Convincing

**Required Elements:**
- Runnable code or reproducible curl/Burp requests (NOT screenshots of code)
- Actual HTTP requests and responses (not described narratively)
- Clear print statements/comments explaining each step
- All dependencies and environment setup documented
- Demonstrates actual impact, not just the existence of the bug

**Format Hierarchy (most to least convincing):**
1. Runnable exploit script with documented output
2. Burp Suite request/response with annotations
3. curl commands with actual output
4. Video walkthrough with HTTP traffic visible
5. Step-by-step screenshots (minimum acceptable)
6. Narrative description only (will likely be rejected)

### PoC Anti-Patterns (What Gets Rejected)

- Screenshots of code instead of runnable code
- Video without accompanying text explanation
- Payload that only works in the reporter's specific environment
- Commands that require destructive actions on the target
- PoC that requires attacker to already have victim's credentials
- Missing dependencies, config files, or environment variables

### PoC Template

```markdown
## Vulnerability: [Specific Type] in [Exact Location]

### Summary
[1-2 sentences: what the bug is and what impact it enables]

### Environment
- Target: [URL/endpoint]
- Tested on: [date, browser/tool version]
- Account type used: [unprivileged user, unauthenticated, etc.]

### Steps to Reproduce
1. [Exact step with specific values]
2. [Exact step with specific values]
3. [Exact step with specific values]

### Proof
[curl command / Burp request]
[Actual response showing the vulnerability]

### Impact
[What an attacker can actually do — demonstrated, not theoretical]

### Suggested Fix
[Optional but builds credibility]
```

---

## 7. False Positive Patterns by Vulnerability Class

### SQL Injection

| Scanner Says | Reality | How to Confirm |
|---|---|---|
| "SQL error in response" | Error message is information disclosure, not necessarily injectable | Inject `AND 1=1` vs `AND 1=2` — different responses? |
| "Time-based blind SQLi" | Network latency caused the delay, not `SLEEP()` | Test with `SLEEP(0)` vs `SLEEP(10)` — consistent delta? |
| "Parameter is injectable" | Application returns same error for any malformed input | Use UNION SELECT to extract actual data or boolean differentiation |
| "Error-based SQLi" | Custom error handler returns same page for all errors | Verify you can extract database version or table names |

**Confirmation Protocol:**
1. Identify the injection point (parameter, header, cookie)
2. Test boolean conditions: true (`' OR '1'='1`) vs false (`' OR '1'='2`)
3. Observe response differences (content length, specific text, status code)
4. Extract concrete data (database version, table name) as proof
5. Use `sqlmap --level=5 --risk=3` only after manual confirmation
6. Vary ONE parameter at a time; keep everything else constant

### Cross-Site Scripting (XSS)

| Scanner Says | Reality | How to Confirm |
|---|---|---|
| "Reflected input in page" | Input is HTML-encoded (`&lt;script&gt;`) — not executable | Check if `<>"'` characters appear unencoded in source |
| "XSS in response body" | Payload lands in a comment, non-rendering context, or JSON response | View the actual rendered page in a browser |
| "DOM-based XSS" | Payload reaches a sink but is sanitized before rendering | Trace the actual data flow from source to sink in DevTools |
| "Stored XSS" | Payload is stored but encoded on output | Check if payload executes when the page is loaded by another user |

**Confirmation Protocol:**
1. Inject a unique canary string (e.g., `bountytest12345`) and find where it reflects
2. Check the encoding context: HTML body, attribute, JavaScript, URL, CSS
3. Test context-appropriate breakout: `"><script>` for attributes, `</script><script>` for JS
4. Confirm execution in a real browser (not just source inspection)
5. Verify it fires in another user's session (for stored XSS)
6. Check CSP headers — does the policy block inline scripts?

**Common XSS False Positives:**
- Payload reflected in JSON response with `Content-Type: application/json` (not rendered as HTML)
- Payload reflected but inside `<!-- HTML comment -->`
- Payload in response but CSP blocks execution
- Self-XSS only (no cross-user impact)
- Payload in a PDF/download, not in browser-rendered context

### Server-Side Request Forgery (SSRF)

| Scanner Says | Reality | How to Confirm |
|---|---|---|
| "Server made DNS lookup" | DNS-only interaction, HTTP was blocked by firewall | Need both DNS AND HTTP callback to confirm SSRF |
| "Internal IP in response" | Application is designed to show internal infrastructure | Check if you can control the URL to reach unintended hosts |
| "SSRF to localhost" | Request was made but nothing sensitive is accessible | Can you reach internal services (metadata, admin panels)? |
| "Blind SSRF detected" | DNS resolution happened but no useful exploitation | Can you scan internal ports, access cloud metadata, exfiltrate data? |

**Confirmation Protocol:**
1. Use Burp Collaborator, Interactsh, or a canary token service
2. Inject your controlled domain into URL parameters, headers, file uploads
3. Confirm you receive an HTTP request (not just DNS)
4. Escalate: try `http://169.254.169.254/latest/meta-data/` (AWS metadata)
5. Try internal port scanning (`http://127.0.0.1:6379/` for Redis, etc.)
6. For blind SSRF: use response time differences or DNS exfiltration

**SSRF Impact Ladder (report the highest you can prove):**
- DNS-only callback → Usually not reportable (no impact)
- HTTP callback to external server → Low (confirms SSRF exists)
- Read cloud metadata (AWS/GCP/Azure) → Critical (credential theft)
- Access internal services → High to Critical
- Full read SSRF (file/response content returned) → Critical

### Remote Code Execution (RCE)

| Scanner Says | Reality | How to Confirm |
|---|---|---|
| "Potential command injection" | Input appears in error message but isn't executed | Use time-based confirmation: `; sleep 10` and measure delay |
| "Deserialization detected" | Serialized object found but execution not proven | Generate an out-of-band callback via deserialization gadget |
| "Template injection possible" | Template syntax in response but expressions aren't evaluated | Inject `{{7*7}}` — does the response contain `49`? |
| "File upload allows PHP" | File uploaded but is it served with PHP execution enabled? | Access the uploaded file and confirm code execution (e.g., `phpinfo()`) |

**Confirmation Protocol:**
1. Start with time-based confirmation (`sleep`, `ping -c 10`, `timeout`)
2. Use out-of-band callbacks (DNS/HTTP to your server) for blind RCE
3. Execute a command with unique, verifiable output (`echo BOUNTY-$(date +%s)`)
4. NEVER use destructive commands (`rm`, `shutdown`, data modification)
5. Document the exact payload and observed response time/callback

---

## 8. Vulnerability vs. Misconfiguration With No Impact

### The Impact Threshold

A vulnerability requires a **demonstrated path from discovery to damage**. A misconfiguration
without impact is an observation, not a security finding.

| Finding | Vulnerability? | Why / Why Not |
|---|---|---|
| Missing `X-Frame-Options` + clickjacking PoC on transfer page | Yes | Demonstrated impact on sensitive action |
| Missing `X-Frame-Options` on marketing page | No | No sensitive action to exploit |
| Open redirect leaking OAuth token | Yes | Token theft proven |
| Open redirect to external site | No | Phishing alone is usually excluded |
| CORS allows `*.example.com` + XSS on subdomain | Yes | Full chain demonstrated |
| CORS allows `*.example.com` with no subdomain XSS | No | Incomplete chain, theoretical only |
| Directory listing showing source code | Yes | Sensitive data exposed |
| Directory listing showing public images | No | No sensitive content |
| Debug endpoint leaking stack traces with credentials | Yes | Credential exposure |
| Debug endpoint showing framework version only | No | Version alone is informational |
| HTTP (no TLS) on authentication endpoint | Yes | Credentials transmitted in cleartext |
| HTTP on public blog with no auth | No | No sensitive data in transit |

### Decision Framework

```
1. Can I access something I shouldn't?          → If no, probably not a vuln
2. Can I modify something I shouldn't?           → If no, probably not a vuln
3. Can I deny access to something?               → If no to all 3, it's informational
4. Does exploitation require unrealistic setup?   → Physical access, MITM = usually excluded
5. Is there a deployed mitigation I'm ignoring?   → CSP, WAF, token validation = check first
```

---

## 9. Vulnerability-Specific Validation Checklists

### SSRF Validation

```
[ ] Injected URL triggers HTTP callback (not just DNS) to controlled server
[ ] Confirmed server-side request (check User-Agent, source IP)
[ ] Tested internal network access (127.0.0.1, 169.254.169.254, 10.x.x.x)
[ ] Attempted cloud metadata access (AWS/GCP/Azure endpoints)
[ ] Checked for response content (full read vs blind)
[ ] Verified bypass of any URL validation (IP encoding, redirects, DNS rebinding)
[ ] Demonstrated actual impact beyond "server made a request"
```

### XSS Validation

```
[ ] Payload executes in a real browser (not just visible in source)
[ ] Payload fires in correct context (not in JSON, comment, or non-rendered area)
[ ] CSP does not block execution
[ ] Cross-user impact demonstrated (not self-XSS)
[ ] Session cookie accessible (no HttpOnly) OR alternative impact shown
[ ] Payload works without requiring victim to modify their browser settings
[ ] Tested in multiple browsers to confirm it's not browser-specific behavior
```

### SQLi Validation

```
[ ] Boolean-based test shows different responses for true vs false conditions
[ ] OR extracted concrete data (DB version, table names, actual records)
[ ] OR time-based test shows consistent, controllable delay
[ ] Confirmed it's the injected payload causing the behavior (not coincidence)
[ ] Varied only one parameter at a time
[ ] Documented the exact injection point and payload
[ ] Shown impact: data extraction, authentication bypass, or data modification
```

### RCE Validation

```
[ ] Command execution confirmed via time delay, DNS callback, or output
[ ] Used benign, non-destructive commands only
[ ] Payload is specific to the target's OS/runtime
[ ] Not relying on LLM-hallucinated output (verified independently)
[ ] Documented exact payload, request, and observed result
[ ] Demonstrated the execution context (what user/permissions)
```

---

## 10. Red Teaming — Avoiding Rabbit Holes

### Time-Boxing Strategy

| Phase | Time Limit | Kill Criteria |
|---|---|---|
| Recon on an asset | 30 min | No interesting attack surface found |
| Initial exploit attempt | 45 min | No indication of vulnerability after basic tests |
| Deep exploitation | 2 hours | Can't escalate beyond initial finding |
| Chain development | 1 hour | Missing link can't be found |

### Focus Framework: RICE for Bug Bounty

Score each potential finding before investing time:

- **R**each: How many users/systems affected?
- **I**mpact: CIA triad impact (Critical/High/Medium/Low)
- **C**onfidence: How sure are you this is exploitable? (Confirmed/Likely/Speculative)
- **E**ffort: Time to develop a full PoC and report

**Pursue findings that are: High Reach + High Impact + Confirmed + Low Effort**

### Common Rabbit Holes to Avoid

1. **Spending hours on WAF bypass for a Low-severity finding** - If the base finding is low impact, bypassing the WAF doesn't make it high impact
2. **Chaining 5 bugs to get Medium severity** - If each link is fragile, the chain will break in triage
3. **Testing staging/dev environments** - Usually out of scope and not reachable by real attackers
4. **Brute-forcing without impact** - Proving rate limiting is weak is not the same as proving account takeover
5. **Reporting scanner output without verification** - Nuclei/Nessus templates have known false positive rates
6. **Pursuing SSRF when you only got DNS** - DNS-only callbacks are rarely rewarded
7. **Information disclosure with no sensitive data** - Stack traces showing framework name are not critical
8. **Fixating on a single target** - If 2 hours yields nothing, move to the next asset

### The 80/20 Rule for Bug Bounty

80% of bounties come from these vulnerability classes:
- **IDOR/BOLA** (access control failures)
- **Authentication/authorization bypass**
- **Stored XSS with cross-user impact**
- **SSRF to internal services or cloud metadata**
- **SQL injection with data extraction**
- **Business logic flaws**

Deprioritize:
- Missing headers without PoC
- Self-XSS
- CSRF on non-sensitive endpoints
- Open redirects without token theft
- Version disclosure
- Theoretical attack chains

---

## Quick Reference: The 60-Second Validity Check

Before writing a single word of your report, answer these questions:

```
1. Can I reproduce this RIGHT NOW?                    → No = Don't report
2. Is the asset in scope?                             → No = Don't report
3. Is this vulnerability class eligible?              → No = Don't report
4. Does my PoC show actual impact?                    → No = Strengthen PoC
5. Would this require the victim to do something      → Yes = Reconsider severity
   unreasonable?
6. Is there a CSP/WAF/token that blocks this?         → Yes = Try bypass or don't report
7. Can a junior analyst reproduce my steps?           → No = Rewrite steps
8. Am I relying on AI output I haven't verified?      → Yes = Verify manually first
9. Have I checked for duplicates?                     → No = Check now
10. Would I mass-close this if I were a triager?      → Yes = Don't report
```

---

## Sources

- [HackerOne Quality Reports Guide](https://docs.hackerone.com/en/articles/8475116-quality-reports)
- [Understanding Bug Bounty Report Invalid Reasons with LLMs (Research)](https://arxiv.org/html/2511.18608v1)
- [AI Slop and Fake Reports in Bug Bounties (TechCrunch)](https://techcrunch.com/2025/07/24/ai-slop-and-fake-reports-are-exhausting-some-security-bug-bounties/)
- [HackenProof Out-of-Scope Bugs](https://docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile/out-of-scope-bugs)
- [Bug Bounty 2026: Brutal Truths for Hunters](https://medium.com/@R.H_Rizvi/bug-bounty-2026-7-brutal-truths-every-hunter-needs-to-know-before-submitting-another-report-efd244fafacc)
- [OWASP Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [OWASP Testing for Reflected XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
- [PortSwigger: Testing for Blind SSRF](https://portswigger.net/burp/documentation/desktop/testing-workflow/ssrf/testing-for-blind-ssrf)
- [Immunefi PoC Guidelines](https://immunefisupport.zendesk.com/hc/en-us/articles/9946217628561-Proof-of-Concept-PoC-Guidelines-and-Rules)
- [GitHub Security Misconfiguration Classification](https://bounty.github.com/classifications/security-misconfiguration.html)
- [Meta Engineering: LLM-Powered Bug Catchers](https://engineering.fb.com/2025/02/05/security/revolutionizing-software-testing-llm-powered-bug-catchers-meta-ach/)
- [OWASP Penetration Testing Methodologies](https://owasp.org/www-project-web-security-testing-guide/v41/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies)
- [YesWeHack: Writing Effective Bug Bounty Reports](https://www.yeswehack.com/learn-bug-bounty/write-effective-bug-bounty-reports)
- [Fake Hallucinated RCEs in LLM Applications](https://www.cyberdefensemagazine.com/fake-hallucinated-remote-code-execution-rces-in-llm-applications/)
