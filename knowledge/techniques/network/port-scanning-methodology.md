---
id: "port-scanning-methodology"
title: "Port Scanning Methodology - Complete Network Reconnaissance"
type: "technique"
category: "network"
subcategory: "port-scanning"
tags: ["nmap", "masscan", "port-scan", "tcp", "udp", "service-detection", "firewall-evasion", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
related: ["nmap-basic", "nmap-full", "masscan", "service-exploitation"]
updated: "2026-03-30"
---

## Overview

Port scanning is the foundation of network penetration testing. Understanding which ports are open, what services run behind them, and how firewalls filter traffic determines your entire attack surface. This guide covers methodology from quick discovery to deep enumeration.

## Scanning Strategy

### Phase 1: Fast Discovery
Start with speed to identify the attack surface before deep-diving.

```bash
# Masscan for rapid full-port sweep (rate-limited for stability)
masscan -p1-65535 TARGET_IP --rate=1000 -oX masscan_results.xml

# Nmap top 1000 ports with version detection
nmap -sV -sC -T4 TARGET -oA nmap_quick

# UDP top 20 ports (often overlooked, high-value targets)
nmap -sU --top-ports 20 -sV TARGET -oA nmap_udp
```

### Phase 2: Deep Enumeration
Focus on discovered open ports with aggressive scripts.

```bash
# Full NSE script scan on discovered ports
nmap -p OPEN_PORTS -sV -sC --script=default,discovery,vuln TARGET -oA nmap_deep

# Version-intensive scan
nmap -p OPEN_PORTS -sV --version-intensity 5 TARGET
```

### Phase 3: Firewall Evasion
When ports appear filtered, try bypass techniques.

```bash
# Fragment packets
nmap -f -p TARGET_PORTS TARGET

# Decoy scan
nmap -D RND:10 -p TARGET_PORTS TARGET

# Source port manipulation (DNS/HTTP often allowed)
nmap --source-port 53 -p TARGET_PORTS TARGET
nmap --source-port 80 -p TARGET_PORTS TARGET

# Idle scan (zombie host)
nmap -sI ZOMBIE_HOST TARGET

# ACK scan to map firewall rules
nmap -sA -p TARGET_PORTS TARGET
```

## High-Value Ports for Pentesting

### Immediate Exploitation Targets
| Port | Service | Why It Matters |
|------|---------|----------------|
| 21 | FTP | Anonymous login, writable directories |
| 22 | SSH | Brute force, key reuse, old versions |
| 23 | Telnet | Cleartext credentials |
| 25/587 | SMTP | Open relay, user enumeration |
| 53 | DNS | Zone transfer, cache poisoning |
| 80/443 | HTTP/S | Web app vulns, default creds |
| 110/143 | POP3/IMAP | Credential interception |
| 139/445 | SMB | EternalBlue, null sessions, shares |
| 389/636 | LDAP | Anonymous bind, AD enumeration |
| 1433 | MSSQL | Default creds, xp_cmdshell |
| 1521 | Oracle | TNS listener attacks |
| 3306 | MySQL | Remote auth bypass, UDF |
| 3389 | RDP | BlueKeep, brute force |
| 5432 | PostgreSQL | Default creds, command execution |
| 5900 | VNC | No-auth instances |
| 6379 | Redis | Unauthenticated access, RCE |
| 8080/8443 | Alt HTTP | Management consoles |
| 9200 | Elasticsearch | Unauthenticated data access |
| 27017 | MongoDB | No-auth instances |

## Deep Dig Prompts

```
Given these nmap scan results [paste output]:
1. Identify the 5 highest-risk services based on version and configuration.
2. Suggest specific exploits or attack vectors for each.
3. Map potential lateral movement paths between services.
4. Identify any services that suggest internal/development infrastructure exposure.
```

```
These ports are filtered by a firewall [list ports]:
1. Suggest 10 firewall evasion techniques specific to this setup.
2. Recommend timing and fragmentation strategies.
3. Identify which ports might be accessible from specific source ports (53, 80, 443).
```

## Tools

- **Nmap** — Industry standard, NSE scripts, OS detection
- **Masscan** — Fastest port scanner, millions of packets/sec
- **RustScan** — Fast initial scan, pipes to nmap for deep analysis
- **Unicornscan** — Asynchronous stateless scanning
- **Zmap** — Single-port internet-wide scanning

## Bug Bounty Tips

- Always scan UDP — most hunters skip it, finding an exposed SNMP or TFTP service is rare and high-value
- Check for non-standard ports (8080, 8443, 9090, etc.) — dev/staging services often live here
- Time your scans: slower rates avoid detection and WAF blocks
- Compare scan results across days — services come and go as deployments change
- Document every open port even if it seems uninteresting — it may become relevant during chain attacks
