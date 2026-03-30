---
id: "nmap-cheatsheet"
title: "Nmap Cheatsheet - Complete Flag Reference"
type: "cheatsheet"
category: "network"
subcategory: "port-scanning"
tags: ["nmap", "cheatsheet", "port-scan", "nse", "flags", "quick-reference"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["port-scanning-methodology", "nmap-basic", "nmap-full"]
updated: "2026-03-30"
---

## Scan Types

| Flag | Description |
|------|-------------|
| `-sS` | SYN scan (default, stealthy, half-open) |
| `-sT` | TCP connect scan (full handshake, no root needed) |
| `-sU` | UDP scan |
| `-sA` | ACK scan (map firewall rules) |
| `-sN` | Null scan (no flags set) |
| `-sF` | FIN scan |
| `-sX` | Xmas scan (FIN+PSH+URG) |
| `-sW` | Window scan |
| `-sM` | Maimon scan |
| `-sI` | Idle/zombie scan |
| `-sO` | IP protocol scan |
| `-sP` / `-sn` | Ping scan (host discovery only) |

## Port Specification

| Flag | Description |
|------|-------------|
| `-p 80` | Single port |
| `-p 80,443` | Multiple ports |
| `-p 1-1000` | Port range |
| `-p-` | All 65535 ports |
| `-p U:53,T:80` | Specific TCP and UDP ports |
| `--top-ports 100` | Top N most common ports |
| `-F` | Fast scan (top 100 ports) |

## Service/Version Detection

| Flag | Description |
|------|-------------|
| `-sV` | Service version detection |
| `--version-intensity 0-9` | Version scan intensity (default 7) |
| `--version-light` | Intensity 2 |
| `--version-all` | Intensity 9 |
| `-A` | Aggressive (OS + version + scripts + traceroute) |

## OS Detection

| Flag | Description |
|------|-------------|
| `-O` | OS detection |
| `--osscan-limit` | Only scan promising hosts |
| `--osscan-guess` | Aggressive OS guessing |

## NSE Scripts

| Flag | Description |
|------|-------------|
| `-sC` | Default scripts (same as `--script=default`) |
| `--script=SCRIPT` | Run specific script |
| `--script=vuln` | Run all vuln category scripts |
| `--script=safe,discovery` | Multiple categories |
| `--script-args=KEY=VALUE` | Script arguments |
| `--script-help=SCRIPT` | Script documentation |

### Essential NSE Scripts
```bash
# Vulnerability scanning
nmap --script vuln TARGET

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users,smb-vuln-* -p 445 TARGET

# HTTP enumeration
nmap --script http-enum,http-title,http-methods,http-headers -p 80,443 TARGET

# DNS
nmap --script dns-brute,dns-zone-transfer -p 53 TARGET

# SSL/TLS
nmap --script ssl-heartbleed,ssl-poodle,ssl-cert,ssl-enum-ciphers -p 443 TARGET

# FTP
nmap --script ftp-anon,ftp-bounce,ftp-vuln-cve2010-4221 -p 21 TARGET

# SSH
nmap --script ssh-auth-methods,ssh-brute -p 22 TARGET
```

## Timing & Performance

| Flag | Description |
|------|-------------|
| `-T0` | Paranoid (IDS evasion, very slow) |
| `-T1` | Sneaky |
| `-T2` | Polite (reduced bandwidth) |
| `-T3` | Normal (default) |
| `-T4` | Aggressive (fast, reliable networks) |
| `-T5` | Insane (fastest, may miss results) |
| `--min-rate N` | Minimum packets per second |
| `--max-rate N` | Maximum packets per second |
| `--min-parallelism N` | Minimum parallel probes |
| `--max-retries N` | Max retransmissions (default 10) |
| `--host-timeout MS` | Max time per host |

## Output Formats

| Flag | Description |
|------|-------------|
| `-oN file` | Normal output |
| `-oX file` | XML output |
| `-oG file` | Grepable output |
| `-oA basename` | All formats at once |
| `-oS file` | ScRiPt KiDdIe output |
| `-v` / `-vv` | Verbose |
| `-d` / `-dd` | Debug |
| `--open` | Only show open ports |
| `--reason` | Show reason for port state |

## Evasion & Stealth

| Flag | Description |
|------|-------------|
| `-f` | Fragment packets |
| `-D RND:10` | Use 10 random decoys |
| `-S SPOOF_IP` | Spoof source IP |
| `-e IFACE` | Use specific interface |
| `--source-port N` | Spoof source port |
| `--data-length N` | Append random data to packets |
| `--ttl N` | Set IP TTL |
| `--randomize-hosts` | Randomize target order |
| `--spoof-mac MAC` | Spoof MAC address |
| `--proxies URL` | Relay through proxies |

## Common Scan Recipes

```bash
# Quick recon
nmap -sV -sC -T4 -oA quick TARGET

# Full port scan
nmap -p- -T4 -oA fullports TARGET

# Deep scan on discovered ports
nmap -p PORTS -sV -sC -A -oA deep TARGET

# Stealth scan
nmap -sS -T2 -f --data-length 24 -oA stealth TARGET

# UDP scan (top 20)
nmap -sU --top-ports 20 -sV -oA udp TARGET

# Vuln scan
nmap --script vuln -p PORTS -oA vulns TARGET

# Subnet discovery
nmap -sn 192.168.1.0/24 -oA discovery
```
