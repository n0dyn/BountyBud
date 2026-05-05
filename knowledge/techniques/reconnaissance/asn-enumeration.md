---
id: "asn-enumeration"
title: "ASN & Network Enumeration for Bug Bounty 2026 - BGP, Peering, Cloud ASN & Attack Surface Expansion"
type: "technique"
category: "reconnaissance"
subcategory: "asn-enumeration"
tags: ["asn", "bgp", "peering", "cloud-enum", "netblock", "shodan", "censys", "bgp-he", "2026"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["subdomain-enumeration", "cloud-asset-enumeration", "osint", "shodan"]
updated: "2026-05-04"
---

## Overview
ASN enumeration expands attack surface beyond DNS: netblocks, peering relationships, cloud provider ASNs, and BGP leaks reveal hidden infrastructure (internal APIs, staging, partner networks). Essential for large targets (FAANG, fintech).

## Techniques
### 1. ASN Discovery
- **BGP.HE.net / Hurricane Electric**: Search domain → ASN → prefixes.
- **Censys / Shodan / ZoomEye**: `asn:AS12345` or `autonomous_system.asn`.
- **Tools**: `amass intel -asn ASxxxx`, `asnmap`, `bgp-he` CLI wrappers.

### 2. Netblock Expansion
- Query whois for ASN prefixes (IPv4/IPv6).
- `masscan` or `nmap` on discovered ranges (rate-limited).
- Cloud-specific: AWS `describe-vpcs`, GCP `gcloud compute networks`, Azure.

### 3. Peering & Relationship Mapping
- Use CAIDA AS relationships or PeeringDB.
- Identify upstream/downstream providers for pivot points.

### 4. Cloud ASN Hunting
- AWS: 16509, 14618, etc.
- Google: 15169, 396982.
- Azure: 8075.
- Search `asn:AS16509 http.title:"Internal"` or exposed services.

### 5. BGP Leaks & Misconfigs
- Monitor for leaked routes revealing internal prefixes.

## Workflow
1. Passive: Domain → ASN via bgp.he.net.
2. Active: Enumerate prefixes, probe for HTTP/HTTPS, SSH, APIs.
3. Cross with subdomain recon: New subdomains often live on ASN-owned ranges.
4. Cloud enum: Use Pacu / CloudEnum on discovered accounts.

## Deep Dig Prompts
```
For target.com:
1. Identify primary ASN(s) and all announced prefixes (IPv4/IPv6).
2. Generate masscan/nmap command for high-value ports on netblocks.
3. List cloud provider ASNs and exposed services (Shodan query).
4. Peering map for potential pivot providers.
5. Impact: "Discovered internal staging API on ASN-owned netblock leading to pre-prod data exposure."
Output commands, Shodan/Censys queries, and recon pipeline integration.
```

## Tools
- amass, asnmap, bgp-he, Censys CLI, Shodan, CloudEnum, Pacu.

## References
- BGP.HE.net, CAIDA, 2026 recon guides, real bug bounty ASN finds.
---
