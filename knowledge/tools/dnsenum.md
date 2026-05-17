---
id: 'dnsenum'
title: 'Dnsenum - Deep DNS Enumeration'
type: 'tool'
category: 'reconnaissance'
subcategory: 'subdomain-enumeration'
tags: ['dns', 'enumeration', 'dnsenum', 'zone-transfer', 'brute-force', 'whois']
difficulty: 'beginner'
platforms: ['linux']
source_url: 'https://github.com/fwaeytens/dnsenum'
updated: '2026-05-17'
---

## Overview
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.

## Command Reference
```bash
dnsenum {domain} --enum -f /usr/share/dnsenum/dns.txt --threads 10 -o {domain}_dnsenum.xml
```
