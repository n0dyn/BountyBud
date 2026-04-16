---
id: "wordlist-reference-cheatsheet"
title: "Wordlist Reference Guide - SecLists, Assetnote & More"
type: "cheatsheet"
category: "reconnaissance"
subcategory: "wordlists"
tags: ["wordlists", "seclists", "assetnote", "fuzzing", "directories", "subdomains", "parameters", "passwords"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: ["ffuf-cheatsheet", "google-dorking-cheatsheet"]
updated: "2026-04-14"
---

## SecLists

The security tester's standard wordlist collection. Install: `sudo apt install seclists` or `git clone https://github.com/danielmiessler/SecLists.git`

Default path: `/usr/share/seclists/` or `/opt/SecLists/`

### Directory / Content Discovery

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Discovery/Web-Content/common.txt` | 4.7K | Quick scan, most common paths |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | 220K | Standard directory brute |
| `Discovery/Web-Content/directory-list-2.3-big.txt` | 1.3M | Thorough directory brute |
| `Discovery/Web-Content/directory-list-2.3-small.txt` | 87K | Fast initial scan |
| `Discovery/Web-Content/raft-medium-directories.txt` | 30K | Good general purpose |
| `Discovery/Web-Content/raft-large-directories.txt` | 62K | Extended coverage |
| `Discovery/Web-Content/raft-medium-files.txt` | 17K | File discovery |
| `Discovery/Web-Content/raft-large-files.txt` | 37K | Extended file discovery |
| `Discovery/Web-Content/big.txt` | 20K | DirBuster's big list |
| `Discovery/Web-Content/combined_words.txt` | 221K | Combined wordlist |
| `Discovery/Web-Content/dirsearch.txt` | 9.8K | dirsearch default |

### Subdomain Discovery

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Discovery/DNS/subdomains-top1million-5000.txt` | 5K | Quick scan |
| `Discovery/DNS/subdomains-top1million-20000.txt` | 20K | Standard scan |
| `Discovery/DNS/subdomains-top1million-110000.txt` | 110K | Thorough scan |
| `Discovery/DNS/deepmagic.com-prefixes-top500.txt` | 500 | Ultra-fast sweep |
| `Discovery/DNS/deepmagic.com-prefixes-top50000.txt` | 50K | Extended sweep |
| `Discovery/DNS/fierce-hostlist.txt` | 2.5K | Fierce tool list |
| `Discovery/DNS/namelist.txt` | 1.9K | Short name list |
| `Discovery/DNS/bitquark-subdomains-top100000.txt` | 100K | Bitquark research |
| `Discovery/DNS/dns-Jhaddix.txt` | 2.2M | Jason Haddix mega list (comprehensive) |
| `Discovery/DNS/combined_subdomains.txt` | 648K | Combined sources |
| `Discovery/DNS/shubs-subdomains.txt` | 484K | Shubs list |

### API / Parameters

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Discovery/Web-Content/api/api-endpoints.txt` | 12K | Common API endpoints |
| `Discovery/Web-Content/api/api-seen-in-wild.txt` | 89K | Real-world API paths |
| `Discovery/Web-Content/burp-parameter-names.txt` | 6.4K | Common parameter names |
| `Discovery/Web-Content/api/objects.txt` | 3K | API object names |
| `Discovery/Web-Content/api/actions.txt` | 600 | API action names |
| `Discovery/Web-Content/api/graphql.txt` | 800 | GraphQL introspection paths |

### Passwords

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Passwords/Leaked-Databases/rockyou.txt` | 14M | Most common password list |
| `Passwords/Common-Credentials/10-million-password-list-top-100000.txt` | 100K | Top 100K passwords |
| `Passwords/Common-Credentials/10-million-password-list-top-10000.txt` | 10K | Top 10K passwords |
| `Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | 1K | Top 1K passwords |
| `Passwords/Common-Credentials/best1050.txt` | 1K | Best 1050 passwords |
| `Passwords/Default-Credentials/default-passwords.csv` | 1.5K | Default creds database |
| `Passwords/Leaked-Databases/rockyou-75.txt` | 59K | Top 75 rockyou patterns |
| `Passwords/darkweb2017-top10000.txt` | 10K | Dark web leaks |

### Usernames

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Usernames/Names/names.txt` | 10K | Common names |
| `Usernames/top-usernames-shortlist.txt` | 17 | Ultra-fast user check |
| `Usernames/xato-net-10-million-usernames.txt` | 8.3M | Massive username list |
| `Usernames/cirt-default-usernames.txt` | 827 | Default usernames |

### Fuzzing / Payloads

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Fuzzing/LFI/LFI-Jhaddix.txt` | 920 | LFI path traversal |
| `Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` | 230 | Linux LFI paths |
| `Fuzzing/LFI/LFI-gracefulsecurity-windows.txt` | 230 | Windows LFI paths |
| `Fuzzing/SQLi/Generic-SQLi.txt` | 267 | SQL injection payloads |
| `Fuzzing/SQLi/quick-SQLi.txt` | 37 | Quick SQLi test |
| `Fuzzing/XSS/XSS-BruteLogic.txt` | 30 | XSS payloads |
| `Fuzzing/XSS/XSS-Jhaddix.txt` | 7.6K | Comprehensive XSS |
| `Fuzzing/SSTI-payloads.txt` | 100+ | SSTI payloads |
| `Fuzzing/command-injection-commix.txt` | 40 | Command injection |
| `Fuzzing/special-chars.txt` | 32 | Special characters |
| `Fuzzing/Unicode.txt` | 65K | Unicode fuzzing |

### Sensitive Files

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Discovery/Web-Content/quickhits.txt` | 2.4K | Quick sensitive file check |
| `Discovery/Web-Content/Common-DB-Backups.txt` | 580 | Database backup files |
| `Discovery/Web-Content/AdobeCQ-AEM.txt` | 150 | Adobe AEM paths |
| `Discovery/Web-Content/CGIs.txt` | 3.5K | CGI scripts |
| `Discovery/Web-Content/Logins.fuzz.txt` | 60 | Login page paths |
| `Discovery/Web-Content/Randomfiles.fuzz.txt` | 20 | Random sensitive files |
| `Discovery/Web-Content/spring-boot.txt` | 40 | Spring Boot actuator |

### Technology-Specific

| Wordlist | Size | Use Case |
|----------|------|----------|
| `Discovery/Web-Content/CMS/wordpress.fuzz.txt` | 7K | WordPress paths |
| `Discovery/Web-Content/CMS/wp-plugins.fuzz.txt` | 13K | WordPress plugins |
| `Discovery/Web-Content/CMS/wp-themes.fuzz.txt` | 21K | WordPress themes |
| `Discovery/Web-Content/CMS/joomla-tests-all.txt` | 15K | Joomla paths |
| `Discovery/Web-Content/CMS/drupal-all.txt` | 5K | Drupal paths |
| `Discovery/Web-Content/IIS.fuzz.txt` | 250 | IIS-specific paths |
| `Discovery/Web-Content/apache.txt` | 30 | Apache-specific |
| `Discovery/Web-Content/nginx.txt` | 30 | Nginx-specific |
| `Discovery/Web-Content/tomcat.txt` | 60 | Tomcat paths |

## Assetnote Wordlists

Updated monthly (28th of each month). Download from https://wordlists.assetnote.io/

Based on real-world data from internet scanning. Higher quality than static lists.

### Key Assetnote Lists

| Wordlist | Use Case |
|----------|----------|
| `httparchive_subdomains_*.txt` | Subdomains from HTTP Archive |
| `httparchive_directories_*.txt` | Directories from HTTP Archive |
| `httparchive_parameters_*.txt` | Parameters from HTTP Archive |
| `httparchive_apiroutes_*.txt` | API routes from HTTP Archive |
| `httparchive_jsp_*.txt` | JSP-specific paths |
| `httparchive_php_*.txt` | PHP-specific paths |
| `httparchive_aspx_*.txt` | ASP.NET-specific paths |
| `manual/best-dns-wordlist.txt` | Curated best DNS list |
| `automated/httparchive_subdomains_2026_04_28.txt` | Latest subdomain list |

### Download Assetnote Lists
```bash
# Download specific list
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt

# Download technology-specific
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2026_04_28.txt

# Best lists for each purpose:
# Subdomains: best-dns-wordlist.txt
# Directories: httparchive_directories_*.txt
# API routes: httparchive_apiroutes_*.txt
# Parameters: httparchive_parameters_*.txt
```

## Other Notable Wordlists

### OneListForAll
```bash
# Combined optimized list
git clone https://github.com/six2dez/OneListForAll.git
# onelistforallshort.txt - 1M lines, balanced
# onelistforallmicro.txt - 50K lines, quick scan
```

### Jhaddix All-the-Things
```bash
# Jason Haddix curated lists
# content_discovery_all.txt - comprehensive directory list
# dns-Jhaddix.txt (in SecLists) - 2.2M subdomains
```

### FuzzDB
```bash
git clone https://github.com/fuzzdb-project/fuzzdb.git
# attack/ - attack payloads
# discovery/ - discovery wordlists
# regex/ - useful regex patterns
```

### PayloadsAllTheThings
```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
# Organized by vulnerability type
# Includes wordlists + technique guides
```

## Recommended Lists by Task

### Quick Recon (under 5 minutes)
```bash
# Subdomains
subfinder -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Directories
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Quick sensitive files
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt
```

### Standard Assessment
```bash
# Subdomains
subfinder -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Directories
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# API endpoints
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Parameters
arjun -u https://target.com/page -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### Deep Dive
```bash
# Subdomains (massive)
puredns bruteforce /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt target.com

# Directories (comprehensive)
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

# Technology-specific
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt

# API (real-world)
ffuf -u https://target.com/FUZZ -w assetnote_httparchive_apiroutes.txt
```

### Password Attacks
```bash
# Quick spray (top passwords)
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt target ssh

# Standard attack
hashcat -m 0 hashes.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

# Rule-based
hashcat -m 0 hashes.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Custom Wordlist Generation

```bash
# CeWL - generate from target website
cewl https://target.com -d 3 -m 5 -w custom_wordlist.txt

# From JavaScript files
cat js_urls.txt | xargs -I{} curl -s {} | grep -oP '[a-zA-Z0-9_/.-]{3,}' | sort -u > js_wordlist.txt

# Combine and deduplicate
cat list1.txt list2.txt list3.txt | sort -u > combined.txt

# Add extensions
for ext in php asp aspx jsp html; do
  sed "s/$/.${ext}/" wordlist.txt
done > wordlist_with_ext.txt

# Generate permutations
hashcat --stdout -a 6 base_words.txt ?d?d?d > permuted.txt
```

## Pro Tips

- Start with small lists (common.txt) then expand
- Use Assetnote for technology-specific fuzzing (PHP, JSP, ASP)
- SecLists `quickhits.txt` finds sensitive files fast
- `dns-Jhaddix.txt` is the gold standard for subdomain brute forcing
- Assetnote lists are monthly-updated from real internet data
- Combine CeWL output with standard lists for target-specific coverage
- `burp-parameter-names.txt` is essential for parameter discovery
- Always deduplicate combined lists: `sort -u`
- For API testing, use both SecLists API lists AND Assetnote API routes
- Technology-specific lists (WordPress, Spring Boot) have much higher hit rates
