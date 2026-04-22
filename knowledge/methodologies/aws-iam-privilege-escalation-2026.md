---
id: "aws-iam-privilege-escalation-2026"
title: "AWS IAM Privilege Escalation (2026 Update)"
type: "methodology"
category: "cloud"
tags: ["aws", "iam", "escalation", "bedrock", "2026"]
difficulty: "expert"
updated: "2026-04-18"
---

## Overview
In 2026, IAM escalation has moved beyond basic `iam:PutUserPolicy` to exploiting **Service-Linked Roles** and **AI Orchestration layers (AWS Bedrock/AgentCore)**.

## 2026 Escalation Paths

### 1. AI Agent Hijacking (The "Bedrock" Path)
If you have `bedrock:InvokeModel` permissions and the role is connected to an **AI Agent** with "Action Groups" (tools):
- Use **Indirect Prompt Injection** to force the agent to call a high-privilege tool.
- Tool: `DeleteAccountData` → Use it to delete S3 buckets.

### 2. The "Indirect" PassRole (Glue/SageMaker)
If you cannot `iam:PassRole` to EC2 (monitored), try passing it to less-monitored services:
- **AWS Glue Crawlers:** Pass a role to a crawler to exfiltrate S3 data.
- **SageMaker Notebooks:** Start a notebook with a privileged role to get shell access with cloud-admin rights.

### 3. Policy Version Injection (`iam:CreatePolicyVersion`)
Check if you can create a new version of a policy you are already attached to.
- Create a `v2` with `Resource: "*", Action: "*"`
- Set as default: `iam:SetDefaultPolicyVersion`
- Result: Full Administrator access.

## Verification Commands (2026 Syntax)
```bash
# Check for policy versioning rights
aws iam list-policy-versions --policy-arn [ARN]
# Inject full admin policy
aws iam create-policy-version --policy-arn [ARN] --policy-document file://admin-policy.json --set-as-default
```

## Deep Dig Prompts
- "Audit this IAM policy for 2026 service-linked escalation paths (Bedrock, SageMaker, StepFunctions)."
- "Craft an AWS CLI sequence to escalate via the CreatePolicyVersion primitive."
