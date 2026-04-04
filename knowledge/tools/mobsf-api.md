---
id: "mobsf-api"
title: "MobSF API Scan"
type: "tool"
category: "mobile"
subcategory: "android"
tags: ["mobile", "mobsf-api"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Mobile Security Framework API scanning.

## Command Reference

```bash
# Note: Requires MobSF setup and APK/IPA file
echo "Mobile app security testing requires MobSF framework setup"
echo "Upload your APK/IPA file to MobSF at http://localhost:8000"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.2   |
| API        | 0.5   |
| Network    | 0.1   |
| Cloud      | 0.2   |
| CMS        | 0.0   |

## Fallback Alternatives

- **apktool** - Manual APK decompilation and analysis
- **jadx** - Java decompiler for Android apps
- **frida** - Dynamic instrumentation for mobile apps

## Context-Aware Parameters

**Upload and scan APK via API**
```bash
curl -F "file=@app.apk" http://localhost:8000/api/v1/upload -H "Authorization: YOUR_API_KEY"
```

**Get scan results via API**
```bash
curl -X POST http://localhost:8000/api/v1/scan -H "Authorization: YOUR_API_KEY" -d "scan_type=apk&file_name=app.apk&hash=HASH"
```

**Generate PDF report**
```bash
curl -X POST http://localhost:8000/api/v1/download_pdf -H "Authorization: YOUR_API_KEY" -d "hash=HASH" -o report.pdf
```
