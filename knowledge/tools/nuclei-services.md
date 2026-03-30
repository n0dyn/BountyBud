---
id: "nuclei-services"
title: "Nuclei Service Detection"
type: "tool"
category: "network"
subcategory: "service-enumeration"
tags: ["service", "nuclei-services"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Service-specific vulnerability scanning using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t technologies/ -rate-limit 50 -o {domain}_service_detection.txt
echo "Service detection results saved to {domain}_service_detection.txt"
```
