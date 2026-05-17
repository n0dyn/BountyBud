---
id: "bola-impact-chains"
title: "BOLA Impact Chains - Beyond Info Disclosure"
type: "technique"
category: "web-application"
subcategory: "idor-advanced"
tags: [bola, idor, chaining, rce-path, data-injection]
difficulty: "advanced"
updated: "2026-05-17"
---

## Overview
Chaining Broken Object Level Authorization (BOLA) with other primitives to achieve critical impact.

## Pattern 1: BOLA to Stored XSS
- Identify a BOLA endpoint that allows viewing other users' data (e.g., address, profile).
- Identify a POST/PUT endpoint that allows updating YOUR data with an XSS payload.
- Chain: Inject XSS into your account -> Trigger an action that causes the victim to view your 'poisoned' object via BOLA.

## Pattern 2: BOLA to State Manipulation
- Switch object IDs in a process flow (e.g., refund target, invite recipient) to manipulate the state of objects you don't own.

