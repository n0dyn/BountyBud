---
id: "graphql-grpc"
title: "GraphQL & gRPC Hunting Masterclass (2026 Edition)"
type: "technique"
category: "api-security"
subcategory: "graphql"
tags: ["graphql", "grpc", "protobuf", "introspection", "batching", "alias-dos", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "dig-deep-asset-classes"]
difficulty: "advanced"
updated: "2026-03-30"
---

# GraphQL & gRPC Hunting Masterclass (2026 Edition)

## Why These Matter
GraphQL powers 70%+ of modern SPAs; gRPC dominates microservices and mobile backends. Both expose massive attack surfaces scanners miss.

## Discovery & Enumeration
- GraphQL: `/graphql`, `/api/graphql`, introspection, batching
- gRPC: server reflection, `.proto` files, binary payloads

## Deep Dig Prompts
```
Given this GraphQL schema [paste introspection]: 
1. Find all queries/mutations missing @auth or rate limiting.
2. Identify objects allowing cross-tenant access.
3. Craft 5 payloads for mass exfiltration, alias DoS, or recursive depth attacks (2026 techniques).
```

```
Given this gRPC reflection output or .proto: 
1. List all services/methods that accept user-controlled input.
2. Suggest 10 binary or protobuf manipulation attacks (field injection, type confusion, large message DoS).
```

## High-Impact Vectors
- GraphQL: Batching/alias DoS, introspection bypass, IDOR via __typename, field-level auth bypass
- gRPC: Protobuf deserialization RCE, reflection → service discovery, unary streaming abuse

## Tools
- GraphQL Voyager, InQL, Clairvoyance
- grpcurl, protobuf-inspector, Burp gRPC extension
