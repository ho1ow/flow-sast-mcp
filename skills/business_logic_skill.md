# Business Logic Skill — flow-sast Phase 4

Scope: race condition, negative/zero price, bypass flow, state machine bypass,
TOCTOU, integer overflow in business context.

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json` / `connect/gitnexus_*.json`:
  - `path.entry` — entry point (API route or business function, file:line)
  - `path.sink` — business sink name (charge, debit, transferFunds, applyDiscount, redeemVoucher…)
  - `path.flow_nodes[]` — call chain; look for read-check-write pattern, missing DB lock/transaction
  - `path.vuln_type` — as classified during Phase 3 (pattern-driven: race, neg_value, state_bypass, toctou, etc.)
  - `path.path_decision` — verify depth

**Supplementary context (catalog/connect)**:
- `catalog/business_ctx.json` → `sensitive_flows` — **primary guide**: which flows are business-critical; race conditions only matter where these flows exist
- `catalog/repo_structure.json` → `process_flows[]` — gitnexus-discovered state transitions and financial operation sequences
- `catalog/repo_structure.json` → `custom_sinks[]` — custom business sinks found by gitnexus 3-pass
- `catalog/repo_intel.json` → `security_notes` — "Payment/billing detected" = mandatory race condition check
- `catalog/data_models.json` → `fields[]` — identify numeric fields (balance, points, quantity) vulnerable to integer/negative value manipulation

---

## 1. Race Condition

**Pattern**: concurrent requests manipulate shared state before check completes.

**VULNERABLE**:
```python
balance = get_balance(user_id)         # T1 reads: 100
if balance >= amount:                   # T1 checks: 100 >= 100 ✓
    deduct(user_id, amount)             # T2 also passes check simultaneously
    # both threads deduct → balance goes negative
```
```php
$voucher = Voucher::where('code', $code)->where('used', false)->first();
if ($voucher) {
    $voucher->used = true;
    $voucher->save();                   # gap between check and save
    applyDiscount();
}
```

**SAFE**:
```python
# Atomic DB operation with row locking
db.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s",
           (amount, user_id, amount))
if db.rowcount == 0:
    raise InsufficientFunds()
```
```php
Voucher::where('code', $code)->where('used', false)
       ->update(['used' => true]);       # atomic UPDATE, check rowcount
```

**Verify**: check-then-act pattern without atomic lock. Look for separate read + write operations on same resource.

**Exploit**: send 10–50 concurrent requests via Turbo Intruder / race condition tools.
```python
import concurrent.futures
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(redeem_voucher, code) for _ in range(20)]
```

---

## 2. Negative / Zero Value Attacks

**Pattern**: numeric input not validated → negative price, zero quantity, etc.

**VULNERABLE**:
```python
total = price * quantity              # quantity=-1 → negative total
account.balance += amount             # amount=-100 → transfers out not in
```

**SAFE**:
```python
if quantity <= 0 or amount <= 0:
    raise ValueError("Invalid value")
```

**Verify from flow_nodes**: numeric user input (`price`, `quantity`, `amount`, `count`) reaches arithmetic without positive-value check.

**Test**: send `quantity=-1`, `amount=-100`, `price=0.001`.

---

## 3. State Machine Bypass

**Pattern**: multi-step flow can be jumped out of order.

**VULNERABLE**:
```python
# Step 3 of checkout — no check that steps 1+2 completed
@app.post('/checkout/confirm')
def confirm_order():
    order = Order.query.get(session['order_id'])
    process_payment(order)             # can call directly without cart/shipping steps
```

**SAFE**: enforce state in DB.
```python
order = Order.query.filter_by(id=order_id, status='payment_pending').first_or_404()
```

**Test**: call step N directly with valid auth, skipping prior steps.

---

## 4. TOCTOU (Time-of-Check to Time-of-Use)

**Pattern**: state checked at one time, used at another — state can change between.

```python
if user.is_premium():                  # check
    time.sleep(0)                      # async gap
    send_premium_content()             # use — user may have cancelled between
```

**Verify**: check-then-use separated by async operation, DB query, or network call.

---

## 5. Business Rule Abuse

**Pattern**: app enforces rules client-side or in a bypassable manner.

**Check**:
- Discount stacking: apply multiple coupons → price goes negative
- Referral self-abuse: refer self via different email → infinite credits
- Gift card: buy with stolen card, redeem before chargeback
- Free trial: create multiple accounts → bypass subscription
- Price manipulation: modify price in request between add-to-cart and checkout

**Verify**: find price/discount/credit calculation functions — are values re-read from DB at payment time, or trusted from session/request?

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| Read-check-write pattern, no DB lock/atomic update | HIGH |
| `UPDATE ... WHERE status = 'pending'` atomic | FALSE POSITIVE |
| Numeric user input → arithmetic, no positive check | HIGH |
| `abs(amount)` forces positive | FALSE POSITIVE (if applied before arithmetic) |
| Multi-step flow, step N accessible without step N-1 state | HIGH |
| Status verified from DB before action | FALSE POSITIVE |
