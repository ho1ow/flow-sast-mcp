# AuthZ / AuthN / Access Control Skill — flow-sast Phase 4

Scope: IDOR, BFLA, broken access control, privilege escalation,
mass assignment, JWT vulnerability, OAuth vulnerability, session fixation/hijacking.

Input: use repo_intel.auth_detection (mechanisms, annotations, auth_relevant_files)
to select the right checklist section.

---

## Section 0: repo_intel Mapping

Read `catalog/repo_intel.md` before analyzing:

| repo_intel.mechanisms | Prioritize |
|---|---|
| JWT / Bearer Token | Section 3 (JWT) |
| Session-based | Section 5 (Session) |
| OAuth2/OIDC | Section 4 (OAuth) |
| RBAC (Spatie, Casbin, Spring Security) | Sections 1 + 2 |
| Multi-tenant indicator | Section 1 — check tenant scope in every query |

---

## 1. IDOR (Insecure Direct Object Reference)

**Primary input (Phase 3 Verify)**:
- **`catalog/endpoints.json` → `idor_candidates[]`** — pre-flagged endpoints with ID-like params + no ownership annotation; use as starting candidate list
- Verified path from `connect/joern_annotated_paths.json` (confirms taint flow for each candidate):
  - `path.entry` — endpoint file:line (matched against `idor_candidates[]`)
  - `path.sink` — DB lookup call (`Model.find`, `Order::find`, `findById`, `where('id', $id)`, etc.)
  - `path.flow_nodes[]` — call chain from ID param → DB query; check for ownership WHERE clause
  - `path.vuln_type` — `idor`
  - `path.path_decision` — verify depth
- **`catalog/data_models.json` → `fields[]` + `sensitive_fields[]`** for the accessed model — determines impact severity (part of Phase 3 Verify, not optional)

**Supplementary context (catalog)**:
- `catalog/repo_intel.json` → `permission_matrix.endpoint_role_map` — role requirements per endpoint
- `catalog/repo_intel.json` → `security_notes` — multi-tenant indicator (must check tenant scope)

**Impact assessment — Claude reads model fields**:
After confirming IDOR exists, look up the model in `data_models.json`:
- Model has `sensitive_fields[]` (password, ssn, medical data) → CRITICAL
- Model has financial fields (balance, card_number) → HIGH
- Model has only non-sensitive business data (order items, shipping address) → MEDIUM
- Use `business_ctx` to understand if the model is business-critical in this domain

**Pattern**: user controls object ID → no ownership check → accesses other users' data.

**VULNERABLE**:
```python
@app.get('/invoice/<invoice_id>')
def get_invoice(invoice_id):
    return Invoice.query.get(invoice_id)          # no ownership check

# Laravel
public function show($id) {
    return Order::find($id);                      # missing: ->where('user_id', auth()->id())
}
```

**SAFE**:
```python
invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
```

**Verify from flow_nodes**:
1. Path/query param → DB lookup
2. Is `user_id` / `owner_id` / `company_id` in WHERE clause?
3. Multi-tenant: is `tenant_id` / `company_id` always scoped?
4. Check `permission_matrix.endpoint_role_map` — if role != expected → BFLA, not just IDOR

**Test**: change `?id=123` → `?id=124`. Check UUID predictability.

---

## 2. BFLA (Broken Function Level Authorization)

**Primary input (Phase 3 Verify)**:
- Verified endpoint confirmed accessible without proper role/auth check (from direct code read in Phase 3):
  - Entry endpoint file:line + HTTP method
  - `auth_tags[]` from `catalog/endpoints.json` — what guards are (or are NOT) applied
  - `path.flow_nodes[]` (if available) — trace request → privileged action; absence of role/auth check node
- **`catalog/data_models.json` → `fields[]` + `sensitive_fields[]`** for models the endpoint reads/writes — determines impact severity of unauthorized access

**Supplementary context (catalog)**:
- `catalog/repo_intel.json` → `permission_matrix.endpoint_role_map` — expected role requirements per endpoint
- `catalog/repo_intel.json` → `permission_matrix.public_endpoints` — explicitly no-auth (`@Public`, `[AllowAnonymous]`)
- `catalog/endpoints.json` → `auth_tags[]` per endpoint — full guard/middleware list

**Pattern**: privileged endpoint — missing role/permission check.

**VULNERABLE**:
```python
@app.delete('/admin/users/<id>')
@login_required                   # only checks authenticated, not admin role
def delete_user(id): ...
```

**SAFE**:
```python
if not current_user.has_role('admin'):
    abort(403)
```

**Verify**: check `permission_matrix.endpoint_role_map` — admin/privileged paths missing role annotation.
Check `permission_matrix.public_endpoints` — any sensitive endpoint accidentally marked public.
Check if admin routes share middleware group with regular user routes.

---

## 3. JWT Vulnerabilities

**3a. Algorithm confusion** — accepting `alg` from token header:
```python
# VULNERABLE
jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)['alg'])
# SAFE — explicit allowlist
jwt.decode(token, key, algorithms=['RS256'])
```

**3b. Weak HMAC secret**:
```bash
hashcat -a 0 -m 16500 <JWT> rockyou.txt
```

**3c. Missing claims validation**:
```python
# VULNERABLE
jwt.decode(token, key, options={"verify_exp": False})
# Missing iss/aud/sub check
```

**3d. Sensitive data in payload** — base64-decode middle segment.

**Payload** (alg:none bypass):
```
eyJhbGciOiJub25lIn0.<payload>.
```

**Verify**: what algorithms does `jwt.decode()` accept? Is `exp` verified? Check `auth_relevant_files` from repo_intel for JWT config.

---

## 4. OAuth / OIDC Vulnerabilities

- **Missing state param** → CSRF on OAuth flow: `GET /callback?code=X` no state = vulnerable
- **Open redirect_uri**: `&redirect_uri=https://attacker.com` → token sent to attacker
- **Code reuse**: server must invalidate code after first use
- **Implicit flow** → token in URL fragment → Referer header leaks token

**Verify**: OAuth callback handler — is `state` compared to session? Is `redirect_uri` validated against registered allowlist?

---

## 5. Session Fixation / Hijacking

**Fixation**:
```php
session_start();                  // VULNERABLE: same session ID before and after login
session_regenerate_id(true);      // SAFE: regenerate after login
```

**Hijacking signals**:
- Session ID in URL (`?PHPSESSID=xxx`) → Referer leakage
- Cookie missing `HttpOnly` + `Secure` + `SameSite`
- Predictable session ID

---

## 6. Mass Assignment

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json`:
  - `path.entry` — controller/route accepting user request body (file:line)
  - `path.sink` — mass assignment call (`fill()`, `Model(**data)`, `User.create(req.body)`)
  - `path.flow_nodes[]` — call chain from request body → model field assignment
  - `path.vuln_type` — `mass_assign`
  - `path.path_decision` — verify depth
- **`catalog/data_models.json` → `fields[]` + `mass_assign_risk[]`** for the target model — read before confirming severity (part of Phase 3 Verify: no high-risk fields = lower severity)

**Supplementary context (catalog)**:
- `catalog/sinks.json` → mass assignment sinks: `fill()`, `Model(**request)`, `User.create(req.body)`

**Field identification — two layers**:

*Layer 1 — Regex pre-tagged* (`mass_assign_risk[]`):
- `is_admin`, `role`, `role_id`, `balance`, `verified`, `status`, `banned`... already flagged.

*Layer 2 — Claude semantic review* (scan `fields[]` yourself):
- Read ALL fields in the model being assigned, identify anything an attacker would want to control:
  - Privilege fields: `subscription_tier`, `account_type`, `user_level`, `clearance`
  - Financial: `wallet_balance`, `points`, `free_trial_end`, `discount_rate`
  - Verification bypass: `kyc_verified`, `id_verified`, `two_factor_enabled`
  - Business-specific: check `business_ctx.sensitive_flows` for domain context
- Severity scales with what fields exist: privilege escalation fields → CRITICAL, financial fields → HIGH

**VULNERABLE**:
```python
user = User(**request.json)       # any field from request assigned
```
```php
$user->fill($request->all());     # without $fillable protection
```
```js
User.create(req.body)
```

**SAFE**: explicit field allowlist.
```python
user = User(name=data['name'], email=data['email'])
```
```php
protected $fillable = ['name', 'email'];
```

**Test**: add fields from `data_models.mass_assign_risk` to request body: `role=admin`, `is_admin=true`, `balance=9999`.

---

## 7. Privilege Escalation

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json` (or direct code read):
  - `path.entry` — role/permission update endpoint (file:line)
  - `path.flow_nodes[]` — trace request → role field assignment; check for caller role validation
  - `path.vuln_type` — `privilege_esc`
- **`catalog/data_models.json` → `fields[]` + `sensitive_fields[]`** for user/account model — what sensitive data the escalated role can access
- **`catalog/repo_intel.json` → `permission_matrix`** — role hierarchy + `endpoint_role_map`; shows full blast radius of escalation

**Supplementary context (catalog)**:
- `catalog/endpoints.json` → endpoints gated on the target role — full list of actions unlocked by escalation

**Vertical** (user → admin): find role assignment endpoints — can user modify own role?
```python
user.role = request.json.get('role', user.role)   # VULNERABLE if not admin-gated
```

**Verify**: role/permission update functions — is caller's current role checked before update?

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| DB lookup by user-controlled ID, no ownership check | HIGH |
| DB lookup scoped by `user_id = current_user.id` | FALSE POSITIVE |
| Admin endpoint with only `@login_required` | HIGH |
| JWT `algorithms=["none"]` or from header | CRITICAL |
| `session_regenerate_id()` after login | FALSE POSITIVE |
| `request.json` → `Model(**data)` no field filter | HIGH |
| `$fillable` properly set | FALSE POSITIVE |
