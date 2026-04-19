# Hardcoded Secrets & Weak Crypto Skill — flow-sast Phase 4

Scope: hardcoded credentials, API keys, private keys, weak hashing,
insecure random, debug backdoors.

**Primary input (Phase 3 Verify)**:
- **Hardcoded secrets (Sections 1, 4, 5)**: direct from `catalog/secrets.json` — bypass Connect/Joern pipeline
  - `secret.file` — source file containing the hardcoded value
  - `secret.type` — category (api_key / jwt_secret / db_password / private_key…)
  - `secret.value` — detected value or masked pattern
  - `secret.confidence` — confirmed vs candidate
- **Weak crypto / insecure random (Sections 2–3)**: verified path from `connect/joern_annotated_paths.json`:
  - `path.entry` — file:line where weak function is called
  - `path.sink` — weak crypto sink (`md5`, `sha1`, `random.randint`, `Math.random`, etc.)
  - `path.flow_nodes[]` — call chain context (is it used for passwords / security tokens?)
  - `path.vuln_type` — `weak_crypto` / `insecure_random`

**Supplementary context (catalog)**:
- `catalog/sources.json` — weak crypto sinks flagged by semgrep: `md5()`, `sha1()`, `random.randint()`, `Math.random()`
- `catalog/repo_intel.json` → `framework_detection.dependencies` — presence of weak libs (e.g. `des`, `rc4`, `md5` npm package)
- `catalog/repo_intel.json` → `auth_detection.annotations` — `DEBUG=True`, default credentials in config files found during auth scan

---

## 1. Hardcoded Secrets

**VULNERABLE patterns**:
```python
SECRET_KEY = "mysecretkey123"
DB_PASSWORD = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_KEY = "sk_live_xxxxxxxxxxxx"
```
```php
define('DB_PASSWORD', 'hardcoded_pass');
$apiKey = "AIzaSyXXXXXXXXXXXX";           // Google API key in source
```
```java
private static final String JWT_SECRET = "supersecretkey";
String token = Jwts.builder().signWith(Keys.hmacShaKeyFor("hardcoded".getBytes()))
```
```js
const JWT_SECRET = 'my-secret-key';
mongoose.connect('mongodb://admin:password@localhost/db');
```

**SAFE**: load from environment / secrets manager.
```python
SECRET_KEY = os.environ['SECRET_KEY']
SECRET_KEY = os.environ.get('SECRET_KEY') or raise RuntimeError("missing")
```

**Verify from flow_nodes / source**: string literal assigned to variable named
`password`, `secret`, `key`, `token`, `api_key`, `access_key`, `private_key`.

**High-value patterns to check**:
- AWS: `AKIA[0-9A-Z]{16}` / `aws_secret_access_key`
- GitHub: `ghp_[A-Za-z0-9]{36}`
- Stripe live: `sk_live_`
- Private key header: `-----BEGIN RSA PRIVATE KEY-----`
- JWT secret used in code directly

---

## 2. Weak Password Hashing

**VULNERABLE**:
```python
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()    # MD5 — broken
hashed = hashlib.sha1(password.encode()).hexdigest()   # SHA1 — weak
hashed = hashlib.sha256(password.encode()).hexdigest() # SHA256 — no salt, fast
```
```php
$hash = md5($password);
$hash = sha1($password);
```

**SAFE**:
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# or
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
```
```php
password_hash($password, PASSWORD_BCRYPT);
password_hash($password, PASSWORD_ARGON2ID);
```

**Verify**: hashing function used for passwords — MD5/SHA1/SHA256 without salt = weak.

---

## 3. Insecure Random

**VULNERABLE** (predictable):
```python
import random
token = str(random.randint(100000, 999999))            # predictable PRNG
session_id = str(int(time.time()))                     # timestamp-based
```
```php
$token = rand(100000, 999999);
$token = mt_rand();
```

**SAFE** (cryptographically secure):
```python
import secrets
token = secrets.token_hex(32)
token = secrets.token_urlsafe(32)
```
```php
$token = bin2hex(random_bytes(32));
```

**Verify**: `random.randint` / `rand()` / `Math.random()` used for security tokens
(password reset, email verification, session ID, CSRF token).

---

## 4. Weak JWT Secret

Covered in authz_skill Section 3, but also check here:
- Short secret (`< 256 bits` for HS256)
- Secret stored in source code
- Default secret (`secret`, `changeme`, `jwt_secret`)

---

## 5. Debug Backdoors

```python
if request.args.get('debug') == 'true':
    return jsonify(internal_state)     # debug param exposes internals

# Hardcoded bypass
if username == 'admin' and password == 'backdoor123':
    return login_success()
```

**Verify**: conditional branches checking hardcoded credentials or magic debug params.

---

## Impact Assessment

| Finding | Severity |
|---|---|
| Live API key (AWS/Stripe/GCP) in source | CRITICAL |
| JWT secret in source | HIGH |
| DB password in source | HIGH |
| MD5/SHA1 for passwords | HIGH |
| `random.randint` for reset token | HIGH |
| Dev/test key with comment "change before prod" | MEDIUM |
| SHA256 without salt for passwords | MEDIUM |
