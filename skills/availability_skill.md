# Rate Limit & Availability Skill — flow-sast Phase 4

Scope: missing rate limit, DoS on specific functions, ReDoS,
resource exhaustion, algorithmic complexity attack.

---

## 1. Missing Rate Limit

**Scope**: chỉ kiểm tra các endpoint đặc thù có nguy cơ cao — KHÔNG scan toàn bộ API.

**High-risk endpoint patterns** (filter trước từ `catalog/endpoints.json`):
- Auth: `/login`, `/signin`, `/authenticate`, `/token`
- Password: `/password-reset`, `/forgot-password`, `/change-password`
- OTP / verification: `/otp`, `/verify`, `/confirm`, `/2fa`
- Email / SMS: `/send-email`, `/resend`, `/notify`
- Signup / registration: `/register`, `/signup`, `/create-account`
- Payment / order: `/checkout`, `/pay`, `/order`, `/purchase`
- Admin / sensitive: `/admin`, `/sudo`, `/impersonate`

**Primary input (Phase 3 Verify)**:
- Filter `catalog/endpoints.json` cho các high-risk paths trên → danh sách ứng viên
- Với mỗi ứng viên, xác nhận trực tiếp từ code:
  - Endpoint file:line + HTTP method
  - `auth_tags[]` — confirmed absence of throttle/limiter tags (`express_mw:rateLimit`, `@limiter.limit`, `middleware:throttle`, `ThrottleRequests`)

**Supplementary context (catalog)**:
- `catalog/repo_intel.json` → `framework_detection.dependencies` — kiểm tra rate-limit library có được cài không (Flask-Limiter, express-rate-limit, django-ratelimit…); nếu không có → HIGH confidence
- `catalog/business_ctx.json` → `sensitive_flows` — bổ sung thêm endpoint đặc thù theo domain (ví dụ: `/redeem`, `/withdraw`, `/transfer`)

**VULNERABLE**:
```python
@app.post('/login')
def login():
    user = authenticate(request.json['email'], request.json['password'])
    # No rate limiting → brute force possible
```

**SAFE** (Flask-Limiter example):
```python
@limiter.limit("5 per minute")
@app.post('/login')
def login(): ...
```

**Verify**:
1. Filter `catalog/endpoints.json` for high-risk paths (`/login`, `/reset`, `/otp`, `/signup`)
2. Check `auth_tags[]` for throttle/limiter middleware
3. If no rate-limit library in `repo_intel.dependencies` AND no CDN/WAF noted → HIGH confidence

**Note**: Rate limit may be at CDN/infrastructure level (not in code) → mark UNCERTAIN if Nginx/Cloudflare in Dockerfile.

**Impact**: brute force credentials, OTP enumeration, account takeover.

---

## 2. DoS on Specific Functions

**Pattern**: user-controlled input triggers expensive operation with no limit.

**VULNERABLE**:
```python
count = int(request.args.get('count', 10))
result = [expensive_operation() for _ in range(count)]    # count=1000000 → DoS

size = request.json.get('size', 100)
data = generate_report(size=size)                         # size=999999 → OOM
```

**SAFE**:
```python
count = min(int(request.args.get('count', 10)), 100)      # cap at 100
```

**Verify from flow_nodes**: user-controlled numeric parameter → loop count, memory allocation, query LIMIT, file generation size — is there a cap?

---

## 3. ReDoS (Regular Expression DoS)

**Pattern**: catastrophically backtracking regex applied to user input → CPU spike.

**VULNERABLE** (backtracking patterns):
```python
import re
pattern = r'^(a+)+$'                          # catastrophic backtracking
re.match(pattern, user_input)                 # input "aaaaab" → exponential time

pattern = r'(\w+\s*)+='                       # vulnerable to long non-matching input
```

**SAFE**: use non-backtracking engine or set timeout:
```python
import re, signal
# Or use Google's re2 library (linear time)
import re2
re2.match(pattern, user_input)
```

**Test**: send input designed to trigger backtracking:
```
"aaaaaaaaaaaaaaaaaaaaaaab"   # for (a+)+ pattern
```

**Verify**: regex patterns containing `(x+)+`, `(x*)*`, `(x|y)+` applied directly to user input.

---

## 4. Resource Exhaustion

**Patterns**:
- Zip bomb: compressed file → enormous when extracted (check file size after extraction)
- XML bomb (billion laughs): deeply nested XML entity expansion
- GraphQL depth attack: deeply nested query → exponential resolver calls
- Unlimited pagination: `?page_size=99999`

**VULNERABLE**:
```python
# No size limit on zip extraction
with zipfile.ZipFile(uploaded) as zf:
    total_size = sum(info.file_size for info in zf.infolist())
    zf.extractall(dest)                       # no size check before extract
```

**SAFE**:
```python
MAX_UNCOMPRESSED = 100 * 1024 * 1024          # 100MB limit
total_size = sum(info.file_size for info in zf.infolist())
if total_size > MAX_UNCOMPRESSED:
    raise ValueError("Archive too large")
```

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| Login endpoint, no rate limit middleware visible | HIGH |
| Rate limit via CDN/infrastructure (not in code) | UNCERTAIN — note it |
| User input → loop count, no cap | HIGH |
| `min(count, MAX)` cap applied | FALSE POSITIVE |
| Catastrophic backtracking regex + user input | HIGH |
| Fixed regex, no user input | FALSE POSITIVE |
