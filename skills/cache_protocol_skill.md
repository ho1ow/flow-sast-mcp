# Cache & Protocol Skill — flow-sast Phase 4

Scope: cache poisoning, web cache deception, host header injection,
HTTP request smuggling, cache timing attack.

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json` (where taint flow exists):
  - `path.entry` — entry point receiving unkeyed/host header input (file:line)
  - `path.sink` — response generation sink (link/redirect/header output, cache write)
  - `path.flow_nodes[]` — call chain; look for unkeyed header flowing into cached response or link generation
  - `path.vuln_type` — `cache_poisoning` / `host_header` / `smuggling` / `cache_deception`
  - `path.path_decision` — verify depth
- For config-based issues (HTTP Smuggling, Cache Deception): directly read infra files during Phase 3
  (`Dockerfile`, `docker-compose.yml`, `nginx.conf`, `varnish.vcl`, cache config)

**Supplementary context (catalog/connect)**:
- **Host Header Injection**: `catalog/sources.json` (header sources: `request.host`, `X-Forwarded-Host`) → `catalog/sinks.json` (link/redirect generation sinks)
- **Cache Poisoning**: `catalog/repo_intel.json` → `framework_detection` — cache middleware (`@Cacheable`, `config/cache.php`, Varnish, CDN)
- **HTTP Smuggling**: `catalog/repo_intel.json` → `framework_detection` — proxy stack (gunicorn+nginx, uvicorn+caddy)
- **Web Cache Deception**: `catalog/endpoints.json` — endpoints serving authenticated content; check for missing `Cache-Control: no-store`

---

## 1. Web Cache Poisoning

**Pattern**: attacker controls unkeyed cache input → response cached with malicious content → served to other users.

**Unkeyed inputs** (common):
- `X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`
- `X-HTTP-Method-Override`
- `Vary` header not including the injected header

**VULNERABLE**:
```python
# Server reflects X-Forwarded-Host in canonical URL in response
host = request.headers.get('X-Forwarded-Host', request.host)
canonical_url = f"https://{host}/page"
return render_template('page.html', canonical=canonical_url)
# If response is cached → all users get attacker-controlled canonical URL
```

**Verify**: check if unkeyed headers (X-Forwarded-Host etc.) are reflected in response
AND the response is cached (check `Cache-Control`, `Vary` headers).

**Payload**: set `X-Forwarded-Host: attacker.com` — if reflected in cacheable response → poison cache.

---

## 2. Web Cache Deception

**Pattern**: trick cache into storing authenticated user's response at a public URL.

```
GET /account/settings/nonexistent.css
```
- App ignores suffix → serves `/account/settings` (authenticated content)
- Cache sees `.css` extension → caches as public resource
- Attacker visits same URL → gets victim's cached data

**Verify**: check if app serves real content for URLs with added static file extensions.
Check cache rules — does `.css`/`.js`/`.png` bypass auth for cache?

---

## 3. Host Header Injection

**Pattern**: `Host` header used in password reset URL, redirects, or absolute URLs in response.

**VULNERABLE**:
```python
reset_url = f"https://{request.headers['Host']}/reset?token={token}"
send_email(user.email, reset_url)          # attacker sets Host: evil.com → token sent to evil.com
```

**SAFE**: use configured base URL, never reflect `Host` header.
```python
reset_url = f"{settings.BASE_URL}/reset?token={token}"
```

**Verify**: password reset, email confirmation, redirect generation — is `Host` header used to build URLs?

---

## 4. HTTP Request Smuggling

**Pattern**: discrepancy in how front-end (CDN/proxy) and back-end parse `Content-Length` vs `Transfer-Encoding` → prefix injected into next request.

**CL.TE** (front-end uses Content-Length, back-end uses Transfer-Encoding):
```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Verify**: look for HTTP/1.1 keep-alive + reverse proxy setups.
Check if TE header can be obfuscated: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`.

**Impact**: bypass front-end auth, poison requests of other users, request hijacking.

---

## 5. Cache Timing Attack

**Pattern**: response time differs based on cache hit/miss → reveals presence of private data.

```python
# If user profile cached → fast response; if not → slow DB query
# Attacker times responses to detect if victim visited a resource
```

**Verify**: endpoints that cache user-specific data with predictable cache keys.
Usually a MEDIUM finding — requires precise timing and specific conditions.

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| `X-Forwarded-Host` reflected in cacheable response | HIGH |
| `Host` header in password reset URL | HIGH |
| BASE_URL from config in reset URL | FALSE POSITIVE |
| Cache-Control: no-store on all sensitive responses | FALSE POSITIVE (cache deception) |
| CL.TE desync on HTTP/1.1 endpoint behind proxy | HIGH — verify with PoC |
