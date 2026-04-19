# SSRF Skill — flow-sast Phase 4

Scope: server-side request forgery (SSRF), blind SSRF.

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json`:
  - `path.entry` — entry point receiving URL/host parameter (file:line)
  - `path.sink` — HTTP call sink name + file
  - `path.flow_nodes[]` — call chain from URL param to HTTP request; check for blocklist/allowlist nodes
  - `path.vuln_type` — `ssrf` / `blind_ssrf`
  - `path.path_decision` — verify depth

**Supplementary context (catalog/connect)**:
- `catalog/sinks.json` — HTTP request sinks: `curl_exec`, `requests.get/post`, `urllib.request.urlopen`, `httpx`, `fetch`, `axios`, `HttpClient`, `WebClient`
- `catalog/sources.json` — URL sources: `request.args['url']`, `req.query.url`, `$_GET['url']`, path params containing URL/host/endpoint
- `catalog/repo_intel.json` → `architecture` — "Webhook/callback detected" = high SSRF surface; cloud provider = metadata endpoint risk
- `catalog/repo_structure.json` → `custom_sinks[]` — custom HTTP wrapper classes (e.g. `HttpProxy`, `FetchService`) appear here

---

## What is SSRF

Server makes HTTP/TCP request to an attacker-controlled URL — enables internal network access,
cloud metadata exfil, internal service scanning, potential RCE via internal endpoints.

---

## VULNERABLE Patterns

```python
url = request.args.get('url')
requests.get(url)                               # direct user-controlled URL

# Indirect — user controls part of URL
base = "https://api.example.com/"
path = request.args.get('endpoint')
requests.get(base + path)                       # path traversal: ../../internal
```
```php
$url = $_GET['url'];
$content = file_get_contents($url);             // SSRF
curl_exec($ch);                                 // curl with user-controlled URL
```
```js
const url = req.query.url;
axios.get(url)                                  // SSRF
fetch(url)
```
```java
URL url = new URL(request.getParameter("url"));
url.openConnection().getInputStream();
```

---

## SAFE Patterns

```python
ALLOWED_DOMAINS = {'api.trusted.com', 'cdn.example.com'}
parsed = urllib.parse.urlparse(url)
if parsed.hostname not in ALLOWED_DOMAINS:
    abort(400)
requests.get(url)
```

Allowlist-based domain check is the only reliable fix.
Blocklist-based (blocking `127.0.0.1`, `169.254.x.x`) is **bypassable**.

---

## Verify from flow_nodes

1. User input reaches HTTP client call (`requests.get`, `curl_exec`, `fetch`, `axios`, `URL.openConnection`)
2. Is there domain allowlist before the call? If yes — likely safe
3. Is there only a blocklist / regex check? → check bypasses

---

## Bypasses (blocklist evasion)

```
http://127.0.0.1/admin             → blocked
http://127.1/admin                 → bypass
http://2130706433/admin            → decimal IP: 127.0.0.1
http://0x7f000001/admin            → hex IP
http://[::1]/admin                 → IPv6 localhost
http://localhost.attacker.com      → DNS rebinding
http://attacker.com@127.0.0.1/     → URL authority bypass
http://127.0.0.1#attacker.com      → fragment bypass
http://attacker.com/redirect → 127.0.0.1   // open redirect + SSRF chain
file:///etc/passwd                 → file:// scheme
dict://127.0.0.1:6379/info         → Redis via dict://
gopher://127.0.0.1:6379/...        → Redis/SMTP via gopher://
```

---

## High-Value Targets

```
http://169.254.169.254/latest/meta-data/              # AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/   # GCP (needs header)
http://169.254.169.254/metadata/instance               # Azure
http://localhost:2375/containers/json                  # Docker API
http://localhost:8080/                                  # internal admin panels
http://internal-service:5432/                          # database ports
```

---

## Blind SSRF Detection

No response body returned — use out-of-band:
- Collaborator/interactsh DNS callback: `http://xxxx.burpcollaborator.net`
- Time-based: `http://10.0.0.1:22` — connection refused = fast, open port = slow
- Error message differences reveal internal topology

---

## Impact Factors (CVSS)

- Cloud metadata accessible → credential theft → HIGH/CRITICAL
- Internal services accessible → lateral movement → HIGH
- Only blind SSRF with no internal reach → MEDIUM
- Filtered by WAF/allowlist → LOW

---

## Remediation

1. Allowlist permitted domains/IPs — never blocklist
2. Resolve DNS to IP and validate IP is not private/loopback before connect
3. Disable unnecessary URL schemes (file://, gopher://, dict://)
4. Use outbound proxy with allowlist if possible
