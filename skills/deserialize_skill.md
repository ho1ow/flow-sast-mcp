# Deserialization Skill — flow-sast Phase 4

Scope: PHP unserialize, Java object deserialization, Python pickle/yaml,
.NET BinaryFormatter, XML deserialization.

**Primary input (Phase 3 Verify)**:
- Verified path from `connect/joern_annotated_paths.json`:
  - `path.entry` — entry point receiving untrusted data (cookie / request / file, file:line)
  - `path.sink` — deserialization sink name + file
  - `path.flow_nodes[]` — call chain from network/file input to deserialize call
  - `path.vuln_type` — `deserialization`
  - `path.path_decision` — verify depth

**Supplementary context (catalog/connect)**:
- `catalog/sinks.json` — deserialization sinks: `unserialize`, `pickle.load/loads`, `yaml.load`, `ObjectInputStream.readObject`, `BinaryFormatter.Deserialize`, `XStream.fromXML`, `marshal.loads`, `jsonpickle.decode`
- `catalog/sources.json` — untrusted data sources feeding into these sinks
- `catalog/repo_intel.json` → `framework_detection` — language/framework determines gadget chain tooling (ysoserial for Java, PHPGGC for PHP)
- `catalog/repo_intel.json` → `security_notes` — "AI model artifact loading" = special case (torch.load, AutoModel.from_pretrained)

---

## Core Risk

Deserialization of untrusted data → attacker crafts gadget chain →
magic methods (`__wakeup`, `__destruct`, `readObject`) execute arbitrary code.

---

## 1. PHP unserialize

**VULNERABLE**:
```php
$data = unserialize($_COOKIE['session']);         // CRITICAL
$data = unserialize(base64_decode($token));       // hidden in token
$obj  = unserialize(file_get_contents($path));
```

**SAFE**: use JSON instead.
```php
$data = json_decode($_COOKIE['session'], true);
```

**Verify**: trace `unserialize()` — does input come from cookie/request/external source?
Check codebase for classes with `__wakeup`, `__destruct`, `__toString` — these form gadget chains.

**Exploit**: use PHPGGC to generate payload for frameworks detected by repo_intel (Laravel, Symfony, etc.).
```bash
phpggc Laravel/RCE1 system id | base64
```

---

## 2. Java Object Deserialization

**VULNERABLE**:
```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();                    // CRITICAL

// Also vulnerable:
XMLDecoder decoder = new XMLDecoder(inputStream);
decoder.readObject();
```

**SAFE**: use Jackson/Gson with strict type binding, or SerialKiller/NotSoSerial agent to whitelist classes.

**Verify**: `readObject()` / `readResolve()` receives network/user input stream.
Check classpath for commons-collections, Spring, Groovy, etc. (ysoserial payloads).

**Exploit**: ysoserial:
```bash
java -jar ysoserial.jar CommonsCollections6 'id' | base64
```

---

## 3. Python pickle / marshal / shelve

**VULNERABLE**:
```python
import pickle
data = pickle.loads(request.get_data())           # CRITICAL — arbitrary code exec
data = pickle.loads(base64.b64decode(token))      # hidden in JWT-like token
data = marshal.loads(user_input)
```

**SAFE**:
```python
import json
data = json.loads(request.get_data())
```

**Payload** (PoC):
```python
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())))
```

---

## 4. YAML unsafe load

**VULNERABLE**:
```python
import yaml
data = yaml.load(user_input)                     # CRITICAL — allows !!python/object
data = yaml.load(user_input, Loader=yaml.Loader) # same risk
```

**SAFE**:
```python
data = yaml.safe_load(user_input)                # only basic types
data = yaml.load(user_input, Loader=yaml.SafeLoader)
```

**Verify from flow_nodes**: `yaml.load()` without `Loader=yaml.SafeLoader` — check if input is user-controlled.

**Payload**:
```yaml
!!python/object/apply:os.system ['id']
```

---

## 5. .NET BinaryFormatter / NetDataContractSerializer

**VULNERABLE**:
```csharp
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);             // CRITICAL — Microsoft deprecated

NetDataContractSerializer s = new NetDataContractSerializer();
s.ReadObject(stream);
```

**SAFE**: use `System.Text.Json` or `JsonSerializer` with explicit type contracts.

**Verify**: input stream origin — does it come from HTTP request, cookie, or external service?
Use ysoserial.net for exploit generation.

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| `pickle.loads(user_input)` | CRITICAL |
| `yaml.load()` without SafeLoader + user input | HIGH |
| `unserialize(cookie)` — PHP gadgets present | HIGH |
| `ObjectInputStream.readObject()` from network | HIGH |
| `json.loads()` / `yaml.safe_load()` | FALSE POSITIVE |
| Deserialization of server-generated, signed token | LOW — verify signature check |

---

## Remediation

1. Replace deserialization with JSON / structured format
2. If unavoidable: whitelist allowed classes (Java SerialKiller, PHP `allowed_classes`)
3. Sign serialized data and verify before deserializing
4. Run deserialization in isolated process / sandbox
