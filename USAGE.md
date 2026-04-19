# flow-sast — Usage Guide

Hướng dẫn prompt từng phase khi dùng **Claude Code** với MCP server `flow-sast`.

> **Trước khi bắt đầu:**
> 1. Đảm bảo MCP đã đăng ký: `claude mcp list` → thấy `flow-sast`
> 2. Index repo bằng GitNexus (nếu dùng): `cd /repo && gitnexus analyze`
> 3. Mở Claude Code trong thư mục target repo: `cd /repo && claude`

---

## Khởi động session

Prompt đầu tiên, khai báo mục tiêu — **Claude tự tạo run_id, tự detect stack**:

```
Tôi muốn audit bảo mật repo này.

repo: /absolute/path/to/target/repo
context file: /path/to/context.md    # bỏ qua nếu không có
```

> Claude sẽ tự generate `run_id` và gọi `repo_intel` đầu tiên để detect stack — không cần khai báo thủ công.  
> Nếu muốn chỉ định `run_id` (VD: resume session cũ), thêm `run_id: 20260417_120000_myapp` vào prompt.

> Claude Code sẽ đọc `CLAUDE.md` trong project và tự biết flow cần làm.  
> Nếu không có CLAUDE.md, dùng các prompt dưới đây theo từng phase.

---

## PRE-PRE PHASE: Codebase Intelligence

Gọi tool này **đầu tiên** — trước context parsing và trước Phase 1.  
Tool tự scan file structure, manifest, config để extract thông tin hệ thống.

```
Trước khi bắt đầu audit, extract intelligence của repo này:

repo_intel:
  run_id: 20260417_120000_myapp
  repo: /absolute/path/to/repo
```

**Kết quả trả về và cách dùng:**

```
framework_detection:
  frameworks: ["Laravel"]        → dùng làm stack param cho semgrep_scan
  languages:  ["PHP"]
  dependencies: { php: [...] }

auth_detection:
  mechanisms: ["JWT", "Spatie Laravel-Permission"]
              → ưu tiên verify các path xuyên qua auth middleware
  auth_relevant_files: [...]    → đọc kỹ trong Phase 3 Verify
  gitnexus_symbols: [...]       → các class/method liên quan đến auth

architecture:
  inferred_notes:
    - "Multi-tenant indicator: company_id"    → enforce trong mọi query
    - "Admin panel detected"                 → kiểm tra auth riêng
    - "Webhook endpoints detected"           → kiểm tra sender validation
    - "Payment/billing detected"             → business-critical flows
    - "Async job/queue detected"             → non-HTTP sources
```

**Output files được lưu:**
```
reports/20260417_120000_myapp/catalog/
├── repo_intel.json   ← structured (feed vào các tool tiếp theo)
└── repo_intel.md     ← human-readable (đọc để hiểu hệ thống)
```

**Sau khi có kết quả, hỏi Claude tổng kết:**
```
Tổng kết repo intel:
- Framework và stack là gì?
- Cơ chế auth/authz thế nào? Có RBAC không?
- Hệ thống có multi-tenant không?
- Những điểm cần lưu ý khi audit là gì?
- Nên đặt stack gì khi gọi semgrep_scan?
```

---

## PRE-PHASE: Context Parsing


**Khi có context file:**

```
Parse context file này và lưu structured output.

parse_context:
  run_id: 20260417_120000_myapp
  context_file: /path/to/context.md
```

**Kiểm tra kết quả:**

```
Tóm tắt business_ctx vừa parse được:
- Có bao nhiêu custom_sinks?
- Có non_http_sources nào không?
- sensitive_flows là gì?
- api_names nào được đặt tên cụ thể? (ví dụ: GetDataSet, ExecSQL)
- function_params nào bị taint?
```

**Không có context file — bỏ qua phase này** và chuyển thẳng Phase 1.

---

## PHASE 1: Catalog

### 1a. Chạy song song (không phụ thuộc nhau)

> Stack được lấy từ `repo_intel.framework_detection.frameworks[0]` — không hardcode.

```
Chạy song song:

1. semgrep_scan:
   run_id: 20260417_120000_myapp
   repo: /path/to/repo
   stack: <repo_intel.frameworks[0]>
   extra_sources:
     - <business_ctx.non_http_sources nếu có>
     - <queue/worker class names nếu "Async job/queue" trong repo_intel.security_notes>

2. api_parse:
   run_id: 20260417_120000_myapp
   repo: /path/to/repo
   stack: <repo_intel.frameworks[0]>

3. secrets_scan:
   run_id: 20260417_120000_myapp
   repo: /path/to/repo
```

### 1b. analyze_catalog — tổng hợp tất cả nguồn (pure Python, không cần LLM)

```
analyze_catalog:
  run_id: 20260417_120000_myapp
  # Không cần param khác — tự đọc từ catalog/ trên disk
```

**Kết quả trả về:**
```
entry_points[]       — tất cả entry points, scored + prioritized
sink_targets[]       — tất cả sinks, scored + prioritized
taint_params[]       — [{function, param, taint_reason}]
gitnexus_params      — pre-computed params cho gitnexus_context (Step 1c)
cypher_hints[]       — ready-to-use Cypher strings cho gitnexus_query (Step 1d)
  [0] high_priority_paths  (HIGH — context-declared entries + confirmed sinks)
  [1] broad_surface        (MEDIUM — tất cả entries OR sinks)
  [2] taint_param_paths    (HIGH — tainted function params → any sink)
stats.high_priority_pairs  — số cặp (entry, sink) HIGH priority
```

**Tại sao cần bước này:**
- Claude không cần đọc thủ công 5 JSON file để extract tên
- Dedup: "ExecSQL" từ context + semgrep → 1 entry thay vì 2 Cypher query riêng
- Scoring: multi-source confirmed → HIGH priority → Cypher hint đầu tiên chạy
- Cypher pre-generated: copy-paste thẳng vào gitnexus_query

### 1c. gitnexus_context — dùng gitnexus_params từ analyze_catalog

```
gitnexus_context:
  run_id: 20260417_120000_myapp
  repo: /path/to/repo
  # Dùng trực tiếp scan_strategy.gitnexus_params — không cần tự extract:
  extra_topics:       <scan_strategy.gitnexus_params.extra_topics>
  api_endpoints:      <scan_strategy.gitnexus_params.api_endpoints>
  semgrep_sink_names: <scan_strategy.gitnexus_params.semgrep_sink_names>
  ctx_api_names:      <scan_strategy.gitnexus_params.ctx_api_names>
  ctx_custom_sinks:   <scan_strategy.gitnexus_params.ctx_custom_sinks>
```

**Kết quả trả về (labeled by source):**
```
api_entry_points[]   {name, source:"api_parse"}
semgrep_sink_names[] {name, source:"semgrep"}
ctx_api_names[]      {name, source:"context"}   ← ExecSQL, GetDataSet
ctx_custom_sinks[]   {name, source:"context"}
custom_sinks[]       (3-pass gitnexus discovery)
```

### 1d. Cypher query — dùng trực tiếp từ scan_strategy.cypher_hints

```
# Cypher đã được pre-generate trong analyze_catalog — copy-paste thẳng:
gitnexus_query:
  run_id: 20260417_120000_myapp
  repo: /path/to/repo
  cypher: <scan_strategy.cypher_hints[0].cypher>   # high_priority_paths
  label:  <scan_strategy.cypher_hints[0].label>
  phase:  catalog

# Chạy tiếp hint[1] (broad_surface) nếu hint[0] có ít kết quả:
gitnexus_query:
  cypher: <scan_strategy.cypher_hints[1].cypher>   # broad_surface
  label:  <scan_strategy.cypher_hints[1].label>
  phase:  catalog
```

### 1e. Cypher query kết hợp (fallback nếu không dùng cypher_hints)

```
Tạo Cypher query thủ công kết hợp 4 nguồn entry + sink:

gitnexus_query:
  run_id: 20260417_120000_myapp
  repo: /path/to/repo
  cypher: |
    MATCH (entry:Symbol)-[:CALLS*1..6]->(sink:Symbol)
    WHERE entry.name IN [<api_entry_points + ctx_api_names>]
       OR sink.name  IN [<semgrep_sink_names + ctx_custom_sinks + gitnexus_custom_sinks>]
    RETURN entry.name AS entry_fn, entry.filePath AS entry_file,
           sink.name  AS sink_fn,  sink.filePath  AS sink_file,
           sink.line  AS sink_line
    LIMIT 60
  label: cross_catalog
  phase: catalog
```

### 1e. Query custom sinks bổ sung (nếu cần)

```
gitnexus_query:
  run_id: 20260417_120000_myapp
  repo: /path/to/repo
  cypher: |
    MATCH (src:Symbol)-[:CALLS*1..5]->(sink:Symbol)
    WHERE sink.name IN ["rawExec", "charge"]
    RETURN src.name AS caller, src.filePath AS file, 
           src.line AS line, sink.name AS sink_name
    LIMIT 50
  label: custom_sinks
  phase: catalog
```

### 1f. Query iterative nếu cần

```
Kết quả vừa rồi thấy flow qua PaymentService. 
Query thêm để xem tất cả callers của PaymentService:

gitnexus_query:
  run_id: 20260417_120000_myapp
  repo: /path/to/repo
  cypher: |
    MATCH (caller:Symbol)-[:CALLS]->(svc:Symbol)
    WHERE svc.filePath CONTAINS 'PaymentService'
    RETURN caller.name, caller.filePath, caller.line, svc.name
    LIMIT 50
  label: payment_callers
  phase: catalog
```

### 1g. Xem tổng kết catalog

```
Tổng kết Phase 1:
- Bao nhiêu sources / sinks semgrep tìm được?
- Bao nhiêu endpoints?
- Có secrets nào không?
- Custom sinks discovery: pass nào tìm được gì?
- Những hướng nào đáng explore trong Phase 2?
```

> **Secrets fast-path:** Nếu `secrets_scan` trả về findings, Claude sẽ review `catalog/secrets.json`
> và gọi `write_findings()` **ngay lập tức** — không cần chạy qua Phase 2 Connect / Joern.

---

## PHASE 2: Connect

### 2a. Generate và chạy path queries

```
Bắt đầu Phase 2 Connect. Nhìn vào toàn bộ catalog output:
- sources.json, sinks.json
- endpoints.json  
- repo_structure.json (entry_points, custom_sinks)
- gitnexus_custom_sinks.json

Generate Cypher path queries trace từ sources → sinks. 
Ưu tiên sensitive_flows từ context.

Chạy:
gitnexus_query:
  run_id: 20260417_120000_myapp
  repo: /path/to/repo
  cypher: |
    MATCH path = (src:Symbol)-[:CALLS*1..8]->(sink:Symbol)
    WHERE src.filePath CONTAINS 'webhook'
      AND sink.name IN ["rawExec", "charge", "query", "execute"]
    RETURN 
      src.name AS entry, src.filePath AS entry_file,
      sink.name AS sink_name, sink.filePath AS sink_file,
      [n in nodes(path) | n.name] AS call_chain
    LIMIT 30
  label: webhook_to_sinks
  phase: connect
```

### 2b. Filter + score (chain cố định)

> **Chain đúng:** gitnexus rows → `fp_filter.filtered_paths` → `joern_filter.updated_paths` → `triage_score`  
> **Không dùng** `joern_filter.cpg_confirmed` làm input cho triage — cần `updated_paths` để giữ `path_decision` + `flow_nodes`.

```
Chạy filter và scoring theo chain:

1. fp_filter:
   run_id: 20260417_120000_myapp
   paths: <rows từ gitnexus_query — có thể là flat gitnexus row hoặc semgrep sink>
   # fp_filter tự normalize 3 format: nested / gitnexus flat / semgrep sink

2. joern_filter (gracefully skip nếu Joern unavailable):
   run_id: 20260417_120000_myapp
   repo: /path/to/repo
   paths: <fp_filter.filtered_paths>
   # Output: joern_filter.updated_paths (ALL paths với path_decision + flow_nodes)
   #         joern_filter.cpg_confirmed (chỉ paths Joern confirm — KHÔNG dùng làm input triage)

3. triage_score:
   run_id: 20260417_120000_myapp
   paths: <joern_filter.updated_paths>   # ← updated_paths, KHÔNG phải cpg_confirmed
   sensitive_flows: <business_ctx.sensitive_flows nếu có>
   # Output: connect/scored_paths.json — input cho Phase 3 Verify
```

### 2c. Xem kết quả triage

```
Hiển thị top 10 scored paths, sắp xếp theo score giảm dần.
Với mỗi path, cho biết:
- entry point (file, function)
- sink (name, type)
- score và triage_detail breakdown
- path_decision từ joern
```

---

## PHASE 3: Verify

### 3a. Load input và context trước khi verify

```
Bắt đầu Phase 3 Verify. Load:
1. connect/scored_paths.json         ← danh sách paths cần verify (đã có score + path_decision)
2. catalog/endpoints.json            ← auth_tags của từng endpoint
3. catalog/sources.json              ← semgrep-detected sources (cross-reference taint)
4. catalog/business_ctx.json         ← sensitive_flows, business impact (nếu có)
5. catalog/repo_intel.md             ← auth mechanism, auth_relevant_files (nếu finding là auth)

Ưu tiên verify theo thứ tự:
  1. path_decision=confirmed + score >= 10
  2. path_decision=confirmed
  3. path_decision=full_verify + score >= 8
  4. Còn lại
```

### 3b. Verify từng path

```
Verify path này:
- Entry: /app/Http/Controllers/WebhookController.php::handlePayment()
- Sink: rawExec() in OrderRepository
- Score: 11, path_decision: confirmed

Đọc source code (filesystem, không dùng MCP tool):
1. WebhookController.php::handlePayment()  ← entry point
2. Trace qua call_chain đến sink
3. Cross-check với sources.json — source này có được semgrep flag không?
4. Đọc flow_nodes (Joern call chain) — tìm custom sanitizer không có trong predefined list
5. Đọc auth_tags từ endpoints.json cho endpoint này — có require auth không?
6. Kết luận: CONFIRMED / FALSE_POSITIVE / UNCERTAIN
```

**Hành động theo `path_decision`:**

| path_decision | Hành động |
|---|---|
| `confirmed` | Joern confirm flow — full verify, đọc flow_nodes kiểm tra custom sanitizer |
| `sanitizer` | Joern thấy sanitizer hint trong flow_nodes — đọc kỹ, dễ FP nếu sanitizer đúng |
| `full_verify` | Không có Joern data — manual trace toàn bộ call chain |
| `object_trace` | Trace lifecycle của object từ source đến sink |
| `skip_no_flow` | Joern không thấy flow — verify nhanh, khả năng cao FP |
| `manual` | Dynamic dispatch — flag để human review |
| `skip_fp` | Test file — bỏ qua |

**Ví dụ — path_decision: full_verify, sink là custom:**

```
Path này đến custom sink "charge" — cần đọc implementation:
1. Đọc PaymentGateway::charge()
2. Hiểu input nào attacker có thể control
3. Tìm xem amount/price field có validated ở layer trên không
4. Cross-check sources.json: entry function có được semgrep detect là source không?
5. Classify: business_logic / business_critical / false_positive
```

### 3c. Classify và ghi findings

```
Classify sink:
classify_sink:
  run_id: 20260417_120000_myapp
  sink_name: rawExec
  business_ctx: [business_ctx object]
```

**Schema bắt buộc cho mỗi finding trước khi write:**

```json
{
  "title": "SQL Injection via rawExec in OrderRepository",
  "severity": "CRITICAL",
  "vuln_type": "sqli",
  "confidence": "HIGH",
  "file": "app/Repositories/OrderRepository.php",
  "line_start": 142,
  "taint_trace": "POST /webhook/payment → handlePayment() → buildQuery() → rawExec()",
  "poc": "order_id=1' OR '1'='1",
  "remediation": "Dùng prepared statements thay vì string concatenation",
  "cwe": "CWE-89",
  "owasp": "A03:2021"
}
```

> Tất cả 8 field bắt buộc: `title, severity, vuln_type, confidence, file, taint_trace, poc, remediation`.  
> `write_findings` sẽ báo warning nếu thiếu field — không block write nhưng markdown sẽ có section trống.

```
Ghi CONFIRMED findings sau mỗi 3 paths verify xong (progressive save):
write_findings:
  run_id: 20260417_120000_myapp
  findings: [confirmed findings]
  file_prefix: technical      # Phase 3 dùng "technical", Phase 4 dùng "final"
```

### 3d. Tổng kết Verify

```
Tổng kết Phase 3:
- Bao nhiêu paths đã verify?
- Bao nhiêu CONFIRMED / FALSE_POSITIVE / UNCERTAIN?
- Findings được lưu tại findings/technical.json và findings/technical.md
- Present findings theo thứ tự severity để chuẩn bị human review
```

---

## ⏸ HUMAN REVIEW

Claude sẽ tự dừng và present findings. Bạn có thể:

**Chấp nhận hết và sang Phase 4:**
```
Accept tất cả findings. Phân tích finding #1 trước (SQLi trong rawExec).
```

**Reject một finding:**
```
Finding #2 là false positive — amount field được validate ở layer trên.
Bỏ finding này, tiếp tục với finding #1.
```

**Hỏi thêm:**
```
Finding #3: path qua QueueConsumer — làm thế nào attacker control được payload?
Explain flow từ SQS → QueueConsumer → sink.
```

**Chỉ analyze một số:**
```
Chỉ analyze finding #1 và #3. Skip #2.
```

---

## PHASE 4: Analyze

### 4a. Deep analysis

```
Analyze finding #1:
- Finding: SQLi qua rawExec() trong OrderRepository
- Entry: POST /webhook/payment, no auth
- Impact context: B2B platform, company_id phải được enforce

Load skill file phù hợp (injection_skill.md) và phân tích:
1. Attack vector cụ thể
2. PoC payload example
3. Real-world impact (dùng business_notes từ business_ctx)
4. CVSS estimate
5. Remediation
```

**Skill files theo vuln type:**

| Vuln type | Skill file |
|---|---|
| sqli, nosql, rce, ssti, xxe, graphql injection | `injection_skill.md` |
| file upload, path traversal, LFI, zip slip | `file_skill.md` |
| ssrf | `ssrf_skill.md` |
| deserialize (PHP, Java, Python pickle, yaml) | `deserialize_skill.md` |
| idor, bfla, jwt, oauth, mass_assign, privesc | `authz_skill.md` |
| race condition, negative value, state bypass | `business_logic_skill.md` |
| hardcoded secrets, weak crypto, insecure random | `hardcode_skill.md` |
| xss, csrf, open redirect, crlf, prototype pollution | `client_side_skill.md` |
| cors, sensitive data leak, insecure cookie/ws | `infosec_skill.md` |
| cache poisoning, host header, smuggling | `cache_protocol_skill.md` |
| rate limit, redos, resource exhaustion | `availability_skill.md` |
| prompt injection, insecure model loading | `special_skill.md` |

**Nếu finding liên quan đến auth/authz (IDOR, BFLA, JWT, OAuth...):**

```
Analyze finding #2 (IDOR):
Đọc catalog/repo_intel.md trước khi load authz_skill:
- auth mechanism (JWT / Session / RBAC) → chọn đúng checklist trong authz_skill Section 0
- multi-tenant indicator → có cần check tenant scope không
- auth_relevant_files → đọc các file đó trước khi verify
```

### 4b. Dynamic confirm với Burp (hỏi user trước)

```
Tôi muốn confirm finding #1 bằng Burp.
Request:
  method: POST
  url: http://localhost/webhook/payment
  headers: {"Content-Type": "application/json"}
  body: {"order_id": "1", "amount": "100"}
payload: 1' OR '1'='1

Có muốn tôi gửi qua Burp không?
```

*(Claude sẽ chờ confirm trước khi gọi `burp_send`)*

---

## Các tình huống thường gặp

### Không có GitNexus

```
GitNexus không available. Chạy Phase 1 với semgrep + api_parse + secrets_scan thôi.
Dùng surface scan từ gitnexus_context để tìm custom sinks.
```

### Resume session bị gián đoạn

```
Resume audit đang làm dở.
run_id: 20260417_120000_myapp

Đọc lại từ reports/20260417_120000_myapp/:
- catalog/repo_intel.md        ← system overview + auth/arch context
- catalog/business_ctx.json    ← nếu có context file
- Đã xong Phase 1 (catalog/) và Phase 2 (connect/)
- Chưa làm Phase 3

Bắt đầu Phase 3 Verify từ connect/scored_paths.json
```

### Context window đầy giữa chừng

```
Context window sắp đầy. Trước khi tiếp tục:
1. Đọc lại reports/20260417_120000_myapp/catalog/repo_intel.md
2. Đọc lại reports/20260417_120000_myapp/connect/scored_paths.json
3. Đọc lại reports/20260417_120000_myapp/catalog/business_ctx.json  (nếu có)
4. Tiếp tục Verify từ path thứ 3 (2 path đầu đã CONFIRMED)
```

### Chỉ muốn scan secrets

```
Chỉ scan secrets cho repo này, không cần full audit.
run_id: 20260417_120000_secrets
secrets_scan:
  run_id: 20260417_120000_secrets
  repo: /path/to/repo
```

> Sau khi scan xong, Claude review `catalog/secrets.json` và gọi `write_findings()` trực tiếp.
> Không cần chạy semgrep / gitnexus / Connect pipeline.

### Chỉ muốn liệt kê API endpoints

```
List tất cả API endpoints của repo này.
run_id: 20260417_120000_api
api_parse:
  run_id: 20260417_120000_api
  repo: /path/to/repo
  stack: express
```

---

## Quick reference — format run_id

```
Format:  YYYYMMDD_HHMMSS_<repo_name>
Example: 20260417_120000_myapp
                         ^^^^^^^
                         tên ngắn của repo, không có ký tự đặc biệt
```

Files sẽ được lưu tại:
```
reports/20260417_120000_myapp/
├── catalog/
│   ├── business_ctx.json
│   ├── sources.json
│   ├── sinks.json
│   ├── endpoints.json
│   ├── secrets.json
│   ├── repo_structure.json
│   └── gitnexus_<label>.json  (nhiều file, mỗi query 1 file)
├── connect/
│   ├── filtered_paths.json
│   ├── cpg_confirmed.json
│   ├── joern_annotated_paths.json
│   ├── scored_paths.json
│   └── gitnexus_<label>.json
├── findings/
│   ├── findings.json
│   └── findings.md
└── evidence/
    └── <finding_id>.http
```
