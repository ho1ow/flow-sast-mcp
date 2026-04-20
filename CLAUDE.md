# flow-sast Security Audit

## Run ID
Format: `YYYYMMDD_HHMMSS_<repo_name>`

Generate at session start from current timestamp + repo basename.
Pass to every tool call throughout the session.

Example: `20260417_103000_myapp`

If the user specifies a run_id (e.g. resuming a session), use that instead.

---

## MCP Tools (flow-sast)

| Tool | Saves to | Notes |
|------|----------|-------|
| `flow-sast__repo_intel` | `catalog/repo_intel.json`, `catalog/repo_intel.md` | Call FIRST — before everything |
| `flow-sast__parse_context` | `catalog/business_ctx.json` | Call if context file provided |
| `flow-sast__semgrep_scan` | `catalog/sources.json`, `catalog/sinks.json` | Pass `extra_sources` from context |
| `flow-sast__api_parse` | `catalog/endpoints.json` | Multi-framework |
| `flow-sast__secrets_scan` | `catalog/secrets.json` | Gitleaks + regex |
| `flow-sast__analyze_catalog` | `catalog/scan_strategy.json` | Call after Phase 1a — synthesizes all sources, outputs gitnexus_params + cypher_hints |
| `flow-sast__gitnexus_context` | `catalog/repo_structure.json`, `catalog/data_models.json` | ⚠️ BYPASSED — dùng `:Symbol` nội bộ → 0 rows. Thay bằng mcp__gitnexus__* trực tiếp (Step 1c) |
| `flow-sast__gitnexus_plan` | `gitnexus_progress.json` | Reads 4 catalog sources → generates Cypher query plan (Function/Class/Method node types) |
| `flow-sast__gitnexus_tick` | `gitnexus_progress.json` | Marks a query label as called ✓ after each mcp__gitnexus__* call |
| `flow-sast__fp_filter` | `connect/filtered_paths.json` | Pattern-based, no LLM |
| `flow-sast__joern_filter` | `connect/cpg_confirmed.json`, `connect/joern_annotated_paths.json` | Optional, skips if Joern down |
| `flow-sast__triage_score` | `connect/scored_paths.json` | Threshold default 6 |
| `flow-sast__classify_sink` | — | Lookup table only |
| `flow-sast__write_findings` | `findings/findings.json`, `findings/findings.md` | After Verify |
| `flow-sast__burp_send` | `evidence/<finding_id>.http` | Ask user first |

If context window fills: read from `reports/<run_id>/` — tools save everything automatically.

---

## Workflow

### PRE-PRE PHASE: Codebase Intelligence
Always call FIRST, before context parsing and before Phase 1:

```
repo_intel(run_id, repo)
  → returns:
      framework_detection: { frameworks, languages, dependencies }
      auth_detection:      { mechanisms, annotations, auth_relevant_files, gitnexus_symbols }
      architecture:        { top_level_dirs, inferred_notes }
      security_notes:      [ combined notes from all detection passes ]
```

Hold in memory — used across all phases:
```
frameworks              → stack param for semgrep_scan + api_parse
auth_mechanisms         → select authz_skill checklist in Phase 4
auth_relevant_files     → read these files in Phase 3 Verify for auth findings
security_notes mapping:
  "Async job/queue"     → semgrep_scan extra_sources: queue consumer class names
  "Webhook/callback"    → gitnexus_context extra_topics: ["webhook","callback"]
  "Payment/billing"     → gitnexus_context extra_topics: ["payment","billing","checkout"]
  "Admin panel"         → gitnexus_context extra_topics: ["admin"]
  "Multi-tenant: X"     → Phase 2: Cypher to check WHERE clauses missing tenant scope
  "File upload/storage" → gitnexus_context extra_topics: ["upload","storage"]
```

---

### PRE-PHASE: Context Parsing
If user provides a context file:

1. Call `parse_context(run_id, context_file)` — saves `catalog/business_ctx.json`.
   Supports markdown, YAML, JSON. No manual extraction needed.

2. Hold `business_ctx` in memory for the full session:
```
custom_sinks      → Phase 2 Cypher queries + classify_sink
                  → gitnexus_context(ctx_custom_sinks)    ← Step 1b
custom_sources    → semgrep_scan extra_sources
sensitive_flows   → triage_score + gitnexus_context extra_topics
non_http_sources  → semgrep_scan extra_sources
api_names         → gitnexus_context(ctx_api_names)       ← Step 1b (NEW)
                    e.g. ["GetDataSet","ExecSQL","ExecSQLTrans"]
function_params   → Phase 3 Verify hint: which params are tainted entry points
                    e.g. [{function:"GetDataSet", param:"sql", taint_reason:"raw SQL from client"}]
business_notes    → Phase 4 Analyze impact assessment
raw_text          → Phase 4 Analyze (full nuance — re-read before skill files)
```

3. If context window fills, reload from: `reports/<run_id>/catalog/business_ctx.json`

---

### Phase 1: Catalog

#### Step 1a — Parallel (no dependencies)
```
semgrep_scan(run_id, repo,
  stack         = <repo_intel.frameworks[0]>,
  extra_sources = <business_ctx.non_http_sources if available>
                + <queue consumer class names if "Async job/queue" in repo_intel.security_notes>)

api_parse(run_id, repo, stack=<repo_intel.frameworks[0]>)

secrets_scan(run_id, repo)
```

**Secrets fast-path**: after secrets_scan, review `catalog/secrets.json` directly.
- Findings trong `.gitnexus/`, `node_modules/`, `vendor/`, `dist/`, `build/` → FALSE_POSITIVE (build artifacts)
- Confirmed secrets trong source code thật → `write_findings()` immediately. Do not route through Connect pipeline.

#### Step 1b — analyze_catalog (sequential, pure Python — no LLM)
```
analyze_catalog(run_id)
  → reads automatically: sinks.json, sources.json, endpoints.json,
                         business_ctx.json, repo_intel.json
  → deduplicates + scores names across all 4 sources
  → returns:
      flow_domains[]   ← READ FIRST — business domain groupings for semantic inference
        [{domain, endpoints[], param_names[], id_params[], path_id_params[],
          handler_names[], sink_hints[], taint_signals[], risk_signals[],
          topic_keywords[]}]
      gitnexus_params  {extra_topics, ctx_api_names, ctx_custom_sinks,
                        semgrep_sink_names, api_endpoints}
      cypher_hints[]   [{label, priority, reason, cypher}]  ← ready-to-use strings
      entry_points[]   scored + prioritized by source count
      sink_targets[]   scored + prioritized by source count
      taint_params[]   [{function, param, taint_reason}]    ← Phase 3 Verify hint
  → saves: catalog/scan_strategy.json
```

Scoring: context declaration (+3) > semgrep detection (+2) > api_parse (+1).  
Multi-source confirmed names → priority HIGH → included in `high_priority_paths` Cypher hint.

#### Step 1b.5 — Flow Inference (Claude reads flow_domains, reasons semantically)

**This is Claude's job — not a tool call.**  
Read `scan_strategy.flow_domains` and infer business flows. For each domain:

```
For each domain in flow_domains (sorted by risk_signals DESC):

  1. Read: domain, endpoints[], param_names[], id_params[], sink_hints[], risk_signals[]

  2. Infer semantic flow:
       domain="payment" + id_params=["order_id","user_id"] + sink_hints=["OracleCommand"]
       → "Payment checkout flow. order_id used in DB query → potential SQLi on order lookup"

       domain="order" + path_id_params=["id"] + risk_signals=["path_id_params","unauthenticated_endpoint"]
       → "Order detail endpoint with path param, no auth → IDOR candidate"

       domain="user" + taint_signals=[{handler:"updateProfile", tainted_params:["avatar_path"]}]
       → "Profile update with tainted avatar_path param → path traversal in file upload"

  3. Generate enriched extra_topics for this flow:
       "payment checkout SQLi" → add: ["payment","checkout","billing","order"]
       "order IDOR"            → add: ["order","item","cart"]
       "user file upload"      → add: ["upload","avatar","file","storage"]

  4. Generate domain-specific Cypher hint (append to scan_strategy.cypher_hints):
       MATCH (entry:<node>)-[:CALLS*1..6]->(sink:<node>)
       WHERE entry.filePath CONTAINS 'payment'   ← domain path filter
         AND sink.name IN ["OracleCommand",...]   ← sink_hints
       RETURN entry.name, entry.filePath, sink.name, sink.filePath
       LIMIT 40
       ← <node> = Method (C#/Java) hoặc Function (Python/JS) — xem repo_intel.frameworks
```

Result: enriched `extra_topics` list (add your inferred domain keywords) fed into gitnexus_context.  
This is what makes gitnexus find `PaymentRepository`, `OrderService`, not just generic sinks.

#### Step 1c — gitnexus discovery (gitnexus MCP trực tiếp)

**Không dùng flow-sast gitnexus_context** — nó cũng dùng `:Symbol` nội bộ → 0 rows.
Dùng gitnexus MCP trực tiếp để lấy cùng dữ liệu.

```
repo_name = basename(repo)   ← ví dụ: "TTKT", "Web"

NODE TYPE (QUAN TRỌNG — sai → 0 rows):
  C# / .NET / Java  → :Method
  Python / JS / TS  → :Function
  → Xác nhận từ gitnexus_plan output: node_types.call_node

1. Đọc 3 resources:
     gitnexus://repo/<repo_name>/context    → file count, symbol count, index status
     gitnexus://repo/<repo_name>/processes  → execution flows (auth, payment, upload...)
     gitnexus://repo/<repo_name>/clusters   → module clusters → domain keywords

2. Cypher — custom sinks:
     MATCH (src:<node>)-[:CALLS]->(sink:<node>)
     WHERE sink.name =~ '(?i).*(exec|query|command|execute|invoke|dispatch|send|write|drop|remove).*'
     RETURN DISTINCT sink.name, sink.filePath LIMIT 40
     ← KHÔNG dùng "delete" trong regex — gitnexus parser conflict với DELETE keyword

   **RETRY RULE**: Nếu kết quả = 0 rows:
     → Kiểm tra lại node type (thử Method nếu dùng Function, hoặc ngược lại)
     → Retry với node type kia TRƯỚC KHI kết luận "không có sinks"
     → KHÔNG được tiếp tục bước tiếp theo khi còn nghi ngờ node type sai

3. Cypher — data models (pattern rộng — bao gồm cả Dao/Service/.NET):
     MATCH (c:Class)
     WHERE c.filePath =~ '.*(Model|Entity|Repository|Schema|Dao|Service|Manager|Helper|Util).*'
     RETURN c.name, c.filePath LIMIT 40

4. Cypher — auth symbols:
     MATCH (n:<node>)
     WHERE n.name =~ '(?i).*(auth|jwt|guard|middleware|token|session|login|logout|authenticate|authorize|permission|role|policy|access).*'
     RETURN n.name AS name, n.filePath AS file, n.startLine AS line LIMIT 30
     ← Dùng startLine, KHÔNG phải line (property không tồn tại trong gitnexus)
   → Merge filePath vào repo_intel.auth_relevant_files[]

5. Ghi nhớ: custom_sinks[], extra_topics[], data_models[], auth_symbols[]

**SEMGREP TIMEOUT FALLBACK** (khi semgrep không chạy được):
  Bước 2 (custom sinks Cypher) + Step 1e (caller discovery) trở thành nguồn taint chính.
  KHÔNG được bỏ qua 1c/1d/1e khi semgrep fail — đây là lúc graph analysis quan trọng nhất.
```

#### Step 1d — Cypher queries (gitnexus_plan + gitnexus MCP trực tiếp)

```
gitnexus_plan(run_id)
  → đọc 4 catalog sources tự động:
      scan_strategy.json  → entry_points, sink_targets, flow_domains
      repo_structure.json → custom_sinks (gitnexus 3-pass)
      business_ctx.json   → custom_sinks, api_names
      endpoints.json      → handler names
  → sinh Cypher queries với đúng node type (Function/Class/Method)
  → lưu gitnexus_progress.json
  → trả về: queries[], summary { total, called, pending }
```

Với mỗi query trong `queries[]` (ưu tiên priority=HIGH trước):
```
1. Gọi mcp__gitnexus__* trực tiếp với query.cypher
2. Nếu kết quả = 0 rows → kiểm tra node type trong query.cypher, retry nếu cần
3. Gọi gitnexus_tick(run_id, query.label, row_count)
4. Lặp đến khi summary.pending == 0
```

**Nếu gitnexus_plan trả về error**: Đọc error message, tìm nguyên nhân, fix rồi retry.
KHÔNG được bỏ qua Step 1d vì error — đây là bước bắt buộc.

#### Step 1e — Caller discovery (gitnexus MCP trực tiếp)

**Bắt buộc sau khi tìm ra sink nodes** — gitnexus cho biết WHO calls nhưng không cho biết HOW.
Workflow đúng: Cypher tìm sink → gitnexus_context lấy callers → grep tại call sites.

```
Với mỗi sink tìm được ở Step 1d (ưu tiên sinks có row_count > 0):
  gitnexus_context(sink_name, sink_file_path)
    → incoming.calls[]   ← danh sách callers (entry points thực sự)
    → lưu vào caller_map[sink_name] = [caller1, caller2, ...]

Kết quả caller_map → Phase 2 Connect:
  - Dùng làm entry points cho Cypher path queries
  - Dùng làm danh sách grep targets (xác nhận string concat tại từng call site)
```

---

### ⛔ GATE: Checklist bắt buộc trước khi sang Phase 2

**KHÔNG được chuyển sang Phase 2 khi chưa hoàn thành:**
```
[ ] 1c-2: Cypher custom sinks trả về kết quả (hoặc đã retry đủ node types)
[ ] 1c-3: Cypher data models đã chạy
[ ] 1c-4: Cypher auth symbols đã chạy
[ ] 1d:   gitnexus_plan đã chạy + tất cả queries đã tick ✓
[ ] 1e:   gitnexus_context(sink) đã chạy cho mỗi sink tìm được → caller_map có data
```

**Lý do gate này tồn tại:**
- Confirmation bias: tìm thấy finding rõ ràng → bỏ qua graph analysis còn lại
- Fast-path IDOR/mass_assign: chỉ bypass Connect pipeline, KHÔNG bypass Phase 1
- Semgrep timeout: khi semgrep fail, graph analysis là nguồn taint DUY NHẤT

---

### Phase 2: Connect

```
1. Review catalog output:
   sources.json + sinks.json          (semgrep taint sources/sinks — có thể rỗng nếu timeout)
   caller_map[]                        (từ Step 1e — nguồn taint chính khi semgrep fail)
   endpoints.json                     (entry points, auth_tags, idor_candidates)
   data_models[]                      (từ Step 1c — model fields)
   business_ctx.custom_sinks          (if provided)

   Fast-paths (bypass Connect pipeline, KHÔNG bypass Phase 1 graph steps):
   - endpoints.json idor_candidates[] → direct Phase 3 Verify (ownership check trace)
   - data_models mass_assign_risk + sinks matching fill()/create() → direct verify
   - secrets.json confirmed findings → direct write_findings (already done Phase 1)

2. Generate Cypher path queries tracing entry_points → sinks.
   Prioritize: sensitive_flows from business_ctx, HIGH-confidence sinks, auth_symbols.

3. gitnexus_plan(run_id) → lấy danh sách queries còn pending từ progress file.
   Với mỗi query: gọi mcp__gitnexus__* trực tiếp → gitnexus_tick(run_id, label, row_count).
   Kết quả mới có thể reveal thêm paths → sinh Cypher mới → tick tiếp.

4. fp_filter(run_id, paths)

5. joern_filter(run_id, repo, paths)      ← optional, gracefully skips if unavailable

6. triage_score(run_id, paths,
     sensitive_flows = business_ctx.sensitive_flows)
```

---

### Phase 3: Verify

Each path carries a `path_decision` from joern_filter:

| path_decision | Meaning | Action |
|---|---|---|
| `confirmed` | Joern confirmed taint flow | Full verify — highest priority |
| `sanitizer` | Joern flow confirmed + sanitizer hint in flow_nodes | Read flow_nodes carefully — may be FP |
| `full_verify` | No Joern data (unavailable or no pattern match) | Full manual trace required |
| `object_trace` | Object-based query type | Trace object lifecycle manually |
| `skip_no_flow` | Joern found no taint flow | Likely FP — verify quickly |
| `skip_fp` | Test / migration file | Skip |
| `manual` | Dynamic dispatch (`$var->method()`) | Flag for human review |

For each scored path:
```
1. Read source files directly (filesystem — no MCP tool)
2. Trace taint path manually through call chain
3. Read path.flow_nodes (Joern call chain) — identify custom sanitizers
   (e.g. safeExecute, escapeInput not in any predefined list)
4. For auth findings: read auth_relevant_files from repo_intel
5. Custom sinks: read implementation → classify vuln_type yourself
6. classify_sink(run_id, sink_name, business_ctx)    ← for known sinks
7. Decision: CONFIRMED (technical data flow exists) / FALSE_POSITIVE / UNCERTAIN
8. write_findings(run_id, confirmed_findings, file_prefix="technical") ← Progressive save
```

---

### ⏸ Human Review
- Present findings in chat with business context
- Wait for user: accept / reject / ask questions
- **DO NOT** auto-proceed to Analyze

---

### Phase 4: Analyze

```
1. Read skill file matching vuln_type:
     injection_skill.md       → sqli, nosql, rce/command, ssti, xxe, xpath,
                                  ldap, expression_injection, graphql, log_injection
     file_skill.md            → file_upload, lfi, rfi, path_traversal, zip_slip
     deserialize_skill.md     → deserialization (php/java/python/dotnet)
     ssrf_skill.md            → ssrf, blind_ssrf
     authz_skill.md           → idor, bfla, jwt, oauth, session, mass_assign, privilege_esc
     business_logic_skill.md  → race, neg_value, state_bypass, toctou
     hardcode_skill.md        → secrets, weak_crypto, insecure_random
     client_side_skill.md     → xss, csrf, clickjacking, open_redirect, crlf, prototype_pollution
     infosec_skill.md         → cors, sensitive_data, insecure_http, websocket, misconfiguration
     cache_protocol_skill.md  → cache_poisoning, cache_deception, host_header, smuggling
     availability_skill.md    → rate_limit, dos, redos, resource_exhaustion
     special_skill.md         → llm_injection, insecure_model_load

2. For authz findings (idor, bfla, jwt, oauth, session, mass_assign, privilege_esc):
   Read catalog/repo_intel.md — auth mechanism, multi-tenant scope, auth_relevant_files.
   Use repo_intel.auth_mechanisms to select the right checklist in authz_skill Section 0.

3. If business_ctx available:
   Re-read business_ctx.raw_text (full original file) — structured fields are lossy.

4. Read skills/system_context_skill.md if business_ctx available.

5. Assess real-world impact using business_notes + raw_text.

   **When reading catalog/data_models.json** (idor, mass_assign, sensitive_data findings):
   - `sensitive_fields[]` and `mass_assign_risk[]` are regex-pre-tagged — use as starting point.
   - Also read the full `fields[]` list and apply your own semantic judgment:
     domain-specific fields (diagnosis, prescription, kyc_verified, fraud_flag, wallet_balance,
     subscription_tier, etc.) may not match the regex but are clearly sensitive.
   - Severity scales with what fields are exposed/assignable — not just whether the vuln exists.

6. Synthesize the final Proof of Concept, Taint Trace, and Attack Vector.
7. Decision: CONFIRMED (Business impact verified) / FALSE_POSITIVE / UNCERTAIN
8. write_findings(run_id, final_findings, file_prefix="final")  ← Dumps to final JSON/MD reports
9. Ask user before calling burp_send to dynamically verify the bug.
```

---

## Rules
- Pass `run_id` to every tool call
- Do NOT run silent across phases
- Human review is mandatory before Phase 4 Analyze
- Always ask before `burp_send`
- Findings scale: CONFIRMED → report | FALSE_POSITIVE → skip | UNCERTAIN → note
- Secrets: fast-path to write_findings — do not route through Connect/Joern
