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
| `flow-sast__gitnexus_context` | `catalog/repo_structure.json`, `catalog/data_models.json` | Returns file tree, custom sinks, and ORM Models/Properties |
| `flow-sast__gitnexus_query` | `catalog/gitnexus_<label>.json` or `connect/gitnexus_<label>.json` | Call iteratively |
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
Confirmed secrets → `write_findings()` immediately. Do not route through Connect pipeline.

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
       MATCH (entry:Symbol)-[:CALLS*1..6]->(sink:Symbol)
       WHERE entry.filePath CONTAINS 'payment'   ← domain path filter
         AND sink.name IN ["OracleCommand",...]   ← sink_hints
       RETURN entry.name, entry.filePath, sink.name, sink.filePath
       LIMIT 40
```

Result: enriched `extra_topics` list (add your inferred domain keywords) fed into gitnexus_context.  
This is what makes gitnexus find `PaymentRepository`, `OrderService`, not just generic sinks.

#### Step 1c — gitnexus_context (sequential, uses analyze_catalog + inferred topics)
```
gitnexus_context(run_id, repo,
  **scan_strategy.gitnexus_params,  ← pre-computed, no manual extraction
  extra_topics = <scan_strategy.extra_topics + inferred domain topics from Step 1b.5>)
```

Returns labeled cross-catalog lists for Cypher:
```
api_entry_points[]   {name, source:"api_parse"}
semgrep_sink_names[] {name, source:"semgrep"}
ctx_api_names[]      {name, source:"context"}   ← ExecSQL, GetDataSet, ExecSQLTrans
ctx_custom_sinks[]   {name, source:"context"}
custom_sinks[]       (gitnexus 3-pass discovery)
```

#### Step 1d — Cypher queries (use scan_strategy.cypher_hints directly)
```
Use scan_strategy.cypher_hints[n].cypher directly as gitnexus_query input.
Priority: HIGH hints first.

gitnexus_query(run_id, repo,
  cypher = scan_strategy.cypher_hints[0].cypher,   ← "high_priority_paths"
  label  = scan_strategy.cypher_hints[0].label,
  phase  = "catalog")
```

Additional Cypher queries if cypher_hints don't cover all custom sinks:
```
  → If custom_sinks found (any confidence):
      gitnexus_query(label="custom_sinks", phase="catalog",
        cypher = "MATCH (src)-[:CALLS*1..5]->(sink)
                  WHERE sink.name IN ['rawExec','charge', ...]
                  RETURN src.name, src.filePath, src.line, sink.name LIMIT 50")

  → If repo_intel.auth_relevant_files found:
      gitnexus_query(label="auth_symbols", phase="catalog",
        cypher = "MATCH (n:Symbol)
                  WHERE n.name =~ '(?i).*(auth|jwt|guard|middleware|token).*'
                  RETURN n.name, n.filePath, n.type LIMIT 30")

  → If "Multi-tenant" in repo_intel.security_notes:
      gitnexus_query(label="tenant_scope", phase="catalog",
        cypher = "MATCH (n:Symbol)
                  WHERE n.filePath CONTAINS 'Repository'
                    AND NOT n.name CONTAINS 'company_id'
                    AND NOT n.name CONTAINS 'tenant_id'
                  RETURN n.name, n.filePath LIMIT 20")
```

---

### Phase 2: Connect

```
1. Review catalog output:
   sources.json + sinks.json          (semgrep taint sources/sinks)
   repo_structure.json custom_sinks   (gitnexus 3-pass: HIGH/MEDIUM/LOW confidence)
   gitnexus_custom_sinks.json         (data flow to custom sinks)
   endpoints.json                     (entry points, auth_tags, idor_candidates)
   data_models.json                   (model fields, sensitive_fields, mass_assign_risk)
   business_ctx.custom_sinks          (if provided)

   Fast-paths that bypass Connect pipeline:
   - endpoints.json idor_candidates[] → direct Phase 3 Verify (ownership check trace)
   - data_models.json mass_assign_risk + sinks matching fill()/create() → direct verify
   - secrets.json confirmed findings → direct write_findings (already done Phase 1)

2. Generate Cypher path queries tracing entry_points → sinks.
   Prioritize: sensitive_flows from business_ctx, HIGH-confidence sinks, auth_symbols.

3. gitnexus_query(run_id, repo, cypher, label, phase="connect") — iterate as needed.
   Each query result can reveal new paths → query further.

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
