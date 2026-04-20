"""
flow_sast_mcp/tools/gitnexus_bridge.py
────────────────────────────────────────
Replaces internal gitnexus Cypher calls in flow-sast.

Root cause of old approach failing:
  1. flow-sast used node type :Symbol — does not exist in gitnexus schema
     (actual types: Function, Class, Method)
  2. gitnexus_query is an orchestration tool, not a Cypher passthrough —
     it returns empty silently when pipeline context is missing

New architecture:
  - gitnexus_plan(run_id): reads 4 catalog sources → generates Cypher query plan
    with correct node types, saves gitnexus_progress.json
  - gitnexus_tick(run_id, label, row_count): marks a query as called ✓

Claude workflow:
  1. Call gitnexus_plan(run_id) → get list of pending queries
  2. For each query: call mcp__gitnexus__* directly with the provided Cypher
  3. Call gitnexus_tick(run_id, label, row_count) after each call → tick ✓
  4. Repeat until summary.pending == 0
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flow_sast_mcp.shared.persistence import read, REPORTS_DIR

# ── Node type mapping by stack ───────────────────────────────────────────────
# Symbol does NOT exist. OOP languages (C#, Java) use Method; dynamic use Function.
_STACK_NODE: dict[str, str] = {
    "dotnet": "Method",   # C# methods indexed as Method
    "java":   "Method",   # Java methods indexed as Method
    "php":    "Method",
    "python": "Function",
    "node":   "Function",
}
_DEFAULT_NODE = "Method"  # safer default — most enterprise repos are OOP
CLASS_NODE = "Class"


def _node_type(run_id: str) -> str:
    """Detect correct call node type from repo_intel stack."""
    intel = read(run_id, "catalog", "repo_intel.json")
    frameworks = intel.get("framework_detection", {}).get("frameworks", [])
    languages  = intel.get("framework_detection", {}).get("languages", [])
    combined   = [str(x).lower() for x in frameworks + languages]
    for item in combined:
        if any(k in item for k in ("dotnet", ".net", "asp.net", "c#", "csharp")):
            return "Method"
        if any(k in item for k in ("java", "spring", "kotlin")):
            return "Method"
        if any(k in item for k in ("python", "django", "flask", "fastapi")):
            return "Function"
        if any(k in item for k in ("node", "express", "nestjs", "javascript", "typescript")):
            return "Function"
    return _DEFAULT_NODE

_PROGRESS_FILE = "gitnexus_progress.json"


# ── Progress file helpers ────────────────────────────────────────────────────

def _progress_path(run_id: str) -> Path:
    p = Path(REPORTS_DIR) / run_id
    p.mkdir(parents=True, exist_ok=True)
    return p / _PROGRESS_FILE


def _load_progress(run_id: str) -> dict:
    p = _progress_path(run_id)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"run_id": run_id, "queries": [], "summary": {}}


def _save_progress(run_id: str, data: dict) -> str:
    p = _progress_path(run_id)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return str(p)


# ── Name extraction helpers ──────────────────────────────────────────────────

def _names(items: list, key: str = "name") -> list[str]:
    """Extract name strings from list of dicts or plain strings. Deduplicates."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        name = item if isinstance(item, str) else (item.get(key, "") if isinstance(item, dict) else "")
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _merge(*lists: list[str], limit: int = 30) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for lst in lists:
        for n in lst:
            if n and n not in seen:
                seen.add(n)
                out.append(n)
                if len(out) >= limit:
                    return out
    return out


# ── Cypher query builders (node type passed in — stack-aware) ───────────────

def _q_cross_catalog(entry_names: list[str], sink_names: list[str], node: str) -> str:
    return (
        f"MATCH (entry:{node})-[:CALLS*1..6]->(sink:{node})\n"
        f"WHERE entry.name IN {json.dumps(entry_names)}\n"
        f"   OR sink.name  IN {json.dumps(sink_names)}\n"
        f"RETURN entry.name AS entry_fn, entry.filePath AS entry_file,\n"
        f"       sink.name  AS sink_fn,  sink.filePath  AS sink_file,\n"
        f"       sink.line  AS sink_line\n"
        f"LIMIT 60"
    )


def _q_sink_only(sink_names: list[str], node: str) -> str:
    return (
        f"MATCH (src:{node})-[:CALLS*1..5]->(sink:{node})\n"
        f"WHERE sink.name IN {json.dumps(sink_names)}\n"
        f"RETURN src.name, src.filePath, src.line,\n"
        f"       sink.name, sink.filePath, sink.line\n"
        f"LIMIT 50"
    )


def _q_domain(domain: str, sink_hints: list[str], node: str) -> str:
    return (
        f"MATCH (entry:{node})-[:CALLS*1..6]->(sink:{node})\n"
        f"WHERE entry.filePath CONTAINS '{domain}'\n"
        f"  AND sink.name IN {json.dumps(sink_hints[:10])}\n"
        f"RETURN entry.name, entry.filePath, sink.name, sink.filePath\n"
        f"LIMIT 40"
    )


def _q_auth(node: str) -> str:
    return (
        f"MATCH (n:{node})\n"
        f"WHERE n.name =~ '(?i).*(auth|jwt|guard|middleware|token|permission|role|login|session).*'\n"
        f"RETURN n.name, n.filePath, n.line\n"
        f"LIMIT 30"
    )


def _q_tenant(node: str) -> str:
    return (
        f"MATCH (n:{node})\n"
        f"WHERE n.filePath CONTAINS 'Repository'\n"
        f"  AND NOT n.name CONTAINS 'company_id'\n"
        f"  AND NOT n.name CONTAINS 'tenant_id'\n"
        f"RETURN n.name, n.filePath\n"
        f"LIMIT 20"
    )


# ── Main functions ───────────────────────────────────────────────────────────

def build_query_plan(run_id: str) -> dict:
    """
    Read 4 catalog sources → generate Cypher query plan with correct node types.
    Saves reports/<run_id>/gitnexus_progress.json. Returns the plan.

    4 sources:
      1. catalog/scan_strategy.json  → entry_points, sink_targets, gitnexus_params, flow_domains
      2. catalog/repo_structure.json → custom_sinks (gitnexus 3-pass discovery)
      3. catalog/business_ctx.json   → custom_sinks, api_names, security_notes
      4. catalog/endpoints.json      → endpoint handler names
    """
    # Source 1: scan_strategy
    strategy    = read(run_id, "catalog", "scan_strategy.json")
    gn_params   = strategy.get("gitnexus_params", {})
    flow_domains = strategy.get("flow_domains", [])
    sec_notes   = strategy.get("security_notes", [])

    s1_entries = _names(gn_params.get("api_endpoints", []))
    s1_ctx_api = _names(gn_params.get("ctx_api_names", []))
    s1_semgrep = _names(gn_params.get("semgrep_sink_names", []))
    s1_ctx_snk = _names(gn_params.get("ctx_custom_sinks", []))

    # Source 2: repo_structure (gitnexus_context output)
    repo_struct = read(run_id, "catalog", "repo_structure.json")
    s2_gn_sinks = _names(repo_struct.get("custom_sinks", []))

    # Source 3: business_ctx
    biz_ctx     = read(run_id, "catalog", "business_ctx.json")
    s3_biz_snk  = _names(biz_ctx.get("custom_sinks", []))
    s3_api      = _names(biz_ctx.get("api_names", []))
    s3_notes    = biz_ctx.get("security_notes", sec_notes)

    # Source 4: endpoints (api_parser saves list directly, not wrapped in dict)
    eps_data    = read(run_id, "catalog", "endpoints.json")
    eps_list    = eps_data if isinstance(eps_data, list) else eps_data.get("endpoints", [])
    s4_handlers = _names(eps_list, key="handler")

    # Detect correct node type for this stack (C# → Method, Python/JS → Function)
    node = _node_type(run_id)

    # Merge
    all_entries = _merge(s1_entries, s1_ctx_api, s3_api, s4_handlers, limit=30)
    all_sinks   = _merge(s1_semgrep, s1_ctx_snk, s2_gn_sinks, s3_biz_snk, limit=30)
    all_custom  = _merge(s2_gn_sinks, s3_biz_snk, s1_ctx_snk, limit=20)

    queries: list[dict] = []

    # Q1: cross_catalog — combined entry + sink
    if all_entries or all_sinks:
        queries.append({
            "label":     "cross_catalog",
            "priority":  "HIGH",
            "reason":    f"{len(all_entries)} entries + {len(all_sinks)} sinks from 4 sources",
            "cypher":    _q_cross_catalog(all_entries, all_sinks, node),
            "called":    False,
            "called_at": None,
            "row_count": None,
        })

    # Q2: custom_sinks — sink-only traversal
    if all_custom:
        queries.append({
            "label":     "custom_sinks",
            "priority":  "HIGH",
            "reason":    f"{len(all_custom)} custom sinks (context + gitnexus discovery)",
            "cypher":    _q_sink_only(all_custom, node),
            "called":    False,
            "called_at": None,
            "row_count": None,
        })

    # Q3: domain-specific flows (max 5 domains, sorted by risk)
    sorted_domains = sorted(
        [d for d in flow_domains if d.get("sink_hints")],
        key=lambda d: len(d.get("risk_signals", [])),
        reverse=True,
    )
    for domain_obj in sorted_domains[:5]:
        domain     = domain_obj.get("domain", "")
        sink_hints = domain_obj.get("sink_hints", [])
        risk       = domain_obj.get("risk_signals", [])
        if not domain:
            continue
        queries.append({
            "label":     f"domain_{domain}",
            "priority":  "HIGH" if risk else "MEDIUM",
            "reason":    f"Domain '{domain}' flow — risk_signals: {risk}",
            "cypher":    _q_domain(domain, sink_hints, node),
            "called":    False,
            "called_at": None,
            "row_count": None,
        })

    # Q4: auth_symbols
    queries.append({
        "label":     "auth_symbols",
        "priority":  "MEDIUM",
        "reason":    "Auth/JWT/guard/middleware symbol discovery",
        "cypher":    _q_auth(node),
        "called":    False,
        "called_at": None,
        "row_count": None,
    })

    # Q5: tenant_scope (only if multi-tenant noted)
    is_multitenant = any(
        "tenant" in str(n).lower() or "multi-tenant" in str(n).lower()
        for n in s3_notes
    )
    if is_multitenant:
        queries.append({
            "label":     "tenant_scope",
            "priority":  "HIGH",
            "reason":    "Multi-tenant detected — check missing tenant_id/company_id scoping",
            "cypher":    _q_tenant(node),
            "called":    False,
            "called_at": None,
            "row_count": None,
        })

    summary = {
        "total":        len(queries),
        "called":       0,
        "pending":      len(queries),
        "entry_count":  len(all_entries),
        "sink_count":   len(all_sinks),
    }

    plan = {
        "run_id":       run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "node_types":   {"call_node": node, "class_node": CLASS_NODE},
        "note": (
            "For each pending query: call mcp__gitnexus__* directly with the Cypher provided. "
            "After each call, invoke gitnexus_tick(run_id, label, row_count) to mark done ✓. "
            "Repeat until summary.pending == 0."
        ),
        "queries":  queries,
        "summary":  summary,
    }

    saved = _save_progress(run_id, plan)
    plan["saved_to"] = saved
    return plan


def tick(run_id: str, label: str, row_count: int) -> dict:
    """
    Mark a query label as called. Updates gitnexus_progress.json.
    Returns updated summary.
    """
    plan = _load_progress(run_id)
    updated = False

    for q in plan.get("queries", []):
        if q["label"] == label:
            q["called"]    = True
            q["called_at"] = datetime.now(timezone.utc).isoformat()
            q["row_count"] = row_count
            updated = True
            break

    queries = plan.get("queries", [])
    called  = sum(1 for q in queries if q.get("called"))
    plan["summary"] = {
        "total":   len(queries),
        "called":  called,
        "pending": len(queries) - called,
    }

    saved = _save_progress(run_id, plan)
    return {
        "label":      label,
        "row_count":  row_count,
        "updated":    updated,
        "summary":    plan["summary"],
        "saved_to":   saved,
        "pending_labels": [
            q["label"] for q in queries if not q.get("called")
        ],
    }
