"""
tools/catalog_analyzer.py
──────────────────────────
MCP tool: analyze_catalog

Input:  run_id (reads Phase 1a JSON files automatically from disk)
Output: { flow_domains, entry_points, sink_targets, taint_params,
          gitnexus_params, cypher_hints, saved_to }
Saves:  catalog/scan_strategy.json

Runs BETWEEN Phase 1a and Phase 1b — pure Python, no LLM.
Merges, deduplicates, and scores catalog outputs from all 4 sources:
  semgrep sinks/sources  → catalog/sinks.json, sources.json
  api_parse endpoints    → catalog/endpoints.json
  parse_context          → catalog/business_ctx.json
  repo_intel             → catalog/repo_intel.json

Key output — flow_domains[]:
  Groups endpoints by business domain (payment, order, user, admin…).
  Each domain carries: endpoints, params, id_params (IDOR signals),
  sink_hints (sinks detected in same files), risk_signals, topic_keywords.
  Claude reads flow_domains and performs semantic flow inference:
    "payment domain with order_id param + OracleCommand sink
     → payment checkout flow → SQLi risk on order lookup
     → feed ['payment','order','checkout'] to gitnexus"
  The inference step is Claude's responsibility — this tool only provides
  the structured signals. No LLM call inside this tool.

gitnexus_params → pre-computed params for gitnexus_context (Step 1c)
cypher_hints[]  → ready-to-use Cypher strings for gitnexus_query (Step 1d)
taint_params[]  → tainted function params for Phase 3 Verify hints
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from flow_sast_mcp.shared.persistence import read, write, ensure_run_dirs, REPORTS_DIR

# Max names per Cypher IN-list to keep queries readable
_MAX_NAMES_PER_LIST = 25

# Source priority scores — context declarations are strongest signal
_SOURCE_SCORES: dict[str, int] = {
    "context":   3,
    "semgrep":   2,
    "api_parse": 1,
}

# Priority bands by aggregated score
_PRIORITY_HIGH   = 5
_PRIORITY_MEDIUM = 3

# Path segments to skip when inferring business domain from URL
_SKIP_PATH_SEGMENTS: frozenset[str] = frozenset({
    "api", "v1", "v2", "v3", "v4", "rest", "graphql", "grpc",
    "public", "private", "internal", "external",
    "web", "app", "service", "services",
    # Infrastructure / meta endpoints — not business domains
    "health", "ping", "status", "metrics", "docs", "swagger",
    "openapi", "actuator", "favicon", "robots",
})

# Param name patterns that indicate an ID-type (IDOR risk)
_ID_PARAM_RE = re.compile(
    r"(?i)^(.*_id|.*_uuid|.*_key|id|uuid|key|ref|code|token|number|num|no)$"
)


# ── Entry point ───────────────────────────────────────────────────────────────

def run(run_id: str) -> dict[str, Any]:
    """Synthesize Phase 1a catalog outputs into a structured scan strategy.

    Reads from reports/<run_id>/catalog/ automatically.
    Call after Phase 1a (semgrep + api_parse + parse_context) completes
    and before Phase 1b (gitnexus_context).
    """
    ensure_run_dirs(run_id)

    semgrep_sinks   = _load(run_id, "sinks.json",         default=[])
    semgrep_sources = _load(run_id, "sources.json",       default=[])
    endpoints_data  = _load(run_id, "endpoints.json",     default={})
    business_ctx    = _load(run_id, "business_ctx.json",  default={})
    repo_intel      = _load(run_id, "repo_intel.json",    default={})
    repo_structure  = _load(run_id, "repo_structure.json", default={})

    endpoints = endpoints_data if isinstance(endpoints_data, list) else endpoints_data.get("endpoints", [])

    # ── 0. Build flow_domains — business domain groupings from endpoints ───────
    flow_domains = _build_flow_domains(endpoints, semgrep_sinks, business_ctx)

    # ── 1. Extract names per source ───────────────────────────────────────────

    # Sink names: semgrep detections
    semgrep_sink_names = _extract_semgrep_names(semgrep_sinks)

    # Source names: semgrep taint sources (entry-point functions)
    semgrep_source_names = _extract_semgrep_names(semgrep_sources)

    # API handler names and paths from api_parse
    api_handler_names = _extract_api_handlers(endpoints)
    api_path_entries  = _extract_api_paths(endpoints)

    # Context-declared API/function names and custom sinks
    ctx_api_names    = [n["name"] for n in business_ctx.get("api_names", []) if n.get("name")]
    ctx_custom_sinks = [s["name"] for s in business_ctx.get("custom_sinks", []) if s.get("name")]
    ctx_taint_params = business_ctx.get("function_params", [])
    sensitive_flows  = [f.get("entry", "") for f in business_ctx.get("sensitive_flows", []) if f.get("entry")]

    # ── 2. Build unified registries with scoring ───────────────────────────────

    entry_registry: dict[str, dict] = {}  # name → {sources, score, tainted_params, ...}
    sink_registry:  dict[str, dict] = {}  # name → {sources, score, vuln_types, ...}

    # Populate entry registry
    for name in ctx_api_names:
        _register(entry_registry, name, "context", score=3)
    for name in sensitive_flows:
        _register(entry_registry, name, "context", score=2)
    for name in semgrep_source_names:
        _register(entry_registry, name, "semgrep", score=2)
    for name in api_handler_names:
        _register(entry_registry, name, "api_parse", score=1)
    for name in api_path_entries:
        _register(entry_registry, name, "api_parse", score=1)

    # Tainted params: boost the function's entry score
    tainted_fn_names = set()
    for tp in ctx_taint_params:
        fn = tp.get("function", "")
        if fn:
            tainted_fn_names.add(fn)
            _register(entry_registry, fn, "context", score=2)
            if fn in entry_registry:
                entry_registry[fn].setdefault("tainted_params", [])
                param = tp.get("param", "")
                if param and param not in entry_registry[fn]["tainted_params"]:
                    entry_registry[fn]["tainted_params"].append(param)

    # Populate sink registry
    for name in ctx_custom_sinks:
        vuln = next((s.get("vuln_type","") for s in business_ctx.get("custom_sinks",[]) if s.get("name")==name), "")
        _register(sink_registry, name, "context", score=3, vuln_type=vuln)
    for sink in semgrep_sinks:
        name = _fn_name(sink.get("code", ""))
        if name:
            _register(sink_registry, name, "semgrep", score=2, vuln_type=sink.get("type",""))

    # Surface sinks from gitnexus_context Pass 3 (always available — no semgrep dependency)
    # HIGH confidence = Pass 1 known-sink wrapper; MEDIUM = heuristic/surface scan
    for sink in repo_structure.get("custom_sinks", []):
        if sink.get("confidence") in ("HIGH", "MEDIUM"):
            name = sink.get("name", "")
            if name:
                score = 2 if sink.get("confidence") == "HIGH" else 1
                _register(sink_registry, name, "surface_scan", score=score,
                           vuln_type=sink.get("vuln_type", "unknown"))

    # ── 3. Prioritize ─────────────────────────────────────────────────────────

    def _prioritize(registry: dict) -> list[dict]:
        items = list(registry.values())
        for item in items:
            s = item["score"]
            item["priority"] = "HIGH" if s >= _PRIORITY_HIGH else ("MEDIUM" if s >= _PRIORITY_MEDIUM else "LOW")
        return sorted(items, key=lambda x: x["score"], reverse=True)

    entry_points = _prioritize(entry_registry)
    sink_targets  = _prioritize(sink_registry)

    # ── 4. Pre-compute gitnexus_context params ────────────────────────────────

    # extra_topics: domain keywords from sensitive_flows + security_notes
    extra_topics = _extract_extra_topics(business_ctx, repo_intel)

    gitnexus_params = {
        "extra_topics":       extra_topics,
        "ctx_api_names":      ctx_api_names[:_MAX_NAMES_PER_LIST],
        "ctx_custom_sinks":   ctx_custom_sinks[:_MAX_NAMES_PER_LIST],
        "semgrep_sink_names": _dedupe(semgrep_sink_names)[:_MAX_NAMES_PER_LIST],
        "api_endpoints":      _dedupe(api_handler_names + api_path_entries)[:_MAX_NAMES_PER_LIST],
    }

    # ── 5. Generate Cypher hints ───────────────────────────────────────────────

    all_entry_names = _dedupe([e["name"] for e in entry_points])
    all_sink_names  = _dedupe([s["name"] for s in sink_targets])

    high_entries = _dedupe([e["name"] for e in entry_points if e["priority"] == "HIGH"])
    high_sinks   = _dedupe([s["name"] for s in sink_targets  if s["priority"] in ("HIGH","MEDIUM")])

    cypher_hints = []

    if high_entries and high_sinks:
        cypher_hints.append({
            "label":    "high_priority_paths",
            "priority": "HIGH",
            "reason":   "context-declared entries + confirmed sinks (multi-source)",
            "cypher":   _cypher_entry_to_sink(high_entries, high_sinks, depth="1..6", limit=60),
        })

    if all_entry_names or all_sink_names:
        cypher_hints.append({
            "label":    "broad_surface",
            "priority": "MEDIUM",
            "reason":   "all entries OR all sinks — broad sweep",
            "cypher":   _cypher_broad(all_entry_names, all_sink_names, depth="1..5", limit=60),
        })

    if tainted_fn_names and all_sink_names:
        cypher_hints.append({
            "label":    "taint_param_paths",
            "priority": "HIGH",
            "reason":   "function_params tainted entry → any sink (shallow trace)",
            "cypher":   _cypher_entry_to_sink(
                list(tainted_fn_names)[:_MAX_NAMES_PER_LIST],
                all_sink_names,
                depth="1..4",
                limit=40,
            ),
        })

    # ── 6. Assemble and save ───────────────────────────────────────────────────

    # Enrich extra_topics with domain keywords discovered from flow_domains
    for domain in flow_domains:
        for kw in domain.get("topic_keywords", []):
            if kw not in extra_topics:
                extra_topics.append(kw)
    extra_topics = sorted(set(extra_topics))
    gitnexus_params["extra_topics"] = extra_topics

    strategy = {
        "flow_domains":     flow_domains,   # ← READ THIS FIRST — Claude's semantic inference input
        "entry_points":     entry_points,
        "sink_targets":     sink_targets,
        "taint_params":     ctx_taint_params,
        "extra_topics":     extra_topics,
        "gitnexus_params":  gitnexus_params,
        "cypher_hints":     cypher_hints,
        "stats": {
            "flow_domain_count":    len(flow_domains),
            "risky_domains":        sum(1 for d in flow_domains if d.get("risk_signals")),
            "entry_count":          len(entry_points),
            "sink_count":           len(sink_targets),
            "high_priority_pairs":  len(high_entries) * len(high_sinks),
            "taint_param_count":    len(ctx_taint_params),
            "cypher_hints_count":   len(cypher_hints),
        },
    }

    saved_to = write(run_id, "catalog", "scan_strategy.json", strategy)
    strategy["saved_to"] = saved_to
    return strategy


# ── Name extraction helpers ───────────────────────────────────────────────────

def _fn_name(code: str) -> str:
    """Extract bare function name from a code snippet: 'OracleCommand(x)' → 'OracleCommand'."""
    if not code:
        return ""
    return re.sub(r"\(.*", "", code).strip().split(".")[-1]


def _extract_semgrep_names(items: list) -> list[str]:
    names = []
    for item in items:
        name = _fn_name(item.get("code", ""))
        if name and len(name) > 2:
            names.append(name)
    return names


def _extract_api_handlers(endpoints: list) -> list[str]:
    names = []
    for ep in endpoints:
        handler = ep.get("handler", "")
        if handler and len(handler) > 2:
            names.append(handler)
    return names


def _extract_api_paths(endpoints: list) -> list[str]:
    """Extract meaningful path segments (not just '/' or version prefixes)."""
    names = []
    for ep in endpoints:
        path = ep.get("path", "")
        if not path:
            continue
        # Last non-param segment: /api/v1/payment/{id} → "payment"
        segments = [s for s in path.split("/") if s and not s.startswith("{") and s not in
                    ("api","v1","v2","v3","rest","graphql")]
        if segments:
            names.append(segments[-1])
    return names


def _extract_extra_topics(business_ctx: dict, repo_intel: dict) -> list[str]:
    topics: set[str] = set()

    # From sensitive_flows entries
    for flow in business_ctx.get("sensitive_flows", []):
        entry = flow.get("entry", "")
        for seg in re.split(r"[/\s_-]", entry):
            seg = re.sub(r"[^a-zA-Z]", "", seg).lower()
            if len(seg) > 3:
                topics.add(seg)

    # From repo_intel security_notes
    security_notes = repo_intel.get("security_notes", [])
    if isinstance(security_notes, list):
        for note in security_notes:
            note_lower = str(note).lower()
            if "webhook" in note_lower:    topics.update(["webhook","callback"])
            if "payment" in note_lower:    topics.update(["payment","billing","checkout"])
            if "admin" in note_lower:      topics.add("admin")
            if "upload" in note_lower:     topics.update(["upload","storage"])
            if "multi-tenant" in note_lower or "company_id" in note_lower:
                topics.update(["company","tenant"])

    # From api_names in context
    for n in business_ctx.get("api_names", []):
        name = n.get("name","")
        if name and len(name) > 3:
            topics.add(name.lower())

    return sorted(topics)


# ── Flow domain builder ───────────────────────────────────────────────────────

def _build_flow_domains(
    endpoints: list,
    semgrep_sinks: list,
    business_ctx: dict,
) -> list[dict]:
    """Group endpoints by business domain and extract structured signals.

    Each domain entry is a structured signal block for Claude's semantic inference.
    Claude reads flow_domains and reasons: which domain has the most risky combination
    of params + sinks + missing auth → feed those domain keywords to gitnexus.

    Grouping: first meaningful URL path segment (skip api/v1/etc.).
    Domain "unknown" collects ungrouped endpoints.
    """
    if not endpoints:
        return []

    # Build index: sink file path → sink names
    sink_files: dict[str, list[str]] = {}
    for sink in semgrep_sinks:
        f = sink.get("file", "")
        name = _fn_name(sink.get("code", ""))
        if f and name:
            sink_files.setdefault(f, [])
            if name not in sink_files[f]:
                sink_files[f].append(name)

    # Index tainted params by function name for quick lookup
    taint_by_fn: dict[str, list[str]] = {}
    for tp in business_ctx.get("function_params", []):
        fn = tp.get("function", "")
        param = tp.get("param", "")
        if fn and param:
            taint_by_fn.setdefault(fn, []).append(param)

    # Group endpoints by domain
    domain_map: dict[str, list[dict]] = {}
    for ep in endpoints:
        domain = _domain_from_path(ep.get("path", ""))
        domain_map.setdefault(domain, []).append(ep)

    result = []
    for domain, eps in sorted(domain_map.items()):
        # Collect all params across domain endpoints
        all_params: list[dict] = []
        for ep in eps:
            all_params.extend(ep.get("params", []))

        param_names = _dedupe([p["name"] for p in all_params if p.get("name")])
        id_params   = [p for p in param_names if _ID_PARAM_RE.match(p)]
        path_id_params = _dedupe([
            p["name"] for ep in eps
            for p in ep.get("params", [])
            if p.get("location") == "path" and _ID_PARAM_RE.match(p.get("name", ""))
        ])

        # Auth coverage: any endpoint in domain missing auth?
        auth_tags_all = [ep.get("auth_tags", []) for ep in eps]
        has_unauth_ep = any(not tags for tags in auth_tags_all)

        # Sink hints: which sinks appear in files that contain the domain name?
        domain_sink_hints: list[str] = []
        for file_path, sink_names in sink_files.items():
            if domain.lower() in file_path.lower():
                for sn in sink_names:
                    if sn not in domain_sink_hints:
                        domain_sink_hints.append(sn)

        # Handler function names in this domain
        handler_names = _dedupe([ep.get("handler", "") for ep in eps if ep.get("handler")])

        # Taint signals: context-declared tainted params for handlers in this domain
        taint_signals: list[dict] = []
        for handler in handler_names:
            if handler in taint_by_fn:
                taint_signals.append({"handler": handler, "tainted_params": taint_by_fn[handler]})

        # Risk signals — structural indicators for Claude to reason about
        risk_signals: list[str] = []
        if path_id_params:
            risk_signals.append("path_id_params")        # IDOR candidate
        if id_params and domain_sink_hints:
            risk_signals.append("id_param_with_sink")    # SQLi/inject candidate
        if has_unauth_ep:
            risk_signals.append("unauthenticated_endpoint")
        if taint_signals:
            risk_signals.append("taint_param_declared")  # context-explicit taint

        # Topic keywords: domain + related business terms Claude might need
        topic_keywords = [domain] if domain != "unknown" else []
        # Add related business terms from params (e.g. "order_id" → "order")
        for param in id_params:
            stem = re.sub(r"[-_](id|uuid|key|ref|code|number|num|no)$", "", param, flags=re.I).lower()
            if stem and stem != domain and len(stem) > 2:
                topic_keywords.append(stem)
        topic_keywords = _dedupe(topic_keywords)

        domain_entry = {
            "domain":           domain,
            "endpoint_count":   len(eps),
            "endpoints": [
                {
                    "method":    ep.get("method"),
                    "path":      ep.get("path"),
                    "handler":   ep.get("handler"),
                    "auth_tags": ep.get("auth_tags", []),
                    "params":    [p["name"] for p in ep.get("params", []) if p.get("name")],
                }
                for ep in eps
            ],
            "param_names":      param_names,
            "id_params":        id_params,
            "path_id_params":   path_id_params,
            "handler_names":    handler_names,
            "sink_hints":       domain_sink_hints,
            "taint_signals":    taint_signals,
            "risk_signals":     risk_signals,
            "topic_keywords":   topic_keywords,
        }
        result.append(domain_entry)

    # Sort: risky domains with sink_hints first, then by endpoint count
    result.sort(key=lambda d: (
        -len(d["risk_signals"]),
        -len(d["sink_hints"]),
        -d["endpoint_count"],
    ))
    return result


def _domain_from_path(path: str) -> str:
    """Extract the first meaningful business domain segment from a URL path.

    /api/v1/payment/checkout/{id} → "payment"
    /order/{id}/items             → "order"
    /health                       → "unknown"
    """
    if not path:
        return "unknown"
    segments = [s for s in path.strip("/").split("/")
                if s and not s.startswith("{") and s.lower() not in _SKIP_PATH_SEGMENTS]
    return segments[0].lower() if segments else "unknown"


# ── Registry helpers ──────────────────────────────────────────────────────────

def _register(
    registry: dict,
    name: str,
    source: str,
    score: int,
    vuln_type: str = "",
) -> None:
    if not name or len(name) < 2:
        return
    if name not in registry:
        registry[name] = {
            "name":    name,
            "sources": [],
            "score":   0,
        }
    entry = registry[name]
    if source not in entry["sources"]:
        entry["sources"].append(source)
        entry["score"] += score
    if vuln_type and "vuln_types" not in entry:
        entry["vuln_types"] = []
    if vuln_type and vuln_type not in entry.get("vuln_types", []):
        entry.setdefault("vuln_types", []).append(vuln_type)


def _dedupe(names: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            result.append(n)
    return result


# ── Cypher generators ─────────────────────────────────────────────────────────

def _cypher_list(names: list[str]) -> str:
    """Format a Python list into a Cypher IN-list string."""
    quoted = ", ".join(f'"{n}"' for n in names[:_MAX_NAMES_PER_LIST])
    return f"[{quoted}]"


def _cypher_entry_to_sink(entries: list[str], sinks: list[str], depth: str, limit: int) -> str:
    return (
        f"MATCH (entry:Function)-[:CALLS*{depth}]->(sink:Function)\n"
        f"WHERE entry.name IN {_cypher_list(entries)}\n"
        f"  AND sink.name  IN {_cypher_list(sinks)}\n"
        "RETURN entry.name AS entry_fn, entry.filePath AS entry_file, entry.line AS entry_line,\n"
        "       sink.name  AS sink_fn,  sink.filePath  AS sink_file,  sink.line  AS sink_line\n"
        f"LIMIT {limit}"
    )


def _cypher_broad(entries: list[str], sinks: list[str], depth: str, limit: int) -> str:
    where_parts = []
    if entries:
        where_parts.append(f"entry.name IN {_cypher_list(entries)}")
    if sinks:
        where_parts.append(f"sink.name  IN {_cypher_list(sinks)}")
    where_clause = "\n   OR ".join(where_parts)
    return (
        f"MATCH (entry:Function)-[:CALLS*{depth}]->(sink:Function)\n"
        f"WHERE {where_clause}\n"
        "RETURN entry.name AS entry_fn, entry.filePath AS entry_file, entry.line AS entry_line,\n"
        "       sink.name  AS sink_fn,  sink.filePath  AS sink_file,  sink.line  AS sink_line\n"
        f"LIMIT {limit}"
    )


# ── I/O helpers ───────────────────────────────────────────────────────────────

def _load(run_id: str, filename: str, default: Any) -> Any:
    """Load a catalog JSON file; return default if missing or invalid."""
    path = Path(REPORTS_DIR) / run_id / "catalog" / filename
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if data else default
    except (json.JSONDecodeError, OSError):
        return default
