"""
tools/gitnexus.py
──────────────────
MCP tools: gitnexus_context + gitnexus_query

gitnexus_context:
  Input:  run_id, repo
  Output: { file_tree, entry_points, custom_sinks, process_flows, saved_to }
  Saves:  catalog/repo_structure.json

gitnexus_query:
  Input:  run_id, repo, cypher, label, phase
  Output: { paths, nodes, saved_to }
  Saves:  catalog/gitnexus_<label>.json  OR  connect/gitnexus_<label>.json
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

GITNEXUS_BINARY = os.environ.get("GITNEXUS_BINARY", "gitnexus")
GITNEXUS_TIMEOUT = int(os.environ.get("GITNEXUS_TIMEOUT", "120"))

# ── Known sink list for wrapper discovery (STEP1_QUERY) ───────────────────────
# Override via env: GITNEXUS_KNOWN_SINKS=exec,system,myCustomSink (comma-separated)
_ENV_KNOWN_SINKS = os.environ.get("GITNEXUS_KNOWN_SINKS", "")
KNOWN_SINKS_CYPHER: list[str] = (
    [s.strip() for s in _ENV_KNOWN_SINKS.split(",") if s.strip()]
    if _ENV_KNOWN_SINKS
    else [
        "exec", "system", "shell_exec", "passthru", "popen", "proc_open",
        "os.system", "subprocess.run", "subprocess.Popen", "child_process.exec",
        "child_process.execSync", "child_process.spawn",
        "mysqli_query", "PDO::exec", "DB::statement", "DB::unprepared",
        "cursor.execute", "engine.execute", "db.query", "sequelize.query", "knex.raw",
        "file_put_contents", "fwrite", "move_uploaded_file", "unlink",
        "fs.writeFile", "fs.writeFileSync", "createWriteStream",
        "render_template_string", "Markup", "innerHTML", "dangerouslySetInnerHTML",
        "curl_exec", "file_get_contents", "requests.get", "urllib.request.urlopen",
        "fetch", "axios.get", "axios.post",
        "unserialize", "pickle.loads", "yaml.load", "jsonpickle.decode",
        "eval", "include", "require",
    ]
)

# ── Application layer directory tokens (structural, not knowledge-based) ──────
# Used to identify files that are likely to contain custom sinks.
# No method-name knowledge — Claude decides what is dangerous.
_APP_LAYER_PRIORITY = [
    # (path_token, layer_name, confidence)  — ordered: MEDIUM layers first
    ("service",    "service",    "MEDIUM"),
    ("repository", "repository", "MEDIUM"),
    ("/repo/",     "repository", "MEDIUM"),
    ("dao",        "dao",        "MEDIUM"),
    ("gateway",    "gateway",    "MEDIUM"),
    ("adapter",    "adapter",    "MEDIUM"),
    ("handler",    "handler",    "LOW"),
    ("controller", "controller", "LOW"),
    ("action",     "action",     "LOW"),
    ("processor",  "processor",  "LOW"),
    ("store/",     "store",      "LOW"),
    ("manager",    "manager",    "LOW"),
    ("dispatcher", "dispatcher", "LOW"),
    ("executor",   "executor",   "LOW"),
    ("writer",     "writer",     "LOW"),
    ("sender",     "sender",     "LOW"),
]

MAX_SURFACE_FUNCTIONS = int(os.environ.get("GITNEXUS_MAX_SURFACE", "150"))

# ── Function definition patterns (multi-language) ─────────────────────────────
# Python / PHP / JS / TS / Go / Ruby: def/function/func keyword
_FUNC_DEF_KEYWORD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|async|final|override)\s+)*"
    r"(?:function\s+|def\s+|func\s+)"
    r"(\w+)\s*[\(:]",
    re.MULTILINE,
)
# Java / C# / Kotlin: modifiers + return type + name(
_FUNC_DEF_TYPED_RE = re.compile(
    r"^\s+(?:(?:public|private|protected|static|final|synchronized|override|async)\s+)+"
    r"(?:void|String|int|long|boolean|Object|List|Map|Response|Result|\w+)\s+"
    r"(\w+)\s*\(",
    re.MULTILINE,
)
# Directories / extensions to skip during file scan
_SCAN_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "vendor", "dist", "build",
    "test", "tests", "spec", "specs", "mock", "mocks", "fixture", "fixtures",
}
_SCAN_SOURCE_EXTS = {".py", ".java", ".js", ".ts", ".go", ".php", ".rb", ".cs", ".kt"}

# Directory names to skip when inferring flow topics from repo structure.
# These are either generic layer names or infrastructure names — not domain keywords.
_FLOW_TOPIC_SKIP = frozenset({
    # Generic structure
    "src", "main", "app", "lib", "pkg", "cmd", "internal", "external",
    "common", "shared", "core", "base", "utils", "util", "helpers", "helper",
    "config", "configuration", "settings", "env",
    "tests", "test", "spec", "specs", "mocks", "fixtures",
    "vendor", "node_modules", "dist", "build", "target",
    "resources", "static", "templates", "views", "public", "assets",
    "docs", "documentation", "scripts", "bin", "migrations",
    # Layer names (used for surface scan — not business domain keywords)
    "service", "services", "controller", "controllers",
    "repository", "repositories", "repo", "repos",
    "handler", "handlers", "action", "actions",
    "processor", "processors", "dao", "gateway", "gateways",
    "adapter", "adapters", "store", "stores",
    "manager", "managers", "dispatcher", "dispatchers",
    "executor", "executors", "writer", "writers",
    "sender", "senders", "receiver", "receivers", "resolver", "resolvers",
    # Infrastructure
    "database", "db", "cache", "redis", "queue", "jobs", "worker", "workers",
    "http", "web", "api", "rest", "graphql", "grpc", "rpc",
    "routes", "route", "models", "model", "entities", "entity",
    "dto", "request", "response", "middleware",
    "event", "events", "listener", "listeners", "observer", "observers",
})

# ── Code-level domain keyword extraction ─────────────────────────────────────
# Class/struct names after stripping layer suffixes reveal the business domain.
# e.g. PaymentService → "payment", PrescriptionRepository → "prescription"
_CLASS_LAYER_SUFFIXES = frozenset({
    "service", "repository", "repo", "controller", "handler", "manager",
    "adapter", "gateway", "processor", "factory", "provider", "builder",
    "listener", "observer", "decorator", "command", "query",
    "request", "response", "exception", "error", "helper", "util",
    "base", "abstract", "impl", "test", "spec", "mock", "facade",
    "interface", "contract", "trait", "mixin", "dto", "vo", "entity",
    "model", "schema", "serializer", "validator", "middleware",
    "interceptor", "filter", "component", "module", "config", "settings",
    "client", "server", "worker", "job", "task", "event", "message",
    "publisher", "subscriber", "consumer", "producer", "emitter",
})

# Class definition regex — covers Python, Java, PHP, TS/JS, C#, Ruby, Kotlin
_CLASS_DEF_RE = re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]+)", re.MULTILINE)
# Go struct: type PaymentService struct
_GO_STRUCT_RE = re.compile(r"\btype\s+([A-Z][A-Za-z0-9_]+)\s+struct\b", re.MULTILINE)
# Route/URL string literals with at least 2 path segments
_ROUTE_STR_RE = re.compile(r"""['"](/[a-zA-Z0-9_/-]{4,}['"])""")
# Common HTTP/REST verbs and generic path segments — not domain keywords
_ROUTE_VERB_SKIP = frozenset({
    "api", "v1", "v2", "v3", "v4", "rest", "graphql", "grpc",
    "create", "update", "delete", "remove", "edit", "patch",
    "list", "show", "index", "store", "destroy", "fetch",
    "find", "search", "get", "post", "put", "new", "all",
    "bulk", "batch", "import", "export", "sync", "status",
    "health", "ping", "info", "version", "docs", "swagger",
})


def _split_camel_case(name: str) -> List[str]:
    """Split PascalCase/CamelCase into words: PaymentService → ['Payment', 'Service']."""
    return re.findall(r"[A-Z][a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\d|\b)", name)


def _extract_code_keywords(repo_path: Path, max_keywords: int = 20) -> List[str]:
    """
    Scan source files and extract business-domain keywords from:
      1. Class / struct names (CamelCase split, layer suffixes removed)
         PaymentGateway → 'payment'   PrescriptionRepo → 'prescription'
      2. Route / URL string literals
         '/api/shipment/create' → 'shipment'

    No hardcoded domain list — adapts to any application domain.
    """
    keywords: set[str] = set()

    for f in repo_path.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in _SCAN_SOURCE_EXTS:
            continue
        if any(skip in f.parts for skip in _SCAN_SKIP_DIRS):
            continue
        if f.name.startswith("."):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # 1. Class/struct names
        for pattern in (_CLASS_DEF_RE, _GO_STRUCT_RE):
            for m in pattern.finditer(content):
                for word in _split_camel_case(m.group(1)):
                    w = word.lower()
                    if (len(w) > 3
                            and w not in _CLASS_LAYER_SUFFIXES
                            and w not in _FLOW_TOPIC_SKIP):
                        keywords.add(w)

        # 2. Route/URL path segments (skip HTTP verbs and generic REST terms)
        for m in _ROUTE_STR_RE.finditer(content):
            for segment in m.group(1).strip("'\"").split("/"):
                seg = re.sub(r"[^a-zA-Z0-9_]", "", segment).lower()
                if (len(seg) > 3
                        and seg not in _CLASS_LAYER_SUFFIXES
                        and seg not in _FLOW_TOPIC_SKIP
                        and seg not in _ROUTE_VERB_SKIP):
                    keywords.add(seg)

        if len(keywords) >= max_keywords:
            break

    return list(keywords)[:max_keywords]


# File structure doc names
README_NAMES = ["README.md", "README.rst", "README.txt", "README", "readme.md"]
MANIFEST_FILES = ["package.json", "composer.json", "pyproject.toml", "go.mod"]
ENV_EXAMPLES = [".env.example", ".env.sample", ".env.template"]


def run_context(
    run_id: str,
    repo: str,
    extra_topics: List[str] = None,
    api_endpoints: List[str] = None,
    semgrep_sink_names: List[str] = None,
    ctx_api_names: List[str] = None,
    ctx_custom_sinks: List[str] = None,
) -> dict:
    """Extract structural info from repo: file tree, entry points, custom wrappers.

    Cross-catalog inputs (returned labeled so Claude can use them in Cypher):
      extra_topics:       domain keywords from business_ctx.sensitive_flows + repo_intel
      api_endpoints:      [ep.path from api_parse.endpoints]  — Phase 1a result
      semgrep_sink_names: [sink function names from semgrep sinks[]] — Phase 1a result
      ctx_api_names:      [business_ctx.api_names[].name]  — parse_context result
      ctx_custom_sinks:   [business_ctx.custom_sinks[].name] — parse_context result

    These are returned as labeled lists for Claude to combine into Cypher queries.
    No cross-source mixing inside this function — each source stays labeled.
    """
    ensure_run_dirs(run_id)
    repo_path = Path(repo)

    result = {
        "file_tree": _build_file_tree(repo_path),
        "entry_points": [],
        "custom_sinks": [],
        "process_flows": [],
        "tech_stack": _detect_tech_stack(repo_path),
        "readme_excerpt": _read_readme(repo_path),
        "manifest_info": _read_manifest(repo_path),
        "env_keys": _read_env_example(repo_path),
    }

    # ── Data Model Extraction ──────────────────────────────────────────────────
    data_models_info = {}
    if _gitnexus_available():
        data_models_info = _discover_data_models(repo)
        if data_models_info:
            write(run_id, "catalog", "data_models.json", data_models_info)
            result["data_models_saved"] = f"logs/{run_id}/catalog/data_models.json"

    # ── Sink discovery: three independent passes, merged by confidence ─────────
    #
    # Pass 1 (primary)    — STEP1_QUERY: known-sink wrappers via GitNexus graph
    #                       HIGH confidence, requires gitnexus binary
    # Pass 2 (structural) — HEURISTIC_SINK_QUERY: high-caller-count functions
    #                       MEDIUM/LOW confidence, requires gitnexus binary
    # Pass 3 (always)     — _function_surface_scan: all functions in app layer dirs
    #                       MEDIUM/LOW confidence, pure Python, no external dependency
    #                       Analogous to _regex_fallback in secrets.py and
    #                       custom rule injection in semgrep.py
    #
    known_sinks: List[dict] = []
    structural_sinks: List[dict] = []

    if _gitnexus_available():
        result["entry_points"] = _discover_endpoints(repo, result["file_tree"])
        known_sinks            = _discover_custom_sinks(repo)       # Pass 1
        structural_sinks       = _discover_heuristic_sinks(repo)    # Pass 2
        flow_topics = _resolve_flow_topics(repo_path, extra_topics or [])
        result["process_flows"] = _discover_process_flows(repo, flow_topics)
        result["flow_topics_used"] = flow_topics

    surface_sinks = _function_surface_scan(repo)                    # Pass 3

    result["custom_sinks"] = _merge_sink_discoveries(
        known_sinks, structural_sinks, surface_sinks
    )

    # ── Cross-catalog inputs — returned labeled, not mixed ─────────────────────
    # Claude uses these to build Cypher queries combining all 4 sources.
    # Each list carries a "source" tag so Claude knows where each name came from.
    if api_endpoints:
        result["api_entry_points"] = [
            {"name": ep, "source": "api_parse"} for ep in api_endpoints
        ]
    if semgrep_sink_names:
        result["semgrep_sink_names"] = [
            {"name": s, "source": "semgrep"} for s in semgrep_sink_names
        ]
    if ctx_api_names:
        result["ctx_api_names"] = [
            {"name": n, "source": "context"} for n in ctx_api_names
        ]
    if ctx_custom_sinks:
        result["ctx_custom_sinks"] = [
            {"name": n, "source": "context"} for n in ctx_custom_sinks
        ]

    saved_to = write(run_id, "catalog", "repo_structure.json", result)
    result["saved_to"] = saved_to
    return result


def run_query(run_id: str, repo: str, cypher: str, label: str, phase: str) -> dict:
    """Execute a Cypher query against GitNexus and save results."""
    ensure_run_dirs(run_id)

    rows = _run_cypher(repo, cypher)
    filename = f"gitnexus_{label}.json"
    saved_to = write(run_id, phase, filename, rows)

    return {
        "rows": rows,
        "count": len(rows),
        "label": label,
        "phase": phase,
        "saved_to": saved_to,
    }


# ── Structural discovery ──────────────────────────────────────────────────────

STEP1_QUERY = """
MATCH (wrapper:Symbol)-[:CALLS]->(known_sink:Symbol)
WHERE known_sink.name IN [{sink_list}]
AND wrapper.filePath CONTAINS 'src/'
AND NOT wrapper.name IN [{sink_list}]
RETURN DISTINCT
    wrapper.name     AS custom_sink_name,
    wrapper.filePath AS file,
    wrapper.line     AS line,
    known_sink.name  AS wraps_sink,
    COUNT(*) AS call_count
ORDER BY call_count DESC
LIMIT 50
"""

# STEP2 is now built dynamically — see _build_endpoint_query() below.
# Keeping this constant only as documentation of the output shape.
_STEP2_MIDDLEWARE_CLAUSE = """
OPTIONAL MATCH (middleware:Symbol)-[:CALLS]->(handler)
WHERE middleware.name CONTAINS 'auth'
   OR middleware.name CONTAINS 'middleware'
   OR middleware.name CONTAINS 'guard'
   OR middleware.name CONTAINS 'jwt'
   OR middleware.name CONTAINS 'permission'
RETURN
    handler.name           AS handler_fn,
    handler.filePath       AS file,
    handler.line           AS line,
    collect(DISTINCT middleware.name) AS auth_middleware
ORDER BY handler.filePath
LIMIT 200
"""

# Generic directory tokens used ONLY when file_tree is empty (last-resort fallback).
_ENDPOINT_FALLBACK_TOKENS = [
    "controller", "route", "handler", "action",
    "endpoint", "api", "view", "resource",
]


def _build_endpoint_query(file_tree: List[str]) -> str:
    """
    Build a Cypher endpoint-discovery query whose WHERE clause is derived from
    the *actual* directory paths present in the repository — not hardcoded tokens.

    Strategy:
      1. Collect every unique directory segment from file_tree (e.g. 'api', 'v1',
         'presentation', 'interfaces', 'web').
      2. Skip generic infrastructure/layer names (same skip-set used elsewhere).
      3. If no meaningful segments survive, fall back to _ENDPOINT_FALLBACK_TOKENS.
      4. Build: WHERE toLower(handler.filePath) CONTAINS '<seg>' OR ...

    This means a project laid out as:
         src/presentation/order/OrderController.php
         src/interfaces/api/v1/PaymentResource.java
    will produce:  CONTAINS 'presentation' OR CONTAINS 'interfaces'
    instead of the old hardcoded CONTAINS 'controller' OR CONTAINS 'route'.
    """
    # ── Extract unique dir segments from the real file tree ───────────────────
    segments: set[str] = set()
    for rel_path in file_tree:
        # Normalize to forward-slash so Path.parts works consistently
        parts = Path(rel_path.replace("\\", "/")).parts
        # All parts except the final filename are directory segments
        for part in parts[:-1]:
            seg = part.lower()
            if (
                len(seg) > 2
                and seg not in _FLOW_TOPIC_SKIP      # generic infrastructure
                and seg not in _SCAN_SKIP_DIRS       # test/vendor/build/etc.
                and not seg.startswith(".")
            ):
                segments.add(seg)

    tokens = sorted(segments) if segments else _ENDPOINT_FALLBACK_TOKENS

    conditions = "\n   OR ".join(
        f"toLower(handler.filePath) CONTAINS '{tok}'"
        for tok in tokens
    )

    return f"""MATCH (handler:Symbol)
WHERE {conditions}
{_STEP2_MIDDLEWARE_CLAUSE}"""


def _discover_custom_sinks(repo: str) -> List[dict]:
    """Pass 1 — known-sink wrappers via graph query. HIGH confidence."""
    sink_list = ", ".join(f'"{s}"' for s in KNOWN_SINKS_CYPHER)
    query = STEP1_QUERY.replace("{sink_list}", sink_list)
    rows = _run_cypher(repo, query)
    sinks = []
    for row in rows:
        sink_id = hashlib.md5(
            f"{row.get('file', '')}:{row.get('custom_sink_name', '')}".encode()
        ).hexdigest()[:10]
        # Infer vuln_type from the known sink this wraps
        wrapped = row.get("wraps_sink", "")
        sinks.append({
            "id": sink_id,
            "name": row.get("custom_sink_name", ""),
            "wraps": wrapped,
            "file": row.get("file", ""),
            "line": row.get("line", 0),
            "call_count": row.get("call_count", 1),
            "vuln_type": _infer_vuln_type_from_known_sink(wrapped),
            "type": "custom_wrapper",
            "confidence": "HIGH",
            "detected_by": ["gitnexus_known_sink"],
        })
    return sinks


# ── Heuristic structural query (Pass 2) ──────────────────────────────────────

HEURISTIC_SINK_QUERY = """
MATCH (caller:Symbol)-[:CALLS]->(fn:Symbol)
WHERE NOT any(skip IN ['test', 'spec', 'mock', 'fixture', 'vendor', 'node_modules']
              WHERE toLower(fn.filePath) CONTAINS skip)
  AND NOT fn.name IN [{known_list}]
WITH fn, COUNT(DISTINCT caller) AS caller_count
WHERE caller_count >= {min_callers}
RETURN DISTINCT
    fn.name        AS sink_name,
    fn.filePath    AS file,
    fn.line        AS line,
    caller_count
ORDER BY caller_count DESC
LIMIT 40
"""

_MIN_CALLERS = int(os.environ.get("GITNEXUS_MIN_CALLERS", "3"))


def _discover_heuristic_sinks(repo: str) -> List[dict]:
    """
    Pass 2 — structural heuristic: functions called by ≥N distinct callers.
    High call-count implies infrastructure/utility layer — likely a sink candidate.
    Confidence: MEDIUM if caller_count >= 5, LOW otherwise (purely structural).
    """
    known_str = ", ".join(f'"{s}"' for s in KNOWN_SINKS_CYPHER)
    query = (
        HEURISTIC_SINK_QUERY
        .replace("{known_list}", known_str)
        .replace("{min_callers}", str(_MIN_CALLERS))
    )
    rows = _run_cypher(repo, query)

    sinks = []
    for row in rows:
        name = row.get("sink_name", "")
        if not name:
            continue
        caller_count = row.get("caller_count", 0)
        uid = hashlib.md5(
            f"{row.get('file', '')}:{name}".encode()
        ).hexdigest()[:10]
        sinks.append({
            "id": uid,
            "name": name,
            "file": row.get("file", ""),
            "line": row.get("line", 0),
            "call_count": caller_count,
            "vuln_type": "unknown",   # Claude classifies — no name-pattern assumption
            "type": "custom_wrapper",
            "confidence": "MEDIUM" if caller_count >= 5 else "LOW",
            "wraps": "unknown",
            "detected_by": ["gitnexus_structural"],
            "note": (
                f"Called by {caller_count} distinct callers — "
                "read implementation to determine if dangerous"
            ),
        })
    return sinks


# ── Surface scan (Pass 3) ─────────────────────────────────────────────────────
# Pure Python, no external dependency.
# Analogous to _regex_fallback in secrets.py and _build_extra_sources_rule
# in semgrep.py: always runs regardless of whether gitnexus is available.

def _function_surface_scan(repo_path: str) -> List[dict]:
    """
    Pass 3 — scan application-layer directories for ALL function definitions.
    No name-based or pattern-based filtering — returns raw structural observations.
    Claude decides which functions are actual sinks.

    Unlike the old _name_pattern_scan, this does NOT depend on SINK_NAME_PATTERNS.
    Any custom sink name (e.g. rawExec, charge, graphExecute) will appear here
    as long as it lives in a service/repository/handler/etc. directory.

    detected_by: ["surface_scan"]
    """
    findings: List[dict] = []
    seen: set[str] = set()
    repo = Path(repo_path)

    # Collect source files tagged by app layer
    layer_files: list[tuple] = []  # (path, rel, layer_name, confidence)
    for f in repo.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in _SCAN_SOURCE_EXTS:
            continue
        if any(skip in f.parts for skip in _SCAN_SKIP_DIRS):
            continue
        rel = str(f.relative_to(repo))
        rel_lower = rel.lower().replace("\\", "/")
        for token, layer_name, confidence in _APP_LAYER_PRIORITY:
            if token in rel_lower:
                layer_files.append((f, rel, layer_name, confidence))
                break  # first (highest-priority) match wins

    # MEDIUM confidence layers first
    layer_files.sort(key=lambda x: 0 if x[3] == "MEDIUM" else 1)

    for f_path, rel, layer_name, confidence in layer_files:
        if len(findings) >= MAX_SURFACE_FUNCTIONS:
            break
        try:
            content = f_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for func_name, lineno in _extract_function_names(content):
            uid = hashlib.md5(
                f"{rel}:{lineno}:{func_name}".encode()
            ).hexdigest()[:10]
            if uid in seen:
                continue
            seen.add(uid)
            findings.append({
                "id": uid,
                "name": func_name,
                "file": rel,
                "line": lineno,
                "call_count": 0,
                "vuln_type": "unknown",       # Claude classifies
                "type": "surface_candidate",
                "confidence": confidence,
                "wraps": "unknown",
                "layer": layer_name,
                "detected_by": ["surface_scan"],
                "note": (
                    f"Function in '{layer_name}' layer — "
                    "read implementation to determine if dangerous"
                ),
            })
    return findings


def _extract_function_names(content: str) -> List[tuple[str, int]]:
    """Return list of (function_name, line_number) from source content."""
    results: List[tuple[str, int]] = []
    _SKIP_KEYWORDS = frozenset(
        {"if", "while", "for", "return", "new", "void", "class", "type",
         "import", "export", "const", "let", "var", "switch", "case"}
    )

    for pattern in (_FUNC_DEF_KEYWORD_RE, _FUNC_DEF_TYPED_RE):
        for m in pattern.finditer(content):
            name = m.group(1)
            if name.lower() in _SKIP_KEYWORDS:
                continue
            lineno = content[: m.start()].count("\n") + 1
            results.append((name, lineno))

    return results


def _infer_vuln_type_from_known_sink(sink_name: str) -> str:
    """Map a known sink name → vuln_type for Pass 1 results."""
    s = sink_name.lower()
    if any(k in s for k in ("query", "execute", "statement", "db::", "pdo", "cursor", "knex", "sequelize")):
        return "sqli"
    if any(k in s for k in ("exec", "system", "shell", "spawn", "popen", "subprocess", "child_process")):
        return "rce"
    if any(k in s for k in ("unserialize", "pickle", "yaml.load", "jsonpickle", "marshal")):
        return "deser"
    if any(k in s for k in ("innerhtml", "dangerouslysetinnerhtml", "markup")):
        return "xss"
    if any(k in s for k in ("curl", "requests.", "urllib", "fetch", "axios")):
        return "ssrf"
    if any(k in s for k in ("file_put", "fwrite", "move_uploaded", "writeFile", "createWriteStream")):
        return "path_traversal"
    if "render_template_string" in s:
        return "ssti"
    return "unknown"


# ── Merge helper ──────────────────────────────────────────────────────────────

_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _merge_sink_discoveries(*discovery_lists: List[dict]) -> List[dict]:
    """
    Merge results from all three discovery passes.
    Dedup by (name.lower(), file): higher confidence wins.
    When the same sink is found by multiple passes, detected_by is union-merged.
    Priority: known_sink (HIGH) > structural (MEDIUM) > name_pattern (LOW).
    """
    seen: dict[str, dict] = {}

    for discoveries in discovery_lists:
        for sink in discoveries:
            key = f"{sink.get('name', '').lower()}::{sink.get('file', '')}"
            existing = seen.get(key)
            if existing is None:
                seen[key] = dict(sink)
            else:
                new_rank = _CONFIDENCE_RANK.get(sink.get("confidence", "LOW"), 1)
                old_rank = _CONFIDENCE_RANK.get(existing.get("confidence", "LOW"), 1)
                merged_by = list(set(
                    existing.get("detected_by", []) + sink.get("detected_by", [])
                ))
                if new_rank > old_rank:
                    seen[key] = dict(sink)
                    seen[key]["detected_by"] = merged_by
                else:
                    existing["detected_by"] = merged_by

    return list(seen.values())


# Separator-agnostic sensitive field patterns — match snake_case, camelCase, PascalCase.
# [_]? between word parts matches: password_hash, passwordHash, PasswordHash.
# Anchored ^...$ to avoid substring false positives.
_SENSITIVE_FIELD_RE = re.compile(
    r'^(?:'
    # Credentials / secrets
    r'password|passwd|pwd|secret|token|'
    r'api[_]?key|private[_]?key|'
    r'salt|.*[_]?hash|credential.*|'
    # Auth/privilege — also mass assignment risk
    r'is[_]?admin|is[_]?staff|is[_]?superuser|is[_]?active|'
    r'role[_]?id|role|permission.*|privilege.*|admin.*|'
    # PII
    r'ssn|social[_]?security.*|passport.*|national[_]?id|'
    r'dob|birth[_]?date|date[_]?of[_]?birth|'
    # Financial
    r'balance|credit[_]?card.*|card[_]?number|cvv|cvc|'
    r'iban|account[_]?number|routing[_]?number|salary|income|debit.*|'
    # Auth tokens — exact names to avoid matching created_at, updated_at, etc.
    r'reset[_]?token|verify[_]?token|verification[_]?token|'
    r'otp|mfa[_]?secret|recovery[_]?code.*|'
    r'access[_]?token|refresh[_]?token|auth[_]?token|'
    r'session[_]?token|remember[_]?token'
    r')$',
    re.IGNORECASE,
)

# HIGH mass-assignment risk — what an attacker would set to escalate privileges or tamper state.
_MASS_ASSIGN_RISK_RE = re.compile(
    r'^(?:'
    r'is[_]?admin|is[_]?staff|is[_]?superuser|is[_]?active|'
    r'is[_]?verified|is[_]?banned|is[_]?locked|'
    r'role|role[_]?id|permission.*|privilege.*|admin.*|'
    r'balance|credits|quota|points|tier|'
    r'plan|plan[_]?id|subscription.*|'
    r'email[_]?verified|phone[_]?verified|verified|status|'
    r'approved|banned|locked|suspended'
    r')$',
    re.IGNORECASE,
)

# Regex to extract word-like identifiers from a raw symbol string
_FIELD_IDENT_RE = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')

# Tokens to skip when extracting field name — language modifiers + primitive type names
_FIELD_MODIFIERS = frozenset({
    # Access / storage modifiers (all languages)
    'private', 'protected', 'public', 'internal', 'static', 'final',
    'readonly', 'abstract', 'override', 'virtual', 'sealed',
    'transient', 'volatile', 'const', 'let', 'var', 'def', 'new',
    # C# property accessors — key fix for "Password { get; set; }"
    'get', 'set', 'init',
    # Primitive / common type names (Java, C#, Go, Python, TS)
    'string', 'str', 'int', 'integer', 'long', 'short', 'byte',
    'float', 'double', 'decimal', 'bool', 'boolean', 'char',
    'object', 'dynamic', 'void', 'null', 'nil',
    'array', 'list', 'dict', 'map', 'optional', 'nullable',
    'uint', 'uint32', 'uint64', 'int32', 'int64', 'float32', 'float64',
})


def _clean_field_name(raw: str) -> str | None:
    """
    Extract the actual field/property name from a raw GitNexus symbol string.

    Handles all major naming conventions:
      "password"                           → "password"         (plain)
      "private String password"            → "password"         (Java)
      "password_hash: str"                 → "password_hash"    (Python type annotation)
      "readonly token: string"             → "token"            (TypeScript)
      "protected $password"                → "password"         (PHP)
      "public string Password { get; set; }" → "Password"       (C# property)
      "public bool IsAdmin { get; set; }"  → "IsAdmin"          (C# bool property)
      "public decimal Balance { get; set; }" → "Balance"        (C# decimal)
    """
    raw = raw.strip()
    # Strip C# property accessor block: "{ get; set; }" / "{ get; init; }" etc.
    brace_pos = raw.find('{')
    if brace_pos != -1:
        raw = raw[:brace_pos].strip()
    # Strip TypeScript/Python type annotation: "name: Type" → "name"
    if ':' in raw:
        raw = raw.split(':')[0].strip()
    # Strip PHP $ prefix
    raw = raw.lstrip('$')
    # Extract all identifiers, return the last one that is not a known modifier/type
    tokens = _FIELD_IDENT_RE.findall(raw)
    for tok in reversed(tokens):
        if tok.lower() not in _FIELD_MODIFIERS:
            return tok
    return tokens[-1] if tokens else None


def _discover_data_models(repo: str) -> dict:
    """Discover database models/entities and their properties using GitNexus.

    Detection covers:
      - Classes/structs with 'model' or 'entity' in name
      - Files under models/, entities/, domain/, schemas/, app/models
      - Django models.py, Rails app/models/, Laravel app/Models/

    Each model entry:
      fields           — cleaned field/property names
      sensitive_fields — fields matching credential/PII/financial patterns
                         → infosec_skill (sensitive data in response)
      mass_assign_risk — fields HIGH risk for mass assignment (role, is_admin, balance…)
                         → authz_skill (mass assignment fast-path)
    """
    query = """
    MATCH (c:Symbol)
    WHERE c.type IN ['Class', 'Struct']
      AND (
        toLower(c.name) CONTAINS 'model'
        OR toLower(c.name) CONTAINS 'entity'
        OR toLower(c.filePath) CONTAINS '/models/'
        OR toLower(c.filePath) CONTAINS '/entities/'
        OR toLower(c.filePath) CONTAINS '/domain/'
        OR toLower(c.filePath) CONTAINS '/schemas/'
        OR toLower(c.filePath) CONTAINS 'models.py'
        OR toLower(c.filePath) CONTAINS '/app/models'
      )
    MATCH (c)-[:CONTAINS]->(field:Symbol)
    WHERE field.type IN ['Property', 'Field', 'Variable', 'Member']
    RETURN c.name AS model_name, c.filePath AS file, collect(DISTINCT field.name) AS fields
    LIMIT 200
    """
    rows = _run_cypher(repo, query)
    models = {}
    for row in rows:
        name = row.get("model_name", "")
        raw_fields = row.get("fields", [])
        if not name or not raw_fields:
            continue
        clean_fields = [
            n for f in raw_fields
            if isinstance(f, str)
            for n in [_clean_field_name(f)]
            if n
        ]
        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped = []
        for f in clean_fields:
            if f not in seen:
                seen.add(f)
                deduped.append(f)
        sensitive = [f for f in deduped if _SENSITIVE_FIELD_RE.match(f)]
        mass_risk = [f for f in deduped if _MASS_ASSIGN_RISK_RE.match(f)]
        models[name] = {
            "file": row.get("file", ""),
            "fields": deduped,
            "sensitive_fields": sensitive,
            "mass_assign_risk": mass_risk,
        }
    return models


def _discover_endpoints(repo: str, file_tree: List[str] = None) -> List[dict]:
    """Discover endpoint handlers using paths derived from the actual file tree."""
    query = _build_endpoint_query(file_tree or [])
    rows = _run_cypher(repo, query)
    endpoints = []
    for row in rows:
        middleware = [m for m in row.get("auth_middleware", []) if m]
        ep_id = hashlib.md5(
            f"{row.get('file', '')}:{row.get('handler_fn', '')}".encode()
        ).hexdigest()[:10]
        endpoints.append({
            "id": ep_id,
            "handler": row.get("handler_fn", ""),
            "file": row.get("file", ""),
            "line": row.get("line", 0),
            "auth_middleware": middleware,
            "auth_required": len(middleware) > 0,
            "tool": "gitnexus",
        })
    return endpoints


def _resolve_flow_topics(repo_path: Path, extra_topics: List[str]) -> List[str]:
    """
    Build the final list of flow-discovery keywords from three sources (in priority):

    1. extra_topics    — caller-supplied keywords from business_ctx.sensitive_flows
                         e.g. ["payment", "webhook", "prescription"]
    2. Env var         — GITNEXUS_FLOW_TOPICS=shipment,tracking,dispatch
    3. Structural      — meaningful directory names inferred from the repo itself

    No hardcoded domain list. Adapts to any application domain.
    Analogous to how semgrep_scan accepts extra_sources from business context.
    """
    topics: list[str] = []
    seen: set[str] = set()

    def _add(kw: str) -> None:
        # Strip to alphanumeric + underscore — same guard used in Cypher query generation
        kw = re.sub(r"[^a-zA-Z0-9_]", "", kw.strip()).lower()
        if kw and len(kw) > 2 and kw not in seen and kw not in _FLOW_TOPIC_SKIP:
            seen.add(kw)
            topics.append(kw)

    # 1. Explicit from caller (business context)
    for t in extra_topics:
        _add(t)

    # 2. Env var override
    for t in os.environ.get("GITNEXUS_FLOW_TOPICS", "").split(","):
        _add(t)

    # 3. Structural inference: meaningful subdirectory names in the repo
    #    e.g. /src/payment/ → "payment",  /modules/prescription/ → "prescription"
    #    Skip hidden dirs (starting with '.') and layer/infrastructure names.
    try:
        for d in repo_path.rglob("*"):
            if (d.is_dir()
                    and not d.name.startswith(".")
                    and d.name.lower() not in _FLOW_TOPIC_SKIP
                    and len(d.name) > 3):
                _add(d.name)
    except OSError:
        pass

    # 4. Code-level extraction: class/struct names + route strings.
    #    Highest semantic signal — reads the codebase itself to discover domain.
    #    e.g. PaymentService → 'payment', '/api/prescription/fill' → 'prescription'
    for kw in _extract_code_keywords(repo_path):
        _add(kw)

    return topics[:15]  # cap to avoid generating too many Cypher queries


def _discover_process_flows(repo: str, topics: List[str]) -> List[dict]:
    """
    Run one Cypher query per topic keyword, returning call graphs around
    functions whose name mentions that domain.

    topics is built by _resolve_flow_topics — no hardcoded domain list here.
    """
    flows = []
    for keyword in topics:
        # Sanitize keyword before embedding in Cypher (alphanumeric only)
        safe_kw = re.sub(r"[^a-zA-Z0-9_]", "", keyword).lower()
        if not safe_kw:
            continue
        query = f"""
MATCH (fn:Symbol)-[:CALLS*1..4]->(related:Symbol)
WHERE toLower(fn.name) CONTAINS '{safe_kw}'
   OR toLower(related.name) CONTAINS '{safe_kw}'
RETURN DISTINCT
    fn.name AS process_fn,
    fn.filePath AS file,
    fn.line AS line,
    collect(DISTINCT related.name)[..8] AS related_calls
ORDER BY fn.filePath
LIMIT 30
"""
        rows = _run_cypher(repo, query)
        if rows:
            flows.append({
                "name": safe_kw.title() + "Flow",
                "topic": safe_kw,
                "functions": [
                    {"name": r.get("process_fn", ""), "file": r.get("file", ""),
                     "line": r.get("line", 0), "calls": r.get("related_calls", [])}
                    for r in rows
                ],
            })
    return flows


# ── Repo structure helpers ────────────────────────────────────────────────────

def _build_file_tree(repo: Path, max_files: int = 200) -> List[str]:
    """Return list of relative source file paths (capped)."""
    skip_dirs = {".git", "node_modules", "__pycache__", "vendor", "dist", "build", ".tox", "venv"}
    source_exts = {".py", ".java", ".js", ".ts", ".go", ".php", ".rb", ".cs"}
    files = []
    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        if any(d in f.parts for d in skip_dirs):
            continue
        if f.suffix.lower() in source_exts:
            files.append(str(f.relative_to(repo)))
        if len(files) >= max_files:
            break
    return sorted(files)


def _detect_tech_stack(repo: Path) -> List[str]:
    hints = []
    markers = {
        "Python/Django": ["manage.py", "wsgi.py", "settings.py"],
        "Python/Flask": ["app.py", "flask"],
        "Python/FastAPI": ["fastapi"],
        "PHP/Laravel": ["artisan", "composer.json"],
        "Node.js/Express": ["package.json", "express"],
        "Java/Spring": ["pom.xml", "build.gradle"],
        "Go": ["go.mod"],
        "Ruby/Rails": ["Gemfile", "config/routes.rb"],
    }
    for tech, files in markers.items():
        if any((repo / f).exists() for f in files):
            hints.append(tech)
    return hints


def _read_readme(repo: Path) -> str:
    for name in README_NAMES:
        f = repo / name
        if f.exists():
            try:
                return f.read_text(encoding="utf-8", errors="ignore")[:3000]
            except OSError:
                pass
    return ""


def _read_manifest(repo: Path) -> dict:
    for name in MANIFEST_FILES:
        f = repo / name
        if not f.exists():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if name == "package.json":
                d = json.loads(content)
                return {"file": name, "name": d.get("name", ""), "description": d.get("description", "")}
            elif name == "composer.json":
                d = json.loads(content)
                return {"file": name, "name": d.get("name", ""), "description": d.get("description", "")}
            elif name == "pyproject.toml":
                n = re.search(r'name\s*=\s*["\']([\w\-]+)', content)
                return {"file": name, "name": n.group(1) if n else ""}
            elif name == "go.mod":
                first = content.splitlines()[0] if content else ""
                return {"file": name, "module": first}
        except Exception:
            pass
    return {}


def _read_env_example(repo: Path) -> List[str]:
    for name in ENV_EXAMPLES:
        f = repo / name
        if f.exists():
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                return [
                    line.split("=")[0].strip()
                    for line in content.splitlines()
                    if "=" in line and not line.strip().startswith("#")
                ][:40]
            except OSError:
                pass
    return []


# ── GitNexus CLI helpers ──────────────────────────────────────────────────────

def _run_cypher(repo: str, query: str) -> List[dict]:
    if not _gitnexus_available():
        return []
    try:
        result = subprocess.run(
            [GITNEXUS_BINARY, "query", "--cypher", query, "--repo", repo, "--format", "json"],
            capture_output=True, text=True, timeout=GITNEXUS_TIMEOUT,
        )
        if result.returncode != 0:
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        return _parse_json_output(raw)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _parse_json_output(raw: str) -> list:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _gitnexus_available() -> bool:
    try:
        r = subprocess.run([GITNEXUS_BINARY, "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
