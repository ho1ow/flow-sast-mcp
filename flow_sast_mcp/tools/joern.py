"""
tools/joern.py
───────────────
MCP tool: joern_filter

Input:  run_id, repo, paths[]
Output: { cpg_confirmed[], updated_paths[], saved_to }
Saves:  connect/cpg_confirmed.json

Returns gracefully if Joern REST server is unavailable.
"""

from __future__ import annotations

import os
import re
import time
from enum import Enum
from typing import Dict, List, Optional

import httpx

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

JOERN_BASE_URL = os.environ.get("JOERN_BASE_URL", "http://localhost:8080")


class PathDecision(Enum):
    CONFIRMED_HIGH        = "confirmed"
    CLAUDE_SANITIZER_ONLY = "sanitizer"
    CLAUDE_FULL_VERIFY    = "full_verify"
    CLAUDE_OBJECT_TRACE   = "object_trace"
    SKIP_NO_FLOW          = "skip_no_flow"
    SKIP_FALSE_POSITIVE   = "skip_fp"
    MANUAL_REVIEW         = "manual"


# SANITIZER_NAMES is intentionally NOT used to make a pass/fail decision.
# The Joern query returns the actual flow_nodes (call chain), which Claude
# reads in Phase 3 Verify to identify sanitizers — including custom ones.
# This avoids false CONFIRMED_HIGH when custom sanitizers are present.
#
# Override via env: JOERN_SANITIZERS=myEscape,sanitizeForSql (comma-separated)
# These are used only as supplementary hints, not authoritative decisions.
_ENV_SANITIZERS = os.environ.get("JOERN_SANITIZERS", "")
SANITIZER_HINTS: set[str] = (
    {s.strip() for s in _ENV_SANITIZERS.split(",") if s.strip()}
    if _ENV_SANITIZERS
    else {
        # Common framework sanitizers — used as soft hints only.
        # Unknown sanitizers are caught by Claude reading flow_nodes in Verify.
        "bindParam", "bindValue", "prepare", "prepared", "escape", "quote",
        "mysqli_real_escape_string", "pg_escape_string", "PDO::quote",
        "parameterize", "sanitize_sql",
        "escapeshellarg", "escapeshellcmd", "shlex.quote", "shlex.split",
        "htmlspecialchars", "htmlentities", "strip_tags", "DOMPurify",
        "bleach.clean", "markupsafe.escape",
        "basename", "realpath", "pathinfo", "os.path.abspath", "os.path.normpath",
        "json_decode", "json.loads",
    }
)

# Dynamic dispatch patterns — flags path for manual review.
# PHP-specific; other language dynamic dispatch falls through to Joern query.
MANUAL_PATTERNS = [r"\$\w+->", r"call_user_func", r"\$\w+\(", r"__call"]

SKIP_FILE_PATTERNS = [
    "/test/", "/tests/", "/spec/", "/fixture/", "/fixtures/",
    "/migration/", "/migrations/", "Test.php", "Spec.php", "_test.go",
]


def run(run_id: str, repo: str, paths: List[dict]) -> dict:
    """Joern CFG-aware taint confirm. Gracefully skips if Joern unavailable."""
    ensure_run_dirs(run_id)

    if not _joern_available():
        result = _fallback_no_joern(paths)
        write(run_id, "connect", "cpg_confirmed.json", result["confirmed"])
        return result

    client = _JoernClient(JOERN_BASE_URL)
    cpg_id = _get_cpg(client, repo)

    if not cpg_id:
        result = _fallback_no_joern(paths)
        write(run_id, "connect", "cpg_confirmed.json", result["confirmed"])
        return result

    confirmed: List[dict] = []
    updated: List[dict] = []

    for path in paths:
        decision, flow_nodes = _decide(client, cpg_id, path)
        annotated = {
            **path,
            "path_decision": decision.value,
            # flow_nodes: actual Joern call-chain — Claude reads in Phase 3
            # to identify sanitizers (including custom ones not in SANITIZER_HINTS)
            "flow_nodes": flow_nodes,
        }
        updated.append(annotated)
        if decision == PathDecision.CONFIRMED_HIGH:
            confirmed.append(annotated)

    saved_to = write(run_id, "connect", "cpg_confirmed.json", confirmed)
    write(run_id, "connect", "joern_annotated_paths.json", updated)

    return {
        "cpg_confirmed": confirmed,
        "updated_paths": updated,
        "confirmed_count": len(confirmed),
        "saved_to": saved_to,
    }


def _decide(client: "_JoernClient", cpg_id: str, path: dict) -> tuple[PathDecision, list]:
    """
    Returns (PathDecision, flow_nodes).
    flow_nodes: list of call-chain code snippets from Joern — Claude reads these
    in Phase 3 Verify to identify sanitizers (including custom ones).
    """
    if _is_test_file(path):
        return PathDecision.SKIP_FALSE_POSITIVE, []
    if path.get("query_type") == "object":
        return PathDecision.CLAUDE_OBJECT_TRACE, []
    if _needs_manual(path):
        return PathDecision.MANUAL_REVIEW, []

    source  = path.get("source", {})
    sink    = path.get("sink", {})
    src_pat = _make_pattern(source)
    snk_pat = _make_pattern(sink)
    if not src_pat or not snk_pat:
        return PathDecision.CLAUDE_FULL_VERIFY, []

    scala_q = _build_taint_query(src_pat, snk_pat)
    try:
        result = client.run_query(cpg_id, scala_q)
    except Exception:
        return PathDecision.CLAUDE_FULL_VERIFY, []

    has_flow   = result.get("has_flow", False)
    flow_nodes = result.get("flow_nodes", [])

    if not has_flow:
        return PathDecision.SKIP_NO_FLOW, []

    # Check flow_nodes against SANITIZER_HINTS as a soft signal.
    # Even if a hint matches, decision is CLAUDE_SANITIZER_ONLY (not auto-skip):
    # Claude reads flow_nodes in Verify and makes the final call.
    # If no hint matches, CONFIRMED_HIGH — but Claude still verifies in Phase 3.
    hint_matched = any(
        hint in node
        for node in flow_nodes
        for hint in SANITIZER_HINTS
    )
    decision = PathDecision.CLAUDE_SANITIZER_ONLY if hint_matched else PathDecision.CONFIRMED_HIGH
    return decision, flow_nodes


def _fallback_no_joern(paths: List[dict]) -> dict:
    updated: List[dict] = []
    for path in paths:
        if _is_test_file(path):
            decision = PathDecision.SKIP_FALSE_POSITIVE
        elif path.get("query_type") == "object":
            decision = PathDecision.CLAUDE_OBJECT_TRACE
        elif _needs_manual(path):
            decision = PathDecision.MANUAL_REVIEW
        else:
            decision = PathDecision.CLAUDE_FULL_VERIFY
        updated.append({**path, "path_decision": decision.value, "flow_nodes": []})

    return {
        "cpg_confirmed": [],
        "updated_paths": updated,
        "confirmed_count": 0,
        "joern_available": False,
    }


def _is_test_file(path: dict) -> bool:
    """Structural check only — test/migration file paths."""
    entry_file = path.get("entry_file", path.get("file", ""))
    return any(p in entry_file for p in SKIP_FILE_PATTERNS)


def _needs_manual(path: dict) -> bool:
    call_chain = " ".join(str(n) for n in path.get("call_chain", []))
    return any(re.search(p, call_chain) for p in MANUAL_PATTERNS)


def _make_pattern(node: dict) -> Optional[str]:
    code = node.get("code", node.get("name", ""))
    if not code:
        return None
    return re.escape(code.split("(")[0].strip())


def _build_taint_query(src_pat: str, snk_pat: str) -> str:
    return f"""
val src  = cpg.call.name("{src_pat}").argument
val sink = cpg.call.name("{snk_pat}").argument
val flows = sink.reachableByFlows(src).l
Map(
  "has_flow"   -> flows.nonEmpty,
  "flow_count" -> flows.size,
  "flow_nodes" -> flows.headOption
                    .map(f => f.elements.map(_.code).distinct.l)
                    .getOrElse(List())
).toJson
"""


def _joern_available() -> bool:
    try:
        r = httpx.get(f"{JOERN_BASE_URL}/health", timeout=3)
        return r.status_code < 500
    except Exception:
        return False


def _get_cpg(client: "_JoernClient", repo_path: str) -> Optional[str]:
    try:
        cpg_id = client.create_cpg(repo_path)
        client.wait_cpg_ready(cpg_id)
        return cpg_id
    except Exception:
        return None


class _JoernClient:
    def __init__(self, base_url: str, timeout: int = 300):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(connect=10.0, read=timeout, write=60.0, pool=10.0),
        )

    def create_cpg(self, repo_path: str) -> str:
        resp = self._http.post("/api/cpg/create", json={"inputPath": repo_path})
        resp.raise_for_status()
        data = resp.json()
        cpg_id = data.get("cpgId") or data.get("projectName") or data.get("id")
        if not cpg_id:
            raise ValueError(f"CPG create returned no ID: {data}")
        return str(cpg_id)

    def wait_cpg_ready(self, cpg_id: str, build_timeout: int = 600, poll_interval: int = 5) -> None:
        deadline = time.time() + build_timeout
        while time.time() < deadline:
            try:
                resp = self._http.get(f"/api/cpg/{cpg_id}/status")
                status = resp.json().get("status", "unknown").upper()
                if status in ("DONE", "READY"):
                    return
                if status in ("FAILED", "ERROR"):
                    raise ValueError(f"CPG build failed: {status}")
            except httpx.HTTPError:
                pass
            time.sleep(poll_interval)
        raise TimeoutError(f"CPG build timed out after {build_timeout}s")

    def run_query(self, cpg_id: str, query: str) -> dict:
        resp = self._http.post("/api/query", json={"query": query, "cpgId": cpg_id})
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return data
        return {}
