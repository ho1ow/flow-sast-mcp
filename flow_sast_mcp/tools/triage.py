"""
tools/triage.py
────────────────
MCP tool: triage_score

Input:  run_id, paths[], sensitive_flows[], cx_findings[]
Output: { scored_paths[], threshold, total_before, total_after, saved_to }
Saves:  connect/scored_paths.json

Scoring model (per MCP architecture spec):
  Semgrep rule match:      +3
  GitNexus structural:     +2
  Joern CFG confirmed:     +2
  Custom sink:             +1
  Direct HTTP source:      +1
  CX source match:         +2
  CX sink match:           +2
  CX same vuln type:       +1
  Sensitive flow match:    +2
  Explicitly listed sink:  +1
"""

from __future__ import annotations

import hashlib
import os
from typing import List

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

TRIAGE_THRESHOLD = int(os.environ.get("TRIAGE_THRESHOLD", "6"))
MAX_PATHS        = int(os.environ.get("MAX_PATHS", "200"))

# Sink severity (base score)
SINK_SEVERITY: dict[str, int] = {
    "EXEC_SINK":        5,
    "DB_SINK":          4,
    "FILE_SINK":        4,
    "DESERIALIZE_SINK": 3,
    "HTML_SINK":        3,
    "URL_SINK":         3,
    "XML_SINK":         3,
    "LOG_SINK":         1,
    "CUSTOM":           2,
}

SINK_TYPE_TO_CAT: dict[str, str] = {
    "sqli": "DB_SINK", "rce": "EXEC_SINK", "path_traversal": "FILE_SINK",
    "xss": "HTML_SINK", "ssrf": "URL_SINK", "redirect": "URL_SINK",
    "deser": "DESERIALIZE_SINK", "xxe": "XML_SINK", "ssti": "HTML_SINK",
    "lfi": "FILE_SINK", "custom": "CUSTOM",
}

TEST_FILE_PATTERNS = [
    "/test/", "/tests/", "/spec/", "/fixture/", "/fixtures/",
    "/migration/", "/migrations/", "/seeder/", "/seeders/",
    "Test.php", "Spec.php", "_test.go", "_test.py", ".test.js", ".spec.ts",
]


ENTRY_POINT_HINTS = ["controller", "route", "handler", "action", "api", "endpoint"]


def run(run_id: str, paths: List[dict], sensitive_flows: List[dict] = None,
        cx_findings: List[dict] = None) -> dict:
    """Score + filter candidate paths."""
    ensure_run_dirs(run_id)
    if sensitive_flows is None:
        sensitive_flows = []
    if cx_findings is None:
        cx_findings = []

    # Dedup by id
    seen: set[str] = set()
    unique_paths: List[dict] = []
    for p in paths:
        pid = p.get("id", hashlib.md5(str(p).encode()).hexdigest()[:12])
        if pid not in seen:
            seen.add(pid)
            unique_paths.append(p)

    scored: List[dict] = []
    skipped = 0

    for path in unique_paths:
        score, detail = _score_path(path, sensitive_flows, cx_findings)
        if score < TRIAGE_THRESHOLD:
            skipped += 1
            continue
        scored.append({**path, "score": score, "triage_score": score, "triage_detail": detail})

    scored.sort(key=lambda p: p.get("score", 0), reverse=True)
    prioritized = scored[:MAX_PATHS]

    saved_to = write(run_id, "connect", "scored_paths.json", prioritized)

    return {
        "scored_paths": prioritized,
        "threshold": TRIAGE_THRESHOLD,
        "total_before": len(unique_paths),
        "total_after": len(prioritized),
        "skipped_below_threshold": skipped,
        "score_distribution": _distribution(scored),
        "saved_to": saved_to,
    }


def _score_path(path: dict, sensitive_flows: List[dict], cx_findings: List[dict]) -> tuple[int, dict]:
    score = 0
    detail: dict = {}

    entry_file  = path.get("entry_file", path.get("file", ""))
    source_code = path.get("source", {}).get("code", "")

    # FP: test/migration file — structural signal
    for pat in TEST_FILE_PATTERNS:
        if pat.lower() in entry_file.lower():
            return -10, {"fp": f"test_file:{pat}"}

    # Base: sink severity
    sink = path.get("sink", {})
    sink_cat = path.get("sink_cat") or SINK_TYPE_TO_CAT.get(sink.get("type", ""), "CUSTOM")
    sev = SINK_SEVERITY.get(sink_cat, 1)
    score += sev
    detail["sink_severity"] = sev

    # Semgrep detection
    if path.get("tool") == "semgrep" or "semgrep" in path.get("detected_by", []):
        score += 3
        detail["semgrep_match"] = 3

    # GitNexus structural path
    if path.get("tool") == "gitnexus" or path.get("query_type") in ("structural", "object"):
        score += 2
        detail["gitnexus_structural"] = 2

    # Joern confirmed
    if path.get("path_decision") == "confirmed":
        score += 2
        detail["joern_confirmed"] = 2

    # Custom sink
    if path.get("sink", {}).get("type") == "custom_wrapper":
        score += 1
        detail["custom_sink"] = 1

    # Direct HTTP source
    if path.get("source", {}).get("type") in ("http_param", "query", "body", "header", "cookie"):
        score += 1
        detail["direct_http_source"] = 1

    # Entry point is public API
    if any(hint in entry_file.lower() for hint in ENTRY_POINT_HINTS):
        score += 2
        detail["entry_point_bonus"] = 2

    # Sensitive flow match
    entry_fn = path.get("entry_fn", source_code)
    for flow in sensitive_flows:
        flow_entry = flow.get("entry", "")
        if flow_entry and (flow_entry in entry_file or flow_entry in entry_fn):
            score += 2
            detail["sensitive_flow_match"] = 2
            break

    # CX findings boost
    if cx_findings:
        cx_boost = _cx_boost(path, cx_findings)
        if cx_boost:
            score += cx_boost
            detail["cx_boost"] = cx_boost

    # Object taint bonus
    if path.get("query_type") == "object":
        score += 1
        detail["object_bonus"] = 1

    return score, detail


def _cx_boost(path: dict, cx_findings: List[dict]) -> int:
    """Check if any CX finding overlaps with this path (file/sink match)."""
    path_file = path.get("entry_file", path.get("file", ""))
    path_sink = path.get("sink", {}).get("name", "")
    path_type = path.get("sink", {}).get("type", "")
    boost = 0
    for cx in cx_findings:
        cx_file = cx.get("file", "")
        cx_sink = cx.get("sink", cx.get("sink_name", ""))
        cx_type = cx.get("vuln_type", "")
        if cx_file and cx_file in path_file:
            boost += 2  # CX source match
        if cx_sink and cx_sink in path_sink:
            boost += 2  # CX sink match
        if cx_type and cx_type == path_type:
            boost += 1  # CX same vuln type
        if boost >= 5:
            break
    return boost


def _distribution(paths: List[dict]) -> dict:
    dist = {">=10": 0, "8-9": 0, "6-7": 0}
    for p in paths:
        s = p.get("score", 0)
        if s >= 10:
            dist[">=10"] += 1
        elif s >= 8:
            dist["8-9"] += 1
        else:
            dist["6-7"] += 1
    return dist
