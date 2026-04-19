"""
shared/tool_logger.py
──────────────────────
Centralized logging for all MCP tool calls.

Each tool call is logged as one JSON line (JSONL) to:
  logs/<run_id>.jsonl          ← per-run call log
  logs/_sessions.jsonl         ← global session index

Log entry schema:
  {
    "ts":          "ISO-8601",
    "run_id":      "20260417_120000_myapp",
    "tool":        "semgrep_scan",
    "args_summary": {...},      # safe subset of args (no file content)
    "status":      "ok"|"error",
    "duration_ms": 1234,
    "result_summary": {...}     # key counts / saved paths, not full payload
  }

Purpose:
  - Track which tools are called in each audit session
  - Measure tool performance (duration)
  - Identify failing tools for debugging
  - Analyse usage patterns to improve the pipeline

Usage:
  from flow_sast_mcp.shared.tool_logger import log_call

  with log_call(run_id, "semgrep_scan", args) as ctx:
      result = semgrep.run(...)
      ctx.set_result(result)
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

LOGS_DIR = os.environ.get("FLOW_SAST_LOGS_DIR", "./logs")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _logs_dir() -> Path:
    p = Path(LOGS_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _append_jsonl(path: Path, record: dict) -> None:
    """Append one JSON record (one line) to a JSONL file, thread-safe enough for MCP."""
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass  # logging must never crash the tool


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


# ── Args summarizer — strips large blobs, keeps what's useful for tracking ──────

_SENSITIVE_KEYS = {"payload", "password", "secret", "token", "key", "api_key"}
_MAX_STR_LEN = 200


def _summarize_args(args: dict) -> dict:
    """Return a safe, compact summary of tool arguments."""
    summary: dict = {}
    for k, v in args.items():
        k_low = k.lower()
        if any(s in k_low for s in _SENSITIVE_KEYS):
            summary[k] = "***REDACTED***"
        elif k == "cypher":
            # Keep first 120 chars of Cypher — useful for analysis
            summary[k] = str(v)[:120] + ("..." if len(str(v)) > 120 else "")
        elif isinstance(v, str) and len(v) > _MAX_STR_LEN:
            summary[k] = v[:_MAX_STR_LEN] + "..."
        elif isinstance(v, list):
            summary[k] = f"[{len(v)} items]"
        elif isinstance(v, dict):
            summary[k] = f"{{dict, {len(v)} keys}}"
        else:
            summary[k] = v
    return summary


def _summarize_result(result: Any, tool: str) -> dict:
    """Extract a compact result summary for logging — not the full payload."""
    if not isinstance(result, dict):
        return {"type": type(result).__name__}

    summary: dict = {}

    # Error passthrough
    if "error" in result:
        summary["error"] = str(result["error"])[:300]
        return summary

    # Common fields across tools
    for key in ("saved_to", "saved_json", "saved_md", "count", "total"):
        if key in result:
            summary[key] = result[key]

    # Tool-specific summaries
    if tool == "semgrep_scan":
        summary["sources"] = len(result.get("sources", []))
        summary["sinks"]   = len(result.get("sinks", []))

    elif tool == "api_parse":
        summary["endpoints"] = len(result.get("endpoints", []))

    elif tool == "secrets_scan":
        findings = result.get("findings", [])
        summary["secrets_found"] = len(findings)
        # Show types but not values
        summary["types"] = list({f.get("type", "?") for f in findings[:20]})

    elif tool == "gitnexus_context":
        summary["entry_points"] = len(result.get("entry_points", []))
        summary["custom_sinks"] = len(result.get("custom_sinks", []))
        summary["file_tree_len"] = len(result.get("file_tree", ""))

    elif tool == "gitnexus_query":
        summary["paths"] = len(result.get("paths", []))
        summary["nodes"] = len(result.get("nodes", []))

    elif tool == "fp_filter":
        summary["kept"]    = len(result.get("kept", []))
        summary["removed"] = len(result.get("removed", []))

    elif tool == "joern_filter":
        summary["confirmed"]   = result.get("confirmed_count", 0)
        summary["full_verify"] = result.get("full_verify_count", 0)
        summary["skipped"]     = result.get("skipped_count", 0)

    elif tool == "triage_score":
        paths = result.get("scored", [])
        summary["total_paths"] = len(paths)
        summary["high_score"]  = max((p.get("score", 0) for p in paths), default=0)

    elif tool == "repo_intel":
        fw = result.get("framework_detection", {})
        auth = result.get("auth_detection", {})
        summary["frameworks"]  = fw.get("frameworks", [])
        summary["mechanisms"]  = auth.get("mechanisms", [])
        summary["annotations"] = len(auth.get("annotations", []))
        summary["security_notes"] = len(result.get("security_notes", []))

    elif tool == "write_findings":
        summary["findings_written"] = len(result.get("findings", []))

    elif tool == "burp_send":
        summary["status_code"] = result.get("status_code")
        summary["evidence"]    = result.get("saved_to")

    return summary


# ── Context manager for wrapping tool calls ────────────────────────────────────

class _CallContext:
    def __init__(self, run_id: str, tool: str, args: dict) -> None:
        self.run_id  = run_id
        self.tool    = tool
        self.args    = args
        self._result: Any = None
        self._status = "ok"
        self._start  = time.monotonic()
        self._ts     = _now_iso()

    def set_result(self, result: Any) -> None:
        self._result = result
        if isinstance(result, dict) and "error" in result:
            self._status = "error"

    def set_error(self, exc: Exception) -> None:
        self._result = {"error": str(exc)}
        self._status = "error"

    def _flush(self) -> None:
        duration_ms = int((time.monotonic() - self._start) * 1000)
        record = {
            "ts":             self._ts,
            "run_id":         self.run_id,
            "tool":           self.tool,
            "args_summary":   _summarize_args(self.args),
            "status":         self._status,
            "duration_ms":    duration_ms,
            "result_summary": _summarize_result(self._result, self.tool),
        }

        logs = _logs_dir()

        # Per-run log
        run_log = logs / f"{self.run_id}.jsonl"
        _append_jsonl(run_log, record)

        # Global session index (one line per call, all runs mixed)
        _append_jsonl(logs / "_all_calls.jsonl", record)

        # Sessions index: only on first call per run
        session_index = logs / "_sessions.jsonl"
        # Mark first call as session start
        if not run_log.exists() or run_log.stat().st_size == len(
            json.dumps(record, ensure_ascii=False, default=str) + "\n"
        ):
            session_record = {
                "run_id":    self.run_id,
                "started_at": self._ts,
                "first_tool": self.tool,
                "repo":      self.args.get("repo", ""),
            }
            _append_jsonl(session_index, session_record)


@contextmanager
def log_call(run_id: str, tool: str, args: dict) -> Generator[_CallContext, None, None]:
    """
    Context manager that logs a tool call to the logs directory.

    Usage:
        with log_call(run_id, "semgrep_scan", arguments) as ctx:
            result = semgrep.run(...)
            ctx.set_result(result)
    """
    ctx = _CallContext(run_id, tool, args)
    try:
        yield ctx
    except Exception as exc:
        ctx.set_error(exc)
        ctx._flush()
        raise
    else:
        ctx._flush()


# ── Standalone summary reader (for debugging / future dashboard) ───────────────

def read_run_log(run_id: str) -> list[dict]:
    """Read all log entries for a given run_id."""
    log_file = _logs_dir() / f"{run_id}.jsonl"
    if not log_file.exists():
        return []
    entries = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def list_runs() -> list[dict]:
    """Read the sessions index — list of all run_ids ever logged."""
    idx = _logs_dir() / "_sessions.jsonl"
    if not idx.exists():
        return []
    runs = []
    for line in idx.read_text(encoding="utf-8").splitlines():
        try:
            runs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return runs
