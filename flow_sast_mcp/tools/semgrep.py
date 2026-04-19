"""
tools/semgrep.py
─────────────────
MCP tool: semgrep_scan

Input:  run_id, repo, stack, extra_sources[]
Output: { sources[], sinks[], saved_to, errors }
Saves:  catalog/sources.json, catalog/sinks.json
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import List

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

# ── Built-in Semgrep rulesets ─────────────────────────────────────────────────
BUILTIN_CONFIGS = [
    "auto",
    "p/security-audit",
    "p/owasp-top-ten",
]

# ── Sink rule ID prefixes → vuln type mapping ─────────────────────────────────
SINK_RULE_PREFIXES = {
    "sqli":           ["sql-injection", "sqli", "raw-query", "execute-string"],
    "rce":            ["exec-", "command-injection", "os-command", "rce", "code-injection"],
    "xss":            ["xss", "innerhtml", "dangerouslysetinnerhtml", "dom-based"],
    "ssrf":           ["ssrf", "server-side-request-forgery", "unvalidated-url"],
    "path_traversal": ["path-traversal", "directory-traversal", "file-inclusion"],
    "redirect":       ["open-redirect", "redirect-", "unvalidated-redirect"],
    "deser":          ["deserialization", "pickle", "yaml.load", "marshal"],
    "xxe":            ["xxe", "xml-external-entity", "xml-injection"],
    "ssti":           ["ssti", "template-injection", "server-side-template"],
    "header_inject":  ["header-injection", "crlf-injection"],
}

SINK_SEVERITY = {
    "sqli": "CRITICAL", "rce": "CRITICAL", "deser": "CRITICAL", "xxe": "HIGH",
    "ssrf": "HIGH", "ssti": "HIGH", "path_traversal": "HIGH",
    "xss": "MEDIUM", "redirect": "MEDIUM", "header_inject": "MEDIUM",
}

# ── Source keywords for classification ────────────────────────────────────────
SOURCE_KEYWORDS = [
    "user-input", "taint-source", "user-controlled",
    "request.get", "request.post", "req.query", "req.body",
    "getparameter", "getheader", "requestparam", "pathvariable",
]


def run(run_id: str, repo: str, stack: str, extra_sources: List[str] = None) -> dict:
    """Run semgrep and return discovered sources and sinks."""
    if extra_sources is None:
        extra_sources = []

    ensure_run_dirs(run_id)
    audit_dir = f"reports/{run_id}"

    # Build command
    cmd = ["semgrep", "--json", "--no-git-ignore"]
    for c in BUILTIN_CONFIGS:
        cmd += ["--config", c]

    # Custom rules dir alongside this project
    custom_rules_path = Path(__file__).parent.parent.parent / "rules"
    if custom_rules_path.exists() and any(custom_rules_path.glob("*.yaml")):
        cmd += ["--config", str(custom_rules_path)]

    # Generate extra_sources rule if provided
    if extra_sources:
        patterns_yaml = _build_extra_sources_rule(extra_sources, run_id)
        if patterns_yaml:
            cmd += ["--config", patterns_yaml]

    cmd += [
        "--timeout", "300",
        "--max-memory", "2048",
        "-j", "4",
        repo,
    ]

    sources: List[dict] = []
    sinks: List[dict] = []
    error_msg = None

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
        raw: dict = {}
        if result.stdout:
            try:
                raw = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass

        semgrep_results = raw.get("results", [])

        for r in semgrep_results:
            rule_id: str = r.get("check_id", "")
            path: str = r.get("path", "")
            start: dict = r.get("start", {})
            line: int = start.get("line", 0)
            code: str = r.get("extra", {}).get("lines", "").strip()
            message: str = r.get("extra", {}).get("message", "")
            severity: str = r.get("extra", {}).get("severity", "WARNING").upper()
            rule_lower = rule_id.lower()

            uid = _uid(rule_id, path, line)
            base = {
                "id": uid,
                "framework": stack,
                "pattern": rule_id,
                "raw_rule_id": rule_id,   # always preserved — Claude reads this
                "file": path,
                "line": line,
                "code": code,
                "message": message,
                "tool": "semgrep",
            }
            if _is_source_rule(rule_lower):
                sources.append({
                    **base,
                    "type": _infer_source_type(rule_lower, code, stack),
                })
            else:
                sink_type = _infer_sink_type(rule_lower)
                if sink_type:
                    sinks.append({
                        **base,
                        "type": sink_type,
                        "severity": SINK_SEVERITY.get(sink_type, "MEDIUM"),
                    })
                else:
                    # Rule ID doesn't match known prefixes — still surface to Claude.
                    # type="semgrep_review" signals Claude to read rule_id + message
                    # and classify manually. Never silently drop Semgrep findings.
                    sinks.append({
                        **base,
                        "type": "semgrep_review",
                        "severity": severity,
                        "note": "Unclassified by prefix matching — Claude to classify via raw_rule_id",
                    })

    except FileNotFoundError:
        error_msg = "semgrep binary not found — install semgrep first"
    except subprocess.TimeoutExpired:
        error_msg = "semgrep scan timed out after 360s"
    except Exception as exc:
        error_msg = str(exc)

    # Save output
    saved_to = f"reports/{run_id}/catalog/"
    write(run_id, "catalog", "sources.json", sources)
    write(run_id, "catalog", "sinks.json", sinks)

    review_sinks = [s for s in sinks if s.get("type") == "semgrep_review"]
    result_dict = {
        "sources": sources,
        "sinks": sinks,
        "source_count": len(sources),
        "sink_count": len(sinks),
        "review_count": len(review_sinks),
        "saved_to": saved_to,
    }
    if error_msg:
        result_dict["error"] = error_msg

    return result_dict


def _build_extra_sources_rule(extra_sources: List[str], run_id: str) -> str | None:
    """Write a temporary Semgrep rule for non-HTTP extra sources and return path."""
    patterns = []
    for src in extra_sources:
        pattern_str = src.replace("::", ".*").replace("...", ".*")
        patterns.append(f"          - pattern-regex: '{pattern_str}'")

    if not patterns:
        return None

    rule_content = f"""rules:
  - id: custom-non-http-source
    message: "Discovered non-HTTP source from business context"
    severity: WARNING
    languages: [python, javascript, typescript, java, go, php, ruby, csharp]
    pattern-either:
{chr(10).join(patterns)}
"""
    path = f"reports/{run_id}/custom_sources.yaml"
    os.makedirs(f"reports/{run_id}", exist_ok=True)
    Path(path).write_text(rule_content, encoding="utf-8")
    return path


def _is_source_rule(rule_lower: str) -> bool:
    return any(kw in rule_lower for kw in SOURCE_KEYWORDS)


def _infer_source_type(rule_lower: str, code: str, stack: str) -> str:
    code_lower = code.lower()
    if any(k in code_lower for k in ["cookie", "getcookie", "cookievalue"]):
        return "cookie"
    if any(k in code_lower for k in ["header", "getheader", "meta['http_"]):
        return "header"
    if any(k in code_lower for k in ["file", "upload", "binary", "multipart"]):
        return "file_upload"
    if any(k in code_lower for k in ["queue", "kafka", "rabbitmq", "sqs", "consumer", "celery"]):
        return "queue"
    if any(k in code_lower for k in ["fetchall", "fetchone", "findbyid", "findone"]):
        return "db_read"
    if any(k in code_lower for k in ["websocket", "ws.on(", "onmessage"]):
        return "websocket"
    return "http_param"


def _infer_sink_type(rule_lower: str) -> str | None:
    for sink_type, prefixes in SINK_RULE_PREFIXES.items():
        if any(p in rule_lower for p in prefixes):
            return sink_type
    return None


def _uid(*parts) -> str:
    return hashlib.md5(":".join(str(p) for p in parts).encode()).hexdigest()[:12]
