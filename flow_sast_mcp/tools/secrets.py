"""
tools/secrets.py
─────────────────
MCP tool: secrets_scan

Input:  run_id, repo
Output: { secrets[], saved_to }
Saves:  catalog/secrets.json

Gitleaks primary, regex fallback.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

CWE_MAP = {
    "generic-api-key":        ("CWE-798", "A07:2021"),
    "aws-access-token":       ("CWE-798", "A07:2021"),
    "aws-secret-access-key":  ("CWE-798", "A07:2021"),
    "github-pat":             ("CWE-798", "A07:2021"),
    "github-fine-grained":    ("CWE-798", "A07:2021"),
    "private-key":            ("CWE-321", "A02:2021"),
    "jwt":                    ("CWE-321", "A02:2021"),
    "stripe-access-token":    ("CWE-798", "A07:2021"),
    "stripe-publishable-key": ("CWE-798", "A07:2021"),
    "slack-access-token":     ("CWE-798", "A07:2021"),
    "sendgrid-api-token":     ("CWE-798", "A07:2021"),
    "twilio-api-key":         ("CWE-798", "A07:2021"),
    "generic-credential":     ("CWE-259", "A07:2021"),
    "password-in-url":        ("CWE-312", "A02:2021"),
}

SEVERITY_MAP = {
    "CRITICAL": ["private-key", "aws-secret-access-key", "stripe-access-token", "github-pat"],
    "HIGH":     ["aws-access-token", "generic-api-key", "jwt", "github-fine-grained",
                 "sendgrid-api-token", "twilio-api-key", "generic-credential"],
}

REGEX_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                                        "aws-access-token",    "CRITICAL"),
    (re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),      "private-key",         "CRITICAL"),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                                "stripe-access-token", "CRITICAL"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'),                                     "github-pat",          "CRITICAL"),
    (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'), "slack-access-token",  "HIGH"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'"][^"\']{6,}["\']'), "generic-credential", "HIGH"),
    (re.compile(r'(?i)(?:api_?key|auth_?token|secret_?key)\s*[=:]\s*["\'"][^"\']{8,}["\']'), "generic-api-key", "HIGH"),
    (re.compile(r'(?i)(?:postgres|mysql|mongodb)://[^:]+:[^@]+@'),           "password-in-url",     "HIGH"),
]
SKIP_DIRS  = {".git", "node_modules", "__pycache__", "vendor", "dist", "build", "test", "tests"}
SKIP_EXTS  = {".pyc", ".pyo", ".class", ".png", ".jpg", ".gif", ".svg", ".woff", ".pdf", ".lock"}
FP_FILTER  = re.compile(
    r'(?i)(example|placeholder|changeme|your.key|xxx|test|fake|env\[|os\.environ|os\.getenv|config\.|process\.env)'
)


def run(run_id: str, repo: str) -> dict:
    """Run Gitleaks (with regex fallback) to detect hardcoded secrets."""
    ensure_run_dirs(run_id)

    findings: List[dict] = []
    gitleaks_results = _run_gitleaks(repo)
    if gitleaks_results is not None:
        findings.extend(_map_gitleaks(gitleaks_results))
    else:
        findings.extend(_regex_fallback(repo))

    saved_to = write(run_id, "catalog", "secrets.json", findings)
    return {
        "secrets": findings,
        "secret_count": len(findings),
        "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high_count": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "saved_to": saved_to,
    }


def _run_gitleaks(repo_path: str):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        report_path = tmp.name
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", repo_path,
             "--report-format", "json", "--report-path", report_path,
             "--no-git", "--exit-code", "0"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            return None
        raw = Path(report_path).read_text(encoding="utf-8", errors="ignore")
        if not raw.strip():
            return []
        return json.loads(raw)
    except FileNotFoundError:
        return None
    except Exception:
        return None
    finally:
        Path(report_path).unlink(missing_ok=True)


def _map_gitleaks(raw_findings: list) -> List[dict]:
    findings = []
    for r in raw_findings:
        rule_id = r.get("RuleID", "generic-api-key")
        cwe, owasp = CWE_MAP.get(rule_id, ("CWE-798", "A07:2021"))
        severity = _get_severity(rule_id)
        finding_id = hashlib.md5(
            f"{r.get('File', '')}:{r.get('StartLine', 0)}:{rule_id}".encode()
        ).hexdigest()[:12]
        findings.append({
            "id": finding_id,
            "category": "hardcode",
            "vuln_type": "hardcoded_secret",
            "title": f"Hardcoded Secret: {rule_id.replace('-', ' ').title()}",
            "severity": severity,
            "confidence": "HIGH",
            "file": r.get("File", ""),
            "line_start": r.get("StartLine", 0),
            "line_end": r.get("EndLine", r.get("StartLine", 0)),
            "code_snippet": _redact(r.get("Match", "")),
            "rule_id": rule_id,
            "cwe": cwe,
            "owasp": owasp,
            "remediation": "Move to environment variable or secrets manager",
            "detected_by": ["gitleaks"],
        })
    return findings


def _regex_fallback(repo_path: str) -> List[dict]:
    findings = []
    seen: set[str] = set()
    repo = Path(repo_path)
    for f in repo.rglob("*"):
        if not f.is_file() or f.suffix in SKIP_EXTS:
            continue
        if any(d in f.parts for d in SKIP_DIRS):
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        rel = str(f.relative_to(repo))
        for lineno, line in enumerate(lines, 1):
            if FP_FILTER.search(line):
                continue
            for pattern, rule_id, severity in REGEX_PATTERNS:
                if pattern.search(line):
                    uid = hashlib.md5(f"{rel}:{lineno}:{rule_id}".encode()).hexdigest()[:12]
                    if uid in seen:
                        continue
                    seen.add(uid)
                    cwe, owasp = CWE_MAP.get(rule_id, ("CWE-798", "A07:2021"))
                    findings.append({
                        "id": uid,
                        "category": "hardcode",
                        "vuln_type": "hardcoded_secret",
                        "title": f"Potential Secret: {rule_id.replace('-', ' ').title()}",
                        "severity": severity,
                        "confidence": "MED",
                        "file": rel,
                        "line_start": lineno,
                        "line_end": lineno,
                        "code_snippet": _redact(line.strip()),
                        "cwe": cwe,
                        "owasp": owasp,
                        "remediation": "Move to environment variable or secrets manager",
                        "detected_by": ["regex_fallback"],
                    })
    return findings


def _get_severity(rule_id: str) -> str:
    for sev, rules in SEVERITY_MAP.items():
        if rule_id in rules:
            return sev
    return "HIGH"


def _redact(text: str) -> str:
    return re.sub(
        r'(["\']?)([A-Za-z0-9+/\-_]{8,})(["\']?)',
        lambda m: f"{m.group(1)}[REDACTED]{m.group(3)}", text, count=1
    )
