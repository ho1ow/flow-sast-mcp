"""
shared/findings_writer.py
──────────────────────────
MCP tool: write_findings

Input:  run_id, findings[]
Output: { saved_to_json, saved_to_md, finding_count }
Saves:  findings/findings.json + findings/findings.md
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs, REPORTS_DIR

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "🔵",
}


def run(run_id: str, findings: List[dict], file_prefix: str = "findings") -> dict:
    """Write verified findings to findings/{file_prefix}.json and findings/{file_prefix}.md."""
    ensure_run_dirs(run_id)

    # Save JSON via persistence helper
    saved_json = write(run_id, "findings", f"{file_prefix}.json", findings)

    # Save Markdown — persistence.write() is JSON-only, so write text directly
    md_content = _generate_markdown(run_id, findings, file_prefix)
    md_path = Path(REPORTS_DIR) / run_id / "findings" / f"{file_prefix}.md"
    md_path.write_text(md_content, encoding="utf-8")

    return {
        "finding_count": len(findings),
        "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high_count": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium_count": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "saved_to_json": saved_json,
        "saved_to_md": str(md_path),
    }


def _generate_markdown(run_id: str, findings: List[dict], file_prefix: str = "findings") -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title_prefix = file_prefix.replace("_", " ").title() if file_prefix != "findings" else "Audit"
    
    lines = [
        f"# flow-sast Security {title_prefix} Findings",
        f"",
        f"**Run ID:** `{run_id}`  ",
        f"**Generated:** {ts}  ",
        f"**Total findings:** {len(findings)}",
        f"",
        "---",
        "",
    ]

    # Summary table
    lines += [
        "## Summary",
        "",
        "| # | Severity | Type | File | Line | Status |",
        "|---|----------|------|------|------|--------|",
    ]
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "MEDIUM")
        emoji = SEVERITY_EMOJI.get(sev, "")
        vuln_type = f.get("vuln_type", "unknown")
        file_path = f.get("file", f.get("entry_file", ""))
        line = f.get("line_start", f.get("line", "?"))
        status = f.get("status", "CONFIRMED")
        lines.append(f"| {i} | {emoji} {sev} | {vuln_type} | `{file_path}` | {line} | {status} |")

    lines += ["", "---", ""]

    # Detailed findings
    lines.append("## Detailed Findings")
    lines.append("")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "MEDIUM")
        emoji = SEVERITY_EMOJI.get(sev, "")
        vuln_type = f.get("vuln_type", "unknown")
        title = f.get("title", f"{emoji} {vuln_type.upper()}")
        file_path = f.get("file", f.get("entry_file", ""))
        line = f.get("line_start", f.get("line", "?"))

        lines += [
            f"### Finding {i}: {title}",
            "",
            f"**Severity:** {emoji} {sev}  ",
            f"**Type:** `{vuln_type}`  ",
            f"**File:** `{file_path}:{line}`  ",
            f"**Confidence:** {f.get('confidence', 'HIGH')}  ",
            f"**CWE:** {f.get('cwe', 'N/A')}  ",
            f"**OWASP:** {f.get('owasp', 'N/A')}  ",
            "",
        ]

        if f.get("code_snippet"):
            lines += [
                "**Code snippet:**",
                "```",
                f.get("code_snippet", ""),
                "```",
                "",
            ]

        if f.get("taint_trace"):
            lines += ["**Taint trace:**", "```", f["taint_trace"], "```", ""]

        if f.get("attack_vector"):
            lines += [f"**Attack vector:** {f['attack_vector']}", ""]

        if f.get("poc"):
            lines += ["**PoC:**", "```", f["poc"], "```", ""]

        if f.get("remediation"):
            lines += [f"**Remediation:** {f['remediation']}", ""]

        if f.get("cvss"):
            lines += [f"**CVSS:** {f['cvss']}", ""]

        lines += ["---", ""]

    return "\n".join(lines)
