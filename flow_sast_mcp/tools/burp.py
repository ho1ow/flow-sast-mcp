"""
tools/burp.py
──────────────
MCP tool: burp_send

Input:  run_id, finding_id, request{}, payload
Output: { response, confirmed, evidence, saved_to }
Saves:  evidence/<finding_id>.http

Wraps burp-mcp-server (c0tton-fluff) via BURP_MCP_BASE_URL.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import httpx

from flow_sast_mcp.shared.persistence import ensure_run_dirs, write

BURP_BASE_URL = os.environ.get("BURP_MCP_BASE_URL", "http://localhost:1337")
REPORTS_DIR   = os.environ.get("REPORTS_DIR", "./reports")


def run(run_id: str, finding_id: str, request: dict, payload: str) -> dict:
    """Send HTTP request+payload via Burp MCP and save evidence."""
    ensure_run_dirs(run_id)

    # Inject payload into request body / query
    modified_request = _inject_payload(request, payload)

    response_data: Optional[dict] = None
    confirmed = False
    error_msg = None

    try:
        response_data = _send_via_burp(modified_request)
        # Simple confirmation: check response body for payload reflection or error patterns
        body = response_data.get("body", "")
        if payload in body:
            confirmed = True
        elif "error" in body.lower() and "sql" in body.lower():
            confirmed = True  # SQLi error indication
    except Exception as exc:
        error_msg = str(exc)

    # Format as .http evidence
    http_evidence = _format_http_evidence(modified_request, response_data, payload, confirmed)

    # Save to evidence/<finding_id>.http
    evidence_dir = Path(REPORTS_DIR) / run_id / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{finding_id}.http"
    evidence_path.write_text(http_evidence, encoding="utf-8")

    result = {
        "confirmed": confirmed,
        "finding_id": finding_id,
        "evidence": http_evidence[:500],
        "saved_to": str(evidence_path),
    }
    if response_data:
        result["response_status"] = response_data.get("status_code")
        result["response_length"] = len(response_data.get("body", ""))
    if error_msg:
        result["error"] = error_msg

    return result


def _inject_payload(request: dict, payload: str) -> dict:
    """Inject payload into request (body or first query param)."""
    modified = dict(request)

    body = modified.get("body", "")
    if body:
        # Try to inject into JSON body
        try:
            parsed_body = json.loads(body)
            # Inject into first value
            for key in parsed_body:
                parsed_body[key] = payload
                break
            modified["body"] = json.dumps(parsed_body)
            return modified
        except (json.JSONDecodeError, TypeError):
            # Form-encoded or plain — append payload
            modified["body"] = body + "&payload=" + payload
            return modified

    url = modified.get("url", "")
    if url:
        sep = "&" if "?" in url else "?"
        modified["url"] = f"{url}{sep}payload={payload}"

    return modified


def _send_via_burp(request: dict) -> dict:
    """Forward request through Burp MCP server."""
    payload_data = {
        "method": request.get("method", "GET"),
        "url": request.get("url", ""),
        "headers": request.get("headers", {}),
        "body": request.get("body", ""),
    }

    resp = httpx.post(
        f"{BURP_BASE_URL}/proxy/send",
        json=payload_data,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _format_http_evidence(request: dict, response: Optional[dict], payload: str, confirmed: bool) -> str:
    lines = [
        f"### Evidence for finding",
        f"### Payload: {payload}",
        f"### Confirmed: {confirmed}",
        "",
        "=== REQUEST ===",
        f"{request.get('method', 'GET')} {request.get('url', '')} HTTP/1.1",
    ]
    for h, v in (request.get("headers") or {}).items():
        lines.append(f"{h}: {v}")
    if request.get("body"):
        lines.extend(["", request["body"]])

    if response:
        lines.extend([
            "",
            "=== RESPONSE ===",
            f"HTTP/1.1 {response.get('status_code', '???')}",
        ])
        for h, v in (response.get("headers") or {}).items():
            lines.append(f"{h}: {v}")
        if response.get("body"):
            lines.extend(["", response["body"][:2000]])

    return "\n".join(lines)
