"""
tools/classifier.py
────────────────────
MCP tool: classify_sink

Lookup-table only — NO LLM calls.
Checks business_ctx.custom_sinks first, then shared KNOWN_SINK_MAPPING.
Custom sinks are classified by Claude Code after reading implementation (Phase 3 Verify).

Input:  run_id, sink_name, business_ctx{}
Output: { vuln_type, confidence, source }
"""

from __future__ import annotations

from flow_sast_mcp.shared.sink_catalog import KNOWN_SINK_MAPPING


def run(run_id: str, sink_name: str, business_ctx: dict = None) -> dict:
    """Lookup-table classification for a sink name."""
    if business_ctx is None:
        business_ctx = {}

    # 1. Business context custom sinks — HIGH confidence wins immediately
    for ks in business_ctx.get("custom_sinks", []):
        if not ks.get("name"):
            continue
        if ks["name"].lower() in sink_name.lower():
            if ks.get("confidence", "").upper() == "HIGH" and ks.get("vuln_type"):
                return {
                    "vuln_type": ks["vuln_type"],
                    "confidence": "HIGH",
                    "source": "business_context",
                }

    # 2. Global lookup table — name-based match only, not implementation-verified
    for known_sink, v_type in KNOWN_SINK_MAPPING.items():
        if known_sink.lower() in sink_name.lower():
            return {
                "vuln_type": v_type,
                "confidence": "MEDIUM",
                "source": "lookup_table",
                "note": "Name-based match — verify implementation confirms this vuln type",
            }

    # 3. Not found — Claude Code classifies after reading implementation
    return {
        "vuln_type": "unknown",
        "confidence": "UNKNOWN",
        "source": "not_found",
        "hint": "Read sink implementation via filesystem and classify vuln_type manually",
    }
