"""
flow_sast_mcp/server.py
────────────────────────
MCP server — registers all flow-sast tools for Claude Code.

Tools exposed (all prefixed flow-sast__ by MCP):
  parse_context,
  semgrep_scan, api_parse, secrets_scan,
  analyze_catalog,                          ← Step 1a→1b synthesis
  gitnexus_context, gitnexus_query,
  gitnexus_plan, gitnexus_tick,             ← bridge: reads 4 sources, correct node types
  fp_filter, joern_filter, triage_score,
  classify_sink, write_findings, burp_send
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from flow_sast_mcp.tools import (
    context_parser,
    repo_intel,
    semgrep,
    api_parser,
    secrets,
    catalog_analyzer,
    gitnexus,
    gitnexus_bridge,
    fp_filter,
    joern,
    triage,
    classifier,
    burp,
)
from flow_sast_mcp.shared import findings_writer


def create_server() -> Server:
    server = Server("flow-sast")

    # ── Tool definitions ───────────────────────────────────────────────────────

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="repo_intel",
                description=(
                    "PRE-PHASE: Extract codebase intelligence before starting the audit. "
                    "Scans manifest files, configs, and code structure to detect: "
                    "framework, tech stack, auth/authz mechanism, architectural patterns, "
                    "and security-relevant notes (multi-tenancy, admin panels, webhooks, payments). "
                    "Optionally uses gitnexus to find auth symbols in the call graph. "
                    "Saves catalog/repo_intel.json and catalog/repo_intel.md. "
                    "Call this FIRST, before parse_context and before Phase 1."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo"],
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Unique run ID (YYYYMMDD_HHMMSS_<repo>)",
                        },
                        "repo": {
                            "type": "string",
                            "description": "Absolute path to the target repository",
                        },
                    },
                },
            ),
            Tool(
                name="parse_context",
                description=(
                    "Parse a free-form business context file (markdown / YAML / JSON) "
                    "and extract structured objects: custom_sinks, custom_sources, "
                    "sensitive_flows, non_http_sources, business_notes. "
                    "Saves catalog/business_ctx.json. "
                    "Call this first before any other tool when a context file is provided."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "context_file"],
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Unique run ID (YYYYMMDD_HHMMSS_<repo>)",
                        },
                        "context_file": {
                            "type": "string",
                            "description": "Absolute path to the context file",
                        },
                    },
                },
            ),
            Tool(
                name="semgrep_scan",
                description=(
                    "Run Semgrep taint analysis on a repository. "
                    "Discovers HTTP + non-HTTP sources and known sinks. "
                    "Saves catalog/sources.json and catalog/sinks.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo", "stack"],
                    "properties": {
                        "run_id": {"type": "string", "description": "Unique run ID (YYYYMMDD_HHMMSS_<repo>)"},
                        "repo": {"type": "string", "description": "Absolute path to repo"},
                        "stack": {"type": "string", "description": "Framework/stack (laravel, django, flask, express, spring, auto…)"},
                        "extra_sources": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Non-HTTP source identifiers from context parsing (e.g. QueueConsumer::getPayload)",
                        },
                    },
                },
            ),
            Tool(
                name="api_parse",
                description=(
                    "Parse API routes and parameters across all frameworks. "
                    "Saves catalog/endpoints.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo", "stack"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "repo": {"type": "string"},
                        "stack": {"type": "string"},
                    },
                },
            ),
            Tool(
                name="secrets_scan",
                description=(
                    "Run Gitleaks (with regex fallback) to detect hardcoded secrets. "
                    "Saves catalog/secrets.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "repo": {"type": "string"},
                    },
                },
            ),
            Tool(
                name="analyze_catalog",
                description=(
                    "Synthesize Phase 1a catalog outputs (semgrep, api_parse, parse_context, repo_intel) "
                    "into a structured scan strategy. "
                    "Call AFTER Phase 1a completes and BEFORE gitnexus_context (Step 1b). "
                    "Reads all catalog JSON files automatically from disk — no params needed except run_id. "
                    "Returns: gitnexus_params (pre-computed for gitnexus_context), "
                    "cypher_hints[] (ready-to-use Cypher strings for gitnexus_query), "
                    "entry_points[] and sink_targets[] scored by multi-source confirmation. "
                    "Saves catalog/scan_strategy.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id"],
                    "properties": {
                        "run_id": {"type": "string"},
                    },
                },
            ),
            Tool(
                name="gitnexus_context",
                description=(
                    "Extract structural information from a repo via GitNexus: "
                    "file tree, entry points, service layers, custom wrappers. "
                    "Saves catalog/repo_structure.json. "
                    "Call in Step 1b (after semgrep_scan + api_parse + parse_context) — "
                    "pass cross-catalog inputs so Claude can build Cypher queries combining "
                    "all source namings. Each input is returned labeled by source."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "repo": {"type": "string"},
                        "extra_topics": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Domain keywords for process-flow discovery. "
                                "Extract from business_ctx.sensitive_flows entries + repo_intel.security_notes."
                            ),
                        },
                        "api_endpoints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Endpoint path/name strings from api_parse.endpoints[] — Phase 1a result. "
                                "Returned as api_entry_points[{name, source:'api_parse'}] "
                                "for Cypher WHERE entry IN [...] queries."
                            ),
                        },
                        "semgrep_sink_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Sink function names detected by semgrep (sinks[].code split on '('). "
                                "Returned as semgrep_sink_names[{name, source:'semgrep'}] "
                                "for Cypher WHERE sink.name IN [...] queries."
                            ),
                        },
                        "ctx_api_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "API/function names from business_ctx.api_names[].name — parse_context result. "
                                "Explicitly named entry points in the context file (e.g. GetDataSet, ExecSQL). "
                                "Returned as ctx_api_names[{name, source:'context'}] for Cypher queries."
                            ),
                        },
                        "ctx_custom_sinks": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Custom sink names from business_ctx.custom_sinks[].name — parse_context result. "
                                "Returned as ctx_custom_sinks[{name, source:'context'}] for Cypher queries."
                            ),
                        },
                    },
                },
            ),
            Tool(
                name="gitnexus_query",
                description=(
                    "Execute a Cypher query against the GitNexus graph database for a repo. "
                    "Call iteratively as you discover new paths. "
                    "Each call saves catalog/gitnexus_<label>.json or connect/gitnexus_<label>.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo", "cypher", "label", "phase"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "repo": {"type": "string"},
                        "cypher": {"type": "string", "description": "Cypher query to execute"},
                        "label": {"type": "string", "description": "Short label for output file naming (e.g. sources, sinks, paths_sqli)"},
                        "phase": {"type": "string", "enum": ["catalog", "connect"], "description": "Current phase determines output subfolder"},
                    },
                },
            ),
            Tool(
                name="gitnexus_plan",
                description=(
                    "Generate a Cypher query plan by reading 4 catalog sources "
                    "(scan_strategy, repo_structure, business_ctx, endpoints). "
                    "Uses correct gitnexus node types (Function/Class/Method — not Symbol). "
                    "Saves gitnexus_progress.json with per-query called/pending status. "
                    "Claude then calls mcp__gitnexus__* directly for each query, "
                    "then calls gitnexus_tick to mark done."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id"],
                    "properties": {
                        "run_id": {"type": "string"},
                    },
                },
            ),
            Tool(
                name="gitnexus_tick",
                description=(
                    "Mark a gitnexus query label as called ✓. "
                    "Updates gitnexus_progress.json. "
                    "Call after each mcp__gitnexus__* query completes. "
                    "Returns updated summary with pending_labels list."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "label", "row_count"],
                    "properties": {
                        "run_id":    {"type": "string"},
                        "label":     {"type": "string", "description": "Query label to tick (e.g. cross_catalog, auth_symbols)"},
                        "row_count": {"type": "integer", "description": "Number of rows returned by the gitnexus query"},
                    },
                },
            ),
            Tool(
                name="fp_filter",
                description=(
                    "Pattern-based false positive filter for candidate paths. "
                    "Removes test files, trusted sources, log-only sinks, low-score paths. "
                    "Saves connect/filtered_paths.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "paths"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "paths": {"type": "array", "items": {"type": "object"}},
                    },
                },
            ),
            Tool(
                name="joern_filter",
                description=(
                    "Joern CFG-aware taint confirmation. Optional — gracefully skips if Joern unavailable. "
                    "Saves connect/cpg_confirmed.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "repo", "paths"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "repo": {"type": "string"},
                        "paths": {"type": "array", "items": {"type": "object"}},
                    },
                },
            ),
            Tool(
                name="triage_score",
                description=(
                    "Score and filter candidate paths. Paths scoring < threshold (default 6) are discarded. "
                    "Saves connect/scored_paths.json."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "paths"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "paths": {"type": "array", "items": {"type": "object"}},
                        "sensitive_flows": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Sensitive flows from context parsing ({entry, risk})",
                        },
                        "cx_findings": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "Optional Checkmarx SARIF seed findings for boost",
                        },
                    },
                },
            ),
            Tool(
                name="classify_sink",
                description=(
                    "Lookup-table classification for a sink name. "
                    "Checks business_ctx.custom_sinks first, then shared lookup table. "
                    "Does NOT call LLM — Claude Code classifies custom sinks after reading implementation."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "sink_name"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "sink_name": {"type": "string"},
                        "business_ctx": {
                            "type": "object",
                            "description": "Parsed business context (custom_sinks, sensitive_flows…)",
                        },
                    },
                },
            ),
            Tool(
                name="write_findings",
                description=(
                    "Write verified findings to JSON and MD reports. "
                    "Use file_prefix (e.g., 'technical' or 'final') for progressive saving."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "findings"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "findings": {"type": "array", "items": {"type": "object"}},
                        "file_prefix": {"type": "string", "description": "Prefix for report files, e.g. 'technical' -> 'technical_findings.md'"}
                    },
                },
            ),
            Tool(
                name="burp_send",
                description=(
                    "Send a request+payload through Burp MCP for dynamic PoC confirmation. "
                    "Saves evidence/<finding_id>.http."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["run_id", "finding_id", "request", "payload"],
                    "properties": {
                        "run_id": {"type": "string"},
                        "finding_id": {"type": "string"},
                        "request": {"type": "object", "description": "HTTP request dict (method, url, headers, body)"},
                        "payload": {"type": "string", "description": "Payload to inject"},
                    },
                },
            ),
        ]

    # ── Tool handlers ──────────────────────────────────────────────────────────

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        import json

        try:
            if name == "repo_intel":
                result = repo_intel.run(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                )
            elif name == "parse_context":
                result = context_parser.run(
                    run_id=arguments["run_id"],
                    context_file=arguments["context_file"],
                )
            elif name == "semgrep_scan":
                result = semgrep.run(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                    stack=arguments["stack"],
                    extra_sources=arguments.get("extra_sources", []),
                )
            elif name == "api_parse":
                result = api_parser.run(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                    stack=arguments["stack"],
                )
            elif name == "secrets_scan":
                result = secrets.run(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                )
            elif name == "analyze_catalog":
                result = catalog_analyzer.run(
                    run_id=arguments["run_id"],
                )
            elif name == "gitnexus_context":
                result = gitnexus.run_context(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                    extra_topics=arguments.get("extra_topics", []),
                    api_endpoints=arguments.get("api_endpoints", []),
                    semgrep_sink_names=arguments.get("semgrep_sink_names", []),
                    ctx_api_names=arguments.get("ctx_api_names", []),
                    ctx_custom_sinks=arguments.get("ctx_custom_sinks", []),
                )
            elif name == "gitnexus_query":
                result = gitnexus.run_query(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                    cypher=arguments["cypher"],
                    label=arguments["label"],
                    phase=arguments["phase"],
                )
            elif name == "gitnexus_plan":
                result = gitnexus_bridge.build_query_plan(
                    run_id=arguments["run_id"],
                )
            elif name == "gitnexus_tick":
                result = gitnexus_bridge.tick(
                    run_id=arguments["run_id"],
                    label=arguments["label"],
                    row_count=arguments["row_count"],
                )
            elif name == "fp_filter":
                result = fp_filter.run(
                    run_id=arguments["run_id"],
                    paths=arguments["paths"],
                )
            elif name == "joern_filter":
                result = joern.run(
                    run_id=arguments["run_id"],
                    repo=arguments["repo"],
                    paths=arguments["paths"],
                )
            elif name == "triage_score":
                result = triage.run(
                    run_id=arguments["run_id"],
                    paths=arguments["paths"],
                    sensitive_flows=arguments.get("sensitive_flows", []),
                    cx_findings=arguments.get("cx_findings", []),
                )
            elif name == "classify_sink":
                result = classifier.run(
                    run_id=arguments["run_id"],
                    sink_name=arguments["sink_name"],
                    business_ctx=arguments.get("business_ctx", {}),
                )
            elif name == "write_findings":
                result = findings_writer.run(
                    run_id=arguments["run_id"],
                    findings=arguments["findings"],
                    file_prefix=arguments.get("file_prefix", "findings")
                )
            elif name == "burp_send":
                result = burp.run(
                    run_id=arguments["run_id"],
                    finding_id=arguments["finding_id"],
                    request=arguments["request"],
                    payload=arguments["payload"],
                )
            else:
                result = {"error": f"Unknown tool: {name}"}

        except Exception as exc:
            result = {"error": str(exc), "tool": name}

        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    return server


# Allow direct run for testing
if __name__ == "__main__":
    import asyncio

    async def _run():
        server = create_server()
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())

    asyncio.run(_run())
