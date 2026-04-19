"""
flow_sast_mcp/tools/context_parser.py
──────────────────────────────────────
Parse a free-form context file (markdown / YAML / JSON) and extract structured
business context. Saves catalog/business_ctx.json.

Supported formats:
  1. YAML document (pure .yaml or .yml)
  2. YAML fenced block inside markdown  (```yaml … ```)
  3. JSON document
  4. Free-form markdown with ## sections:
       ## Custom Sinks
       ## Custom Sources
       ## Sensitive Flows
       ## Business Notes
       ## API Names        ← NEW
       ## Function Params  ← NEW

Output schema (business_ctx.json):
  {
    "custom_sinks": [
        {"name": str, "class": str, "vuln_type": str,
         "confidence": "HIGH", "note": str}
    ],
    "custom_sources": [
        {"name": str, "class": str, "source_type": str, "note": str}
    ],
    "sensitive_flows": [
        {"entry": str, "risk": str, "description": str}
    ],
    "non_http_sources": ["ClassName::methodName", ...],
    "api_names": [
        {"name": str, "path": str, "method": str, "params": [str], "note": str}
    ],
    "function_params": [
        {"function": str, "param": str, "taint_reason": str}
    ],
    "business_notes": str
  }

api_names  → gitnexus_context(ctx_api_names)   → Cypher WHERE sink.name IN [...]
function_params → gitnexus_context hint: which params are tainted entry points
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs


# ── Public entry point ────────────────────────────────────────────────────────

def run(run_id: str, context_file: str) -> dict[str, Any]:
    """
    Parse *context_file* and save structured output to catalog/business_ctx.json.

    Returns:
        {
          "saved": "<path>",
          "summary": { counts per field },
          "business_ctx": { … full parsed object … }
        }
    """
    ensure_run_dirs(run_id)

    path = Path(context_file)
    if not path.exists():
        return {"error": f"Context file not found: {context_file}"}

    raw = path.read_text(encoding="utf-8")
    ctx = _parse(raw)

    saved_path = write(run_id, "catalog", "business_ctx.json", ctx)

    return {
        "saved": saved_path,
        "summary": {
            "custom_sinks": len(ctx["custom_sinks"]),
            "custom_sources": len(ctx["custom_sources"]),
            "sensitive_flows": len(ctx["sensitive_flows"]),
            "non_http_sources": len(ctx["non_http_sources"]),
            "api_names": len(ctx["api_names"]),
            "function_params": len(ctx["function_params"]),
            "has_business_notes": bool(ctx["business_notes"]),
        },
        "business_ctx": ctx,
    }


# ── Parsing strategies ────────────────────────────────────────────────────────

def _empty_ctx() -> dict[str, Any]:
    return {
        "custom_sinks": [],
        "custom_sources": [],
        "sensitive_flows": [],
        "non_http_sources": [],
        "api_names": [],
        "function_params": [],
        "business_notes": "",
        # raw_text preserves the full original file so Phase 4 Analyze can
        # re-read nuance that didn't fit into the structured fields.
        # Downstream tools that only accept structured fields ignore this key.
        "raw_text": "",
    }


def _parse(raw: str) -> dict[str, Any]:
    """Try parsing strategies in priority order."""

    # 1. JSON
    ctx = _try_json(raw)
    if ctx:
        result = _normalize(ctx)
        result["raw_text"] = raw
        return result

    # 2. YAML fenced block inside markdown
    yaml_blocks = re.findall(r"```(?:yaml|yml)\n(.*?)```", raw, re.DOTALL)
    for block in yaml_blocks:
        ctx = _try_yaml(block)
        if ctx and _looks_like_business_ctx(ctx):
            result = _normalize(ctx)
            result["raw_text"] = raw
            return result

    # 3. Pure YAML document
    ctx = _try_yaml(raw)
    if ctx and _looks_like_business_ctx(ctx):
        result = _normalize(ctx)
        result["raw_text"] = raw
        return result

    # 4. Free-form markdown (primary format for human-written context files)
    result = _parse_markdown(raw)
    result["raw_text"] = raw
    return result


# ── Strategy implementations ──────────────────────────────────────────────────

def _try_json(raw: str) -> dict | None:
    raw = raw.strip()
    if not raw.startswith("{"):
        return None
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _try_yaml(raw: str) -> dict | None:
    try:
        import yaml  # PyYAML is optional
        data = yaml.safe_load(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _looks_like_business_ctx(data: dict) -> bool:
    known_keys = {"custom_sinks", "custom_sources", "sensitive_flows",
                  "non_http_sources", "business_notes"}
    return bool(known_keys & data.keys())


# ── Markdown parser ───────────────────────────────────────────────────────────

def _parse_markdown(raw: str) -> dict[str, Any]:
    ctx = _empty_ctx()

    # Split at top-level ## headers (keep header text with body)
    sections = re.split(r"^##\s+", raw, flags=re.MULTILINE)

    for section in sections:
        if not section.strip():
            continue
        lines = section.splitlines()
        title = lines[0].strip().lower()
        body = "\n".join(lines[1:])

        if "custom sink" in title:
            ctx["custom_sinks"] = _parse_sink_items(body)

        elif "custom source" in title:
            items = _parse_source_items(body)
            ctx["custom_sources"] = items
            # Derive non_http_sources from custom sources
            for item in items:
                qualified = _qualify(item.get("class", ""), item.get("name", ""))
                if qualified and qualified not in ctx["non_http_sources"]:
                    ctx["non_http_sources"].append(qualified)

        elif "sensitive flow" in title:
            ctx["sensitive_flows"] = _parse_flow_items(body)

        elif any(k in title for k in ("api name", "api endpoint", "webmethod", "web method")):
            ctx["api_names"] = _parse_api_names_section(body)

        elif any(k in title for k in ("function param", "taint param", "dangerous param")):
            ctx["function_params"] = _parse_function_params_section(body)

        elif "business note" in title or "system overview" in title:
            # Collect all non-empty lines and bullet points
            note_lines = [
                l.lstrip("- *").strip()
                for l in body.splitlines()
                if l.strip() and not l.startswith("#")
            ]
            chunk = "\n".join(note_lines)
            if ctx["business_notes"]:
                ctx["business_notes"] += "\n" + chunk
            else:
                ctx["business_notes"] = chunk

    return ctx


def _parse_sink_items(body: str) -> list[dict]:
    return _parse_items(body, _build_sink)


def _parse_source_items(body: str) -> list[dict]:
    return _parse_items(body, _build_source)


def _parse_flow_items(body: str) -> list[dict]:
    return _parse_items(body, _build_flow)


def _parse_api_names_section(body: str) -> list[dict]:
    """Parse ## API Names section.

    Supports two formats:
      Sub-headings:  ### GetDataSet  (with kv pairs below)
      Bullet list:   - GetDataSet(sql, connStr): raw SQL from client
    """
    if re.search(r"^###\s+", body, re.MULTILINE):
        return _parse_items(body, _build_api_name)

    items = []
    for line in body.splitlines():
        line = line.strip().lstrip("-*•").strip()
        if not line or line.startswith("#"):
            continue
        params_match = re.search(r"\(([^)]+)\)", line)
        params = [p.strip() for p in params_match.group(1).split(",")] if params_match else []
        name_raw = line.split("(")[0].split(":")[0].strip()
        name = re.sub(r"\(.*\)", "", name_raw).strip()
        if not name:
            continue
        colon_parts = line.split(":", 1)
        note = colon_parts[1].strip() if len(colon_parts) > 1 and "(" not in colon_parts[0] else ""
        item: dict[str, Any] = {"name": name}
        if params:
            item["params"] = params
        if note:
            item["note"] = note
        items.append(item)
    return items


def _parse_function_params_section(body: str) -> list[dict]:
    """Parse ## Function Params section.

    Supports two formats:
      Sub-headings:  ### GetDataSet  with - Param: sql  - Taint reason: raw SQL
      Inline:        - GetDataSet(sql, connStr): raw SQL passed to OracleCommand
    """
    if re.search(r"^###\s+", body, re.MULTILINE):
        return _parse_items(body, _build_function_param)

    items = []
    for line in body.splitlines():
        line = line.strip().lstrip("-*•").strip()
        if not line or line.startswith("#"):
            continue
        fn_match = re.match(r"(\w+)\s*\(([^)]+)\)\s*:?\s*(.*)", line)
        if fn_match:
            func = fn_match.group(1)
            taint_reason = fn_match.group(3).strip()
            for param in fn_match.group(2).split(","):
                param = param.strip()
                if param:
                    items.append({"function": func, "param": param, "taint_reason": taint_reason})
        else:
            parts = line.split(":", 1)
            func = parts[0].strip()
            taint = parts[1].strip() if len(parts) > 1 else ""
            if func:
                items.append({"function": func, "param": "", "taint_reason": taint})
    return items


def _parse_items(body: str, builder) -> list[dict]:
    """Split body at ### sub-headings and call builder on each."""
    subsections = re.split(r"^###\s+", body, flags=re.MULTILINE)
    result = []
    for sub in subsections:
        sub = sub.strip()
        if not sub:
            continue
        lines = sub.splitlines()
        heading = lines[0].strip()
        rest = "\n".join(lines[1:])
        kv = _extract_kv(rest)
        item = builder(heading, kv, rest)
        if item:
            result.append(item)
    return result


# ── Item builders ─────────────────────────────────────────────────────────────

def _build_sink(heading: str, kv: dict, raw_body: str) -> dict | None:
    # Heading may be "ClassName::methodName" or just "methodName"
    cls, name = _split_heading(heading)

    item: dict[str, Any] = {"confidence": "HIGH"}
    item["name"] = kv.get("method") or name
    item["class"] = kv.get("class") or cls or ""
    item["vuln_type"] = (
        kv.get("vuln_type")
        or kv.get("vuln type")
        or _infer_vuln_type(raw_body)
        or "unknown"
    )
    item["note"] = kv.get("risk") or kv.get("note") or ""

    # Strip method signature → keep just the method name
    item["name"] = re.sub(r"\(.*\)", "", item["name"]).strip()

    return item if item["name"] else None


def _build_source(heading: str, kv: dict, raw_body: str) -> dict | None:
    cls, name = _split_heading(heading)

    item: dict[str, Any] = {}
    item["name"] = kv.get("method") or name
    item["class"] = kv.get("class") or cls or ""
    item["source_type"] = kv.get("source_type") or kv.get("source type") or "unknown"
    item["note"] = kv.get("note") or ""

    item["name"] = re.sub(r"\(.*\)", "", item["name"]).strip()

    return item if item["name"] else None


def _build_flow(heading: str, kv: dict, raw_body: str) -> dict | None:
    # Heading may look like "/webhook/payment (POST)"
    entry = re.sub(r"\s*\(.*?\)", "", heading).strip()

    item: dict[str, Any] = {}
    item["description"] = heading
    item["entry"] = kv.get("entry") or entry
    item["risk"] = kv.get("risk") or kv.get("impact") or ""

    return item if item["entry"] else None


def _build_api_name(heading: str, kv: dict, raw_body: str) -> dict | None:
    """Builder for ### sub-heading format in ## API Names sections."""
    # Heading: "GetDataSet" or "GetDataSet(sql, connStr)" or "POST /api/data"
    fn_match = re.match(r"(\w+)\s*(?:\(([^)]*)\))?", heading)
    name = kv.get("name") or kv.get("method_name") or (fn_match.group(1) if fn_match else heading.strip())
    name = re.sub(r"\(.*\)", "", name).strip()
    if not name:
        return None

    inline_params = fn_match.group(2) if fn_match and fn_match.group(2) else ""
    raw_params = kv.get("params") or kv.get("param") or kv.get("parameters") or inline_params
    params = [p.strip() for p in raw_params.split(",") if p.strip()] if raw_params else []

    item: dict[str, Any] = {"name": name}
    if kv.get("path") or kv.get("url") or kv.get("route"):
        item["path"] = kv.get("path") or kv.get("url") or kv.get("route")
    if kv.get("method") or kv.get("http_method"):
        item["method"] = kv.get("method") or kv.get("http_method")
    if params:
        item["params"] = params
    note = kv.get("note") or kv.get("risk") or kv.get("description") or ""
    if note:
        item["note"] = note
    return item


def _build_function_param(heading: str, kv: dict, raw_body: str) -> dict | None:
    """Builder for ### sub-heading format in ## Function Params sections."""
    fn_match = re.match(r"(\w+)\s*(?:\(([^)]*)\))?", heading)
    func = fn_match.group(1) if fn_match else heading.strip()
    if not func:
        return None

    inline_param = fn_match.group(2) if fn_match and fn_match.group(2) else ""
    param = kv.get("param") or kv.get("params") or inline_param
    taint_reason = kv.get("taint_reason") or kv.get("taint") or kv.get("note") or kv.get("risk") or ""

    return {"function": func, "param": param.strip(), "taint_reason": taint_reason}


# ── YAML-structured normalizer ────────────────────────────────────────────────

def _normalize(data: dict) -> dict[str, Any]:
    """Normalize a YAML/JSON-parsed dict into the canonical schema.
    raw_text is set by _parse() after this call, not here."""
    ctx = _empty_ctx()

    for s in data.get("custom_sinks", []):
        if not isinstance(s, dict):
            continue
        s.setdefault("confidence", "HIGH")
        s.setdefault("note", "")
        ctx["custom_sinks"].append(s)

    for s in data.get("custom_sources", []):
        if not isinstance(s, dict):
            continue
        s.setdefault("note", "")
        ctx["custom_sources"].append(s)
        qualified = _qualify(s.get("class", ""), s.get("name", ""))
        if qualified and qualified not in ctx["non_http_sources"]:
            ctx["non_http_sources"].append(qualified)

    for f in data.get("sensitive_flows", []):
        if not isinstance(f, dict):
            continue
        f.setdefault("description", f.get("entry", ""))
        ctx["sensitive_flows"].append(f)

    # non_http_sources may be explicit in YAML too
    for src in data.get("non_http_sources", []):
        if isinstance(src, str) and src not in ctx["non_http_sources"]:
            ctx["non_http_sources"].append(src)

    for a in data.get("api_names", []):
        if isinstance(a, dict) and a.get("name"):
            ctx["api_names"].append(a)
        elif isinstance(a, str) and a:
            ctx["api_names"].append({"name": a})

    for p in data.get("function_params", []):
        if isinstance(p, dict) and p.get("function"):
            p.setdefault("param", "")
            p.setdefault("taint_reason", "")
            ctx["function_params"].append(p)

    ctx["business_notes"] = data.get("business_notes", "")
    # raw_text intentionally NOT copied from data — set by _parse() from the
    # original file bytes, not from the already-parsed/transformed dict.

    return ctx


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_kv(body: str) -> dict[str, str]:
    """
    Extract key-value pairs from lines like:
      - Class: `App\\Foo`
      - Vuln type: sqli
      **Key**: value
    """
    kv: dict[str, str] = {}
    pattern = re.compile(
        r"[-*]\s*\*{0,2}([\w][\w\s]*?)\*{0,2}:\s*(.+)",
        re.IGNORECASE,
    )
    for line in body.splitlines():
        m = pattern.match(line.strip())
        if m:
            key = m.group(1).strip().lower().replace(" ", "_")
            value = m.group(2).strip().strip("`").strip('"').strip("'")
            kv[key] = value
    return kv


def _split_heading(heading: str) -> tuple[str, str]:
    """Split 'ClassName::methodName' → ('ClassName', 'methodName')."""
    if "::" in heading:
        parts = heading.split("::", 1)
        return parts[0].strip(), parts[1].strip()
    return "", heading.strip()


def _qualify(cls: str, name: str) -> str:
    """Build 'SimpleClassName::methodName' for non_http_sources list."""
    if not name:
        return ""
    # Use just the last segment of a namespaced class
    simple_cls = cls.split("\\")[-1].split(".")[-1] if cls else ""
    return f"{simple_cls}::{name}" if simple_cls else name


def _infer_vuln_type(text: str) -> str:
    """Guess vuln_type from free-text risk description."""
    text = text.lower()
    mapping = [
        (["sql", "sqli", "injection", "query"], "sqli"),
        (["rce", "command", "exec", "shell"], "rce"),
        (["xss", "cross-site scripting", "html inject"], "xss"),
        (["ssrf", "server-side request"], "ssrf"),
        (["path traversal", "lfi", "file inclus"], "lfi"),
        (["xxe", "xml entity"], "xxe"),
        (["deserializ", "unserializ", "pickle"], "deserialize"),
        (["ssti", "template inject"], "ssti"),
        (["redirect", "open redirect"], "redirect"),
        (["idor", "broken object"], "idor"),
        (["business", "payment", "amount", "price", "order"], "business_critical"),
    ]
    for keywords, vuln_type in mapping:
        if any(kw in text for kw in keywords):
            return vuln_type
    return ""
