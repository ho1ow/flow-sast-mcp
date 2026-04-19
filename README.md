# flow-sast-mcp

MCP server for the **flow-sast** security audit pipeline.  
Exposes all audit tools to Claude Code via the Model Context Protocol — Claude drives the entire pipeline iteratively, decides what to query next, and reads source code directly. No pre-fixed queries.

---

## Pipeline Overview

```
Claude Code
        │
        ▼
┌─────────────────────────────────────────────────┐
│ PRE-PHASE: CONTEXT PARSING                      │
│                                                 │
│  parse_context(run_id, context_file)            │
│  → extract structured objects:                  │
│      ├─ custom_sinks[]    { name, class, vuln } │
│      ├─ custom_sources[]  { name, class, type } │
│      ├─ sensitive_flows[] { entry, risk }        │
│      ├─ non_http_sources[]  ← feed semgrep       │
│      ├─ api_names[]       { name, params, note } │  ← NEW
│      ├─ function_params[] { fn, param, taint }  │  ← NEW
│      └─ business_notes      ← feed analyze      │
│  → saves: catalog/business_ctx.json             │
└──────────────────────────┬──────────────────────┘
                           ↓
┌─────────────────────────────────────────────────┐
│ PHASE 1: CATALOG                                │
│                                                 │
│  Step 1a — Parallel:                            │
│  semgrep_scan  → sources.json, sinks.json       │
│  api_parse     → endpoints.json                 │
│  secrets_scan  → secrets.json                   │
│                                                 │
│  Step 1b — analyze_catalog (pure Python):        │
│  → reads all 1a JSONs from disk automatically   │
│  → merge + score + dedup across 4 sources       │
│  → gitnexus_params (pre-computed)               │
│  → cypher_hints[] (ready-to-use Cypher strings) │
│  → saves: catalog/scan_strategy.json            │
│                                                 │
│  Step 1c — gitnexus_context(**gitnexus_params)  │
│  → labeled cross-catalog lists                  │
│  → saves: catalog/repo_structure.json           │
│                                                 │
│  Step 1d — gitnexus_query(cypher_hints[n])      │
│  → Cypher pre-generated, copy from hints        │
│  → sees result → queries again if needed        │
└──────────────────────────┬──────────────────────┘
                           ↓
┌─────────────────────────────────────────────────┐
│ PHASE 2: CONNECT                                │
│                                                 │
│  Claude generates path queries from catalog     │
│  → gitnexus_query(cypher)  [iterative]          │
│  → candidate_paths[]                            │
│                                                 │
│  fp_filter(run_id, paths)                       │
│  → filtered_paths[]                             │
│                                                 │
│  joern_filter(run_id, paths)  [optional]        │
│  → cpg_confirmed[]                              │
│                                                 │
│  triage_score(run_id, paths, sensitive_flows)   │
│  → scored_paths[]  (threshold ≥ 6)             │
│  → saves: connect/scored_paths.json             │
└──────────────────────────┬──────────────────────┘
                           ↓
┌─────────────────────────────────────────────────┐
│ PHASE 3: VERIFY                                 │
│                                                 │
│  Claude reads source code directly              │
│  (filesystem access — no MCP call needed)       │
│  → trace taint path                             │
│  → check sanitizer                              │
│  → object taint trace                           │
│  → custom sink: read implementation             │
│  → CONFIRMED / FALSE_POSITIVE / UNCERTAIN       │
│                                                 │
│  classify_sink(run_id, sink, business_ctx)      │
│  → known sinks: lookup table (no LLM)           │
│  → custom sinks: Claude classifies              │
│  → write_findings(run_id, findings)             │
│  → saves: findings/findings.json + .md         │
└──────────────────────────┬──────────────────────┘
                           ↓
              ⏸ HUMAN REVIEW
              Claude presents findings in chat
              User: accept / reject / ask
                           ↓
┌─────────────────────────────────────────────────┐
│ PHASE 4: ANALYZE                                │
│                                                 │
│  Claude reads skill file for vuln type          │
│  (skills/server_side_skill.md, etc.)            │
│  → deep vuln analysis                           │
│  → PoC payload construction                     │
│  → CVSS estimate                                │
│                                                 │
│  burp_send(run_id, finding_id, request, payload)│
│  → dynamic PoC confirm                          │
│  → saves: evidence/<finding_id>.http           │
└─────────────────────────────────────────────────┘
```

---

## Tools

| Tool | Phase | Saves |
|------|-------|-------|
| `parse_context` | Pre | `catalog/business_ctx.json` |
| `semgrep_scan` | Catalog | `catalog/sources.json`, `catalog/sinks.json` |
| `api_parse` | Catalog | `catalog/endpoints.json` |
| `secrets_scan` | Catalog | `catalog/secrets.json` |
| `gitnexus_context` | Catalog | `catalog/repo_structure.json` |
| `gitnexus_query` | Catalog / Connect | `catalog/gitnexus_<label>.json` or `connect/gitnexus_<label>.json` |
| `fp_filter` | Connect | `connect/filtered_paths.json` |
| `joern_filter` | Connect | `connect/cpg_confirmed.json` |
| `triage_score` | Connect | `connect/scored_paths.json` |
| `classify_sink` | Verify | — (lookup only) |
| `write_findings` | Verify | `findings/findings.json`, `findings/findings.md` |
| `burp_send` | Analyze | `evidence/<finding_id>.http` |

---

## Installation

### 1. Install flow-sast-mcp

```bash
git clone https://github.com/yourorg/flow-sast-mcp
cd flow-sast-mcp
pip install -e .
```

Or with `uv`:
```bash
uv pip install -e .
```

Configure environment:
```bash
cp .env.example .env
# Edit .env — see section below
```

### 2. Register with your AI client

flow-sast-mcp uses the standard **MCP stdio transport** — any MCP-compatible client works.  
The server command is always: `python -m flow_sast_mcp`

#### Auto-installer *(recommended)*

Make sure you have installed the package first:
```bash
pip install -e .
```

Then run the auto-installer to register the MCP server with your AI clients:

```bash
# Install all detected clients at once
flow-sast-install-mcp

# Or specify which clients to install
flow-sast-install-mcp --clients claude cursor codex

# Check what's detected without changing anything
flow-sast-install-mcp --list

# Uninstall from all detected clients
flow-sast-install-mcp --uninstall

# Preview changes before applying
flow-sast-install-mcp --dry-run
```

Supported clients: `claude` `cursor` `codex` `gemini` `antigravity` `windsurf` `opencode`



```json
{
  "flow-sast": {
    "command": "python",
    "args": ["-m", "flow_sast_mcp"],
    "env": {
      "JOERN_BASE_URL": "http://localhost:8080",
      "BURP_MCP_BASE_URL": "http://localhost:1337",
      "GITNEXUS_BINARY": "gitnexus",
      "TRIAGE_THRESHOLD": "6",
      "MAX_PATHS": "200"
    }
  }
}
```

---

#### Claude Code (Anthropic)

```bash
# One-liner (recommended)
claude mcp add flow-sast --scope user -- python -m flow_sast_mcp

# Verify
claude mcp list
```

Or add manually to `~/.claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "flow-sast": {
      "command": "python",
      "args": ["-m", "flow_sast_mcp"]
    }
  }
}
```

> Deepest integration: CLAUDE.md in project root auto-loads the full workflow.

---

#### Antigravity (Google DeepMind)

Add to Antigravity MCP settings (via IDE extension or config file):
```json
{
  "mcpServers": {
    "flow-sast": {
      "command": "python",
      "args": ["-m", "flow_sast_mcp"],
      "env": {
        "GITNEXUS_BINARY": "gitnexus",
        "TRIAGE_THRESHOLD": "6"
      }
    }
  }
}
```

---

#### Cursor

Global config at `~/.cursor/mcp.json` (applies to all projects):
```json
{
  "mcpServers": {
    "flow-sast": {
      "command": "python",
      "args": ["-m", "flow_sast_mcp"],
      "env": {
        "GITNEXUS_BINARY": "gitnexus",
        "TRIAGE_THRESHOLD": "6",
        "MAX_PATHS": "200"
      }
    }
  }
}
```

Or project-scoped at `.cursor/mcp.json` in the repo root.

---

#### OpenAI Codex

```bash
codex mcp add flow-sast -- python -m flow_sast_mcp
```

Or via `~/.codex/config.toml`:
```toml
[mcp_servers.flow-sast]
command = "python"
args    = ["-m", "flow_sast_mcp"]

[mcp_servers.flow-sast.env]
GITNEXUS_BINARY  = "gitnexus"
TRIAGE_THRESHOLD = "6"
MAX_PATHS        = "200"
```

---

#### Gemini CLI (Google)

Add to `~/.gemini/settings.json`:
```json
{
  "mcpServers": {
    "flow-sast": {
      "command": "python",
      "args": ["-m", "flow_sast_mcp"],
      "env": {
        "GITNEXUS_BINARY": "gitnexus",
        "TRIAGE_THRESHOLD": "6"
      }
    }
  }
}
```

---

#### Windsurf (Codeium)

Add to `~/.codeium/windsurf/mcp_settings.json`:
```json
{
  "mcpServers": {
    "flow-sast": {
      "command": "python",
      "args": ["-m", "flow_sast_mcp"],
      "env": {
        "GITNEXUS_BINARY": "gitnexus",
        "TRIAGE_THRESHOLD": "6",
        "MAX_PATHS": "200"
      }
    }
  }
}
```

---

#### OpenCode

Add to `~/.config/opencode/config.json`:
```json
{
  "mcp": {
    "flow-sast": {
      "type": "local",
      "command": ["python", "-m", "flow_sast_mcp"]
    }
  }
}
```

---

#### Generic (any stdio MCP client)

The server reads from stdin and writes to stdout via MCP stdio protocol:
```bash
# Test the server starts correctly
python -m flow_sast_mcp

# Expected output:
# MCP server "flow-sast" listening on stdio
```

For any client that supports custom MCP servers, point it at:
- **command:** `python`
- **args:** `["-m", "flow_sast_mcp"]`
- **cwd:** path to this repo (so `.env` is picked up)

---



### 2. Required tools

#### Semgrep — static taint analysis *(highly recommended)*

```bash
# pip
pip install semgrep

# brew (macOS)
brew install semgrep

# verify
semgrep --version
```

> Without Semgrep, `semgrep_scan` returns empty results. The rest of the pipeline (gitnexus, joern) still works.

---

#### Gitleaks — secret detection *(optional, regex fallback built-in)*

```bash
# brew (macOS/Linux)
brew install gitleaks

# Windows (scoop)
scoop install gitleaks

# Direct binary — https://github.com/gitleaks/gitleaks/releases
# e.g. Linux amd64:
curl -Lo gitleaks.tar.gz \
  https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks.tar.gz && sudo mv gitleaks /usr/local/bin/

# verify
gitleaks version
```

> Without Gitleaks, `secrets_scan` falls back to built-in regex patterns (lower coverage).

---

#### GitNexus — graph-based code analysis *(optional)*

GitNexus indexes a codebase into a knowledge graph and exposes Cypher queries over it.  
GitHub: [abhigyanpatwari/GitNexus](https://github.com/abhigyanpatwari/GitNexus)

```bash
# Requires Node.js 18+
node --version

# Install globally
npm install -g gitnexus

# Verify
gitnexus --version
```

**Index the target repo before running flow-sast:**

```bash
cd /path/to/target/repo
gitnexus analyze          # index repo → builds knowledge graph
gitnexus analyze --force  # force full re-index
```

flow-sast-mcp calls GitNexus via the CLI query interface:
```bash
# Example query (called internally by gitnexus_query tool)
gitnexus query --cypher "MATCH (n:Symbol) RETURN n LIMIT 10" \
               --repo /path/to/repo \
               --format json
```

Override binary path if not on `PATH`:
```bash
# .env
GITNEXUS_BINARY=/custom/path/to/gitnexus
GITNEXUS_TIMEOUT=120
```

> Without GitNexus, `gitnexus_context` falls back to `_function_surface_scan` (pure Python, structural scan). `gitnexus_query` returns empty results — other tools (semgrep, api_parse, secrets) still work normally.

---

#### Joern — CFG taint confirmation *(optional)*

Joern provides interprocedural data-flow analysis via a REST server. Used in Phase 2 to confirm taint paths.

```bash
# Requires Java 11+
java -version

# Download Joern
curl -Lo joern.zip \
  https://github.com/joernio/joern/releases/latest/download/joern-cli.zip
unzip joern.zip && cd joern-cli

# Start REST server
./joern-server.sh --host 0.0.0.0 --port 8080 &

# verify
curl http://localhost:8080/health
```

Set in `.env`:
```
JOERN_BASE_URL=http://localhost:8080
```

> Without Joern, `joern_filter` gracefully skips and annotates paths as `CLAUDE_FULL_VERIFY` — Claude reads source to verify instead.

---

#### Burp Suite + burp-mcp-server — dynamic PoC *(optional)*

Used in Phase 4 to send actual HTTP payloads and confirm exploitability.

```bash
# 1. Install Burp Suite Community or Pro
#    https://portswigger.net/burp/releases

# 2. Install burp-mcp-server extension (c0tton-fluff)
#    In Burp → Extensions → Add → burp-mcp-server.jar
#    Default listens on port 1337

# 3. Set in .env
BURP_MCP_BASE_URL=http://localhost:1337
```

> Without Burp, `burp_send` returns an error. All other phases work normally.

---

### 3. Environment variables

`.env.example`:
```bash
# Joern REST server (optional)
JOERN_BASE_URL=http://localhost:8080

# Burp MCP server (optional)
BURP_MCP_BASE_URL=http://localhost:1337

# GitNexus binary path (default: gitnexus on PATH)
GITNEXUS_BINARY=gitnexus

# GitNexus query timeout seconds (default: 120)
GITNEXUS_TIMEOUT=120

# Triage threshold — paths scoring below this are dropped (default: 6)
TRIAGE_THRESHOLD=6

# Max paths kept after triage (default: 200)
MAX_PATHS=200

# Where to write reports/<run_id>/ (default: ./reports)
REPORTS_DIR=./reports

# Override known sinks list for gitnexus Pass 1 (comma-separated)
# GITNEXUS_KNOWN_SINKS=rawExec,charge,myCustomSink

# Override flow topic keywords (comma-separated)
# GITNEXUS_FLOW_TOPICS=payment,shipment,prescription
```

---

## Usage

```bash
cd /path/to/target/repo
claude
```

In the Claude Code session:
```
Audit this repo for security vulnerabilities.
Context file: /path/to/context.md
Stack: laravel
run_id: 20260417_120000_myapp
```

See [CLAUDE.md](CLAUDE.md) for the full workflow Claude Code follows.

---

## Comparison: scan tool vs MCP

| | scan tool | flow-sast-mcp |
|---|---|---|
| Discovery | Fixed queries, runs once | Iterative, Claude decides each query |
| Flexibility | Fixed by phase | Adaptive to actual results |
| Miss rate on custom sinks | Higher | Lower |
| Reproducibility | High | Lower |
| Setup | `python scan.py` | MCP server + Claude Code |
| Token cost | Lower | Higher (many tool calls) |
| Use case | Automated CI, many repos | Interactive deep audit, single repo |
