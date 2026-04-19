"""
install_mcp.py
──────────────
Auto-register flow-sast-mcp into supported AI clients.

Usage:
  python install_mcp.py                    # detect + install all available clients
  python install_mcp.py --clients claude cursor codex
  python install_mcp.py --uninstall        # remove from all detected clients
  python install_mcp.py --list             # list what's detected
  python install_mcp.py --dry-run          # show what would be changed

Entry point (after pip install -e .):
  flow-sast-install-mcp
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
    except ImportError:
        tomllib = None  # type: ignore

# ── MCP server config injected into each client ───────────────────────────────

def _server_python() -> str:
    """Return the Python executable that has flow_sast_mcp installed."""
    return sys.executable


def _server_block() -> dict:
    return {
        "command": _server_python(),
        "args": ["-m", "flow_sast_mcp"],
        "env": {
            "JOERN_BASE_URL": "http://localhost:8080",
            "BURP_MCP_BASE_URL": "http://localhost:1337",
            "GITNEXUS_BINARY": "gitnexus",
            "TRIAGE_THRESHOLD": "6",
            "MAX_PATHS": "200",
        },
    }


SERVER_NAME = "flow-sast"

HOME = Path.home()


# ── Helper: JSON config file ────────────────────────────────────────────────--

def _read_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _write_json(path: Path, data: dict, dry_run: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2) + "\n"
    if dry_run:
        print(f"  [dry-run] would write {path}:\n{content}")
    else:
        path.write_text(content, encoding="utf-8")
        print(f"  ✓ wrote {path}")


def _inject_mcp_servers(config: dict, uninstall: bool, key: str = "mcpServers") -> dict:
    """Add/overwrite or remove SERVER_NAME under config[key]."""
    if uninstall:
        if key in config and SERVER_NAME in config[key]:
            del config[key][SERVER_NAME]
            # Clean up empty parent if it was the only one
            if not config[key]:
                del config[key]
    else:
        config.setdefault(key, {})[SERVER_NAME] = _server_block()
    return config


# ── Client handlers ────────────────────────────────────────────────────────────

class ClientResult:
    def __init__(self, name: str, detected: bool, status: str, note: str = ""):
        self.name    = name
        self.detected = detected
        self.status  = status   # "ok" | "skipped" | "error" | "dry-run"
        self.note    = note

    def __str__(self) -> str:
        icon = {"ok": "✅", "skipped": "⏭ ", "error": "❌", "dry-run": "🔍"}.get(self.status, "  ")
        det  = "detected" if self.detected else "not found"
        note = f" — {self.note}" if self.note else ""
        return f"  {icon} {self.name:20s} [{det}]{note}"


def _install_claude(dry_run: bool, uninstall: bool) -> ClientResult:
    """Claude Code: uses `claude mcp add/remove` CLI if available, falls back to JSON."""
    name = "Claude Code"
    # Try CLI first
    claude_bin = shutil.which("claude")
    if claude_bin:
        if uninstall:
            cmd = [claude_bin, "mcp", "remove", SERVER_NAME]
        else:
            cmd = [
                claude_bin, "mcp", "add", SERVER_NAME,
                "--scope", "user",
                "--", _server_python(), "-m", "flow_sast_mcp",
            ]
        
        if dry_run:
            print(f"  [dry-run] would run: {' '.join(cmd)}")
            return ClientResult(name, True, "dry-run", "via claude CLI")
        try:
            subprocess.run(cmd, check=True, capture_output=True, shell=(os.name == "nt"))
            return ClientResult(name, True, "ok", "via claude CLI")
        except subprocess.CalledProcessError as e:
            return ClientResult(name, True, "error", e.stderr.decode()[:80])

    # Fallback: edit JSON config
    candidates = [
        HOME / ".claude" / "claude_desktop_config.json",
        Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json",
    ]
    for cfg_path in candidates:
        if cfg_path.parent.exists() or cfg_path.exists():
            cfg = _read_json(cfg_path)
            cfg = _inject_mcp_servers(cfg, uninstall, "mcpServers")
            _write_json(cfg_path, cfg, dry_run)
            status = "dry-run" if dry_run else "ok"
            return ClientResult(name, True, status, str(cfg_path))

    return ClientResult(name, False, "skipped", "claude CLI not found and no config dir detected")


def _install_cursor(dry_run: bool, uninstall: bool) -> ClientResult:
    """Cursor: ~/.cursor/mcp.json"""
    name = "Cursor"
    cfg_path = HOME / ".cursor" / "mcp.json"
    detected = cfg_path.exists() or (HOME / ".cursor").exists()
    if not detected:
        return ClientResult(name, False, "skipped", "~/.cursor/ not found")
    cfg = _read_json(cfg_path)
    cfg = _inject_mcp_servers(cfg, uninstall, "mcpServers")
    _write_json(cfg_path, cfg, dry_run)
    return ClientResult(name, True, "dry-run" if dry_run else "ok", str(cfg_path))


def _install_codex(dry_run: bool, uninstall: bool) -> ClientResult:
    """OpenAI Codex: codex CLI or ~/.codex/config.toml"""
    name = "Codex"
    codex_bin = shutil.which("codex")
    if codex_bin:
        if uninstall:
            cmd = [codex_bin, "mcp", "remove", SERVER_NAME]
        else:
            cmd = [codex_bin, "mcp", "add", SERVER_NAME,
                   "--", _server_python(), "-m", "flow_sast_mcp"]
        if dry_run:
            print(f"  [dry-run] would run: {' '.join(cmd)}")
            return ClientResult(name, True, "dry-run", "via codex CLI")
        try:
            subprocess.run(cmd, check=True, capture_output=True, shell=(os.name == "nt"))
            return ClientResult(name, True, "ok", "via codex CLI")
        except subprocess.CalledProcessError:
            pass  # fall through to toml

    # TOML config fallback
    toml_path = HOME / ".codex" / "config.toml"
    detected  = toml_path.exists() or (HOME / ".codex").exists()
    if not detected:
        return ClientResult(name, False, "skipped", "codex not found")

    if dry_run:
        action = "remove from" if uninstall else "append to"
        print(f"  [dry-run] would {action} {toml_path}")
        return ClientResult(name, True, "dry-run", str(toml_path))

    toml_path.parent.mkdir(parents=True, exist_ok=True)
    existing = toml_path.read_text(encoding="utf-8") if toml_path.exists() else ""
    lines = existing.splitlines(keepends=True)
    
    # Strip old [mcp_servers.flow-sast*] blocks
    filtered, skip = [], False
    for line in lines:
        if line.strip().startswith(f"[mcp_servers.{SERVER_NAME}"):
            skip = True
        elif skip and line.strip().startswith("["):
            skip = False
        if not skip:
            filtered.append(line)
            
    if uninstall:
        toml_path.write_text("".join(filtered), encoding="utf-8")
        print(f"  ✓ removed from {toml_path}")
    else:
        # Build TOML section manually (avoid tomllib write dep)
        block = _server_block()
        env_lines = "\n".join(f'{k} = "{v}"' for k, v in block["env"].items())
        args_str  = ", ".join(f'"{a}"' for a in block["args"])
        toml_section = (
            f'\n[mcp_servers.{SERVER_NAME}]\n'
            f'command = "{block["command"]}"\n'
            f'args    = [{args_str}]\n'
            f'\n[mcp_servers.{SERVER_NAME}.env]\n'
            f'{env_lines}\n'
        )
        toml_path.write_text("".join(filtered) + toml_section, encoding="utf-8")
        print(f"  ✓ wrote {toml_path}")
        
    return ClientResult(name, True, "ok", str(toml_path))


def _install_gemini(dry_run: bool, uninstall: bool) -> ClientResult:
    """Gemini CLI: ~/.gemini/settings.json"""
    name = "Gemini CLI"
    cfg_path = HOME / ".gemini" / "settings.json"
    detected = cfg_path.exists() or (HOME / ".gemini").exists()
    if not detected:
        return ClientResult(name, False, "skipped", "~/.gemini/ not found")
    cfg = _read_json(cfg_path)
    cfg = _inject_mcp_servers(cfg, uninstall, "mcpServers")
    _write_json(cfg_path, cfg, dry_run)
    return ClientResult(name, True, "dry-run" if dry_run else "ok", str(cfg_path))


def _install_antigravity(dry_run: bool, uninstall: bool) -> ClientResult:
    """Antigravity (Google DeepMind): ~/.antigravity/settings.json"""
    name = "Antigravity"
    cfg_path = HOME / ".antigravity" / "settings.json"
    detected = cfg_path.exists() or (HOME / ".antigravity").exists()
    if not detected:
        return ClientResult(name, False, "skipped", "~/.antigravity/ not found")
    cfg = _read_json(cfg_path)
    cfg = _inject_mcp_servers(cfg, uninstall, "mcpServers")
    _write_json(cfg_path, cfg, dry_run)
    return ClientResult(name, True, "dry-run" if dry_run else "ok", str(cfg_path))


def _install_windsurf(dry_run: bool, uninstall: bool) -> ClientResult:
    """Windsurf (Codeium): ~/.codeium/windsurf/mcp_settings.json"""
    name = "Windsurf"
    cfg_path = HOME / ".codeium" / "windsurf" / "mcp_settings.json"
    detected = cfg_path.exists() or (HOME / ".codeium").exists()
    if not detected:
        return ClientResult(name, False, "skipped", "~/.codeium/ not found")
    cfg = _read_json(cfg_path)
    cfg = _inject_mcp_servers(cfg, uninstall, "mcpServers")
    _write_json(cfg_path, cfg, dry_run)
    return ClientResult(name, True, "dry-run" if dry_run else "ok", str(cfg_path))


def _install_opencode(dry_run: bool, uninstall: bool) -> ClientResult:
    """OpenCode: ~/.config/opencode/config.json"""
    name = "OpenCode"
    cfg_path = HOME / ".config" / "opencode" / "config.json"
    detected = cfg_path.exists() or (HOME / ".config" / "opencode").exists()
    if not detected:
        return ClientResult(name, False, "skipped", "~/.config/opencode/ not found")
    cfg = _read_json(cfg_path)
    
    if uninstall:
        if "mcp" in cfg and SERVER_NAME in cfg["mcp"]:
            del cfg["mcp"][SERVER_NAME]
            if not cfg["mcp"]:
                del cfg["mcp"]
    else:
        block = _server_block()
        cfg.setdefault("mcp", {})[SERVER_NAME] = {
            "type":    "local",
            "command": [block["command"]] + block["args"],
        }
    _write_json(cfg_path, cfg, dry_run)
    return ClientResult(name, True, "dry-run" if dry_run else "ok", str(cfg_path))


# ── Registry ───────────────────────────────────────────────────────────────────

CLIENTS: dict[str, callable] = {
    "claude":      _install_claude,
    "cursor":      _install_cursor,
    "codex":       _install_codex,
    "gemini":      _install_gemini,
    "antigravity": _install_antigravity,
    "windsurf":    _install_windsurf,
    "opencode":    _install_opencode,
}


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    if sys.stdout.encoding.lower() != "utf-8" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="flow-sast-install-mcp",
        description="Auto-register flow-sast-mcp into AI coding clients.",
    )
    parser.add_argument(
        "--clients", "-c",
        nargs="+",
        metavar="CLIENT",
        choices=list(CLIENTS),
        help=f"Clients to configure. Choices: {', '.join(CLIENTS)}. Default: all.",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="Detect installed clients and exit.",
    )
    parser.add_argument(
        "--uninstall", "-u",
        action="store_true",
        help="Remove flow-sast-mcp configuration from the matched clients.",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show what would be changed without writing anything.",
    )
    args = parser.parse_args()

    targets = args.clients or list(CLIENTS)

    print(f"\nflow-sast-mcp installer")
    print(f"  server  : {_server_python()} -m flow_sast_mcp")
    print(f"  targets : {', '.join(targets)}")
    if args.dry_run:
        print("  mode    : DRY RUN — no files will be modified")
    print()

    results: list[ClientResult] = []
    for key in targets:
        fn = CLIENTS[key]
        if args.list:
            # Only detect, don't write
            r = fn(dry_run=True, uninstall=False)
            r.status = "detected" if r.detected else "not found"
        else:
            r = fn(dry_run=args.dry_run, uninstall=args.uninstall)
        results.append(r)

    print("\nResults:")
    for r in results:
        print(r)

    installed = [r for r in results if r.status == "ok"]
    skipped   = [r for r in results if r.status == "skipped"]
    errors    = [r for r in results if r.status == "error"]

    print(f"\n  {len(installed)} installed, {len(skipped)} skipped, {len(errors)} errors")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
