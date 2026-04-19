"""
shared/persistence.py
──────────────────────
Helper used by ALL tools to read/write output files.

Folder convention:
  reports/<run_id>/
  ├── catalog/          ← Phase 1
  ├── connect/          ← Phase 2
  ├── findings/         ← Phase 3 (after Verify + Classify)
  └── evidence/         ← Phase 4 (Burp confirm)

run_id format: YYYYMMDD_HHMMSS_<repo_name>
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# Reports root can be overridden via env var
REPORTS_DIR = os.environ.get("REPORTS_DIR", "./reports")


def _phase_dir(run_id: str, phase: str) -> Path:
    d = Path(REPORTS_DIR) / run_id / phase
    d.mkdir(parents=True, exist_ok=True)
    return d


def write(run_id: str, phase: str, filename: str, data: Any) -> str:
    """Write JSON data to reports/<run_id>/<phase>/<filename>. Returns saved path."""
    target = _phase_dir(run_id, phase) / filename
    target.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return str(target)


def read(run_id: str, phase: str, filename: str) -> Any:
    """Read JSON from reports/<run_id>/<phase>/<filename>. Returns {} if missing."""
    target = _phase_dir(run_id, phase) / filename
    if not target.exists():
        return {}
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def list_runs() -> list[str]:
    """List all existing run IDs found under REPORTS_DIR."""
    root = Path(REPORTS_DIR)
    if not root.exists():
        return []
    return sorted(
        [d.name for d in root.iterdir() if d.is_dir()],
        reverse=True,
    )


def ensure_run_dirs(run_id: str) -> str:
    """Create the full folder structure for a run_id. Returns the run root path."""
    root = Path(REPORTS_DIR) / run_id
    for sub in ("catalog", "connect", "findings", "evidence"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    return str(root)
