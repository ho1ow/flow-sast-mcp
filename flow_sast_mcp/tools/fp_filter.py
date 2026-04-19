"""
tools/fp_filter.py
───────────────────
MCP tool: fp_filter

Input:  run_id, paths[]
Output: { filtered_paths[], removed_count, saved_to }
Saves:  connect/filtered_paths.json

Structural false positive filter — runs BEFORE joern_filter.
No LLM calls. No method-name knowledge.
Decisions based only on: score threshold, file path structure.
Claude classifies anything that passes through here.
"""

from __future__ import annotations

from typing import List, Tuple

from flow_sast_mcp.shared.persistence import write, ensure_run_dirs

# ── Structural path patterns only — no method name knowledge ──────────────────

TEST_FILE_PATTERNS = [
    "/test/", "/tests/", "/spec/", "/fixture/", "/fixtures/",
    "/migration/", "/migrations/", "/seeder/", "/seeders/",
    "Test.php", "Spec.php", "_test.go", "_test.py", ".test.js",
    ".spec.ts", ".spec.js", "/UnitTests/", "/IntegrationTests/",
]

UTILITY_PATH_PATTERNS = [
    "/helper/", "/helpers/", "/util/", "/utils/",
    "/abstract/", "/base/", "/trait/", "/interface/", "/contract/",
]

FP_MIN_SCORE = 4


def run(run_id: str, paths: List[dict]) -> dict:
    """Structural false positive filter for candidate paths."""
    ensure_run_dirs(run_id)

    passed: List[dict]       = []
    skipped: List[dict]      = []
    low_priority: List[dict] = []

    for path in paths:
        decision, reason = _evaluate(path)
        annotated = {**path, "fp_decision": decision, "fp_reason": reason}
        if decision == "skip":
            skipped.append(annotated)
        elif decision == "low_priority":
            low_priority.append(annotated)
        else:
            passed.append(annotated)

    filtered = passed + low_priority
    saved_to = write(run_id, "connect", "filtered_paths.json", filtered)

    return {
        "filtered_paths": filtered,
        "removed_count": len(skipped),
        "pass_count": len(passed),
        "low_priority_count": len(low_priority),
        "skip_reasons": _count_reasons(skipped),
        "saved_to": saved_to,
    }


def _evaluate(path: dict) -> Tuple[str, str]:
    entry_file = path.get("entry_file", path.get("source", {}).get("file", ""))
    score      = path.get("score", path.get("triage_score", 0))

    # Score too low — not worth investigating
    if score < FP_MIN_SCORE:
        return "skip", f"score_too_low:{score}"

    # Entry point is in a test or migration file
    if _is_test_file(entry_file):
        return "skip", "test_or_migration_file"

    # Sink defined in a test file
    sink_file = path.get("sink", {}).get("file", "")
    if sink_file and _is_test_file(sink_file):
        return "skip", "sink_in_test_file"

    # Entry point is a utility/helper/abstract class (low attack surface)
    if any(p in entry_file.lower() for p in UTILITY_PATH_PATTERNS):
        return "low_priority", "utility_class_entry"

    # Object taint and feedback paths always pass for deeper analysis
    if path.get("query_type") in ("feedback", "object"):
        return "pass", path.get("query_type") + "_path"

    return "pass", "no_structural_fp_matched"


def _is_test_file(path: str) -> bool:
    path_lower = path.lower().replace("\\", "/")
    return any(p.lower().replace("\\", "/") in path_lower for p in TEST_FILE_PATTERNS)


def _count_reasons(paths: List[dict]) -> dict:
    from collections import Counter
    return dict(Counter(p.get("fp_reason", "")[:30] for p in paths).most_common(5))
