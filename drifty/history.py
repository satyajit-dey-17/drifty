"""
history.py — Drift history persistence for drifty.

Appends scan results to .drifty/history.json after every run.
Provides load and summarize functions for the drifty history command.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding

HISTORY_FILE = ".drifty/history.json"


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------


def append_findings(findings: list[DriftFinding], workspace: Path) -> None:
    """
    Append a scan result entry to .drifty/history.json.
    Always writes, even on zero findings (clean scan = useful data point).
    """
    history_path = workspace / HISTORY_FILE
    history_path.parent.mkdir(parents=True, exist_ok=True)

    history = _load_raw(history_path)

    counts = _count_by_severity(findings)
    entry = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "workspace": workspace.name or str(workspace),
        "total": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "findings": [asdict(f) for f in findings],
    }

    history.append(entry)

    history_path.write_text(json.dumps(history, indent=2, default=str))


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def load_history(workspace: Path, last: int = 10) -> list[dict]:
    """
    Load the last N scan entries from .drifty/history.json.
    Returns newest-first.
    """
    history_path = workspace / HISTORY_FILE
    if not history_path.exists():
        return []
    history = _load_raw(history_path)
    return list(reversed(history))[:last]


def most_drifted_resources(workspace: Path, last: int = 10) -> list[dict]:
    """
    Return resources ranked by how many times they appeared in drift findings,
    across the last N scans. Each entry: {addr, count, severity}.
    """
    entries = load_history(workspace, last=last)
    counts: dict[str, dict] = {}

    for entry in entries:
        for finding in entry.get("findings", []):
            addr = f"{finding['resource_type']}.{finding['resource_name']}"
            if addr not in counts:
                counts[addr] = {"addr": addr, "count": 0, "severity": finding["severity"]}
            counts[addr]["count"] += 1
            # Escalate severity if a more severe finding is seen
            from drifty.scorer import SEVERITY_ORDER

            existing = SEVERITY_ORDER.get(counts[addr]["severity"], 3)
            incoming = SEVERITY_ORDER.get(finding["severity"], 3)
            if incoming < existing:
                counts[addr]["severity"] = finding["severity"]

    return sorted(counts.values(), key=lambda x: x["count"], reverse=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_raw(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _count_by_severity(findings: list[DriftFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
