"""
ignore.py — Ignore list management for drifty.

Loads and persists .drifty/ignore.yaml. Filters DriftFindings against
the ignore list and returns suppressed findings separately so the
reporter can show them dimmed under a "Suppressed" label.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding

IGNORE_FILE = ".drifty/ignore.yaml"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def add_ignore(
    resource: str,
    workspace: Path,
    reason: str = "",
) -> None:
    """
    Add a resource address to the ignore list.
    No-op if the resource is already ignored.
    """
    ignores = load_ignores(workspace)

    if any(i["resource"] == resource for i in ignores):
        return  # already ignored

    ignores.append(
        {
            "resource": resource,
            "reason": reason,
            "ignored_at": datetime.now(timezone.utc).isoformat(),
            "ignored_by": os.environ.get("USER", "unknown"),
        }
    )
    _save_ignores(ignores, workspace)


def remove_ignore(resource: str, workspace: Path) -> bool:
    """
    Remove a resource address from the ignore list.
    Returns True if removed, False if it wasn't in the list.
    """
    ignores = load_ignores(workspace)
    filtered = [i for i in ignores if i["resource"] != resource]
    if len(filtered) == len(ignores):
        return False
    _save_ignores(filtered, workspace)
    return True


def load_ignores(workspace: Path) -> list[dict]:
    """Load ignore entries from .drifty/ignore.yaml. Returns [] if missing."""
    ignore_path = workspace / IGNORE_FILE
    if not ignore_path.exists():
        return []
    try:
        data = yaml.safe_load(ignore_path.read_text()) or {}
        return data.get("ignores", []) if isinstance(data, dict) else []
    except yaml.YAMLError:
        return []


def filter_findings(
    findings: list[DriftFinding],
    workspace: Path,
) -> tuple[list[DriftFinding], list[DriftFinding]]:
    """
    Split findings into (active, suppressed) based on the ignore list.

    Returns:
        active     — findings not in the ignore list
        suppressed — findings matched by an ignore entry
    """
    ignores = load_ignores(workspace)
    ignored_resources = {i["resource"] for i in ignores}

    active = []
    suppressed = []

    for finding in findings:
        addr = f"{finding.resource_type}.{finding.resource_name}"
        if addr in ignored_resources:
            suppressed.append(finding)
        else:
            active.append(finding)

    return active, suppressed


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


def _save_ignores(ignores: list[dict], workspace: Path) -> None:
    ignore_path = workspace / IGNORE_FILE
    ignore_path.parent.mkdir(parents=True, exist_ok=True)
    ignore_path.write_text(yaml.dump({"ignores": ignores}, default_flow_style=False))
