from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(".drifty")
STATE_FILE = STATE_DIR / "state.json"


def _hash_finding(finding) -> str:
    stable = json.dumps(
        {
            "resource_type": finding.resource_type,
            "resource_name": finding.resource_name,
            "resource_id": finding.resource_id,
            "changed_attributes": finding.changed_attributes,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(stable.encode()).hexdigest()


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"last_scan": None, "known_findings": {}}
    with STATE_FILE.open() as f:
        return json.load(f)


def save_state(known_findings: dict) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    state = {
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "known_findings": known_findings,
    }
    with STATE_FILE.open("w") as f:
        json.dump(state, f, indent=2)


def diff_findings(new_findings: list, state: dict) -> list:
    known = state.get("known_findings", {})
    return [
        f
        for f in new_findings
        if known.get(f"{f.resource_type}.{f.resource_name}") != _hash_finding(f)
    ]


def build_known_findings(findings: list) -> dict:
    return {f"{f.resource_type}.{f.resource_name}": _hash_finding(f) for f in findings}
