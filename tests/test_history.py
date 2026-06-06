"""
tests/test_history.py — Unit tests for drifty/history.py
"""

from __future__ import annotations

import json

from drifty.history import (
    _count_by_severity,
    _load_raw,
    append_findings,
    load_history,
    most_drifted_resources,
)
from drifty.scanner import DriftFinding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(
    severity: str = "high",
    resource_type: str = "aws_instance",
    resource_name: str = "api_server",
    resource_id: str = "i-0abc1234",
) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name=resource_name,
        resource_id=resource_id,
        severity=severity,
        changed_attributes=[
            {"attribute": "instance_type", "before": "t3.medium", "after": "t3.large"}
        ],
        remediation_hint="terraform import aws_instance.api_server i-0abc1234",
    )


# ---------------------------------------------------------------------------
# append_findings
# ---------------------------------------------------------------------------


def test_append_creates_history_file(tmp_path):
    append_findings([_finding()], tmp_path)
    history_file = tmp_path / ".drifty" / "history.json"
    assert history_file.exists()


def test_append_zero_findings_still_writes(tmp_path):
    append_findings([], tmp_path)
    history_file = tmp_path / ".drifty" / "history.json"
    data = json.loads(history_file.read_text())
    assert len(data) == 1
    assert data[0]["total"] == 0


def test_append_multiple_scans_accumulate(tmp_path):
    append_findings([_finding("critical")], tmp_path)
    append_findings([_finding("high"), _finding("low")], tmp_path)
    history = load_history(tmp_path, last=10)
    assert len(history) == 2


def test_append_severity_counts_correct(tmp_path):
    findings = [_finding("critical"), _finding("critical"), _finding("low")]
    append_findings(findings, tmp_path)
    history_file = tmp_path / ".drifty" / "history.json"
    data = json.loads(history_file.read_text())
    entry = data[0]
    assert entry["critical"] == 2
    assert entry["low"] == 1
    assert entry["high"] == 0
    assert entry["total"] == 3


def test_append_serializes_findings(tmp_path):
    append_findings([_finding()], tmp_path)
    history_file = tmp_path / ".drifty" / "history.json"
    data = json.loads(history_file.read_text())
    assert data[0]["findings"][0]["resource_type"] == "aws_instance"


def test_append_creates_drifty_dir_if_missing(tmp_path):
    workspace = tmp_path / "myproject"
    workspace.mkdir()
    append_findings([], workspace)
    assert (workspace / ".drifty" / "history.json").exists()


# ---------------------------------------------------------------------------
# load_history
# ---------------------------------------------------------------------------


def test_load_history_empty_when_no_file(tmp_path):
    assert load_history(tmp_path) == []


def test_load_history_returns_newest_first(tmp_path):
    append_findings([_finding("critical")], tmp_path)
    append_findings([_finding("low")], tmp_path)
    history = load_history(tmp_path, last=10)
    assert history[0]["findings"][0]["severity"] == "low"
    assert history[1]["findings"][0]["severity"] == "critical"


def test_load_history_respects_last_param(tmp_path):
    for _ in range(5):
        append_findings([_finding()], tmp_path)
    history = load_history(tmp_path, last=3)
    assert len(history) == 3


def test_load_history_corrupted_file_returns_empty(tmp_path):
    history_path = tmp_path / ".drifty" / "history.json"
    history_path.parent.mkdir(parents=True)
    history_path.write_text("not valid json{{{")
    assert load_history(tmp_path) == []


# ---------------------------------------------------------------------------
# most_drifted_resources
# ---------------------------------------------------------------------------


def test_most_drifted_resources_empty(tmp_path):
    assert most_drifted_resources(tmp_path) == []


def test_most_drifted_resources_counts(tmp_path):
    append_findings([_finding("high", resource_name="server_a")], tmp_path)
    append_findings([_finding("high", resource_name="server_a")], tmp_path)
    append_findings([_finding("low", resource_name="server_b")], tmp_path)
    top = most_drifted_resources(tmp_path, last=10)
    assert top[0]["addr"] == "aws_instance.server_a"
    assert top[0]["count"] == 2
    assert top[1]["addr"] == "aws_instance.server_b"


def test_most_drifted_resources_severity_escalation(tmp_path):
    """If same resource drifts at low then critical, severity should escalate to critical."""
    append_findings([_finding("low", resource_name="server_a")], tmp_path)
    append_findings([_finding("critical", resource_name="server_a")], tmp_path)
    top = most_drifted_resources(tmp_path, last=10)
    assert top[0]["severity"] == "critical"


def test_most_drifted_resources_sorted_descending(tmp_path):
    append_findings([_finding(resource_name="rarely")], tmp_path)
    for _ in range(4):
        append_findings([_finding(resource_name="often")], tmp_path)
    top = most_drifted_resources(tmp_path, last=10)
    assert top[0]["addr"] == "aws_instance.often"


# ---------------------------------------------------------------------------
# _count_by_severity
# ---------------------------------------------------------------------------


def test_count_by_severity_mixed():
    findings = [_finding("critical"), _finding("critical"), _finding("low")]
    counts = _count_by_severity(findings)
    assert counts["critical"] == 2
    assert counts["low"] == 1
    assert counts.get("high", 0) == 0


def test_count_by_severity_empty():
    assert _count_by_severity([]) == {}


# ---------------------------------------------------------------------------
# _load_raw
# ---------------------------------------------------------------------------


def test_load_raw_missing_file(tmp_path):
    assert _load_raw(tmp_path / "nonexistent.json") == []


def test_load_raw_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid}")
    assert _load_raw(bad) == []


def test_load_raw_non_list_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"key": "value"}')
    assert _load_raw(bad) == []
