from __future__ import annotations

import json
from pathlib import Path

import pytest

from drifty.scanner import DriftFinding
from drifty.state import (
    _hash_finding,
    build_known_findings,
    diff_findings,
    load_state,
    save_state,
)


@pytest.fixture
def finding():
    return DriftFinding(
        resource_type="aws_security_group",
        resource_name="main",
        resource_id="sg-0abc1234",
        changed_attributes=[{"attribute": "ingress", "before": "10.0.0.0/8", "after": "0.0.0.0/0"}],
        severity="critical",
        attributed_to="arn:aws:iam::123456789:user/john.doe",
        attributed_at="2026-06-03T14:22:11Z",
        attributed_action="ModifySecurityGroupRules",
        remediation_hint="terraform import aws_security_group.main sg-0abc1234",
    )


@pytest.fixture
def another_finding():
    return DriftFinding(
        resource_type="aws_instance",
        resource_name="api_server",
        resource_id="i-0def5678",
        changed_attributes=[{"attribute": "instance_type", "before": "t3.medium", "after": "t3.large"}],
        severity="high",
        attributed_to=None,
        attributed_at=None,
        attributed_action=None,
        remediation_hint="Update instance_type in main.tf",
    )


# ---------------------------------------------------------------------------
# _hash_finding
# ---------------------------------------------------------------------------

def test_hash_is_deterministic(finding):
    assert _hash_finding(finding) == _hash_finding(finding)


def test_hash_changes_when_attribute_changes(finding):
    original_hash = _hash_finding(finding)
    finding.changed_attributes[0]["after"] = "192.168.0.0/16"
    assert _hash_finding(finding) != original_hash


def test_hash_ignores_attribution_fields(finding):
    h1 = _hash_finding(finding)
    finding.attributed_to = "someone-else"
    finding.attributed_at = "2026-01-01T00:00:00Z"
    assert _hash_finding(finding) == h1


# ---------------------------------------------------------------------------
# load_state
# ---------------------------------------------------------------------------

def test_load_state_returns_empty_default_when_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = load_state()
    assert state == {"last_scan": None, "known_findings": {}}


def test_load_state_reads_existing_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state_dir = tmp_path / ".drifty"
    state_dir.mkdir()
    state_file = state_dir / "state.json"
    state_file.write_text(json.dumps({"last_scan": "2026-06-06T10:00:00Z", "known_findings": {"aws_security_group.main": "abc123"}}))

    state = load_state()
    assert state["known_findings"]["aws_security_group.main"] == "abc123"


# ---------------------------------------------------------------------------
# save_state
# ---------------------------------------------------------------------------

def test_save_state_creates_dir_and_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    save_state({"aws_security_group.main": "abc123"})

    state_file = tmp_path / ".drifty" / "state.json"
    assert state_file.exists()
    data = json.loads(state_file.read_text())
    assert data["known_findings"]["aws_security_group.main"] == "abc123"
    assert data["last_scan"] is not None


def test_save_state_overwrites_existing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    save_state({"aws_security_group.main": "old_hash"})
    save_state({"aws_security_group.main": "new_hash"})

    state_file = tmp_path / ".drifty" / "state.json"
    data = json.loads(state_file.read_text())
    assert data["known_findings"]["aws_security_group.main"] == "new_hash"


# ---------------------------------------------------------------------------
# diff_findings
# ---------------------------------------------------------------------------

def test_diff_returns_all_when_state_empty(finding, another_finding):
    state = {"last_scan": None, "known_findings": {}}
    result = diff_findings([finding, another_finding], state)
    assert len(result) == 2


def test_diff_returns_empty_when_nothing_changed(finding):
    known = build_known_findings([finding])
    state = {"last_scan": "2026-06-06T10:00:00Z", "known_findings": known}
    result = diff_findings([finding], state)
    assert result == []


def test_diff_detects_changed_finding(finding):
    known = build_known_findings([finding])
    state = {"last_scan": "2026-06-06T10:00:00Z", "known_findings": known}
    finding.changed_attributes[0]["after"] = "192.168.0.0/16"
    result = diff_findings([finding], state)
    assert len(result) == 1


def test_diff_detects_new_resource(finding, another_finding):
    known = build_known_findings([finding])
    state = {"last_scan": "2026-06-06T10:00:00Z", "known_findings": known}
    result = diff_findings([finding, another_finding], state)
    assert len(result) == 1
    assert result[0].resource_name == "api_server"


# ---------------------------------------------------------------------------
# build_known_findings
# ---------------------------------------------------------------------------

def test_build_known_findings_keys(finding, another_finding):
    known = build_known_findings([finding, another_finding])
    assert "aws_security_group.main" in known
    assert "aws_instance.api_server" in known


def test_build_known_findings_values_are_hashes(finding):
    known = build_known_findings([finding])
    assert known["aws_security_group.main"] == _hash_finding(finding)