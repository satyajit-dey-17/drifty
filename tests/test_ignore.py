"""
tests/test_ignore.py — Unit tests for drifty/ignore.py
"""

from __future__ import annotations

from drifty.ignore import (
    _save_ignores,
    add_ignore,
    filter_findings,
    load_ignores,
    remove_ignore,
)
from drifty.scanner import DriftFinding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(
    resource_type: str = "aws_instance",
    resource_name: str = "api_server",
    severity: str = "high",
) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name=resource_name,
        resource_id="i-0abc1234",
        severity=severity,
        changed_attributes=[
            {"attribute": "instance_type", "before": "t3.medium", "after": "t3.large"}
        ],
        remediation_hint="terraform import aws_instance.api_server i-0abc1234",
    )


# ---------------------------------------------------------------------------
# load_ignores
# ---------------------------------------------------------------------------


def test_load_ignores_no_file(tmp_path):
    assert load_ignores(tmp_path) == []


def test_load_ignores_empty_file(tmp_path):
    ignore_path = tmp_path / ".drifty" / "ignore.yaml"
    ignore_path.parent.mkdir(parents=True)
    ignore_path.write_text("")
    assert load_ignores(tmp_path) == []


def test_load_ignores_invalid_yaml(tmp_path):
    ignore_path = tmp_path / ".drifty" / "ignore.yaml"
    ignore_path.parent.mkdir(parents=True)
    ignore_path.write_text("{{invalid: yaml: content")
    assert load_ignores(tmp_path) == []


def test_load_ignores_valid(tmp_path):
    _save_ignores([{"resource": "aws_instance.api_server", "reason": "approved"}], tmp_path)
    ignores = load_ignores(tmp_path)
    assert len(ignores) == 1
    assert ignores[0]["resource"] == "aws_instance.api_server"


# ---------------------------------------------------------------------------
# add_ignore
# ---------------------------------------------------------------------------


def test_add_ignore_creates_file(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    ignore_path = tmp_path / ".drifty" / "ignore.yaml"
    assert ignore_path.exists()


def test_add_ignore_persists_entry(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path, reason="approved")
    ignores = load_ignores(tmp_path)
    assert ignores[0]["resource"] == "aws_instance.api_server"
    assert ignores[0]["reason"] == "approved"


def test_add_ignore_sets_ignored_by(tmp_path, monkeypatch):
    monkeypatch.setenv("USER", "satyajit")
    add_ignore("aws_instance.api_server", tmp_path)
    ignores = load_ignores(tmp_path)
    assert ignores[0]["ignored_by"] == "satyajit"


def test_add_ignore_no_duplicate(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    add_ignore("aws_instance.api_server", tmp_path)
    assert len(load_ignores(tmp_path)) == 1


def test_add_ignore_multiple_resources(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    add_ignore("aws_security_group.main", tmp_path)
    assert len(load_ignores(tmp_path)) == 2


# ---------------------------------------------------------------------------
# remove_ignore
# ---------------------------------------------------------------------------


def test_remove_ignore_returns_true_when_found(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    assert remove_ignore("aws_instance.api_server", tmp_path) is True


def test_remove_ignore_returns_false_when_not_found(tmp_path):
    assert remove_ignore("aws_instance.api_server", tmp_path) is False


def test_remove_ignore_deletes_entry(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    add_ignore("aws_security_group.main", tmp_path)
    remove_ignore("aws_instance.api_server", tmp_path)
    ignores = load_ignores(tmp_path)
    assert len(ignores) == 1
    assert ignores[0]["resource"] == "aws_security_group.main"


# ---------------------------------------------------------------------------
# filter_findings
# ---------------------------------------------------------------------------


def test_filter_findings_no_ignores(tmp_path):
    findings = [_finding(), _finding("aws_security_group", "main")]
    active, suppressed = filter_findings(findings, tmp_path)
    assert len(active) == 2
    assert len(suppressed) == 0


def test_filter_findings_suppresses_ignored(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    findings = [_finding(), _finding("aws_security_group", "main")]
    active, suppressed = filter_findings(findings, tmp_path)
    assert len(active) == 1
    assert len(suppressed) == 1
    assert suppressed[0].resource_name == "api_server"


def test_filter_findings_all_suppressed(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    findings = [_finding()]
    active, suppressed = filter_findings(findings, tmp_path)
    assert active == []
    assert len(suppressed) == 1


def test_filter_findings_empty_input(tmp_path):
    active, suppressed = filter_findings([], tmp_path)
    assert active == []
    assert suppressed == []


def test_filter_findings_partial_match(tmp_path):
    add_ignore("aws_instance.api_server", tmp_path)
    findings = [
        _finding("aws_instance", "api_server"),
        _finding("aws_instance", "db_server"),
        _finding("aws_security_group", "main"),
    ]
    active, suppressed = filter_findings(findings, tmp_path)
    assert len(active) == 2
    assert len(suppressed) == 1
