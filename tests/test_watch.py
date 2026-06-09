from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from drifty.scanner import DriftFinding
from drifty.watch import _meets_threshold, _run_cycle


@pytest.fixture
def critical_finding():
    return DriftFinding(
        resource_type="aws_security_group",
        resource_name="main",
        resource_id="sg-0abc1234",
        changed_attributes=[{"attribute": "ingress", "before": "10.0.0.0/8", "after": "0.0.0.0/0"}],
        severity="critical",
        attributed_to=None,
        attributed_at=None,
        attributed_action=None,
        remediation_hint="terraform import aws_security_group.main sg-0abc1234",
    )


@pytest.fixture
def low_finding():
    return DriftFinding(
        resource_type="aws_s3_bucket",
        resource_name="assets",
        resource_id="assets-bucket-prod",
        changed_attributes=[
            {"attribute": "tags.LastModified", "before": "2026-05-15", "after": "2026-06-01"}
        ],
        severity="low",
        attributed_to=None,
        attributed_at=None,
        attributed_action=None,
        remediation_hint=None,
    )


# ---------------------------------------------------------------------------
# _meets_threshold
# ---------------------------------------------------------------------------


def test_meets_threshold_exact_match(critical_finding):
    assert _meets_threshold(critical_finding, "critical") is True


def test_meets_threshold_above(critical_finding):
    assert _meets_threshold(critical_finding, "low") is True


def test_meets_threshold_below(low_finding):
    assert _meets_threshold(low_finding, "high") is False


def test_meets_threshold_equal(low_finding):
    assert _meets_threshold(low_finding, "low") is True


# ---------------------------------------------------------------------------
# _run_cycle
# ---------------------------------------------------------------------------


def test_run_cycle_no_new_drift(tmp_path, monkeypatch, critical_finding):
    monkeypatch.chdir(tmp_path)
    mock_scan = MagicMock(return_value=([critical_finding], []))

    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="low",
        notifier=None,
        run_scan=mock_scan,
    )

    notifier = MagicMock()
    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="low",
        notifier=notifier,
        run_scan=mock_scan,
    )

    notifier.send.assert_not_called()


def test_run_cycle_new_drift_triggers_notifier(
    tmp_path, monkeypatch, critical_finding, low_finding
):
    monkeypatch.chdir(tmp_path)

    mock_scan = MagicMock(return_value=([low_finding], []))
    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="low",
        notifier=None,
        run_scan=mock_scan,
    )

    mock_scan.return_value = ([low_finding, critical_finding], [])
    notifier = MagicMock()
    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="low",
        notifier=notifier,
        run_scan=mock_scan,
    )

    notifier.send.assert_called_once()
    sent = notifier.send.call_args[0][0]
    assert len(sent) == 1
    assert sent[0].resource_name == "main"


def test_run_cycle_threshold_filters_notifier(tmp_path, monkeypatch, low_finding):
    monkeypatch.chdir(tmp_path)
    mock_scan = MagicMock(return_value=([low_finding], []))
    notifier = MagicMock()

    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="high",
        notifier=notifier,
        run_scan=mock_scan,
    )

    notifier.send.assert_not_called()


def test_run_cycle_scan_failure_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_scan = MagicMock(side_effect=RuntimeError("terraform not found"))
    notifier = MagicMock()

    # Should not raise
    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="low",
        notifier=notifier,
        run_scan=mock_scan,
    )

    notifier.send.assert_not_called()


def test_run_cycle_saves_state_after_scan(tmp_path, monkeypatch, critical_finding):
    monkeypatch.chdir(tmp_path)
    mock_scan = MagicMock(return_value=([critical_finding], []))

    _run_cycle(
        workspace=tmp_path,
        profile="default",
        attribute=False,
        threshold="low",
        notifier=None,
        run_scan=mock_scan,
    )

    state_file = tmp_path / ".drifty" / "state.json"
    assert state_file.exists()
