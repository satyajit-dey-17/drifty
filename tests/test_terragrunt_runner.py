"""
Tests for drifty/terragrunt/runner.py

All subprocess calls are mocked — no real Terragrunt, Terraform, or AWS.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("drifty.terragrunt.runner")

from drifty.terragrunt.models import TerragruntUnit
from drifty.terragrunt.runner import check_terragrunt_binary, scan_unit, scan_all_units


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECURITY_GROUP_DRIFT_LINE = json.dumps({
    "type": "resource_drift",
    "change": {
        "resource": {
            "addr": "aws_security_group.main",
            "resource_type": "aws_security_group",
            "resource_name": "main",
            "provider_name": "registry.terraform.io/hashicorp/aws",
        },
        "action": "update",
        "before": {"id": "sg-0abc1234", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
        "after": {"id": "sg-0abc1234", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
    },
})

CLEAN_LINE = json.dumps({"type": "version", "terraform": "1.7.0"})


def _make_unit(tmp_path: Path, rel: str = "envs/prod/networking") -> TerragruntUnit:
    unit_path = tmp_path / rel
    unit_path.mkdir(parents=True, exist_ok=True)
    hcl = unit_path / "terragrunt.hcl"
    hcl.write_text('terraform {\n  source = "git::https://example.com/mod"\n}\n')
    return TerragruntUnit(
        path=unit_path,
        rel_path=rel,
        hcl_file=hcl,
        is_runnable=True,
        env_hint="prod",
    )


# ---------------------------------------------------------------------------
# Binary check
# ---------------------------------------------------------------------------


class TestCheckTerragruntBinary:
    def test_raises_when_binary_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(Exception, match="terragrunt"):
                check_terragrunt_binary()

    def test_passes_when_binary_present(self):
        with patch("shutil.which", return_value="/usr/local/bin/terragrunt"):
            check_terragrunt_binary()  # should not raise


# ---------------------------------------------------------------------------
# scan_unit — successful cases
# ---------------------------------------------------------------------------


class TestScanUnitSuccess:
    def test_clean_unit_returns_success_status(self, tmp_path):
        unit = _make_unit(tmp_path)
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = CLEAN_LINE + "\n"
        mock_completed.stderr = ""

        with patch("subprocess.run", return_value=mock_completed):
            result = scan_unit(unit)

        assert result.status == "success"
        assert result.findings == []
        assert result.error_message is None

    def test_drifted_unit_returns_drifted_status(self, tmp_path):
        unit = _make_unit(tmp_path)
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = SECURITY_GROUP_DRIFT_LINE + "\n"
        mock_completed.stderr = ""

        with patch("subprocess.run", return_value=mock_completed):
            result = scan_unit(unit)

        assert result.status == "drifted"
        assert len(result.findings) == 1
        assert result.findings[0].resource_type == "aws_security_group"

    def test_duration_is_recorded(self, tmp_path):
        unit = _make_unit(tmp_path)
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = CLEAN_LINE
        mock_completed.stderr = ""

        with patch("subprocess.run", return_value=mock_completed):
            result = scan_unit(unit)

        assert result.duration_seconds >= 0.0


# ---------------------------------------------------------------------------
# scan_unit — failure cases
# ---------------------------------------------------------------------------


class TestScanUnitFailure:
    def test_init_nonzero_returns_failed(self, tmp_path):
        unit = _make_unit(tmp_path)
        mock_fail = MagicMock()
        mock_fail.returncode = 1
        mock_fail.stdout = ""
        mock_fail.stderr = "Error: Could not load plugin"

        with patch("subprocess.run", return_value=mock_fail):
            result = scan_unit(unit)

        assert result.status == "failed"
        assert result.error_message is not None
        assert len(result.findings) == 0

    def test_timeout_returns_failed_with_message(self, tmp_path):
        import subprocess
        unit = _make_unit(tmp_path)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="terragrunt", timeout=300)):
            result = scan_unit(unit)

        assert result.status == "failed"
        assert "timeout" in result.error_message.lower()

    def test_binary_not_found_returns_failed(self, tmp_path):
        unit = _make_unit(tmp_path)

        with patch("subprocess.run", side_effect=FileNotFoundError("terragrunt not found")):
            result = scan_unit(unit)

        assert result.status == "failed"
        assert result.error_message is not None


# ---------------------------------------------------------------------------
# scan_all_units — aggregation
# ---------------------------------------------------------------------------


class TestScanAllUnits:
    def test_returns_results_for_all_units(self, tmp_path):
        units = [_make_unit(tmp_path, f"envs/prod/unit{i}") for i in range(3)]
        mock_ok = MagicMock()
        mock_ok.returncode = 0
        mock_ok.stdout = CLEAN_LINE
        mock_ok.stderr = ""

        with patch("subprocess.run", return_value=mock_ok):
            results = scan_all_units(units)

        assert len(results) == 3

    def test_results_sorted_by_rel_path(self, tmp_path):
        # Create units in reverse order to verify sort
        units = [
            _make_unit(tmp_path, "envs/staging/networking"),
            _make_unit(tmp_path, "envs/prod/networking"),
            _make_unit(tmp_path, "envs/prod/compute"),
        ]
        mock_ok = MagicMock()
        mock_ok.returncode = 0
        mock_ok.stdout = CLEAN_LINE
        mock_ok.stderr = ""

        with patch("subprocess.run", return_value=mock_ok):
            results = scan_all_units(units)

        rel_paths = [r.unit.rel_path for r in results]
        assert rel_paths == sorted(rel_paths)

    def test_partial_failure_recorded_correctly(self, tmp_path):
        units = [_make_unit(tmp_path, f"envs/prod/unit{i}") for i in range(3)]
        mock_ok = MagicMock(returncode=0, stdout=CLEAN_LINE, stderr="")
        mock_fail = MagicMock(returncode=1, stdout="", stderr="Error")

        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            # Fail on every call that involves 'unit1'
            cmd = args[0] if args else kwargs.get("args", [])
            cwd = kwargs.get("cwd", "")
            if "unit1" in str(cwd):
                return mock_fail
            return mock_ok

        with patch("subprocess.run", side_effect=side_effect):
            results = scan_all_units(units)

        statuses = [r.status for r in results]
        assert "failed" in statuses
        assert statuses.count("failed") == 1

    def test_fail_fast_stops_after_first_failure(self, tmp_path):
        units = [_make_unit(tmp_path, f"envs/prod/unit{i}") for i in range(5)]
        mock_fail = MagicMock(returncode=1, stdout="", stderr="Error")

        with patch("subprocess.run", return_value=mock_fail):
            results = scan_all_units(units, fail_fast=True)

        # fail_fast: stops after the first failure, so fewer than 5 results
        assert len(results) < 5
        assert results[0].status == "failed"