"""
CLI-level tests for `drifty terragrunt` sub-commands.
Uses typer.testing.CliRunner — no real binaries required.
"""

from __future__ import annotations

import re
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

pytest.importorskip("drifty.terragrunt.cli")

from drifty.cli import app
from drifty.terragrunt.models import TerragruntUnit, UnitScanResult, TerragruntScanReport

runner = CliRunner()

MONOREPO = Path(__file__).parent / "fixtures" / "terragrunt_monorepo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_unit(tmp_path: Path, rel: str) -> TerragruntUnit:
    unit_path = tmp_path / rel
    unit_path.mkdir(parents=True, exist_ok=True)
    hcl = unit_path / "terragrunt.hcl"
    hcl.write_text('terraform {\n  source = "."\n}\n')
    return TerragruntUnit(
        path=unit_path,
        rel_path=rel,
        hcl_file=hcl,
        is_runnable=True,
        env_hint=None,
    )


def _clean_result(unit: TerragruntUnit) -> UnitScanResult:
    return UnitScanResult(
        unit=unit,
        status="success",
        findings=[],
        suppressed=[],
        error_message=None,
        duration_seconds=0.1,
    )


def _failed_result(unit: TerragruntUnit, msg: str = "init failed") -> UnitScanResult:
    return UnitScanResult(
        unit=unit,
        status="failed",
        findings=[],
        suppressed=[],
        error_message=msg,
        duration_seconds=0.0,
    )


# ---------------------------------------------------------------------------
# discover subcommand
# ---------------------------------------------------------------------------


class TestTerragruntDiscover:
    def test_discover_lists_units(self):
        result = runner.invoke(app, ["terragrunt", "discover", "--root", str(MONOREPO)])
        assert result.exit_code == 0
        assert "networking" in result.output

    def test_discover_invalid_root_exits_2(self, tmp_path):
        nonexistent = str(tmp_path / "does_not_exist")
        result = runner.invoke(app, ["terragrunt", "discover", "--root", nonexistent])
        assert result.exit_code == 2

    def test_discover_empty_dir_exits_0(self, tmp_path):
        result = runner.invoke(app, ["terragrunt", "discover", "--root", str(tmp_path)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# scan --discover-only
# ---------------------------------------------------------------------------


class TestTerragruntScanDiscoverOnly:
    def test_discover_only_exits_0(self):
        result = runner.invoke(
            app,
            ["terragrunt", "scan", "--root", str(MONOREPO), "--discover-only"],
        )
        assert result.exit_code == 0

    def test_discover_only_does_not_call_subprocess(self):
        with patch("subprocess.run") as mock_sub:
            runner.invoke(
                app,
                ["terragrunt", "scan", "--root", str(MONOREPO), "--discover-only"],
            )
            mock_sub.assert_not_called()


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_exit_0_when_no_drift(self, tmp_path):
        unit = _make_unit(tmp_path, "envs/prod/networking")
        result_obj = _clean_result(unit)

        with patch("drifty.terragrunt.cli.check_terragrunt_binary"):
            with patch("drifty.terragrunt.cli.scan_all_units", return_value=[result_obj]):
                with patch("drifty.terragrunt.cli.discover_units", return_value=[unit]):
                    r = runner.invoke(app, ["terragrunt", "scan", "--root", str(tmp_path)])
        assert r.exit_code == 0

    def test_exit_1_when_drift_found(self, tmp_path):
        from drifty.scanner import DriftFinding

        unit = _make_unit(tmp_path, "envs/prod/networking")
        finding = DriftFinding(
            resource_type="aws_security_group",
            resource_name="main",
            resource_id="sg-abc",
            changed_attributes=[{"attribute": "ingress", "before": [], "after": []}],
            severity="critical",
        )
        result_obj = UnitScanResult(
            unit=unit,
            status="drifted",
            findings=[finding],
            suppressed=[],
            error_message=None,
            duration_seconds=0.5,
        )

        with patch("drifty.terragrunt.cli.check_terragrunt_binary"):
            with patch("drifty.terragrunt.cli.scan_all_units", return_value=[result_obj]):
                with patch("drifty.terragrunt.cli.discover_units", return_value=[unit]):
                    r = runner.invoke(app, ["terragrunt", "scan", "--root", str(tmp_path)])
        assert r.exit_code == 1

    def test_exit_2_when_binary_missing(self, tmp_path):
        from drifty.terragrunt.runner import TerragruntBinaryError

        unit = _make_unit(tmp_path, "envs/prod/networking")
        with patch(
            "drifty.terragrunt.cli.check_terragrunt_binary",
            side_effect=TerragruntBinaryError("terragrunt not found"),
        ):
            with patch("drifty.terragrunt.cli.discover_units", return_value=[unit]):
                r = runner.invoke(app, ["terragrunt", "scan", "--root", str(tmp_path)])
        assert r.exit_code == 2

    def test_exit_2_when_all_units_failed(self, tmp_path):
        units = [_make_unit(tmp_path, f"envs/prod/unit{i}") for i in range(2)]
        results = [_failed_result(u) for u in units]

        with patch("drifty.terragrunt.cli.check_terragrunt_binary"):
            with patch("drifty.terragrunt.cli.scan_all_units", return_value=results):
                with patch("drifty.terragrunt.cli.discover_units", return_value=units):
                    r = runner.invoke(app, ["terragrunt", "scan", "--root", str(tmp_path)])
        assert r.exit_code == 2

    def test_exit_3_when_partial_failure(self, tmp_path):
        units = [_make_unit(tmp_path, f"envs/prod/unit{i}") for i in range(2)]
        results = [_clean_result(units[0]), _failed_result(units[1])]

        with patch("drifty.terragrunt.cli.check_terragrunt_binary"):
            with patch("drifty.terragrunt.cli.scan_all_units", return_value=results):
                with patch("drifty.terragrunt.cli.discover_units", return_value=units):
                    r = runner.invoke(app, ["terragrunt", "scan", "--root", str(tmp_path)])
        assert r.exit_code == 3


class TestJsonOutput:
    def test_json_output_valid_schema(self, tmp_path):
        unit = _make_unit(tmp_path, "envs/prod/networking")
        result_obj = _clean_result(unit)

        with patch("drifty.terragrunt.cli.check_terragrunt_binary"):
            with patch("drifty.terragrunt.cli.scan_all_units", return_value=[result_obj]):
                with patch("drifty.terragrunt.cli.discover_units", return_value=[unit]):
                    r = runner.invoke(
                        app,
                        ["terragrunt", "scan", "--root", str(tmp_path), "--output", "json"],
                    )

        assert r.exit_code == 0
        data = json.loads(r.output)
        assert "scan_time" in data
        assert "total_units" in data
        assert "unit_results" in data
        assert isinstance(data["unit_results"], list)
        
# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_json_output_valid_schema(self, tmp_path):
        unit = _make_unit(tmp_path, "envs/prod/networking")
        result_obj = _clean_result(unit)

        with patch("drifty.terragrunt.cli.check_terragrunt_binary"):
            with patch("drifty.terragrunt.cli.scan_all_units", return_value=[result_obj]):
                with patch("drifty.terragrunt.cli.discover_units", return_value=[unit]):
                    r = runner.invoke(
                        app,
                        ["terragrunt", "scan", "--root", str(tmp_path), "--output", "json"],
                    )

        assert r.exit_code == 0
        data = json.loads(r.output)
        assert "scan_time" in data
        assert "total_units" in data
        assert "unit_results" in data
        assert isinstance(data["unit_results"], list)

# ---------------------------------------------------------------------------
# Regression: existing commands unaffected
# ---------------------------------------------------------------------------


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class TestRegressionExistingCommands:
    def test_scan_help_still_works(self):
        r = runner.invoke(app, ["scan", "--help"])
        output = _strip_ansi(r.output)
        assert r.exit_code == 0
        assert "--workspace" in output
        assert "--attribute" in output

    def test_terragrunt_does_not_add_flags_to_scan(self):
        r = runner.invoke(app, ["scan", "--help"])
        output = _strip_ansi(r.output)
        assert "--root" not in output
        assert "--discover-only" not in output

    def test_drifty_help_shows_terragrunt(self):
        r = runner.invoke(app, ["--help"])
        output = _strip_ansi(r.output)
        assert r.exit_code == 0
        assert "terragrunt" in output