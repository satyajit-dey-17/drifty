"""
runner.py — safe Terragrunt/Terraform subprocess execution.

Execution model (Phase 1, serial):
  1. check_terragrunt_binary()   — fail fast before touching any unit
  2. For each TerragruntUnit:
       a. terragrunt init --terragrunt-non-interactive
       b. terragrunt plan -refresh-only -json -no-color
       c. Parse stdout JSON Lines via existing drifty.scanner._parse_output()
       d. Score each finding via existing drifty.scorer.score()
       e. Return UnitScanResult

Security invariants (enforced, never relaxed):
  - subprocess.run() is always called with a list argument — shell=True is NEVER used.
  - shutil.which() validates the binary before any execution.
  - All calls have an explicit timeout.
  - No apply, destroy, or state-mutating commands are ever issued.

Phase 2 extension point:
  scan_all_units() accepts max_workers: int | None = None.
  In Phase 1 this parameter is ignored and execution is always serial.
  Phase 2 wraps the loop body in concurrent.futures.ThreadPoolExecutor
  without changing the function signature or the UnitScanResult data model.
"""

from __future__ import annotations

import re as _re
import shutil
import subprocess
import time
from pathlib import Path

from rich.console import Console

from drifty.scanner import _parse_output
from drifty.scorer import score
from drifty.terragrunt.models import TerragruntUnit, UnitScanResult

err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TerragruntBinaryError(RuntimeError):
    """Raised when the terragrunt binary cannot be found on PATH."""


class TerragruntUnitError(RuntimeError):
    """Raised when a unit fails in a way that should abort the scan (--fail-fast)."""


# ---------------------------------------------------------------------------
# Binary validation
# ---------------------------------------------------------------------------


def check_terragrunt_binary() -> str:
    """
    Verify that `terragrunt` is installed and executable.

    Returns the resolved binary path on success.
    Raises TerragruntBinaryError with an actionable message on failure.
    """
    binary = shutil.which("terragrunt")
    if binary is None:
        raise TerragruntBinaryError(
            "terragrunt binary not found on PATH.\n"
            "  Install: https://terragrunt.gruntwork.io/docs/getting-started/install/\n"
            "  Ensure terragrunt is on your shell PATH before running drifty terragrunt scan."
        )
    return binary


# ---------------------------------------------------------------------------
# Single-unit scan
# ---------------------------------------------------------------------------


def scan_unit(
    unit: TerragruntUnit,
    *,
    profile: str | None = None,
    attribute: bool = False,
    min_severity: str | None = None,
    unit_timeout: int = 300,
    config_overrides: dict[str, str] | None = None,
) -> UnitScanResult:
    """
    Scan a single TerragruntUnit for drift.

    Runs `terragrunt init` then `terragrunt plan -refresh-only -json`,
    parses output with the existing drifty.scanner._parse_output(), and
    scores each finding with drifty.scorer.score().

    All subprocess calls use argument lists (shell=False) with explicit timeouts.
    On any failure the unit is marked status='failed' and scanning continues
    (partial failure model). The caller decides whether to abort via fail_fast.
    """
    start = time.monotonic()

    # --- Step 1: terragrunt init ---
    init_failure = _run_init(
        ["terragrunt", "init", "-input=false"],
        cwd=unit.path,
        timeout=unit_timeout,
        unit=unit,
    )
    if init_failure is not None:
        return init_failure

    # --- Step 2: terragrunt plan -refresh-only -json ---
    plan_outcome = _run_plan(
        [
            "terragrunt",
            "plan",
            "-refresh-only",
            "-json",
            "-no-color",
        ],
        cwd=unit.path,
        timeout=unit_timeout,
        unit=unit,
    )
    if isinstance(plan_outcome, UnitScanResult):
        return plan_outcome

    returncode, stdout, stderr = plan_outcome

    # Terraform plan exit codes:
    #   0 = no changes, 1 = error, 2 = changes present (drift detected)
    # exit 1 is a genuine failure; exit 0 and 2 both proceed to parsing.
    if returncode == 1:
        duration = time.monotonic() - start
        msg = _extract_error_message(stderr, stdout)
        err_console.print(
            f"[red]✗ Plan failed for unit:[/red] [bold]{unit.rel_path}[/bold]\n" f"  {msg}"
        )
        return UnitScanResult(
            unit=unit,
            status="failed",
            findings=[],
            suppressed=[],
            error_message=msg,
            duration_seconds=duration,
        )

    # --- Step 3: parse JSON Lines output ---
    lines = stdout.splitlines()
    try:
        raw_findings = _parse_output(lines)
    except Exception as exc:  # noqa: BLE001
        duration = time.monotonic() - start
        msg = f"Failed to parse plan output: {exc}"
        err_console.print(
            f"[red]✗ Parse error for unit:[/red] [bold]{unit.rel_path}[/bold]\n  {msg}"
        )
        return UnitScanResult(
            unit=unit,
            status="failed",
            findings=[],
            suppressed=[],
            error_message=msg,
            duration_seconds=duration,
        )

    # --- Step 4: score findings ---
    for finding in raw_findings:
        finding.severity = score(finding, config_overrides)

    # --- Step 5: apply min_severity filter ---
    if min_severity:
        from drifty.scorer import meets_threshold

        raw_findings = [f for f in raw_findings if meets_threshold(f.severity, min_severity)]

    duration = time.monotonic() - start
    status: str = "drifted" if raw_findings else "success"

    return UnitScanResult(
        unit=unit,
        status=status,
        findings=raw_findings,
        suppressed=[],
        error_message=None,
        duration_seconds=duration,
    )


# ---------------------------------------------------------------------------
# Multi-unit orchestration
# ---------------------------------------------------------------------------


def scan_all_units(
    units: list[TerragruntUnit],
    *,
    profile: str | None = None,
    attribute: bool = False,
    min_severity: str | None = None,
    unit_timeout: int = 300,
    config_overrides: dict[str, str] | None = None,
    fail_fast: bool = False,
    max_workers: int | None = None,  # Phase 2 extension point — ignored in Phase 1
) -> list[UnitScanResult]:
    """
    Scan all units serially and return results sorted by rel_path.

    fail_fast=True stops after the first failed unit (not drifted — only failed).
    max_workers is reserved for Phase 2 concurrent execution; ignored in Phase 1.
    """
    sorted_units = sorted(units, key=lambda u: u.rel_path)
    results: list[UnitScanResult] = []

    for unit in sorted_units:
        result = scan_unit(
            unit,
            profile=profile,
            attribute=attribute,
            min_severity=min_severity,
            unit_timeout=unit_timeout,
            config_overrides=config_overrides,
        )
        results.append(result)

        if fail_fast and result.status == "failed":
            break

    return results


# ---------------------------------------------------------------------------
# Internal subprocess helpers
# ---------------------------------------------------------------------------


def _run_init(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int,
    unit: TerragruntUnit,
) -> UnitScanResult | None:
    """
    Run an init-style command (non-zero exit is always an error).

    Returns:
      None            — success, caller should proceed
      UnitScanResult  — failure, caller should return this immediately
    """
    outcome = _run_subprocess(cmd, cwd=cwd, timeout=timeout, unit=unit, allow_nonzero=False)
    if isinstance(outcome, UnitScanResult):
        return outcome
    return None


def _run_plan(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int,
    unit: TerragruntUnit,
) -> UnitScanResult | tuple[int, str, str]:
    """
    Run a plan-style command (non-zero exit may be meaningful, not always an error).

    Returns:
      tuple(returncode, stdout, stderr)  — subprocess completed; caller interprets exit code
      UnitScanResult                     — subprocess-level failure (missing binary, timeout)
    """
    return _run_subprocess(cmd, cwd=cwd, timeout=timeout, unit=unit, allow_nonzero=True)


def _run_subprocess(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int,
    unit: TerragruntUnit,
    allow_nonzero: bool = False,
) -> UnitScanResult | tuple[int, str, str]:
    """
    Core subprocess wrapper. shell=False always — never shell=True.

    Returns:
      tuple(returncode, stdout, stderr)  on completion (allow_nonzero=True or returncode==0)
      UnitScanResult(status='failed')    on FileNotFoundError, TimeoutExpired, or
                                         non-zero exit when allow_nonzero=False
    """
    try:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError:
        msg = (
            f"Binary not found: '{cmd[0]}'. "
            "Ensure terragrunt and terraform are installed and on PATH."
        )
        err_console.print(
            f"[red]✗ Binary missing for unit:[/red] [bold]{unit.rel_path}[/bold]\n  {msg}"
        )
        return UnitScanResult(
            unit=unit,
            status="failed",
            findings=[],
            suppressed=[],
            error_message=msg,
            duration_seconds=0.0,
        )
    except subprocess.TimeoutExpired:
        msg = (
            f"Command timed out after {timeout}s: {' '.join(cmd)}\n"
            "  Increase --unit-timeout if this unit is slow to initialise."
        )
        err_console.print(
            f"[yellow]⚠ Timeout for unit:[/yellow] [bold]{unit.rel_path}[/bold]\n  {msg}"
        )
        return UnitScanResult(
            unit=unit,
            status="failed",
            findings=[],
            suppressed=[],
            error_message=msg,
            duration_seconds=float(timeout),
        )

    if not allow_nonzero and completed.returncode != 0:
        msg = _extract_error_message(completed.stderr, completed.stdout)
        err_console.print(
            f"[red]✗ Command failed for unit:[/red] [bold]{unit.rel_path}[/bold]\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  {msg}"
        )
        return UnitScanResult(
            unit=unit,
            status="failed",
            findings=[],
            suppressed=[],
            error_message=msg,
            duration_seconds=0.0,
        )

    return (completed.returncode, completed.stdout, completed.stderr)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


_LOG_PREFIX = _re.compile(r"^\d{2}:\d{2}:\d{2}\.\d+\s+(WARN|INFO|DEBUG|ERROR|STDOUT|STDERR)\s+")


def _extract_error_message(stderr: str, stdout: str) -> str:
    for source in (stderr, stdout):
        for line in source.splitlines():
            stripped = line.strip()
            # Skip empty, JSON, and Terragrunt log-prefixed lines
            if not stripped:
                continue
            if stripped.startswith("{"):
                continue
            if _LOG_PREFIX.match(stripped):
                continue
            return stripped[:300]
    return "Command failed with no diagnostic output."
