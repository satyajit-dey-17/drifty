"""
cli.py — Typer sub-app for `drifty terragrunt` commands.

Registered into the main drifty app via:
    app.add_typer(terragrunt_app, name="terragrunt")

Commands:
    drifty terragrunt discover   — list discovered units, no terraform execution
    drifty terragrunt scan       — discover and scan all units for drift
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from drifty.config import load_config
from drifty.terragrunt.discovery import discover_units
from drifty.terragrunt.models import TerragruntScanReport
from drifty.terragrunt.reporter import (
    build_report,
    render_discover_table,
    render_json,
    render_terminal,
)
from drifty.terragrunt.runner import (
    TerragruntBinaryError,
    check_terragrunt_binary,
    scan_all_units,
)

terragrunt_app = typer.Typer(
    name="terragrunt",
    help="Terragrunt-aware drift detection across multiple units.",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_CLEAN = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2
EXIT_PARTIAL = 3


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


@terragrunt_app.command("discover")
def cmd_discover(
    root: Path = typer.Option(
        Path("."),
        "--root",
        "-r",
        help="Root directory to discover Terragrunt units from.",
        show_default=True,
    ),
    exclude: str = typer.Option(
        "",
        "--exclude",
        help=(
            "Comma-separated directory names to exclude in addition to defaults "
            "(.terragrunt-cache, .git, .terraform, node_modules)."
        ),
    ),
) -> None:
    """
    Recursively discover runnable Terragrunt units and display them.

    No Terraform or Terragrunt commands are executed. Use this to validate
    discovery before committing to a full scan.
    """
    extra_excludes = [e.strip() for e in exclude.split(",") if e.strip()]

    try:
        units = discover_units(root, exclude=extra_excludes if extra_excludes else None)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ Discovery failed:[/red] {exc}")
        raise typer.Exit(code=EXIT_ERROR)

    render_discover_table(units, root)
    raise typer.Exit(code=EXIT_CLEAN)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@terragrunt_app.command("scan")
def cmd_scan(
    root: Path = typer.Option(
        Path("."),
        "--root",
        "-r",
        help="Root directory to discover Terragrunt units from.",
        show_default=True,
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal | json.",
        show_default=True,
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        "-s",
        help="Minimum severity to report: critical | high | medium | low.",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="AWS CLI profile for CloudTrail attribution.",
        show_default=True,
    ),
    attribute: bool = typer.Option(
        False,
        "--attribute",
        "-a",
        help="Enable CloudTrail attribution for each finding.",
    ),
    exclude: str = typer.Option(
        "",
        "--exclude",
        help=(
            "Comma-separated directory names to exclude in addition to defaults "
            "(.terragrunt-cache, .git, .terraform, node_modules)."
        ),
    ),
    unit_timeout: int = typer.Option(
        300,
        "--unit-timeout",
        help="Per-unit subprocess timeout in seconds.",
        show_default=True,
    ),
    discover_only: bool = typer.Option(
        False,
        "--discover-only",
        help="Print discovered units and exit without running terraform.",
    ),
    fail_fast: bool = typer.Option(
        False,
        "--fail-fast",
        help="Abort scan after the first unit failure.",
    ),
) -> None:
    """
    Discover and scan all Terragrunt units for drift.

    Exit codes:
      0 — all units scanned, no drift detected
      1 — one or more units have drift
      2 — operational failure (missing binary, invalid root, all units failed)
      3 — partial scan failure (some units failed, some succeeded)
    """
    # --- Validate root ---
    try:
        resolved_root = root.resolve()
        if not resolved_root.exists():
            raise FileNotFoundError(f"Root directory does not exist: {root}")
        if not resolved_root.is_dir():
            raise ValueError(f"Root path is not a directory: {root}")
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ Invalid root:[/red] {exc}")
        raise typer.Exit(code=EXIT_ERROR)

    # --- Discover units ---
    extra_excludes = [e.strip() for e in exclude.split(",") if e.strip()]
    try:
        units = discover_units(root, exclude=extra_excludes if extra_excludes else None)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ Discovery failed:[/red] {exc}")
        raise typer.Exit(code=EXIT_ERROR)

    # --- Discover-only mode ---
    if discover_only:
        render_discover_table(units, root)
        raise typer.Exit(code=EXIT_CLEAN)

    if not units:
        console.print(
            "[yellow]⚠ No runnable Terragrunt units found under:[/yellow] "
            f"[bold]{resolved_root}[/bold]"
        )
        raise typer.Exit(code=EXIT_CLEAN)

    # --- Validate binary before touching any unit ---
    try:
        check_terragrunt_binary()
    except TerragruntBinaryError as exc:
        err_console.print(f"[red]✗ {exc}[/red]")
        raise typer.Exit(code=EXIT_ERROR)

    # --- Load config for severity overrides ---
    config = load_config(resolved_root)
    config_overrides: dict[str, str] = config.get("severity_overrides") or {}

    # --- Scan all units ---
    results = scan_all_units(
        units,
        profile=profile,
        attribute=attribute,
        min_severity=min_severity,
        unit_timeout=unit_timeout,
        config_overrides=config_overrides,
        fail_fast=fail_fast,
    )

    # --- Build aggregated report ---
    report: TerragruntScanReport = build_report(resolved_root, results)

    # --- Render output ---
    if output == "json":
        render_json(report)
    else:
        render_terminal(report, with_attribution=attribute)

    # --- Exit code contract ---
    raise typer.Exit(code=_exit_code(report))


# ---------------------------------------------------------------------------
# Exit code logic
# ---------------------------------------------------------------------------


def _exit_code(report: TerragruntScanReport) -> int:
    """
    Derive the correct exit code from a completed scan report.

      0 — clean (no drift, no failures)
      1 — drift found (regardless of failures)
      2 — all units failed or zero units scanned successfully
      3 — partial failure (some failed, some succeeded or drifted)
    """
    has_drift = report.drifted_units > 0
    has_failures = report.failed_units > 0
    all_failed = report.failed_units == report.total_units and report.total_units > 0

    if all_failed:
        return EXIT_ERROR
    if has_failures and not all_failed:
        # Partial failure: some units worked, some didn't
        # Report drift (exit 1) if also present, else partial (exit 3)
        return EXIT_DRIFT if has_drift else EXIT_PARTIAL
    if has_drift:
        return EXIT_DRIFT
    return EXIT_CLEAN
