"""
reporter.py — Rich terminal and JSON output for Terragrunt scan results.

Delegates individual finding rendering to drifty.reporter._render_finding_block()
so output is visually consistent with `drifty scan` output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from drifty.reporter import _render_finding_block
from drifty.scorer import SEVERITY_ORDER
from drifty.terragrunt.models import TerragruntScanReport, TerragruntUnit, UnitScanResult

console = Console()
err_console = Console(stderr=True)

# Status badge styles
_STATUS_STYLE: dict[str, tuple[str, str]] = {
    "success": ("✓", "bold green"),
    "drifted": ("⚠", "bold yellow"),
    "failed": ("✗", "bold red"),
    "skipped": ("⊘", "dim"),
}


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------


def build_report(
    root: Path,
    results: list[UnitScanResult],
) -> TerragruntScanReport:
    """Aggregate a list of UnitScanResults into a TerragruntScanReport."""
    all_findings = [f for r in results for f in r.findings]
    severity_summary: dict[str, int] = {}
    for f in all_findings:
        severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1

    return TerragruntScanReport(
        scan_time=datetime.now(tz=timezone.utc).isoformat(),
        root=root.resolve(),
        total_units=len(results),
        scanned_units=sum(1 for r in results if r.status != "skipped"),
        drifted_units=sum(1 for r in results if r.status == "drifted"),
        failed_units=sum(1 for r in results if r.status == "failed"),
        skipped_units=sum(1 for r in results if r.status == "skipped"),
        total_findings=len(all_findings),
        severity_summary=severity_summary,
        unit_results=sorted(results, key=lambda r: r.unit.rel_path),
    )


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------


def render_terminal(report: TerragruntScanReport, with_attribution: bool = False) -> None:
    """Render the full aggregated report to the terminal using Rich."""
    console.print()
    console.print("[bold cyan]🔍 drifty — Terragrunt Drift Intelligence[/bold cyan]")
    console.print(f"Root: [bold]{report.root}[/bold]  |  " f"[dim]{report.scan_time}[/dim]")
    console.print()

    # Per-unit blocks
    for result in report.unit_results:
        _render_unit_block(result, with_attribution=with_attribution)

    # Aggregate summary panel
    _render_summary_panel(report)


def _render_unit_block(result: UnitScanResult, with_attribution: bool = False) -> None:
    """Render a single unit's header and its findings."""
    icon, style = _STATUS_STYLE.get(result.status, ("?", "white"))
    env = f"  [dim][{result.unit.env_hint}][/dim]" if result.unit.env_hint else ""
    duration = f"  [dim]{result.duration_seconds:.1f}s[/dim]"

    console.print(f"[{style}]{icon} {result.unit.rel_path}[/{style}]{env}{duration}")

    if result.status == "failed" and result.error_message:
        console.print(f"   [red dim]{result.error_message.splitlines()[0]}[/red dim]")

    if result.findings:
        sorted_findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
        for finding in sorted_findings:
            _render_finding_block(finding, with_attribution=with_attribution)
    elif result.status == "success":
        console.print("   [dim]No drift detected.[/dim]")

    console.print()


def _render_summary_panel(report: TerragruntScanReport) -> None:
    """Render the aggregate summary panel."""
    lines = []

    clean = report.scanned_units - report.drifted_units - report.failed_units
    unit_line = (
        f"[bold]{report.total_units}[/bold] units  |  "
        f"[green]{clean} clean[/green]  |  "
        f"[yellow]{report.drifted_units} drifted[/yellow]  |  "
        f"[red]{report.failed_units} failed[/red]"
    )
    lines.append(unit_line)

    if report.total_findings:
        sev = report.severity_summary
        finding_parts = [f"[bold]{report.total_findings} finding(s)[/bold]"]
        if sev.get("critical"):
            finding_parts.append(f"[bold red]{sev['critical']} Critical[/bold red]")
        if sev.get("high"):
            finding_parts.append(f"[bold orange1]{sev['high']} High[/bold orange1]")
        if sev.get("medium"):
            finding_parts.append(f"[bold yellow]{sev['medium']} Medium[/bold yellow]")
        if sev.get("low"):
            finding_parts.append(f"[bold green]{sev['low']} Low[/bold green]")
        lines.append("  •  ".join(finding_parts))

    border = "yellow" if report.drifted_units else ("red" if report.failed_units else "green")
    console.print(Panel("\n".join(lines), title="Terragrunt Scan Summary", border_style=border))
    console.print(Rule(style="dim"))
    console.print()


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


def render_json(report: TerragruntScanReport) -> None:
    """Emit structured JSON to stdout. Suitable for CI/CD piping."""
    print(json.dumps(_report_to_dict(report), indent=2, default=str))


def _report_to_dict(report: TerragruntScanReport) -> dict:
    return {
        "scan_time": report.scan_time,
        "root": str(report.root),
        "total_units": report.total_units,
        "scanned_units": report.scanned_units,
        "drifted_units": report.drifted_units,
        "failed_units": report.failed_units,
        "skipped_units": report.skipped_units,
        "total_findings": report.total_findings,
        "severity_summary": report.severity_summary,
        "dependency_graph": report.dependency_graph,
        "unit_results": [_unit_result_to_dict(r) for r in report.unit_results],
    }


def _unit_result_to_dict(result: UnitScanResult) -> dict:
    return {
        "unit": {
            "rel_path": result.unit.rel_path,
            "path": str(result.unit.path),
            "env_hint": result.unit.env_hint,
            "is_runnable": result.unit.is_runnable,
        },
        "status": result.status,
        "duration_seconds": result.duration_seconds,
        "error_message": result.error_message,
        "findings": [
            {
                "resource_type": f.resource_type,
                "resource_name": f.resource_name,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "changed_attributes": f.changed_attributes,
                "remediation_hint": f.remediation_hint,
            }
            for f in result.findings
        ],
    }


# ---------------------------------------------------------------------------
# Discover-only renderer
# ---------------------------------------------------------------------------


def render_discover_table(units: list[TerragruntUnit], root: Path) -> None:
    """Render a Rich table of discovered units (dry-run / --discover-only)."""
    console.print()
    console.print("[bold cyan]🔍 drifty — Terragrunt Unit Discovery[/bold cyan]")
    console.print(f"Root: [bold]{root.resolve()}[/bold]")
    console.print()

    if not units:
        console.print(
            Panel(
                "[yellow]No runnable Terragrunt units found.[/yellow]\n"
                "[dim]Check that terragrunt.hcl files contain a terraform{} block.[/dim]",
                border_style="yellow",
            )
        )
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", style="dim", no_wrap=True, width=4)
    table.add_column("Unit Path", style="cyan")
    table.add_column("Env", style="yellow", no_wrap=True)
    table.add_column("HCL File", style="dim")

    for i, unit in enumerate(units, 1):
        table.add_row(
            str(i),
            unit.rel_path,
            unit.env_hint or "—",
            str(unit.hcl_file.name),
        )

    console.print(table)
    console.print(f"\n[dim]{len(units)} runnable unit(s) discovered.[/dim]\n")
