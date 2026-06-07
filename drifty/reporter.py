"""
reporter.py — renders DriftFinding lists as Rich terminal output, JSON, or Markdown.

This is the user-facing layer. The terminal output is the primary "wow moment":
color-coded severity rows, attribution, remediation hints, and a summary panel.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from drifty.scorer import SEVERITY_ORDER, severity_badge, severity_color, severity_emoji

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def render(
    findings: list[DriftFinding],
    output_format: str = "terminal",
    workspace: Path = Path("."),
    suppressed: list[DriftFinding] | None = None,
    with_attribution: bool = False,
) -> None:
    """
    Dispatch to the correct renderer based on output_format.
    """
    if output_format == "json":
        _render_json(findings)
    elif output_format == "markdown":
        _render_markdown(findings, workspace)
    else:
        _render_terminal(
            findings, workspace, suppressed=suppressed or [], with_attribution=with_attribution
        )


# ---------------------------------------------------------------------------
# Terminal renderer (Rich)
# ---------------------------------------------------------------------------


def _render_terminal(
    findings: list[DriftFinding],
    workspace: Path,
    suppressed: list[DriftFinding] | None = None,
    with_attribution: bool = False,
) -> None:
    console.print()
    console.print("[bold cyan]🔍 drifty — Terraform Drift Intelligence[/bold cyan]")
    console.print(
        f"Scanning workspace: [bold]{workspace}[/bold]  |  "
        f"[dim]{datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]"
    )
    console.print()

    if not findings:
        console.print(
            Panel(
                "[bold green]✓ No drift detected.[/bold green]\n"
                "[dim]Your infrastructure matches your Terraform state.[/dim]",
                border_style="green",
            )
        )
        if suppressed:
            console.print()
            console.print(
                f"[dim]── {len(suppressed)} finding(s) suppressed by ignore list ──[/dim]"
            )
            for f in suppressed:
                addr = f"{f.resource_type}.{f.resource_name}"
                emoji = severity_emoji(f.severity)
                console.print(f"[dim]   ⊘  {emoji} {addr}  ({f.resource_id})[/dim]")
            console.print()
        return

    # Sort: critical first
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))

    # Summary panel
    counts = _count_by_severity(sorted_findings)
    n = len(sorted_findings)
    summary_parts = [f"[bold]{n} drift{'s' if n != 1 else ''} detected[/bold]"]
    if counts.get("critical"):
        summary_parts.append(f"[bold red]{counts['critical']} Critical[/bold red]")
    if counts.get("high"):
        summary_parts.append(f"[bold orange1]{counts['high']} High[/bold orange1]")
    if counts.get("medium"):
        summary_parts.append(f"[bold yellow]{counts['medium']} Medium[/bold yellow]")
    if counts.get("low"):
        summary_parts.append(f"[bold green]{counts['low']} Low[/bold green]")

    console.print(
        Panel(
            "  •  ".join(summary_parts),
            border_style="cyan",
            padding=(0, 2),
        )
    )
    console.print()

    # Individual finding blocks
    for finding in sorted_findings:
        _render_finding_block(finding, with_attribution=with_attribution)

    # Suppressed findings
    suppressed = suppressed or []
    if suppressed:
        console.print(f"[dim]── {len(suppressed)} finding(s) suppressed by ignore list ──[/dim]")
        for f in suppressed:
            addr = f"{f.resource_type}.{f.resource_name}"
            emoji = severity_emoji(f.severity)
            console.print(f"[dim]   ⊘  {emoji} {addr}  ({f.resource_id})[/dim]")
        console.print()

    # Footer
    console.print(Rule(style="dim"))
    console.print(
        "[dim]Run [bold]drifty report --format markdown[/bold] " "to export this as a report.[/dim]"
    )
    console.print()


def _render_finding_block(finding: DriftFinding, with_attribution: bool = False) -> None:
    """Render a single DriftFinding as a color-coded terminal block."""
    emoji = severity_emoji(finding.severity)
    badge = severity_badge(finding.severity)
    color = severity_color(finding.severity)
    addr = f"{finding.resource_type}.{finding.resource_name}"

    # Header line: emoji + severity + address + id
    header = Text()
    header.append(f"{emoji} ", style="")
    header.append(badge, style=color)
    header.append(f"  {addr}", style="bold white")
    header.append(f"  ({finding.resource_id})", style="dim")
    console.print(header)

    # Changed attributes
    for change in finding.changed_attributes:
        attr = change.get("attribute", "")
        before = _format_value(change.get("before"))
        after = _format_value(change.get("after"))
        console.print(
            f"   [dim]Changed:[/dim]  [cyan]{attr}[/cyan]  "
            f"[dim]→[/dim]  [bold]{after}[/bold]  [dim](was: {before})[/dim]"
        )

    # Attribution
    if finding.attributed_to:
        console.print(f"   [dim]Who:[/dim]      [yellow]{finding.attributed_to}[/yellow]")
        console.print(f"   [dim]When:[/dim]     {_format_timestamp(finding.attributed_at)}")
        console.print(f"   [dim]Action:[/dim]   [magenta]{finding.attributed_action}[/magenta]")
    elif with_attribution:
        no_attr = "attribution unavailable (event outside 90-day CloudTrail window)"
        console.print(f"   [dim]Who:[/dim]      [dim italic]{no_attr}[/dim italic]")

    # Remediation hint
    if finding.remediation_hint:
        console.print(f"   [dim]Fix:[/dim]      [green]{finding.remediation_hint}[/green]")

    console.print()


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


def _render_json(findings: list[DriftFinding]) -> None:
    """
    Emit structured JSON to stdout. Suitable for CI/CD piping.
    Format: {"scan_time": ..., "total": N, "findings": [...]}
    """
    output = {
        "scan_time": datetime.now(tz=timezone.utc).isoformat(),
        "total": len(findings),
        "severity_summary": _count_by_severity(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    print(json.dumps(output, indent=2, default=str))


def _finding_to_dict(finding: DriftFinding) -> dict:
    return {
        "resource_type": finding.resource_type,
        "resource_name": finding.resource_name,
        "resource_id": finding.resource_id,
        "severity": finding.severity,
        "changed_attributes": finding.changed_attributes,
        "attribution": {
            "principal": finding.attributed_to,
            "timestamp": finding.attributed_at,
            "action": finding.attributed_action,
        },
        "remediation_hint": finding.remediation_hint,
    }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def _render_markdown(findings: list[DriftFinding], workspace: Path) -> None:
    """
    Render findings as GitHub-flavored Markdown to stdout.
    Suitable for Confluence, Notion, or PR comments.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    lines.append("# 🔍 drifty — Drift Report")
    lines.append(f"\n**Workspace:** `{workspace}`  ")
    lines.append(f"**Scanned:** {now}  ")
    lines.append(f"**Total drifts:** {len(findings)}\n")

    if not findings:
        lines.append("✅ **No drift detected.** Infrastructure matches Terraform state.")
        print("\n".join(lines))
        return

    # Summary table
    counts = _count_by_severity(findings)
    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev, 0) > 0:
            emoji = severity_emoji(sev)
            lines.append(f"| {emoji} {sev.capitalize()} | {counts[sev]} |")
    lines.append("")

    # Findings
    lines.append("## Findings\n")
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))

    for i, finding in enumerate(sorted_findings, 1):
        emoji = severity_emoji(finding.severity)
        badge = severity_badge(finding.severity)
        addr = f"{finding.resource_type}.{finding.resource_name}"

        lines.append(f"### {i}. {emoji} `{addr}` — {badge}")
        lines.append(f"\n**Resource ID:** `{finding.resource_id}`\n")

        # Changed attributes table
        if finding.changed_attributes:
            lines.append("**Changed Attributes:**\n")
            lines.append("| Attribute | Before | After |")
            lines.append("|-----------|--------|-------|")
            for change in finding.changed_attributes:
                attr = change.get("attribute", "")
                before = _format_value(change.get("before"))
                after = _format_value(change.get("after"))
                lines.append(f"| `{attr}` | `{before}` | `{after}` |")
            lines.append("")

        # Attribution
        lines.append("**Attribution:**\n")
        if finding.attributed_to:
            lines.append(f"- **Who:** `{finding.attributed_to}`")
            lines.append(f"- **When:** {_format_timestamp(finding.attributed_at)}")
            lines.append(f"- **Action:** `{finding.attributed_action}`")
        else:
            lines.append("- _Attribution unavailable (event outside 90-day CloudTrail window)_")
        lines.append("")

        # Remediation
        if finding.remediation_hint:
            lines.append("**Remediation:**\n")
            if finding.remediation_hint.startswith("terraform"):
                lines.append(f"```hcl\n{finding.remediation_hint}\n```")
            else:
                lines.append(f"> {finding.remediation_hint}")
            lines.append("")

        lines.append("---\n")

    print("\n".join(lines))


# ---------------------------------------------------------------------------
# report command entry point
# ---------------------------------------------------------------------------


def generate_report(
    findings: list[DriftFinding],
    format: str = "markdown",
    output_file: Path | None = None,
    workspace: Path = Path("."),
) -> None:
    """
    Generate a standalone drift report and write to file or stdout.
    Called by `drifty report` command.
    """
    if format == "json":
        content = _capture_json(findings)
        ext = ".json"
    else:
        content = _capture_markdown(findings, workspace)
        ext = ".md"

    if output_file is None:
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        output_file = Path(f"drifty-report-{now}{ext}")

    output_file.write_text(content, encoding="utf-8")
    console.print(f"[green]✓ Report written to:[/green] [bold cyan]{output_file}[/bold cyan]")


def _capture_json(findings: list[DriftFinding]) -> str:
    output = {
        "scan_time": datetime.now(tz=timezone.utc).isoformat(),
        "total": len(findings),
        "severity_summary": _count_by_severity(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    return json.dumps(output, indent=2, default=str)


def _capture_markdown(findings: list[DriftFinding], workspace: Path) -> str:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        _render_markdown(findings, workspace)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _count_by_severity(findings: list[DriftFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _format_value(value) -> str:
    """Render an attribute value compactly for display."""
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        dumped = json.dumps(value, separators=(",", ":"))
        return dumped if len(dumped) <= 60 else dumped[:57] + "..."
    return str(value)


def _format_timestamp(ts: str | None) -> str:
    """Format an ISO timestamp into a clean UTC display string."""
    if not ts:
        return "unknown"
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return ts
