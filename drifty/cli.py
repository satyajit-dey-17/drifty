"""
drifty — Terraform Drift Intelligence
Entry point for all CLI commands via Typer.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from drifty import __version__
from drifty.config import (
    init_workspace,
    set_config_value,
    show_config,
)
from drifty.github import post_pr_comment  # add this
from drifty.history import load_history, most_drifted_resources
from drifty.ignore import add_ignore, load_ignores, remove_ignore
from drifty.watch import cmd_watch

app = typer.Typer(
    name="drifty",
    help="Terraform drift intelligence: detect, attribute, score, and fix IaC drift.",
    add_completion=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)

config_app = typer.Typer(
    name="config",
    help="Manage drifty configuration.",
    rich_markup_mode="rich",
)
app.add_typer(config_app, name="config")

app.command("watch")(cmd_watch)

console = Console()


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]drifty[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# Root options
# ---------------------------------------------------------------------------


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show drifty version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """
    [bold cyan]drifty[/bold cyan] — Terraform Drift Intelligence

    Detect what drifted, who changed it, how dangerous it is, and how to fix it.
    """


# ---------------------------------------------------------------------------
# drifty init
# ---------------------------------------------------------------------------


@app.command("init")
def cmd_init(
    workspace: Path = typer.Option(
        Path("."),
        "--workspace",
        "-w",
        help="Path to Terraform workspace directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
) -> None:
    """
    Initialize a [bold].drifty/config.yaml[/bold] in the current workspace.
    """
    init_workspace(workspace)


# ---------------------------------------------------------------------------
# drifty scan
# ---------------------------------------------------------------------------


@app.command("scan")
def cmd_scan(
    workspace: Path = typer.Option(
        Path("."),
        "--workspace",
        "-w",
        help="Path to Terraform workspace directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="AWS CLI profile to use for CloudTrail lookups.",
    ),
    attribute: bool = typer.Option(
        False, "--attribute", "-a", help="Enable CloudTrail attribution (who caused each drift)."
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity filter: critical | high | medium | low.",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal (default) | json | markdown.",
    ),
    notify: str | None = typer.Option(
        None,
        "--notify",
        "-n",
        help="Send results to: slack (requires webhook in config).",
    ),
) -> None:
    """
    Scan a Terraform workspace for infrastructure drift.

    Runs [bold]terraform plan -refresh-only -json[/bold], attributes each drift
    to a CloudTrail event, scores severity, and suggests remediations.

    [bold]Examples:[/bold]

      [cyan]drifty scan[/cyan]

      [cyan]drifty scan --workspace ./infra --attribute --output json[/cyan]

      [cyan]drifty scan --severity high --notify slack[/cyan]
    """
    # Validate output format
    valid_outputs = ("terminal", "json", "markdown")
    if output not in valid_outputs:
        console.print(
            f"[red]✗ Invalid output format:[/red] [bold]{output}[/bold]. "
            f"Choose from: {', '.join(valid_outputs)}"
        )
        raise typer.Exit(code=1)

    # Validate severity filter
    valid_severities = ("critical", "high", "medium", "low")
    if severity and severity.lower() not in valid_severities:
        console.print(
            f"[red]✗ Invalid severity:[/red] [bold]{severity}[/bold]. "
            f"Choose from: {', '.join(valid_severities)}"
        )
        raise typer.Exit(code=1)

    # Validate notify target
    valid_notify = ("slack",)
    if notify and notify.lower() not in valid_notify:
        console.print(
            f"[red]✗ Invalid notify target:[/red] [bold]{notify}[/bold]. "
            f"Choose from: {', '.join(valid_notify)}"
        )
        raise typer.Exit(code=1)

    # -----------------------------------------------------------------------
    # STUB: real logic wired in Step 4 (scanner), Step 5 (scorer),
    #       Step 6 (cloudtrail), Step 7 (reporter)
    # -----------------------------------------------------------------------
    from drifty.reporter import render
    from drifty.scanner import run_scan

    findings, suppressed = run_scan(
        workspace=workspace,
        profile=profile,
        with_attribution=attribute,
        severity_filter=severity,
    )

    # ── Notify ──────────────────────────────────────────────────────────────
    if notify:
        if notify == "slack":
            from drifty.config import load_config
            from drifty.notifiers.slack import notify_slack

            cfg = load_config(workspace)
            webhook_url = cfg.get("slack_webhook") if cfg else None

            if not webhook_url:
                console.print(
                    "[red]✗ slack_webhook not configured.[/red]\n"
                    "  Run: [bold]drifty config set slack_webhook=https://hooks.slack.com/...[/bold]"
                )
            else:
                success = notify_slack(findings, webhook_url=webhook_url, workspace=workspace)
                if success and findings:
                    console.print("[green]✓ Slack notification sent.[/green]")
        else:
            console.print(
                f"[red]✗ Unknown notifier:[/red] [bold]{notify}[/bold]. "
                "Currently supported: [bold]slack[/bold]"
            )

    # ── Render ──────────────────────────────────────────────────────────────
    render(findings, suppressed=suppressed, output_format=output, workspace=workspace)


# ---------------------------------------------------------------------------
# drifty report
# ---------------------------------------------------------------------------
@app.command("report")
def cmd_report(
    workspace: Path = typer.Option(
        Path("."),
        "--workspace",
        "-w",
        help="Path to Terraform workspace directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report format: markdown | json.",
    ),
    output_file: Path | None = typer.Option(
        None,
        "--out",
        help="File path to write report to. Defaults to ./drifty-report-YYYY-MM-DD.md",
    ),
) -> None:
    """
    Generate a standalone drift report for the current workspace.

    [bold]Examples:[/bold]

      [cyan]drifty report[/cyan]

      [cyan]drifty report --format json --out ./reports/drift.json[/cyan]
    """
    valid_formats = ("markdown", "json")
    if format not in valid_formats:
        console.print(
            f"[red]✗ Invalid format:[/red] [bold]{format}[/bold]. "
            f"Choose from: {', '.join(valid_formats)}"
        )
        raise typer.Exit(code=1)

    from drifty.reporter import generate_report
    from drifty.scanner import run_scan

    findings, _ = run_scan(workspace=workspace, profile="default")
    generate_report(findings, format=format, output_file=output_file, workspace=workspace)


# ---------------------------------------------------------------------------
# drifty report-pr
# ---------------------------------------------------------------------------


@app.command("report-pr")
def cmd_report_pr(
    workspace: Path = typer.Option(
        Path("."),
        "--workspace",
        "-w",
        help="Path to Terraform workspace directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="AWS CLI profile to use for CloudTrail lookups.",
    ),
    attribute: bool = typer.Option(
        False, "--attribute", "-a", help="Enable CloudTrail attribution."
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity filter: critical | high | medium | low.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="GitHub token. Defaults to GITHUB_TOKEN env var.",
    ),
    repo: str | None = typer.Option(
        None,
        "--repo",
        help="GitHub repository (owner/repo). Defaults to GITHUB_REPOSITORY env var.",
    ),
    pr: int | None = typer.Option(
        None,
        "--pr",
        help="Pull request number. Defaults to PR_NUMBER env var.",
    ),
) -> None:
    """
    Scan for drift and post the report as a GitHub PR comment.

    Reads [bold]GITHUB_TOKEN[/bold], [bold]GITHUB_REPOSITORY[/bold],
    and [bold]PR_NUMBER[/bold] from environment (set automatically in GitHub Actions).

    [bold]Examples:[/bold]

      [cyan]drifty report-pr[/cyan]

      [cyan]drifty report-pr --attribute --severity high[/cyan]

      [cyan]drifty report-pr --repo owner/infra --pr 42 --token ghp_xxx[/cyan]
    """
    from drifty.scanner import run_scan

    findings, suppressed = run_scan(
        workspace=workspace,
        profile=profile,
        with_attribution=attribute,
        severity_filter=severity,
    )
    success = post_pr_comment(
        findings,
        suppressed=suppressed,
        workspace=workspace,
        github_token=token,
        repository=repo,
        pr_number=pr,
    )

    if success:
        console.print("[green]✓ Drift report posted to PR.[/green]")
    else:
        console.print("[red]✗ Failed to post PR comment. Check warnings above.[/red]")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# drifty config show
# ---------------------------------------------------------------------------


@config_app.command("show")
def cmd_config_show() -> None:
    """
    Display the current drifty configuration.
    """
    show_config()


# ---------------------------------------------------------------------------
# drifty history
# ---------------------------------------------------------------------------


@app.command("history")
def cmd_history(
    workspace: Path = typer.Option(
        Path("."),
        "--workspace",
        "-w",
        help="Path to Terraform workspace directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    last: int = typer.Option(
        10,
        "--last",
        "-n",
        help="Number of most recent scans to show.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity filter: critical | high | medium | low.",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal | json.",
    ),
) -> None:
    """
    Show drift history from previous scans.

    Reads from [bold].drifty/history.json[/bold] in the workspace.

    [bold]Examples:[/bold]

      [cyan]drifty history[/cyan]

      [cyan]drifty history --last 30 --severity high[/cyan]

      [cyan]drifty history --output json[/cyan]
    """
    from drifty.scorer import SEVERITY_ORDER

    entries = load_history(workspace, last=last)

    if not entries:
        console.print(
            "[yellow]No history found.[/yellow] Run [bold cyan]drifty scan[/bold cyan] first."
        )
        raise typer.Exit()

    # Apply severity filter — keep entry if it has findings at or above threshold
    if severity:
        threshold = SEVERITY_ORDER.get(severity.lower(), 3)
        entries = [
            e
            for e in entries
            if any(SEVERITY_ORDER.get(f["severity"], 3) <= threshold for f in e.get("findings", []))
        ]

    if output == "json":
        console.print_json(json.dumps(entries, indent=2, default=str))
        raise typer.Exit()

    # ── Terminal table ────────────────────────────────────────────────────
    from rich.table import Table

    console.print(
        f"\n[bold cyan]🕓 drifty history[/bold cyan] — last {last} scans  "
        f"(workspace: [bold]{workspace.name}[/bold])\n"
    )

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Scan", style="dim", min_width=20)
    table.add_column("Total", justify="right")
    table.add_column("🔴", justify="right")
    table.add_column("🟠", justify="right")
    table.add_column("🟡", justify="right")
    table.add_column("🟢", justify="right")

    for entry in entries:
        scanned_at = entry["scanned_at"][:16].replace("T", " ")
        total = entry["total"]
        crit = entry["critical"] or ("—" if total == 0 else "0")
        high = entry["high"] or ("—" if total == 0 else "0")
        med = entry["medium"] or ("—" if total == 0 else "0")
        low = entry["low"] or ("—" if total == 0 else "0")
        table.add_row(scanned_at, str(total), str(crit), str(high), str(med), str(low))

    console.print(table)

    # ── Most drifted resources ─────────────────────────────────────────────
    top = most_drifted_resources(workspace, last=last)
    if top:
        from drifty.scorer import severity_emoji

        console.print("\n[bold]Most drifted resources:[/bold]")
        for r in top[:10]:
            emoji = severity_emoji(r["severity"])
            console.print(
                f"  [cyan]{r['addr']:<45}[/cyan] "
                f"[bold]{r['count']}[/bold] time{'s' if r['count'] != 1 else ''}  "
                f"{emoji} {r['severity']}"
            )
    console.print()


# ---------------------------------------------------------------------------
# drifty ignore
# ---------------------------------------------------------------------------


@app.command("ignore")
def cmd_ignore(
    resource: str | None = typer.Argument(
        None,
        help="Resource address to ignore. Example: aws_instance.api_server",
        metavar="RESOURCE",
    ),
    workspace: Path = typer.Option(
        Path("."),
        "--workspace",
        "-w",
        help="Path to Terraform workspace directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    reason: str = typer.Option(
        "",
        "--reason",
        "-r",
        help="Reason for ignoring this resource.",
    ),
    remove: bool = typer.Option(
        False,
        "--remove",
        help="Remove a resource from the ignore list.",
    ),
    list_all: bool = typer.Option(
        False,
        "--list",
        "-l",
        help="List all currently ignored resources.",
    ),
) -> None:
    """
    Manage the drifty ignore list.

    Suppressed resources still appear in scan output under a
    [dim]Suppressed[/dim] label — they are never silently hidden.

    [bold]Examples:[/bold]

      [cyan]drifty ignore aws_instance.api_server[/cyan]

      [cyan]drifty ignore aws_instance.api_server --reason "approved by security"[/cyan]

      [cyan]drifty ignore aws_instance.api_server --remove[/cyan]

      [cyan]drifty ignore --list[/cyan]
    """
    if list_all:
        ignores = load_ignores(workspace)
        if not ignores:
            console.print("[dim]No resources currently ignored.[/dim]")
            raise typer.Exit()
        console.print(f"\n[bold]Ignored resources[/bold] (workspace: {workspace.name})\n")
        for entry in ignores:
            console.print(f"  [cyan]{entry['resource']}[/cyan]")
            if entry.get("reason"):
                console.print(f"    reason:     {entry['reason']}")
            console.print(f"    ignored_at: {entry['ignored_at'][:10]}")
            console.print(f"    ignored_by: {entry.get('ignored_by', 'unknown')}")
        console.print()
        raise typer.Exit()

    if not resource:
        console.print(
            "[red]✗ Provide a resource address or use --list.[/red]\n"
            "  Example: [bold cyan]drifty ignore aws_instance.api_server[/bold cyan]"
        )
        raise typer.Exit(code=1)

    if remove:
        removed = remove_ignore(resource, workspace)
        if removed:
            console.print(f"[green]✓ Removed[/green] [cyan]{resource}[/cyan] from ignore list.")
        else:
            console.print(f"[yellow]⚠ {resource}[/yellow] was not in the ignore list.")
        raise typer.Exit()

    add_ignore(resource, workspace, reason=reason)
    console.print(
        f"[green]✓ Ignoring[/green] [cyan]{resource}[/cyan]. "
        f"It will appear as [dim]suppressed[/dim] in future scans."
    )


# ---------------------------------------------------------------------------
# drifty config set
# ---------------------------------------------------------------------------


@config_app.command("set")
def cmd_config_set(
    key_value: str = typer.Argument(
        ...,
        help="Config key=value pair. Example: slack_webhook=https://hooks.slack.com/...",
        metavar="KEY=VALUE",
    ),
) -> None:
    """
    Set a configuration value.

    [bold]Examples:[/bold]

      [cyan]drifty config set slack_webhook=https://hooks.slack.com/T.../B.../xxx[/cyan]

      [cyan]drifty config set default_severity=high[/cyan]

      [cyan]drifty config set default_profile=prod[/cyan]
    """
    if "=" not in key_value:
        console.print(
            "[red]✗ Invalid format.[/red] Use [bold]KEY=VALUE[/bold], "
            "e.g. [cyan]drifty config set slack_webhook=https://...[/cyan]"
        )
        raise typer.Exit(code=1)

    key, _, value = key_value.partition("=")
    set_config_value(key.strip(), value.strip())


# ---------------------------------------------------------------------------
# Entry point (for direct execution: python -m drifty)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
