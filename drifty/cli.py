"""
drifty — Terraform Drift Intelligence
Entry point for all CLI commands via Typer.
"""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from drifty import __version__
from drifty.config import (
    init_workspace,
    set_config_value,
    show_config,
)

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
        False,
        "--attribute",
        "-a",
        help="Enable CloudTrail attribution (who caused each drift).",
        is_flag=True,
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

    findings = run_scan(
        workspace=workspace,
        profile=profile,
        with_attribution=attribute,
        severity_filter=severity.lower() if severity else None,
    )

    render(findings, output_format=output, workspace=workspace)

    if notify:
        console.print(
            f"\n[yellow]⚠ Notify via [bold]{notify}[/bold] not yet configured. "
            "Run [bold]drifty config set slack_webhook=<URL>[/bold] first.[/yellow]"
        )


# ---------------------------------------------------------------------------
# drifty report
# ---------------------------------------------------------------------------
@app.command("report")
def cmd_report(
    workspace: Path = typer.Option(
        Path("."),
        "--workspace", "-w",
        help="Path to Terraform workspace directory.",
        exists=True, file_okay=False, dir_okay=True, resolve_path=True,
    ),
    format: str = typer.Option(
        "markdown", "--format", "-f",
        help="Report format: markdown | json.",
    ),
    output_file: Path | None = typer.Option(
        None, "--out",
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

    findings = run_scan(workspace=workspace, profile="default")
    generate_report(findings, format=format, output_file=output_file, workspace=workspace)

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
