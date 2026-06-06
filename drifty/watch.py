from __future__ import annotations

import signal
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from drifty.state import (
    build_known_findings,
    diff_findings,
    load_state,
    save_state,
)

console = Console()

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _meets_threshold(finding, threshold: str) -> bool:
    return _SEVERITY_RANK.get(finding.severity, 0) >= _SEVERITY_RANK[threshold]


def _handle_shutdown(sig, frame) -> None:
    console.print("\n👋 [bold]drifty watch stopped.[/bold]")
    sys.exit(0)


def cmd_watch(
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
        help="AWS CLI profile to use.",
    ),
    interval: int = typer.Option(
        300,
        "--interval",
        "-i",
        help="Seconds between scans.",
        min=30,
    ),
    notify: str | None = typer.Option(
        None,
        "--notify",
        "-n",
        help="Notifier to alert on new drift: slack.",
    ),
    threshold: str = typer.Option(
        "low",
        "--threshold",
        "-t",
        help="Minimum severity to trigger a notification: critical | high | medium | low.",
    ),
    attribute: bool = typer.Option(
        False,
        "--attribute",
        "-a",
        help="Enable CloudTrail attribution on each scan.",
        is_flag=True,
    ),
) -> None:
    """
    Poll a Terraform workspace for new drift on an interval.

    Compares each scan against the previous one and only alerts on
    [bold]new[/bold] findings — known drift is silently tracked.

    [bold]Examples:[/bold]

      [cyan]drifty watch[/cyan]

      [cyan]drifty watch --interval 60 --notify slack --threshold high[/cyan]

      [cyan]drifty watch --workspace ./infra --attribute[/cyan]
    """
    from drifty.scanner import run_scan

    # Validate notify
    valid_notify = ("slack",)
    if notify and notify.lower() not in valid_notify:
        console.print(
            f"[red]✗ Invalid notify target:[/red] [bold]{notify}[/bold]. "
            f"Choose from: {', '.join(valid_notify)}"
        )
        raise typer.Exit(code=1)

    # Validate threshold
    if threshold.lower() not in _SEVERITY_RANK:
        console.print(
            f"[red]✗ Invalid threshold:[/red] [bold]{threshold}[/bold]. "
            f"Choose from: {', '.join(_SEVERITY_RANK)}"
        )
        raise typer.Exit(code=1)

    # Resolve notifier
    notifier = None
    if notify:
        from drifty.config import load_config
        from drifty.notifiers import get_notifier

        cfg = load_config(workspace)
        webhook_url = cfg.get("slack_webhook") if cfg else None
        if not webhook_url:
            console.print(
                "[red]✗ slack_webhook not configured.[/red]\n"
                "  Run: [bold]drifty config set slack_webhook=https://hooks.slack.com/...[/bold]"
            )
            raise typer.Exit(code=1)
        notifier = get_notifier(notify, webhook_url=webhook_url)

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    console.print(
        f"\n👀 [bold cyan]drifty watch[/bold cyan] started\n"
        f"   Workspace : [dim]{workspace}[/dim]\n"
        f"   Interval  : [dim]{interval}s[/dim]\n"
        f"   Threshold : [dim]{threshold}[/dim]\n"
        f"   Notify    : [dim]{notify or 'none'}[/dim]\n"
        f"\nPress [bold]Ctrl+C[/bold] to stop.\n"
    )

    while True:
        _run_cycle(
            workspace=workspace,
            profile=profile,
            attribute=attribute,
            threshold=threshold,
            notifier=notifier,
            run_scan=run_scan,
        )
        time.sleep(interval)


def _run_cycle(*, workspace, profile, attribute, threshold, notifier, run_scan) -> None:
    """Single watch cycle — extracted for testability."""
    from datetime import datetime

    ts = datetime.now().strftime("%H:%M:%S")

    state = load_state()

    try:
        all_findings = run_scan(
            workspace=workspace,
            profile=profile,
            with_attribution=attribute,
            severity_filter=None,
        )
    except Exception as e:
        console.print(f"[dim][{ts}][/dim] [yellow]⚠️  Scan failed: {e}[/yellow]")
        return

    new_drift = diff_findings(all_findings, state)
    save_state(build_known_findings(all_findings))

    if not new_drift:
        console.print(f"[dim][{ts}][/dim] [green]✅ No new drift detected.[/green]")
        return

    filtered = [f for f in new_drift if _meets_threshold(f, threshold)]

    console.print(
        f"[dim][{ts}][/dim] [red]🔴 {len(filtered)} new finding(s)[/red] "
        f"([dim]{len(new_drift) - len(filtered)} below threshold[/dim])"
    )

    if notifier and filtered:
        notifier.send(filtered)
