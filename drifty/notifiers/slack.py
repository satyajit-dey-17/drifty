"""
slack.py — Slack notification backend for drifty.

Formats DriftFindings into Slack Block Kit JSON and POSTs to a webhook URL.
Only sends a message if findings is non-empty.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from drifty.scorer import SEVERITY_ORDER, severity_emoji

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding

# Slack Block Kit color map (used in attachment fallback)
SEVERITY_COLOR = {
    "critical": "#E53935",
    "high": "#FB8C00",
    "medium": "#FDD835",
    "low": "#43A047",
}

MAX_FINDINGS_IN_MESSAGE = 10  # Slack has a 50-block limit; keep messages clean


def notify_slack(
    findings: list[DriftFinding],
    webhook_url: str,
    workspace: Path = Path("."),
    timeout: int = 10,
) -> bool:
    """
    POST a drift summary to a Slack incoming webhook.

    Returns True on success, False on any failure.
    Only sends if findings is non-empty.
    """
    if not findings:
        return True  # nothing to notify about

    payload = _build_payload(findings, workspace)

    try:
        response = httpx.post(
            webhook_url,
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return True
    except httpx.TimeoutException:
        _print_warning("Slack notification timed out.")
        return False
    except httpx.HTTPStatusError as e:
        _print_warning(f"Slack webhook returned {e.response.status_code}: {e.response.text}")
        return False
    except httpx.RequestError as e:
        _print_warning(f"Slack notification failed: {e}")
        return False


def _build_payload(findings: list[DriftFinding], workspace: Path) -> dict:
    """Build the full Slack Block Kit payload."""
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
    counts = _count_by_severity(findings)
    workspace_name = workspace.name or str(workspace)

    blocks: list[dict] = []

    # ── Header ──────────────────────────────────────────────────────────────
    total = len(findings)
    summary = _severity_summary_text(counts)
    blocks.append(
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🔍 drifty detected {total} drift{'s' if total != 1 else ''}",
                "emoji": True,
            },
        }
    )

    # ── Workspace + severity summary ────────────────────────────────────────
    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Workspace:* `{workspace_name}`    {summary}",
            },
        }
    )

    blocks.append({"type": "divider"})

    # ── Finding blocks (cap at MAX_FINDINGS_IN_MESSAGE) ──────────────────────
    displayed = sorted_findings[:MAX_FINDINGS_IN_MESSAGE]
    for finding in displayed:
        blocks.append(_build_finding_block(finding))

    # ── Overflow notice ──────────────────────────────────────────────────────
    if len(findings) > MAX_FINDINGS_IN_MESSAGE:
        overflow = len(findings) - MAX_FINDINGS_IN_MESSAGE
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_...and {overflow} more finding{'s' if overflow != 1 else ''}. "
                        f"Run `drifty report --format markdown` for the full report._",
                    }
                ],
            }
        )

    # ── Footer ───────────────────────────────────────────────────────────────
    blocks.append({"type": "divider"})
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Sent by *drifty* · `pip install drifty` · "
                    "<https://github.com/satyajit-dey-17/drifty|GitHub>",
                }
            ],
        }
    )

    return {
        "text": f"drifty: {total} drift{'s' if total != 1 else ''} detected in `{workspace_name}`",
        "blocks": blocks,
    }


def _build_finding_block(finding: DriftFinding) -> dict:
    """Build a single Slack section block for one DriftFinding."""
    emoji = severity_emoji(finding.severity)
    addr = f"{finding.resource_type}.{finding.resource_name}"

    # Build the change lines
    lines: list[str] = []
    lines.append(f"{emoji} *{finding.severity.upper()}*  `{addr}`  _({finding.resource_id})_")

    for change in finding.changed_attributes[:3]:  # cap at 3 attrs per finding
        attr = change.get("attribute", "")
        after = _format_value(change.get("after"))
        before = _format_value(change.get("before"))
        lines.append(f"  › *{attr}*: `{before}` → `{after}`")

    if len(finding.changed_attributes) > 3:
        extra = len(finding.changed_attributes) - 3
        lines.append(f"  › _...{extra} more attribute{'s' if extra != 1 else ''}_")

    # Attribution
    if finding.attributed_to:
        principal = _shorten_arn(finding.attributed_to)
        lines.append(f"  › by *{principal}* via `{finding.attributed_action}`")
    else:
        lines.append("  › _attribution unavailable (outside 90-day CloudTrail window)_")

    # Remediation
    if finding.remediation_hint:
        lines.append(f"  › Fix: `{finding.remediation_hint}`")

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "\n".join(lines),
        },
    }


def _severity_summary_text(counts: dict[str, int]) -> str:
    """Build a compact severity summary string: 🔴 1 Critical  🟠 2 High"""
    parts = []
    for sev, emoji in [("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "🟢")]:
        if counts.get(sev, 0) > 0:
            parts.append(f"{emoji} {counts[sev]} {sev.capitalize()}")
    return "    ".join(parts)


def _count_by_severity(findings: list[DriftFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _shorten_arn(arn: str) -> str:
    """
    Shorten an IAM ARN for display.
    arn:aws:iam::123456789:user/john.doe → john.doe
    arn:aws:iam::123456789:role/ops-team → ops-team (role)
    """
    if not arn.startswith("arn:"):
        return arn
    parts = arn.split(":")
    if len(parts) < 6:
        return arn
    resource = parts[-1]  # e.g. "user/john.doe" or "role/ops-team"
    if "/" in resource:
        kind, name = resource.split("/", 1)
        return name if kind == "user" else f"{name} ({kind})"
    return resource


def _format_value(value) -> str:
    """Compact value display for Slack (shorter than terminal renderer)."""
    import json

    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        dumped = json.dumps(value, separators=(",", ":"))
        return dumped if len(dumped) <= 40 else dumped[:37] + "..."
    s = str(value)
    return s if len(s) <= 40 else s[:37] + "..."


def _print_warning(msg: str) -> None:
    """Print a warning to stderr using Rich if available, else plain print."""
    try:
        from rich.console import Console

        Console(stderr=True).print(f"[yellow]⚠ {msg}[/yellow]")
    except ImportError:
        import sys

        print(f"⚠ {msg}", file=sys.stderr)


class SlackNotifier:
    """Notifier wrapper used by watch mode."""

    def __init__(
        self,
        webhook_url: str,
        workspace: Path = Path("."),
        timeout: int = 10,
    ) -> None:
        self.webhook_url = webhook_url
        self.workspace = workspace
        self.timeout = timeout

    def send(self, findings: list[DriftFinding]) -> bool:
        return notify_slack(
            findings=findings,
            webhook_url=self.webhook_url,
            workspace=self.workspace,
            timeout=self.timeout,
        )
