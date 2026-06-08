"""
github.py — GitHub PR comment backend for drifty.

Posts a formatted drift report as a PR comment via the GitHub REST API.
Reads GITHUB_TOKEN, GITHUB_REPOSITORY, and PR_NUMBER from environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from drifty.scorer import SEVERITY_ORDER, severity_emoji

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding

GITHUB_API = "https://api.github.com"
MAX_FINDINGS_IN_COMMENT = 20


def post_pr_comment(
    findings: list[DriftFinding],
    suppressed: list[DriftFinding] | None = None,
    workspace: Path = Path("."),
    github_token: str | None = None,
    repository: str | None = None,
    pr_number: int | None = None,
    timeout: int = 15,
) -> bool:
    """
    Post a drift report as a GitHub PR comment.

    Resolves credentials from args first, then environment variables:
      GITHUB_TOKEN       — personal access token or Actions GITHUB_TOKEN
      GITHUB_REPOSITORY  — owner/repo (e.g. acme/infra)
      PR_NUMBER          — pull request number

    Returns True on success, False on any failure.
    """
    token = github_token or os.environ.get("GITHUB_TOKEN")
    repo = repository or os.environ.get("GITHUB_REPOSITORY")
    pr_raw = pr_number or os.environ.get("PR_NUMBER")

    if pr_raw is None:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if event_path:
            try:

                with open(event_path) as f:
                    event = json.load(f)
                pr_raw = (event.get("pull_request") or {}).get("number") or event.get("number")
            except Exception:
                pr_raw = None

    if not token:
        _print_warning("GITHUB_TOKEN not set. Cannot post PR comment.")
        return False
    if not repo:
        _print_warning("GITHUB_REPOSITORY not set (expected format: owner/repo).")
        return False
    if not pr_raw:
        _print_warning(
            "PR number not found. Pass --pr, set PR_NUMBER, or run in a pull_request workflow."
        )
        return False

    try:
        pr = int(pr_raw)
    except (ValueError, TypeError):
        _print_warning(f"PR number must be an integer, got: {pr_raw!r}")
        return False

    body = _build_comment(findings, workspace, suppressed=suppressed or [])
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr}/comments"

    try:
        response = httpx.post(
            url,
            json={"body": body},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=timeout,
        )
        response.raise_for_status()
        return True
    except httpx.TimeoutException:
        _print_warning("GitHub API request timed out.")
        return False
    except httpx.HTTPStatusError as e:
        _print_warning(f"GitHub API returned {e.response.status_code}: {e.response.text}")
        return False
    except httpx.RequestError as e:
        _print_warning(f"GitHub PR comment failed: {e}")
        return False


def _build_comment(
    findings: list[DriftFinding],
    workspace: Path,
    suppressed: list[DriftFinding] | None = None,
) -> str:
    """Build the full Markdown comment body."""
    suppressed = suppressed or []
    workspace_name = workspace.name or str(workspace)
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 3))
    total = len(findings)

    lines: list[str] = []

    # ── Header ───────────────────────────────────────────────────────────────
    if not findings:
        lines.append("## 🔍 drifty — No Drift Detected")
        lines.append(f"\n✅ Workspace `{workspace_name}` is clean. No infrastructure drift found.")
        lines.append("\n---")
        lines.append("_Reported by [drifty](https://github.com/satyajit-dey-17/drifty)_")
        return "\n".join(lines)

    lines.append(f"## 🔍 drifty — {total} Drift{'s' if total != 1 else ''} Detected")
    lines.append(f"\n**Workspace:** `{workspace_name}`  ")
    lines.append(_severity_summary(findings))
    lines.append("\n---")

    # ── Finding blocks ────────────────────────────────────────────────────────
    displayed = sorted_findings[:MAX_FINDINGS_IN_COMMENT]
    for finding in displayed:
        lines.append(_build_finding_block(finding))

    if total > MAX_FINDINGS_IN_COMMENT:
        overflow = total - MAX_FINDINGS_IN_COMMENT
        lines.append(
            f"\n> _{overflow} more finding{'s' if overflow != 1 else ''} not shown. "
            f"Run `drifty report --format markdown` for the full report._"
        )
    if suppressed:
        lines.append("\n### Suppressed")
        lines.append(
            f"\n_{len(suppressed)} finding{'s' if len(suppressed) != 1 else ''} "
            "were suppressed by ignore rules._"
        )
    # ── Footer ────────────────────────────────────────────────────────────────
    lines.append("\n---")
    lines.append(
        "_Reported by [drifty](https://github.com/satyajit-dey-17/drifty) · "
        "`pip install drifty`_"
    )

    return "\n".join(lines)


def _build_finding_block(finding: DriftFinding) -> str:
    """Build a collapsible Markdown block for one DriftFinding."""
    emoji = severity_emoji(finding.severity)
    addr = f"{finding.resource_type}.{finding.resource_name}"
    summary = f"{emoji} **{finding.severity.upper()}** — `{addr}` ({finding.resource_id})"

    inner: list[str] = []

    # Changed attributes table
    inner.append("| Attribute | Before | After |")
    inner.append("|---|---|---|")
    for change in finding.changed_attributes[:5]:
        attr = change.get("attribute", "")
        before = _fmt(change.get("before"))
        after = _fmt(change.get("after"))
        inner.append(f"| `{attr}` | `{before}` | `{after}` |")
    if len(finding.changed_attributes) > 5:
        extra = len(finding.changed_attributes) - 5
        inner.append(f"| _...{extra} more_ | | |")

    # Attribution
    inner.append("")
    if finding.attributed_to:
        principal = finding.attributed_to
        action = finding.attributed_action or "unknown"
        inner.append(f"**Who:** `{principal}`  ")
        inner.append(f"**Action:** `{action}`  ")
        if finding.attributed_at:
            inner.append(f"**When:** `{finding.attributed_at}`  ")
    else:
        inner.append("**Who:** _attribution unavailable (outside 90-day CloudTrail window)_  ")

    # Remediation
    if finding.remediation_hint:
        inner.append(f"\n**Fix:**\n```\n{finding.remediation_hint}\n```")

    body = "\n".join(inner)
    return f"\n<details>\n<summary>{summary}</summary>\n\n{body}\n</details>\n"


def _severity_summary(findings: list[DriftFinding]) -> str:
    """One-line badge-style severity summary."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev, emoji in [("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "🟢")]:
        if counts.get(sev, 0):
            parts.append(f"{emoji} **{counts[sev]} {sev.capitalize()}**")
    return "  ".join(parts)


def _fmt(value) -> str:
    """Compact value for table cells."""

    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        dumped = json.dumps(value, separators=(",", ":"))
        return dumped if len(dumped) <= 50 else dumped[:47] + "..."
    s = str(value)
    return s if len(s) <= 50 else s[:47] + "..."


def _print_warning(msg: str) -> None:
    try:
        from rich.console import Console

        Console(stderr=True).print(f"[yellow]⚠ {msg}[/yellow]")
    except ImportError:
        import sys

        print(f"⚠ {msg}", file=sys.stderr)
