"""
scanner.py — runs `terraform plan -refresh-only -json` and parses drift findings.

Terraform emits newline-delimited JSON (JSON Lines) to stdout when run with -json.
Each line is a message object with a `type` field. We care about:
  - type == "resource_drift"     → a resource has drifted from state
  - type == "planned_change"     → used to cross-check drift (ignored for now)
  - type == "diagnostic"         → errors/warnings from terraform itself
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from drifty.history import append_findings
from drifty.ignore import filter_findings

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class DriftFinding:
    resource_type: str
    resource_name: str
    resource_id: str
    changed_attributes: list[dict]
    severity: str = "low"
    attributed_to: str | None = None
    attributed_at: str | None = None
    attributed_action: str | None = None
    remediation_hint: str | None = None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_scan(
    workspace: Path,
    profile: str = "default",
    with_attribution: bool = False,
    severity_filter: str | None = None,
) -> tuple[list[DriftFinding], list[DriftFinding]]:
    """
    Full scan pipeline:
      1. Run terraform plan -refresh-only -json
      2. Parse JSON Lines output into DriftFinding list
      3. Score each finding (scorer.py)
      4. Optionally attribute each finding (cloudtrail.py)
      5. Apply severity filter
      6. Filter against ignore list
      7. Persist active findings to history
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Running terraform plan -refresh-only ...[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("scan", total=None)
        raw_output, error_output = _run_terraform(workspace)

    if raw_output is None:
        return [], []

    findings = _parse_output(raw_output)

    if not findings:
        return [], []

    # Score every finding
    from drifty.scorer import score

    for finding in findings:
        finding.severity = score(finding)

    # CloudTrail attribution
    if with_attribution:
        from drifty.cloudtrail import attribute_finding

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Looking up CloudTrail events ...[/bold cyan]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("cloudtrail", total=len(findings))
            for finding in findings:
                attribution = attribute_finding(finding, profile=profile)
                if attribution:
                    finding.attributed_to = attribution.get("principal")
                    finding.attributed_at = attribution.get("timestamp")
                    finding.attributed_action = attribution.get("action")
                progress.advance(task)

    # Severity filter
    if severity_filter:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_order.get(severity_filter, 3)
        findings = [f for f in findings if severity_order.get(f.severity, 3) <= threshold]

    active, suppressed = filter_findings(findings, workspace)
    append_findings(active, workspace)
    return active, suppressed


# ---------------------------------------------------------------------------
# Terraform subprocess
# ---------------------------------------------------------------------------


def _run_terraform(workspace: Path) -> tuple[list[str] | None, str]:
    """
    Run `terraform plan -refresh-only -json` in the given workspace directory.

    Returns (lines, stderr) where lines is a list of raw JSON strings.
    Returns (None, error_message) on failure.
    """
    cmd = ["terraform", "plan", "-refresh-only", "-json", "-no-color"]

    try:
        result = subprocess.run(
            cmd,
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        console.print(
            "[red]✗ terraform not found in PATH.[/red]\n"
            "  Install Terraform: [link=https://developer.hashicorp.com/terraform/install]"
            "https://developer.hashicorp.com/terraform/install[/link]"
        )
        return None, "terraform not found"
    except subprocess.TimeoutExpired:
        console.print(
            "[red]✗ terraform plan timed out after 5 minutes.[/red]\n"
            "  Try running [bold]terraform plan -refresh-only[/bold] manually to diagnose."
        )
        return None, "timeout"

    if result.returncode == 1:
        err_console.print("[red]✗ terraform plan failed:[/red]")
        _print_terraform_diagnostics(result.stdout)
        if result.stderr:
            console.print(f"[red]{result.stderr}[/red]")
        return None, result.stderr

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return lines, result.stderr


# ---------------------------------------------------------------------------
# JSON Lines parser
# ---------------------------------------------------------------------------


def _parse_output(lines: list[str]) -> list[DriftFinding]:
    findings: list[DriftFinding] = []

    for line in lines:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_type = msg.get("type", "")

        if msg_type == "resource_drift":
            finding = _parse_drift_message(msg)
            if finding:
                findings.append(finding)

        elif msg_type == "diagnostic":
            severity = msg.get("@level", "warning")
            detail = msg.get("diagnostic", {}).get("detail", "")
            summary = msg.get("diagnostic", {}).get("summary", "")
            if severity == "error":
                console.print(f"[red]terraform error:[/red] {summary} — {detail}")

    return findings


def _parse_drift_message(msg: dict) -> DriftFinding | None:
    change = msg.get("change", {})
    resource = change.get("resource", {})

    resource_type = resource.get("resource_type", "")
    resource_name = resource.get("resource_name", "")
    addr = resource.get("addr", f"{resource_type}.{resource_name}")

    before = change.get("before") or {}
    after = change.get("after") or {}

    if not resource_type:
        return None

    resource_id = after.get("id") or before.get("id") or addr
    changed_attributes = _diff_attributes(before, after)
    remediation = _build_remediation_hint(resource_type, resource_name, resource_id)

    return DriftFinding(
        resource_type=resource_type,
        resource_name=resource_name,
        resource_id=str(resource_id),
        changed_attributes=changed_attributes,
        remediation_hint=remediation,
    )


def _diff_attributes(before: dict, after: dict) -> list[dict]:
    changed = []
    all_keys = set(before.keys()) | set(after.keys())

    for key in sorted(all_keys):
        if key.startswith("_"):
            continue
        val_before = before.get(key)
        val_after = after.get(key)
        if val_before != val_after:
            changed.append({"attribute": key, "before": val_before, "after": val_after})

    return changed


def _build_remediation_hint(
    resource_type: str,
    resource_name: str,
    resource_id: str,
) -> str:
    addr = f"{resource_type}.{resource_name}"

    importable = {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_policy",
        "aws_instance",
        "aws_s3_bucket",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_public_access_block",
        "aws_rds_instance",
        "aws_lb",
        "aws_alb",
        "aws_lambda_function",
        "aws_autoscaling_group",
        "aws_cloudwatch_metric_alarm",
        "aws_vpc",
        "aws_subnet",
        "aws_route_table",
        "aws_internet_gateway",
    }

    if resource_type in importable:
        return f"terraform import {addr} {resource_id}"

    return f"Update {addr} in your Terraform config and run terraform apply to reconcile"


def _print_terraform_diagnostics(stdout: str) -> None:
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
            if msg.get("type") == "diagnostic":
                diag = msg.get("diagnostic", {})
                err_console.print(f"  [red]{diag.get('summary', '')}[/red]")
                if diag.get("detail"):
                    err_console.print(f"  [dim]{diag['detail']}[/dim]")
        except json.JSONDecodeError:
            pass
