"""
scanner.py — runs `terraform plan -refresh-only -json` and parses drift findings.

Terraform emits newline-delimited JSON (JSON Lines) to stdout when run with -json.
Each line is a message object with a `type` field. We care about:
  - type == "resource_drift"     → a resource has drifted from state
  - type == "planned_change"     → used to cross-check drift (ignored for now)
  - type == "diagnostic"         → errors/warnings from terraform itself

Attribute diffs are extracted from a saved plan file via `terraform show -json`,
which provides full before/after values for each changed resource.
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
      1. Run terraform plan -refresh-only -json -out=.drifty/refresh.tfplan
      2. Run terraform show -json on the saved plan to get before/after diffs
      3. Parse JSON Lines output into DriftFinding list
      4. Score each finding (scorer.py)
      5. Optionally attribute each finding (cloudtrail.py)
      6. Apply severity filter
      7. Filter against ignore list
      8. Persist active findings to history
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Running terraform plan -refresh-only ...[/bold cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("scan", total=None)
        raw_output, plan_json, error_output = _run_terraform(workspace)

    if raw_output is None:
        return [], []

    findings = _parse_output(raw_output, plan_json)

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


def _run_terraform(workspace: Path) -> tuple[list[str] | None, dict | None, str]:
    """
    Step 1: terraform plan -refresh-only -json -out=.drifty/refresh.tfplan
            Captures JSON Lines stream for drift detection + resource IDs.

    Step 2: terraform show -json .drifty/refresh.tfplan
            Extracts full before/after attribute values for changed resources.

    Returns (json_lines, plan_json, stderr).
    Returns (None, None, error_message) on failure.
    """
    plan_dir = workspace / ".drifty"
    plan_dir.mkdir(exist_ok=True)
    plan_file = plan_dir / "refresh.tfplan"

    cmd = [
        "terraform",
        "plan",
        "-refresh-only",
        "-json",
        "-no-color",
        f"-out={plan_file}",
    ]

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
        return None, None, "terraform not found"
    except subprocess.TimeoutExpired:
        console.print(
            "[red]✗ terraform plan timed out after 5 minutes.[/red]\n"
            "  Try running [bold]terraform plan -refresh-only[/bold] manually to diagnose."
        )
        return None, None, "timeout"

    if result.returncode == 1:
        err_console.print("[red]✗ terraform plan failed:[/red]")
        _print_terraform_diagnostics(result.stdout)
        if result.stderr:
            console.print(f"[red]{result.stderr}[/red]")
        return None, None, result.stderr

    lines = [line for line in result.stdout.splitlines() if line.strip()]

    # Step 2 — convert saved plan file to full JSON for before/after diffs
    plan_json = None
    if plan_file.exists():
        try:
            show_result = subprocess.run(
                ["terraform", "show", "-json", "-no-color", str(plan_file)],
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if show_result.returncode == 0:
                plan_json = json.loads(show_result.stdout)
        except Exception:
            pass  # plan_json stays None — changed_attributes will be empty
        finally:
            plan_file.unlink(missing_ok=True)  # always clean up temp file

    return lines, plan_json, result.stderr


# ---------------------------------------------------------------------------
# JSON Lines parser
# ---------------------------------------------------------------------------


def _build_diff_map(plan_json: dict | None) -> dict[str, tuple[dict, dict]]:
    """
    Build a map of resource address → (before, after) from a saved plan JSON.

    terraform show -json <planfile> emits a "resource_changes" array where
    each entry has change.before and change.after with full attribute values.
    Only includes resources with actual changes (excludes no-op entries).
    """
    if not plan_json:
        return {}

    diff_map: dict[str, tuple[dict, dict]] = {}

    for rc in plan_json.get("resource_changes", []):
        actions = rc.get("change", {}).get("actions", [])
        if "no-op" in actions:
            continue
        addr = rc.get("address", "")
        before = rc.get("change", {}).get("before") or {}
        after = rc.get("change", {}).get("after") or {}
        if addr:
            diff_map[addr] = (before, after)

    return diff_map


def _parse_output(output: list[str], plan_json: dict | None = None) -> list[DriftFinding]:
    findings = []

    # Pass 1: build address → real AWS ID map from refresh_complete hooks
    id_map: dict[str, str] = {}
    for line in output:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("type") == "refresh_complete":
            hook = msg.get("hook", {})
            resource = hook.get("resource", {})
            addr = resource.get("addr")
            id_value = hook.get("id_value")
            if addr and id_value:
                id_map[addr] = id_value

    # Build before/after diff map from saved plan JSON
    diff_map = _build_diff_map(plan_json)

    # Pass 2: process resource_drift messages with real IDs + attribute diffs
    for line in output:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("type") != "resource_drift":
            continue
        finding = _parse_drift_message(msg, id_map, diff_map)
        if finding:
            findings.append(finding)

    return findings


def _parse_drift_message(
    msg: dict,
    id_map: dict[str, str] | None = None,
    diff_map: dict[str, tuple[dict, dict]] | None = None,
) -> DriftFinding | None:
    change = msg.get("change", {})
    resource = change.get("resource", {})

    addr = resource.get("addr", "")
    resource_type = resource.get("resource_type", "")
    resource_name = resource.get("resource_name", "")

    if not resource_type:
        return None

    # before/after: prefer diff_map (from saved plan), fall back to inline
    # (inline exists in mocked test data but not in real terraform output)
    if diff_map and addr in diff_map:
        before, after = diff_map[addr]
    else:
        before = change.get("before") or {}
        after = change.get("after") or {}

    # resource_id: prefer id_map, then inline before/after id field, then addr
    resource_id = (id_map or {}).get(addr) or after.get("id") or before.get("id") or addr

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
