"""
mcp_server.py — Exposes Drifty as an MCP (Model Context Protocol) server.

Tools exposed:
  - detect_drift : run terraform plan -refresh-only and return drift findings
  - score_drift  : return severity scores for each drifted resource
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("drifty")


@mcp.tool()
def detect_drift(
    working_dir: str,
    aws_profile: str = "default",
    severity_filter: str | None = None,
) -> dict:
    """
    Detect Terraform infrastructure drift in the given working directory.

    Runs terraform plan -refresh-only and returns drifted resources
    with changed attributes and remediation hints.

    Args:
        working_dir:     Absolute path to your Terraform workspace.
        aws_profile:     AWS CLI profile to use (default: "default").
        severity_filter: Only return findings at or above this level.
                         Options: "critical", "high", "medium", "low".
    """
    from drifty.scanner import run_scan

    workspace = Path(working_dir)
    if not workspace.exists():
        return {"error": f"Directory not found: {working_dir}"}

    active, suppressed = run_scan(
        workspace=workspace,
        profile=aws_profile,
        with_attribution=False,
        severity_filter=severity_filter,
    )

    return {
        "findings": [
            {
                "resource_type": f.resource_type,
                "resource_name": f.resource_name,
                "resource_id": f.resource_id,
                "address": f.address,
                "severity": f.severity,
                "changed_attributes": f.changed_attributes,
                "remediation_hint": f.remediation_hint,
            }
            for f in active
        ],
        "suppressed_count": len(suppressed),
        "total": len(active),
    }


@mcp.tool()
def score_drift(working_dir: str, aws_profile: str = "default") -> dict:
    """
    Return a severity summary for all drifted resources in the workspace.

    Faster than detect_drift — no full attribute diff payload.

    Args:
        working_dir: Absolute path to your Terraform workspace.
        aws_profile: AWS CLI profile to use (default: "default").
    """
    from drifty.scanner import run_scan

    workspace = Path(working_dir)
    if not workspace.exists():
        return {"error": f"Directory not found: {working_dir}"}

    active, _ = run_scan(workspace=workspace, profile=aws_profile)

    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    resources = []

    for f in active:
        sev = f.severity or "low"
        summary[sev] = summary.get(sev, 0) + 1
        resources.append({"address": f.address, "severity": sev})

    return {"summary": summary, "resources": resources}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
