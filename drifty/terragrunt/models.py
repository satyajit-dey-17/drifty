"""
models.py — dataclasses for the Terragrunt-aware drift detection pipeline.

TerragruntUnit          — a single discovered, runnable Terragrunt configuration unit
UnitScanResult          — result of scanning one unit (findings, status, error)
TerragruntScanReport    — aggregated report across all units in a scan run

Phase 2 extension points (dependency graph / blast radius):
  TerragruntUnit.dependencies       — populated by Phase 2 dependency parser
  TerragruntScanReport.dependency_graph — adjacency map for blast-radius analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding


@dataclass
class TerragruntUnit:
    """A single discoverable, runnable Terragrunt configuration unit."""

    path: Path
    """Absolute path to the directory containing terragrunt.hcl."""

    rel_path: str
    """Path relative to the scan root — used for display and sorting."""

    hcl_file: Path
    """Absolute path to the terragrunt.hcl file."""

    is_runnable: bool
    """True when the unit contains a terraform{} block and is independently deployable."""

    env_hint: str | None
    """
    Environment label inferred from path segments (e.g. 'prod', 'staging').
    None when no recognisable environment segment is present.
    """

    # Phase 2 extension point — defaults to empty list so Phase 1 data is forward-compatible.
    dependencies: list[Path] = field(default_factory=list)
    """
    Absolute paths to units this unit declares as Terragrunt dependencies.
    Populated by the Phase 2 dependency parser; always empty in Phase 1.
    """


@dataclass
class UnitScanResult:
    """Result of scanning a single TerragruntUnit."""

    unit: TerragruntUnit
    status: Literal["success", "drifted", "failed", "skipped"]
    findings: list[DriftFinding]
    suppressed: list[DriftFinding]
    error_message: str | None
    duration_seconds: float


@dataclass
class TerragruntScanReport:
    """Aggregated result of scanning all discovered units in one invocation."""

    scan_time: str
    """ISO 8601 timestamp of when the scan started."""

    root: Path
    """Absolute path to the scan root directory."""

    total_units: int
    scanned_units: int
    drifted_units: int
    failed_units: int
    skipped_units: int
    total_findings: int
    severity_summary: dict[str, int]

    unit_results: list[UnitScanResult]
    """Sorted by UnitScanResult.unit.rel_path — deterministic output guaranteed."""

    # Phase 2 extension point — always empty dict in Phase 1.
    dependency_graph: dict[str, list[str]] = field(default_factory=dict)
    """
    Adjacency map: rel_path → list of rel_paths this unit depends on.
    Populated by Phase 2 blast-radius analysis; always empty in Phase 1.
    """
