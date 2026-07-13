"""
drifty.terragrunt — Terragrunt-aware drift detection sub-package.

Public surface:
  discovery.py  — recursive unit discovery
  models.py     — TerragruntUnit, UnitScanResult, TerragruntScanReport
  runner.py     — safe subprocess execution (Commit 3)
  reporter.py   — Rich + JSON output (Commit 4)
  cli.py        — Typer sub-app (Commit 4)
"""
