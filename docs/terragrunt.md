# Terragrunt-Aware Drift Detection

`drifty terragrunt` extends drifty's drift intelligence across an entire
Terragrunt monorepo — discovering every runnable unit, scanning each one
with `terraform plan -refresh-only`, and aggregating results into a single
report.

## Requirements

- `terragrunt` installed and on `PATH`
  ([install guide](https://terragrunt.gruntwork.io/docs/getting-started/install/))
- `terraform` installed and on `PATH`
- AWS credentials available (same as `drifty scan`)
- A Terragrunt repository with `terragrunt.hcl` files

## Commands

### `drifty terragrunt discover`

Recursively discovers all runnable Terragrunt units without executing any
Terraform commands. Use this to validate what will be scanned.

```bash
drifty terragrunt discover --root ./infra
```

A unit is considered **runnable** when its `terragrunt.hcl` contains a
`terraform {}` block. Root configs (`remote_state {}` only) and shared
generate configs are excluded automatically.

**Flags**

| Flag | Default | Description |
|---|---|---|
| `--root` / `-r` | `.` | Root directory to start discovery from |
| `--exclude` | `` | Comma-separated extra directory names to skip |

The following directories are **always** excluded regardless of `--exclude`:
`.terragrunt-cache`, `.git`, `.terraform`, `node_modules`, `.venv`, `venv`,
`__pycache__`.

---

### `drifty terragrunt scan`

Discovers all runnable units and scans each one for drift.

```bash
# Basic scan
drifty terragrunt scan --root ./infra

# High-severity only, with CloudTrail attribution
drifty terragrunt scan --root ./infra --min-severity high --attribute

# JSON output for CI/CD pipelines
drifty terragrunt scan --root ./infra --output json | jq '.drifted_units'

# Validate discovery before scanning (no terraform executed)
drifty terragrunt scan --root ./infra --discover-only

# Abort on first unit failure
drifty terragrunt scan --root ./infra --fail-fast

# Extend timeout for slow units
drifty terragrunt scan --root ./infra --unit-timeout 600
```

**Flags**

| Flag | Default | Description |
|---|---|---|
| `--root` / `-r` | `.` | Root directory to discover units from |
| `--output` / `-o` | `terminal` | `terminal` or `json` |
| `--min-severity` / `-s` | all | Minimum severity: `critical` `high` `medium` `low` |
| `--profile` / `-p` | `default` | AWS CLI profile for CloudTrail attribution |
| `--attribute` / `-a` | off | Enable CloudTrail attribution per finding |
| `--exclude` | `` | Extra directory names to skip |
| `--unit-timeout` | `300` | Per-unit subprocess timeout in seconds |
| `--discover-only` | off | Print units and exit, no terraform execution |
| `--fail-fast` | off | Stop after the first unit failure |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | All units scanned, no drift detected |
| `1` | One or more units have drift |
| `2` | Operational failure (missing binary, invalid root, all units failed) |
| `3` | Partial scan failure (some units failed, some succeeded) |

---

## How it works

1. **Discovery** — walks the root directory with `os.walk`, pruning excluded
   dirs. For each `terragrunt.hcl` found, checks for a `terraform {}` block
   via regex to determine runnability.
2. **Execution** — for each unit (serial in Phase 1):
   - `terragrunt init --terragrunt-non-interactive`
   - `terragrunt plan -refresh-only -json -no-color`
3. **Parsing** — reuses `drifty.scanner._parse_output()` on the JSON Lines
   output — no duplication of parsing logic.
4. **Scoring** — reuses `drifty.scorer.score()` per finding, respecting any
   `severity_overrides` in `.drifty/config.yaml`.
5. **Reporting** — aggregates into a `TerragruntScanReport` and renders via
   Rich terminal output or structured JSON.

## Security guarantees

- All subprocess calls use argument lists — `shell=True` is never used.
- The `terragrunt` binary is validated with `shutil.which()` before any
  execution.
- Every subprocess call has an explicit timeout.
- No `apply`, `destroy`, or state-mutating commands are ever issued.
- Secrets and credentials are never logged.

## JSON output schema

```json
{
  "scan_time": "2026-07-13T14:00:00+00:00",
  "root": "/path/to/infra",
  "total_units": 3,
  "scanned_units": 3,
  "drifted_units": 1,
  "failed_units": 0,
  "skipped_units": 0,
  "total_findings": 2,
  "severity_summary": { "critical": 1, "high": 1 },
  "dependency_graph": {},
  "unit_results"