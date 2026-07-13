# Release Notes

## v0.8.0 — Terragrunt-Aware Drift Detection

### What's new

drifty can now scan an entire Terragrunt monorepo in a single command.

**`drifty terragrunt discover`** recursively walks a root directory,
identifies every runnable Terragrunt unit (those with a `terraform {}` block),
and displays them in a Rich table — with no Terraform execution.

**`drifty terragrunt scan`** scans every discovered unit by running
`terragrunt plan -refresh-only -json`, reusing drifty's existing drift parsing,
severity scoring, and Rich/JSON reporting pipeline. Results are aggregated into
a single report with per-unit status and an overall severity summary.

### Exit code contract (new, additive)

| Code | Meaning |
|------|---------|
| `0`  | All units clean |
| `1`  | Drift detected |
| `2`  | Operational failure (missing binary, invalid root, all units failed) |
| `3`  | Partial failure (some units failed, some succeeded) |

### Real output

```text
$ drifty terragrunt scan --root ./infra

🔍 drifty — Terragrunt Drift Intelligence
Root: ./infra  |  2026-07-13T13:42:04Z

✓ envs/prod/app      1.0s   No drift detected.
✓ envs/prod/db       1.6s   No drift detected.
✓ envs/staging/app   1.6s   No drift detected.

╭────────────────────── Terragrunt Scan Summary ───────────────────────╮
│ 3 units  |  3 clean  |  0 drifted  |  0 failed                       │
╰──────────────────────────────────────────────────────────────────────╯
```

Exit code: `0`

### Security

All subprocess calls use argument lists (`shell=False`). The `terragrunt`
binary is validated with `shutil.which()` before any execution. No `apply`,
`destroy`, or state-mutating commands are ever issued.

### Phase 2 preview

The data model includes forward-compatible extension points for dependency
graph and blast-radius analysis (`TerragruntUnit.dependencies`,
`TerragruntScanReport.dependency_graph`). These are empty in v0.8.0 and will
be populated in a future release without breaking the existing schema.

