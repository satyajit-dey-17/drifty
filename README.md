# 🔍 drifty

> Detect Terraform drift, attribute the change, assess risk, and fix it fast.

[![PyPI version](https://badge.fury.io/py/drifty.svg)](https://pypi.org/project/drifty/)
[![Python](https://img.shields.io/pypi/pyversions/drifty)](https://pypi.org/project/drifty/)
[![CI](https://github.com/satyajit-dey-17/drifty/actions/workflows/test.yml/badge.svg)](https://github.com/satyajit-dey-17/drifty/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```bash
pip install drifty
```

---

## The Problem

`terraform plan` tells you **what** drifted. It does not provide native attribution for **who** changed it, how risky the change is, or the best way to respond.

Manual changes in the AWS console during incidents, auto-scaling events, and ad-hoc CLI commands can silently diverge infrastructure from Terraform state. By the time the drift is noticed, it is often unclear whether it came from a teammate, approved automation, or a potential security issue.

Platforms such as Spacelift and HCP Terraform can detect drift on a schedule, but they are broader IaC platforms that are heavier, more expensive, and do not natively focus on attribution or severity scoring.

**drifty fills this gap.** It gives teams a lightweight way to detect drift, enrich it with CloudTrail context, prioritize what matters, and act quickly.

---

## Demo

```text
$ drifty scan --workspace ./infra --attribute

🔍 drifty — Terraform Drift Intelligence
Scanning workspace: ./infra  |  2026-06-05 14:00 UTC

╭─────────────────────────────────────────────────────────────╮
│  3 drifts detected  -   1 Critical  -   1 High  -   1 Low   │
╰─────────────────────────────────────────────────────────────╯

🔴 CRITICAL  aws_security_group.main  (sg-0abc1234)
   Changed:  ingress.0.cidr_blocks  →  ["0.0.0.0/0"]  (was: ["10.0.0.0/8"])
   Who:      arn:aws:iam::123456789:user/john.doe
   When:     2026-06-03 14:22:11 UTC
   Action:   ModifySecurityGroupRules
   Suggested action: reconcile state with Terraform import or revert with terraform apply

🟠 HIGH  aws_instance.api_server  (i-0def5678)
   Changed:  instance_type  →  t3.large  (was: t3.medium)
   Who:      arn:aws:iam::123456789:role/ops-automation
   When:     2026-06-02 09:15:44 UTC
   Action:   ModifyInstanceAttribute
   Suggested action: reconcile state with Terraform import or revert with terraform apply

🟢 LOW  aws_s3_bucket.assets  (assets-bucket-prod)
   Changed:  tags.LastModified  →  "2026-06-01"  (was: "2026-05-15")
   Who:      attribution unavailable (event outside 90-day CloudTrail window)
   Suggested action: add tag to Terraform config or run terraform apply to reconcile

──────────────────────────────────────────────────────────────
Run `drifty report --format markdown` to export this as a report.
```

---

## Install

**Requirements:** Python 3.10+, AWS credentials configured, and Terraform available in your workspace.

```bash
pip install drifty
```

---

## Quick Start

```bash
# 1. Initialize config in your Terraform workspace
cd ./infra
drifty init

# 2. Scan for drift
drifty scan

# 3. Scan with CloudTrail attribution
drifty scan --attribute

# 4. Filter to critical and high only
drifty scan --severity high

# 5. Output as JSON for CI/CD piping
drifty scan --output json | jq '.findings[] | select(.severity=="critical")'

# 6. Export a markdown report
drifty report --format markdown --out ./drift-report.md

# 7. Send drift summary to Slack
drifty config set slack_webhook=https://hooks.slack.com/services/xxx/yyy/zzz
drifty scan --notify slack

# 8. Watch for new drift continuously
drifty watch --interval 300 --threshold high --notify slack

# 9. Watch with CloudTrail attribution on every cycle
drifty watch --interval 300 --attribute --notify slack

# 10. Post drift report as a GitHub PR comment
drifty report-pr --attribute --severity high

# 11. View drift history across previous scans
drifty history

# 12. Show last 30 scans, high severity and above
drifty history --last 30 --severity high

# 13. Suppress a known or accepted drift
drifty ignore aws_instance.api_server --reason "approved by security team"

# 14. List all ignored resources
drifty ignore --list

# 15. Remove an ignore entry
drifty ignore aws_instance.api_server --remove
```

---

## Why It Stands Out

`drifty` is designed for engineers who want drift detection without adopting a full platform. It works locally, fits naturally into CI, and adds attribution, severity, reporting, and notifications on top of Terraform's existing workflow.

A particularly strong workflow is continuous monitoring with Slack alerts and optional CloudTrail attribution. That combination helps teams catch new drift quickly without creating repeated noise.

---

## How It Works

```text
drifty scan
    │
    ├─ 1. runs: terraform plan -refresh-only -json
    │
    ├─ 2. parses JSON Lines output → extracts resource_drift entries
    │
    ├─ 3. scores each finding
    │       critical → IAM, security groups, S3 policies
    │       high     → EC2 instances, RDS, load balancers
    │       medium   → Lambda, Auto Scaling, CloudWatch
    │       low      → tag-only changes
    │
    ├─ 4. attributes each finding via CloudTrail (if --attribute)
    │       boto3 → LookupEvents by resource ID
    │       returns: IAM principal, timestamp, API action
    │
    └─ 5. renders output
            terminal → Rich color-coded output
            json     → structured output for CI/CD
            markdown → report for docs and collaboration
```

---

## Commands

### `drifty scan`

```text
Options:
  --workspace PATH    Terraform directory (default: current dir)
  --profile TEXT      AWS CLI profile (default: "default")
  --attribute         Enable CloudTrail attribution
  --severity TEXT     Minimum severity: critical | high | medium | low
  --output TEXT       Output format: terminal | json | markdown
  --notify TEXT       Send results to: slack
```

### `drifty init`

Initializes `.drifty/config.yaml` in the workspace with default settings.

### `drifty config set KEY=VALUE`

```bash
drifty config set default_severity=high
drifty config set default_profile=prod
drifty config set slack_webhook=https://hooks.slack.com/...
drifty config set cloudtrail_lookback_days=30
```

### `drifty report`

```bash
drifty report --format markdown --out ./reports/drift-$(date +%F).md
drifty report --format json
```

### `drifty scan --notify slack`

Sends a Slack Block Kit message when drift is found. Configure `slack_webhook` in `.drifty/config.yaml` first.

```bash
# One-time setup
drifty config set slack_webhook=https://hooks.slack.com/services/T.../B.../xxx

# Then run with notifications
drifty scan --notify slack
drifty scan --attribute --notify slack --severity high
```

The Slack message includes:

- Severity summary
- Per-finding blocks with changed attributes, attribution, and remediation hints
- A cap of 10 findings per message to stay within Slack block limits

### `drifty watch`

Continuously monitors a Terraform workspace for drift and alerts when new findings appear.

```text
Options:
  --workspace PATH    Terraform directory (default: current dir)
  --interval INT      Polling interval in seconds (default: 300)
  --threshold TEXT    Minimum severity to trigger alert: critical | high | medium | low
  --notify TEXT       Notifier to use when new drift is detected: slack
  --attribute         Enable CloudTrail attribution on each cycle
```

```bash
# Poll every 5 minutes, alert on high+ drift via Slack
drifty watch --interval 300 --threshold high --notify slack --attribute

# Run locally with a faster interval for testing
drifty watch --interval 60 --threshold low
```

`drifty watch` tracks state between cycles using a finding hash stored in `.drifty/state.json`. It only alerts on **new** drift so previously seen findings do not create repeated noise.

### `drifty report-pr`

Scans for drift and posts a formatted report as a comment on a GitHub Pull Request.

```text
Options:
  --workspace PATH    Terraform directory (default: current dir)
  --profile TEXT      AWS CLI profile
  --attribute         Enable CloudTrail attribution
  --severity TEXT     Minimum severity filter: critical | high | medium | low
  --token TEXT        GitHub token (defaults to GITHUB_TOKEN env var)
  --repo TEXT         Repository in owner/repo format (defaults to GITHUB_REPOSITORY env var)
  --pr INT            Pull request number (defaults to PR_NUMBER env var)
```

```bash
# In GitHub Actions
drifty report-pr --attribute --severity high

# Locally against a specific PR
drifty report-pr --repo acme/infra --pr 42 --token ghp_xxx
```

Each finding renders as a collapsible `<details>` block with changed attributes, attribution details, and a remediation hint.

Example GitHub Actions step:

```yaml
- name: Drift Report
  run: drifty report-pr --attribute --severity high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    PR_NUMBER: ${{ github.event.pull_request.number }}
```

### `drifty history`

Shows drift trends from previous scans. Findings are automatically persisted to `.drifty/history.json` after every `drifty scan`.

```text
Options:
  --workspace PATH    Terraform directory (default: current dir)
  --last INT          Number of recent scans to show (default: 10)
  --severity TEXT     Minimum severity filter: critical | high | medium | low
  --output TEXT       terminal | json
```

```bash
drifty history
drifty history --last 30 --severity high
drifty history --output json
```

### `drifty ignore`

Manages the ignore list for suppressing known or accepted drift. Suppressed resources still appear in scan output under a dimmed **Suppressed** label rather than being silently hidden.

```text
Options:
  RESOURCE            Resource address to ignore, for example aws_instance.api_server
  --workspace PATH    Terraform directory (default: current dir)
  --reason TEXT       Reason for ignoring this resource
  --remove            Remove a resource from the ignore list
  --list              List all currently ignored resources
```

```bash
drifty ignore aws_instance.api_server
drifty ignore aws_instance.api_server --reason "approved by security team"
drifty ignore aws_instance.api_server --remove
drifty ignore --list
```

Ignore entries are persisted to `.drifty/ignore.yaml` with timestamp and author.

---

## Severity Rules

| Resource Type | Severity |
|---|---|
| `aws_iam_role_policy`, `aws_iam_policy` | 🔴 Critical |
| `aws_security_group`, `aws_security_group_rule` | 🔴 Critical |
| `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block` | 🔴 Critical |
| `aws_instance` (type or AMI change) | 🟠 High |
| `aws_rds_instance`, `aws_lb`, `aws_alb` | 🟠 High |
| `aws_lambda_function`, `aws_autoscaling_group` | 🟡 Medium |
| `aws_cloudwatch_metric_alarm` | 🟡 Medium |
| `aws_instance` (tag-only change) | 🟢 Low |
| `aws_s3_bucket` (tag-only change) | 🟢 Low |

Override any rule per workspace:

```yaml
# .drifty/config.yaml
severity_overrides:
  aws_lambda_function: high
  aws_cloudwatch_metric_alarm: low
```

---

## drifty vs. Alternatives

| Feature | `terraform plan` | Spacelift / HCP Terraform | **drifty** |
|---|---|---|---|
| Detects drift | ✅ | ✅ | ✅ |
| Native attribution | ❌ | ❌ | ✅ CloudTrail |
| Severity score | ❌ | ❌ | ✅ |
| Remediation guidance | ❌ | ❌ | ✅ |
| JSON / Markdown output | ❌ | Partial | ✅ |
| Works locally / in CI | ✅ | ❌ SaaS only | ✅ |
| Cost | Free | $$$ | Free |
| Install | N/A | Platform setup | `pip install drifty` |
| Slack alerts | ❌ | ❌ | ✅ |
| Continuous drift watch | ❌ | ✅ Scheduled | ✅ |
| GitHub PR comment | ❌ | ❌ | ✅ |
| Drift history / trends | ❌ | ❌ | ✅ |
| Ignore / suppress drift | ❌ | ❌ | ✅ |

---

## Configuration Reference

```yaml
# .drifty/config.yaml
default_profile: default
default_severity: null
default_output: terminal
slack_webhook: null
cloudtrail_lookback_days: 90
severity_overrides: {}
```

---

## Release

drifty is packaged with Poetry, built from `pyproject.toml`, and published to PyPI. Poetry requires a package version to be defined in `pyproject.toml`, either in `project.version` or `tool.poetry.version`, and that version is the source of truth for the built package metadata.

The recommended GitHub Actions pattern is to build distributions in one job, store them as artifacts, and publish them from a separate PyPI job that runs on tag pushes with trusted publishing enabled. For repeatable releases, use the tag as the release trigger, keep the package version aligned with `pyproject.toml`, and configure the PyPI publish step to skip already-uploaded files on reruns.

Tagged releases can also create or update a GitHub Release with changelog-derived notes while PyPI publication is handled separately in the publish job.

Example local development flow:

```bash
poetry version patch
poetry build
poetry publish -r testpypi
```

Example GitHub Actions publish step:

```yaml
- name: Publish distribution 📦 to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    skip-existing: true
```

---

## Roadmap

- [x] Slack notifications via `--notify slack`
- [x] Continuous drift watch
- [x] GitHub PR comment integration
- [x] Drift history
- [x] Ignore / suppress drift
- [ ] Azure and GCP provider support

---

## Contributing

```bash
git clone https://github.com/satyajit-dey-17/drifty.git
cd drifty
poetry install
poetry run pytest -v
poetry run ruff check drifty/
poetry run black drifty/
```

Please open an issue before submitting a large PR. See [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) for bug and feature templates.

---

## License

MIT © [Satyajit Dey](https://github.com/satyajit-dey-17)