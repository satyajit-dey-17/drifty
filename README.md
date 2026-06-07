# 🔍 drifty

> Terraform drift intelligence — detect what changed, who changed it, how dangerous it is, and how to fix it.

[![PyPI version](https://badge.fury.io/py/drifty.svg)](https://pypi.org/project/drifty/)
[![Python](https://img.shields.io/pypi/pyversions/drifty)](https://pypi.org/project/drifty/)
[![CI](https://github.com/satyajit-dey-17/drifty/actions/workflows/test.yml/badge.svg)](https://github.com/satyajit-dey-17/drifty/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

```bash
pip install drifty
```

---

## The Problem

`terraform plan` tells you **what** drifted. It doesn't tell you **who** changed it, **how dangerous** the change is, or **what to do** about it.

Manual changes in the AWS console during incidents, auto-scaling events, and ad-hoc CLI commands silently diverge your infrastructure from your Terraform state. By the time you notice, you don't know if it was a colleague, a runbook, or a security incident.

Enterprise platforms like Spacelift and HCP Terraform Cloud detect drift on a schedule — but they're full IaC platforms that are heavyweight, expensive, and still offer zero attribution or severity intelligence.

**drifty fills this exact gap.**

---

## Demo

```text
$ drifty scan --workspace ./infra --attribute

🔍 drifty — Terraform Drift Intelligence
Scanning workspace: ./infra  |  2026-06-05 14:00 UTC

╭─────────────────────────────────────────────────────────────╮
│  3 drifts detected  -   1 Critical  -   1 High  -   1 Low      │
╰─────────────────────────────────────────────────────────────╯

🔴 CRITICAL  aws_security_group.main  (sg-0abc1234)
   Changed:  ingress.0.cidr_blocks  →  ["0.0.0.0/0"]  (was: ["10.0.0.0/8"])
   Who:      arn:aws:iam::123456789:user/john.doe
   When:     2026-06-03 14:22:11 UTC
   Action:   ModifySecurityGroupRules
   Fix:      terraform import aws_security_group.main sg-0abc1234

🟠 HIGH  aws_instance.api_server  (i-0def5678)
   Changed:  instance_type  →  t3.large  (was: t3.medium)
   Who:      arn:aws:iam::123456789:role/ops-automation
   When:     2026-06-02 09:15:44 UTC
   Action:   ModifyInstanceAttribute
   Fix:      terraform import aws_instance.api_server i-0def5678

🟢 LOW  aws_s3_bucket.assets  (assets-bucket-prod)
   Changed:  tags.LastModified  →  "2026-06-01"  (was: "2026-05-15")
   Who:      attribution unavailable (event outside 90-day CloudTrail window)
   Fix:      Add tag to Terraform config or run terraform apply to reconcile

──────────────────────────────────────────────────────────────
Run `drifty report --format markdown` to export this as a report.
```

---

## Install

**Requirements:** Python 3.10+, Terraform 1.1+, AWS credentials configured

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

# 3. Scan with CloudTrail attribution (who caused each drift)
drifty scan --attribute

# 4. Filter to critical and high only
drifty scan --severity high

# 5. Output as JSON (for CI/CD piping)
drifty scan --output json | jq '.findings[] | select(.severity=="critical")'

# 6. Export a markdown report
drifty report --format markdown --out ./drift-report.md

# 7. Send drift summary to Slack
drifty config set slack_webhook=https://hooks.slack.com/services/xxx/yyy/zzz
drifty scan --notify slack

# 8. Watch for new drift continuously (poll every 5 minutes)
drifty watch --interval 300 --threshold high --notify slack

# 9. Watch with CloudTrail attribution on every cycle
drifty watch --interval 300 --attribute --notify slack

# 10. Post drift report as a GitHub PR comment
drifty report-pr --attribute --severity high

# 11. View drift history across previous scans
drifty history

# 12. Show last 30 scans, high severity and above
drifty history --last 30 --severity high

# 13. Suppress a known/accepted drift
drifty ignore aws_instance.api_server --reason "approved by security team"

# 14. List all ignored resources
drifty ignore --list

# 15. Remove an ignore entry
drifty ignore aws_instance.api_server --remove
```

---

## How It Works

```text
drifty scan
    │
    ├─ 1. runs: terraform plan -refresh-only -json
    │
    ├─ 2. parses JSON Lines output → extracts resource_drift entries
    │
    ├─ 3. scores each finding (scorer.py)
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
            terminal → Rich color-coded table
            json     → structured output for CI/CD
            markdown → report for Confluence / Notion
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

Sends a Slack Block Kit message when drift is found. Requires a webhook URL configured in `.drifty/config.yaml`.

```bash
# One-time setup
drifty config set slack_webhook=https://hooks.slack.com/services/T.../B.../xxx

# Then just add the flag
drifty scan --notify slack
drifty scan --attribute --notify slack --severity high
```

The Slack message includes:
- Severity summary (🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low counts)
- Per-finding blocks with changed attributes, CloudTrail attribution, and remediation hint
- Capped at 10 findings per message to stay within Slack's block limit

### `drifty watch`

Continuously monitors your Terraform workspace for drift and alerts when new findings appear.

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

# Run locally with a fast interval for testing
drifty watch --interval 60 --threshold low
```

drifty watch tracks state between cycles using a finding hash stored in `.drifty/state.json`. It only alerts on **new** drift — findings already seen in the previous cycle are suppressed to avoid repeated noise.

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
# In GitHub Actions (env vars set automatically)
drifty report-pr --attribute --severity high

# Locally against a specific PR
drifty report-pr --repo acme/infra --pr 42 --token ghp_xxx
```

Each finding renders as a collapsible `<details>` block with a changed attributes table, CloudTrail attribution, and a remediation hint. Add this step to your workflow:

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

Manages the ignore list for suppressing known or accepted drift. Suppressed resources
still appear in scan output under a dimmed **Suppressed** label — never silently hidden.

```text
Options:
  RESOURCE            Resource address to ignore. Example: aws_instance.api_server
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

Ignore entries are persisted to `.drifty/ignore.yaml` with timestamp and author (`$USER`).

---

## Severity Rules

| Resource Type | Severity |
|---|---|
| `aws_iam_role_policy`, `aws_iam_policy` | 🔴 Critical |
| `aws_security_group`, `aws_security_group_rule` | 🔴 Critical |
| `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block` | 🔴 Critical |
| `aws_instance` (type/AMI change) | 🟠 High |
| `aws_rds_instance`, `aws_lb`, `aws_alb` | 🟠 High |
| `aws_lambda_function`, `aws_autoscaling_group` | 🟡 Medium |
| `aws_cloudwatch_metric_alarm` | 🟡 Medium |
| `aws_instance` (tag-only change) | 🟢 Low |
| `aws_s3_bucket` (tag-only change) | 🟢 Low |

Override any rule per-workspace:

```yaml
# .drifty/config.yaml
severity_overrides:
  aws_lambda_function: high
  aws_cloudwatch_metric_alarm: low
```

---

## drifty vs. the Alternatives

| Feature | `terraform plan` | Spacelift / HCP TF | **drifty** |
|---|---|---|---|
| Detects drift | ✅ | ✅ | ✅ |
| Who caused it | ❌ | ❌ | ✅ CloudTrail |
| Severity score | ❌ | ❌ | ✅ |
| Remediation hint | ❌ | ❌ | ✅ |
| JSON / Markdown output | ❌ | partial | ✅ |
| Works locally / in CI | ✅ | ❌ SaaS only | ✅ |
| Cost | free | $$$ | free |
| Install | N/A | platform setup | `pip install drifty` |
| Slack / webhook alerts | ❌ | ❌ | ✅ v0.2.0 |
| Continuous drift watch | ❌ | ✅ scheduled | ✅ v0.3.0 |
| GitHub PR comment | ❌ | ❌ | ✅ v0.4.0 |
| Drift history / trends | ❌ | ❌ | ✅ v0.5.0 |
| Ignore / suppress drift | ❌ | ❌ | ✅ v0.6.0 |

---

## Configuration Reference

```yaml
# .drifty/config.yaml
default_profile: default          # AWS CLI profile
default_severity: null            # minimum severity filter (null = show all)
default_output: terminal          # terminal | json | markdown
slack_webhook: null               # Slack incoming webhook URL
cloudtrail_lookback_days: 90      # max 90 (CloudTrail API limit)
severity_overrides: {}            # per-resource type overrides
```

---

## Roadmap

- [x] `--notify slack` — post drift summary to Slack webhook _(v0.2.0)_
- [x] `drifty watch` — continuous drift monitoring (poll on interval)
- [x] GitHub PR comment integration
- [x] Drift history — persist findings to `.drifty/history.json`
- [x] `drifty ignore` — suppress known/accepted drift entries
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

Please open an issue before submitting a large PR.
See [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) for bug and feature templates.

---

## License

MIT © [Satyajit Dey](https://github.com/satyajit-dey-17)