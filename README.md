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
- [ ] `drifty watch` — continuous drift monitoring (poll on interval)
- [ ] Azure and GCP provider support
- [ ] GitHub PR comment integration
- [ ] Drift history — persist findings to `.drifty/history.json`
- [ ] `drifty ignore` — suppress known/accepted drift entries

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