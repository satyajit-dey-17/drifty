# Changelog

All notable changes to drifty will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-06-06

### Added
- `drifty report-pr` command — scans for drift and posts a formatted report as a GitHub PR comment
- `drifty/github.py` — GitHub REST API backend, collapsible `<details>` Markdown blocks per finding
- Reads `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `PR_NUMBER` from environment (native GitHub Actions support)
- 25 new tests (163 total)

## [0.3.0] - 2026-06-06

### Added
- `drifty watch` command — continuous drift monitoring with configurable `--interval`
- `drifty/state.py` — finding hashing, `load_state()`, `save_state()`, `diff_findings()`, `build_known_findings()`
- `drifty/watch.py` — `cmd_watch()` with `--notify`, `--threshold`, `--attribute` flags; `_run_cycle()` extracted for testability
- Notifier registry pattern in `drifty/notifiers/__init__.py` — `get_notifier(name, **kwargs)` for extensible integrations (PagerDuty, Teams, etc.)
- 22 new tests (138 total)

## [0.2.0] - 2026-06-05

### Added
- `--notify slack` flag on `drifty scan` — posts a Slack Block Kit summary when drift is detected
- `drifty/notifiers/slack.py` — Block Kit payload builder with severity grouping, attribution, and remediation hints
- `drifty/notifiers/__init__.py` — notifier plugin registry (extensible for PagerDuty, Teams, etc.)
- 33 new tests for the Slack notifier (116 total)

### Changed
- Slack message caps at 10 findings to respect Slack's block limit; overflow count shown in footer

---

## [0.1.0] - 2026-06-04
### Added
- Initial release
- `drifty scan` — detect Terraform drift via `terraform plan -refresh-only -json`
- CloudTrail attribution with `--attribute` flag
- Severity scoring for 14 AWS resource types
- Terminal (Rich), JSON, and Markdown output modes
- `drifty init`, `drifty config show/set` commands
- `drifty report` for standalone markdown export


