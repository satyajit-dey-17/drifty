# Changelog

All notable changes to drifty will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

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


