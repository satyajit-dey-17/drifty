# Changelog

All notable changes to drifty will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).


## [0.8.0] - 2026-07-13

### Added
- `drifty terragrunt` sub-command group for Terragrunt-aware drift detection
- `drifty terragrunt discover` — recursively discovers runnable Terragrunt units
  from a root directory; respects `.terragrunt-cache`, `.git`, `.terraform`,
  `node_modules`, and configurable extra exclusions
- `drifty terragrunt scan` — scans all discovered units sequentially using the
  existing drift scoring and reporting pipeline
  - Flags: `--root`, `--output`, `--min-severity`, `--profile`, `--attribute`,
    `--exclude`, `--unit-timeout`, `--discover-only`, `--fail-fast`
- `drifty/terragrunt/` package: `models.py`, `discovery.py`, `runner.py`,
  `reporter.py`, `cli.py`
- Formalized exit code contract:
  `0` clean · `1` drift found · `2` operational failure · `3` partial failure
- `tests/fixtures/terragrunt_monorepo/` — fixture directory tree for unit tests
- `docs/terragrunt.md` — full feature documentation and design rationale
- `examples/terragrunt_scan.sh` — CI-ready example script
- Phase 2 extension points: `TerragruntUnit.dependencies` and
  `TerragruntScanReport.dependency_graph` fields (both default to empty;
  reserved for upcoming blast-radius analysis)

## [0.7.0] - 2026-06-28

### Added
- `drifty/mcp_server.py` — MCP (Model Context Protocol) server exposing Drifty as a callable tool for AI assistants
- `drifty-mcp` CLI entrypoint registered in `pyproject.toml` — compatible with Cursor, Claude Desktop, and any stdio MCP client
- Two MCP tools:
  - `detect_drift(working_dir, aws_profile, severity_filter)` — full drift report with changed attributes and remediation hints
  - `score_drift(working_dir, aws_profile)` — fast severity summary with per-resource breakdown
- `mcp` optional dependency group: `pip install "drifty[mcp]"` — no impact on existing installs
- `examples/mcp_client_test.py` — raw JSON-RPC smoke test client for local MCP server verification (no subscription needed)

## [0.6.4] - 2026-06-09

### Fixed
- Updated the GitHub PR report workflow to run on `pull_request` events and manual dispatch, with lint and formatting checks before posting the drift report.
- PR comments are now updated in place instead of creating duplicate comments on every run.
- Added Ruff and Black validation to the PR report workflow so formatting and lint errors fail early before comment posting.

## [0.6.2] - 2026-06-08

### Added
- `report-pr.yml` GitHub Actions workflow — runs `drifty report-pr --attribute --severity high` on pull request events
- README usage examples for `drifty report-pr --attribute --severity high`

### Fixed
- `drifty/github.py` — fixed GitHub PR comment posting flow for pull request reporting
- GitHub PR report path now correctly targets PR discussion comments using `owner/repo` and PR number inputs
- `tests/test_watch.py` — fixed watch-cycle related test behavior and coverage
- PR reporting and watch-related changes validated with updated test coverage

### Changed
- `README.md` — refreshed install, Slack notification, GitHub PR comment, and release sections
- GitHub PR reporting docs now show the exact workflow step:
  - `drifty report-pr --attribute --severity high`
  - `GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}`
  - `GITHUB_REPOSITORY=${{ github.repository }}`
  - `PR_NUMBER=${{ github.event.pull_request.number }}`

## [0.6.0] - 2026-06-06

### Added
- `drifty ignore` command — suppress known/accepted drift entries from scan output
- `drifty/ignore.py` — `add_ignore()`, `remove_ignore()`, `load_ignores()`, `filter_findings()`
- Suppressed findings shown dimmed under a **Suppressed** label in terminal output — never silently hidden
- Ignore entries persisted to `.drifty/ignore.yaml` with timestamp and `$USER` attribution
- `--reason`, `--remove`, `--list` flags on `drifty ignore`
- `run_scan()` now returns `(active, suppressed)` tuple — ignore list applied before history persistence
- 24 new tests (199 total)

## [0.5.0] - 2026-06-06

### Added
- `drifty history` command — shows drift trends across previous scans
- `drifty/history.py` — `append_findings()`, `load_history()`, `most_drifted_resources()`
- Scan results auto-persisted to `.drifty/history.json` after every `drifty scan`
- Per-scan table with severity counts and most-drifted resources ranking
- 19 new tests (182 total)

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
