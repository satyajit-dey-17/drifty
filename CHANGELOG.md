# Changelog

All notable changes to drifty will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-06-04
### Added
- Initial release
- `drifty scan` — detect Terraform drift via `terraform plan -refresh-only -json`
- CloudTrail attribution with `--attribute` flag
- Severity scoring for 14 AWS resource types
- Terminal (Rich), JSON, and Markdown output modes
- `drifty init`, `drifty config show/set` commands
- `drifty report` for standalone markdown export
