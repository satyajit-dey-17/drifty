# Release Notes

## v0.6.5

### Fixed
- Fixed severity overrides so tag-only drift on EC2, S3, Lambda, and similar resources stays LOW instead of being forced to HIGH or CRITICAL.
- Fixed CloudTrail attribution so tag-only drift now prefers `CreateTags` and `DeleteTags` instead of unrelated events like `RunInstances`.
- Fixed `--output table` so table output now appears correctly with `--attribute`.
- Fixed CLI help text so `medium` severity is shown.
- Fixed `state.py` so `--workspace` is respected.
- Fixed CLI config handling so `severity_overrides` is stored as a proper YAML map instead of a string.
- Fixed Lambda ARN wildcard handling in drift matching.
