"""
Tests for scanner.py — drift parsing and the run_scan pipeline.
Uses mock terraform JSON output instead of a real terraform binary.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from drifty.scanner import (
    _build_remediation_hint,
    _diff_attributes,
    _parse_drift_message,
    _parse_output,
    run_scan,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SECURITY_GROUP_DRIFT = {
    "type": "resource_drift",
    "change": {
        "resource": {
            "addr": "aws_security_group.main",
            "resource_type": "aws_security_group",
            "resource_name": "main",
            "provider_name": "registry.terraform.io/hashicorp/aws",
        },
        "action": "update",
        "before": {"id": "sg-0abc1234", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
        "after": {"id": "sg-0abc1234", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
    },
}

INSTANCE_DRIFT = {
    "type": "resource_drift",
    "change": {
        "resource": {
            "addr": "aws_instance.api_server",
            "resource_type": "aws_instance",
            "resource_name": "api_server",
            "provider_name": "registry.terraform.io/hashicorp/aws",
        },
        "action": "update",
        "before": {"id": "i-0def5678", "instance_type": "t3.medium"},
        "after": {"id": "i-0def5678", "instance_type": "t3.large"},
    },
}

TAG_ONLY_DRIFT = {
    "type": "resource_drift",
    "change": {
        "resource": {
            "addr": "aws_s3_bucket.assets",
            "resource_type": "aws_s3_bucket",
            "resource_name": "assets",
            "provider_name": "registry.terraform.io/hashicorp/aws",
        },
        "action": "update",
        "before": {"id": "assets-bucket-prod", "tags": {"LastModified": "2026-05-15"}},
        "after": {"id": "assets-bucket-prod", "tags": {"LastModified": "2026-06-01"}},
    },
}


def _lines(*dicts) -> list[str]:
    """Convert drift message dicts to JSON Lines strings."""
    return [json.dumps(d) for d in dicts]


# ---------------------------------------------------------------------------
# _diff_attributes
# ---------------------------------------------------------------------------


class TestDiffAttributes:
    def test_single_changed_attribute(self):
        before = {"instance_type": "t3.medium", "id": "i-123"}
        after = {"instance_type": "t3.large", "id": "i-123"}
        result = _diff_attributes(before, after)
        assert len(result) == 1
        assert result[0]["attribute"] == "instance_type"
        assert result[0]["before"] == "t3.medium"
        assert result[0]["after"] == "t3.large"

    def test_no_changes(self):
        attrs = {"id": "sg-123", "name": "test"}
        result = _diff_attributes(attrs, attrs)
        assert result == []

    def test_multiple_changed_attributes(self):
        before = {"a": 1, "b": 2, "c": 3}
        after = {"a": 9, "b": 2, "c": 7}
        result = _diff_attributes(before, after)
        changed_keys = {r["attribute"] for r in result}
        assert changed_keys == {"a", "c"}

    def test_skips_internal_keys(self):
        before = {"_internal": "x", "name": "old"}
        after = {"_internal": "y", "name": "new"}
        result = _diff_attributes(before, after)
        keys = [r["attribute"] for r in result]
        assert "_internal" not in keys
        assert "name" in keys

    def test_added_attribute(self):
        before = {"id": "i-123"}
        after = {"id": "i-123", "new_field": "value"}
        result = _diff_attributes(before, after)
        assert any(r["attribute"] == "new_field" for r in result)

    def test_removed_attribute(self):
        before = {"id": "i-123", "old_field": "value"}
        after = {"id": "i-123"}
        result = _diff_attributes(before, after)
        assert any(r["attribute"] == "old_field" for r in result)


# ---------------------------------------------------------------------------
# _parse_drift_message
# ---------------------------------------------------------------------------


class TestParseDriftMessage:
    def test_parses_security_group(self):
        finding = _parse_drift_message(SECURITY_GROUP_DRIFT)
        assert finding is not None
        assert finding.resource_type == "aws_security_group"
        assert finding.resource_name == "main"
        assert finding.resource_id == "sg-0abc1234"
        assert len(finding.changed_attributes) == 1
        assert finding.changed_attributes[0]["attribute"] == "ingress"

    def test_parses_instance_type_change(self):
        finding = _parse_drift_message(INSTANCE_DRIFT)
        assert finding is not None
        assert finding.resource_type == "aws_instance"
        assert finding.resource_id == "i-0def5678"
        attrs = finding.changed_attributes
        assert any(a["attribute"] == "instance_type" for a in attrs)

    def test_returns_none_for_missing_resource_type(self):
        bad_msg = {"type": "resource_drift", "change": {"resource": {}, "before": {}, "after": {}}}
        result = _parse_drift_message(bad_msg)
        assert result is None

    def test_remediation_hint_generated(self):
        finding = _parse_drift_message(SECURITY_GROUP_DRIFT)
        assert finding.remediation_hint is not None
        assert "terraform import" in finding.remediation_hint
        assert "sg-0abc1234" in finding.remediation_hint


# ---------------------------------------------------------------------------
# _parse_output (JSON Lines parser)
# ---------------------------------------------------------------------------


class TestParseOutput:
    def test_parses_multiple_drifts(self):
        lines = _lines(SECURITY_GROUP_DRIFT, INSTANCE_DRIFT)
        findings = _parse_output(lines)
        assert len(findings) == 2

    def test_ignores_non_drift_messages(self):
        lines = _lines(
            {"type": "version", "terraform": "1.7.0"},
            SECURITY_GROUP_DRIFT,
            {"type": "outputs", "outputs": {}},
        )
        findings = _parse_output(lines)
        assert len(findings) == 1

    def test_ignores_invalid_json_lines(self):
        lines = ["not json at all", json.dumps(SECURITY_GROUP_DRIFT), "{broken"]
        findings = _parse_output(lines)
        assert len(findings) == 1

    def test_empty_output(self):
        assert _parse_output([]) == []

    def test_tag_only_drift_parsed(self):
        lines = _lines(TAG_ONLY_DRIFT)
        findings = _parse_output(lines)
        assert len(findings) == 1
        assert findings[0].resource_type == "aws_s3_bucket"


# ---------------------------------------------------------------------------
# _build_remediation_hint
# ---------------------------------------------------------------------------


class TestBuildRemediationHint:
    def test_importable_resource_returns_import_command(self):
        hint = _build_remediation_hint("aws_security_group", "main", "sg-0abc1234")
        assert hint == "terraform import aws_security_group.main sg-0abc1234"

    def test_unknown_resource_returns_apply_hint(self):
        hint = _build_remediation_hint("aws_some_custom_resource", "test", "custom-id")
        assert "terraform apply" in hint

    def test_lambda_is_importable(self):
        hint = _build_remediation_hint("aws_lambda_function", "handler", "my-func")
        assert "terraform import" in hint


# ---------------------------------------------------------------------------
# run_scan integration (mocked subprocess)
# ---------------------------------------------------------------------------


class TestRunScan:
    def test_returns_empty_list_on_terraform_failure(self, tmp_path):
        with patch("drifty.scanner._run_terraform", return_value=(None, "error")):
            findings, suppressed = run_scan(workspace=tmp_path)
        assert findings == []
        assert suppressed == []

    def test_returns_empty_list_when_no_drift(self, tmp_path):
        no_drift_lines = [json.dumps({"type": "version", "terraform": "1.7.0"})]
        with patch("drifty.scanner._run_terraform", return_value=(no_drift_lines, "")):
            findings, suppressed = run_scan(workspace=tmp_path)
        assert findings == []
        assert suppressed == []

    def test_run_scan_scores_findings(self, tmp_path):
        lines = _lines(SECURITY_GROUP_DRIFT, INSTANCE_DRIFT)
        with patch("drifty.scanner._run_terraform", return_value=(lines, "")):
            findings, _ = run_scan(workspace=tmp_path)
        assert len(findings) == 2
        severities = {f.resource_type: f.severity for f in findings}
        assert severities["aws_security_group"] == "critical"
        assert severities["aws_instance"] == "high"

    def test_severity_filter_removes_low_findings(self, tmp_path):
        lines = _lines(SECURITY_GROUP_DRIFT, TAG_ONLY_DRIFT)
        with patch("drifty.scanner._run_terraform", return_value=(lines, "")):
            findings, _ = run_scan(workspace=tmp_path, severity_filter="high")
        resource_types = [f.resource_type for f in findings]
        assert "aws_security_group" in resource_types
        assert "aws_s3_bucket" not in resource_types

    def test_run_scan_calls_cloudtrail_when_attribution_enabled(self, tmp_path):
        lines = _lines(SECURITY_GROUP_DRIFT)
        mock_attribution = {
            "principal": "arn:aws:iam::123:user/test",
            "timestamp": "2026-06-03T14:22:11+00:00",
            "action": "ModifySecurityGroupRules",
        }
        with patch("drifty.scanner._run_terraform", return_value=(lines, "")):
            with patch("drifty.cloudtrail.attribute_finding", return_value=mock_attribution):
                findings, _ = run_scan(workspace=tmp_path, with_attribution=True)
        assert findings[0].attributed_to == "arn:aws:iam::123:user/test"
        assert findings[0].attributed_action == "ModifySecurityGroupRules"
