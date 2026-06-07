"""
Tests for scorer.py — severity rules, tag-only detection, threshold logic.
"""

from __future__ import annotations

import pytest

from drifty.scanner import DriftFinding
from drifty.scorer import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    _is_tag_only_change,
    meets_threshold,
    score,
    severity_color,
    severity_emoji,
)


def make_finding(resource_type: str, attrs: list | None = None) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name="test",
        resource_id="test-id",
        changed_attributes=attrs or [{"attribute": "some_attr", "before": "old", "after": "new"}],
    )


def tag_change(attr: str = "tags") -> list[dict]:
    return [{"attribute": attr, "before": {"k": "old"}, "after": {"k": "new"}}]


# ---------------------------------------------------------------------------
# Exact severity map matches
# ---------------------------------------------------------------------------


class TestSeverityMapExactMatch:
    @pytest.mark.parametrize(
        "resource_type",
        [
            "aws_iam_role_policy",
            "aws_iam_policy",
            "aws_security_group",
            "aws_security_group_rule",
            "aws_s3_bucket_policy",
            "aws_s3_bucket_public_access_block",
        ],
    )
    def test_critical_resources(self, resource_type):
        assert score(make_finding(resource_type)) == CRITICAL

    @pytest.mark.parametrize(
        "resource_type",
        [
            "aws_instance",
            "aws_rds_instance",
            "aws_lb",
            "aws_alb",
        ],
    )
    def test_high_resources(self, resource_type):
        assert score(make_finding(resource_type)) == HIGH

    @pytest.mark.parametrize(
        "resource_type",
        [
            "aws_lambda_function",
            "aws_autoscaling_group",
            "aws_cloudwatch_metric_alarm",
        ],
    )
    def test_medium_resources(self, resource_type):
        assert score(make_finding(resource_type)) == MEDIUM


# ---------------------------------------------------------------------------
# Tag-only downgrade
# ---------------------------------------------------------------------------


class TestTagOnlyDowngrade:
    def test_instance_tag_only_is_low(self):
        f = make_finding("aws_instance", tag_change("tags.Name"))
        assert score(f) == LOW

    def test_instance_tag_all_only_is_low(self):
        f = make_finding("aws_instance", tag_change("tags_all"))
        assert score(f) == LOW

    def test_instance_non_tag_change_is_high(self):
        f = make_finding(
            "aws_instance",
            [{"attribute": "instance_type", "before": "t3.medium", "after": "t3.large"}],
        )
        assert score(f) == HIGH

    def test_mixed_tag_and_non_tag_is_not_downgraded(self):
        f = make_finding(
            "aws_instance",
            [
                {"attribute": "tags.Name", "before": "old", "after": "new"},
                {"attribute": "instance_type", "before": "t3.medium", "after": "t3.large"},
            ],
        )
        # Mixed change: instance_type is not a tag attr → should NOT downgrade
        assert score(f) == HIGH

    def test_s3_bucket_tag_only_is_low(self):
        f = make_finding("aws_s3_bucket", tag_change("tags"))
        assert score(f) == LOW

    def test_empty_changed_attributes_not_tag_only(self):
        f = make_finding("aws_instance", [])
        # Empty changes → _is_tag_only_change returns False → uses exact map → HIGH
        assert score(f) == HIGH


# ---------------------------------------------------------------------------
# Prefix fallback
# ---------------------------------------------------------------------------


class TestPrefixFallback:
    def test_unknown_iam_resource_is_critical(self):
        assert score(make_finding("aws_iam_instance_profile")) == CRITICAL

    def test_unknown_eks_resource_is_high(self):
        assert score(make_finding("aws_eks_node_group")) == HIGH

    def test_unknown_lambda_resource_is_medium(self):
        assert score(make_finding("aws_lambda_permission")) == MEDIUM

    def test_completely_unknown_resource_is_medium(self):
        assert score(make_finding("aws_completely_new_service")) == MEDIUM


# ---------------------------------------------------------------------------
# Config overrides
# ---------------------------------------------------------------------------


class TestConfigOverrides:
    def test_override_raises_lambda_to_high(self):
        f = make_finding("aws_lambda_function")
        result = score(f, config_overrides={"aws_lambda_function": "high"})
        assert result == HIGH

    def test_override_takes_priority_over_tag_downgrade(self):
        f = make_finding("aws_instance", tag_change("tags.Name"))
        result = score(f, config_overrides={"aws_instance": "critical"})
        assert result == CRITICAL

    def test_invalid_override_value_falls_through(self):
        f = make_finding("aws_security_group")
        # Invalid override value → falls through to normal scoring
        result = score(f, config_overrides={"aws_security_group": "not_a_severity"})
        assert result == CRITICAL


# ---------------------------------------------------------------------------
# meets_threshold
# ---------------------------------------------------------------------------


class TestMeetsThreshold:
    @pytest.mark.parametrize(
        "severity,threshold,expected",
        [
            ("critical", "critical", True),
            ("critical", "high", True),
            ("critical", "medium", True),
            ("critical", "low", True),
            ("high", "critical", False),
            ("high", "high", True),
            ("high", "medium", True),
            ("medium", "high", False),
            ("low", "high", False),
            ("low", "low", True),
        ],
    )
    def test_threshold_matrix(self, severity, threshold, expected):
        assert meets_threshold(severity, threshold) == expected


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


class TestDisplayHelpers:
    def test_severity_emoji_critical(self):
        assert severity_emoji(CRITICAL) == "🔴"

    def test_severity_emoji_low(self):
        assert severity_emoji(LOW) == "🟢"

    def test_severity_color_critical(self):
        assert "red" in severity_color(CRITICAL)

    def test_severity_color_unknown(self):
        assert severity_color("unknown") == "white"


# ---------------------------------------------------------------------------
# _is_tag_only_change
# ---------------------------------------------------------------------------


class TestIsTagOnlyChange:
    def test_pure_tag_change(self):
        f = make_finding("aws_instance", tag_change("tags"))
        assert _is_tag_only_change(f) is True

    def test_dotted_tag_path(self):
        f = make_finding("aws_instance", tag_change("tags.Environment"))
        assert _is_tag_only_change(f) is True

    def test_non_tag_attribute(self):
        f = make_finding(
            "aws_instance", [{"attribute": "instance_type", "before": "a", "after": "b"}]
        )
        assert _is_tag_only_change(f) is False

    def test_empty_attributes(self):
        f = make_finding("aws_instance", [])
        assert _is_tag_only_change(f) is False
