"""
Tests for cloudtrail.py — attribution logic using moto to mock AWS CloudTrail.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from moto import mock_aws

from drifty.cloudtrail import (
    _build_lookup_values,
    _extract_principal,
    _is_automated_service_event,
    format_attribution,
)
from drifty.scanner import DriftFinding


def make_finding(resource_type: str, resource_id: str) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name="test",
        resource_id=resource_id,
        changed_attributes=[],
    )


# ---------------------------------------------------------------------------
# _build_lookup_values
# ---------------------------------------------------------------------------


class TestBuildLookupValues:
    def test_security_group_returns_id_only(self):
        values = _build_lookup_values("aws_security_group", "sg-0abc1234")
        assert values[0] == "sg-0abc1234"

    def test_s3_bucket_returns_id_and_arn(self):
        values = _build_lookup_values("aws_s3_bucket", "my-bucket")
        assert "my-bucket" in values
        assert any("arn:aws:s3:::my-bucket" in v for v in values)

    def test_lambda_returns_id_and_arn_pattern(self):
        values = _build_lookup_values("aws_lambda_function", "my-func")
        assert "my-func" in values
        assert any("function:my-func" in v for v in values)

    def test_no_duplicate_values(self):
        values = _build_lookup_values("aws_instance", "i-123")
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# _extract_principal
# ---------------------------------------------------------------------------


class TestExtractPrincipal:
    def _make_event(self, username="", arn=None, identity_type="IAMUser"):
        ct_event = {"userIdentity": {"type": identity_type}}
        if arn:
            ct_event["userIdentity"]["arn"] = arn
        return {
            "Username": username,
            "CloudTrailEvent": json.dumps(ct_event),
        }

    def test_prefers_arn_from_cloudtrail_event(self):
        event = self._make_event(username="john.doe", arn="arn:aws:iam::123:user/john.doe")
        result = _extract_principal(event)
        assert result == "arn:aws:iam::123:user/john.doe"

    def test_falls_back_to_username_field(self):
        event = {
            "Username": "john.doe",
            "CloudTrailEvent": json.dumps({"userIdentity": {}}),
        }
        result = _extract_principal(event)
        assert result == "john.doe"

    def test_returns_unknown_for_empty_event(self):
        event = {"Username": "", "CloudTrailEvent": "{}"}
        result = _extract_principal(event)
        assert result == "unknown"

    def test_handles_malformed_cloudtrail_json(self):
        event = {"Username": "fallback", "CloudTrailEvent": "not-json"}
        result = _extract_principal(event)
        assert result == "fallback"


# ---------------------------------------------------------------------------
# _is_automated_service_event
# ---------------------------------------------------------------------------


class TestIsAutomatedServiceEvent:
    def test_elb_service_is_automated(self):
        assert _is_automated_service_event("elasticloadbalancing.amazonaws.com") is True

    def test_autoscaling_service_is_automated(self):
        assert _is_automated_service_event("autoscaling.amazonaws.com") is True

    def test_human_user_is_not_automated(self):
        assert _is_automated_service_event("arn:aws:iam::123:user/john.doe") is False

    def test_ops_role_is_not_automated(self):
        assert _is_automated_service_event("arn:aws:iam::123:role/ops-team") is False


# ---------------------------------------------------------------------------
# format_attribution
# ---------------------------------------------------------------------------


class TestFormatAttribution:
    def test_with_full_attribution(self):
        f = make_finding("aws_security_group", "sg-123")
        f.attributed_to = "arn:aws:iam::123:user/john.doe"
        f.attributed_at = "2026-06-03T14:22:11+00:00"
        f.attributed_action = "ModifySecurityGroupRules"
        result = format_attribution(f)
        assert "john.doe" in result
        assert "ModifySecurityGroupRules" in result

    def test_without_attribution(self):
        f = make_finding("aws_s3_bucket", "my-bucket")
        result = format_attribution(f)
        assert "unavailable" in result
        assert "90-day" in result


# ---------------------------------------------------------------------------
# attribute_finding — moto mock (no real AWS needed)
# ---------------------------------------------------------------------------


@mock_aws
def test_attribute_finding_handles_missing_profile():
    """attribute_finding with a nonexistent profile should return None gracefully."""
    from drifty.cloudtrail import attribute_finding

    f = make_finding("aws_security_group", "sg-0abc1234")
    # "nonexistent-profile" will raise ProfileNotFound → should return None
    result = attribute_finding(f, profile="nonexistent-profile")
    assert result is None


@mock_aws
def test_attribute_finding_returns_none_when_no_events():
    """With moto mocking CloudTrail (no seeded events), should return None."""
    from drifty.cloudtrail import attribute_finding

    # Create a real boto3 session that moto intercepts
    with patch("drifty.cloudtrail.boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.client.return_value = mock_client

        # Paginator returns empty events
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = iter([{"Events": []}])

        f = make_finding("aws_security_group", "sg-0abc1234")
        result = attribute_finding(f, profile="default")

    assert result is None
