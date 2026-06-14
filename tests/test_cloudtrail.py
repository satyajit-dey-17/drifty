"""
Tests for cloudtrail.py — attribution logic.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from moto import mock_aws

from drifty.cloudtrail import (
    _candidate_resource_names,
    _event_match_score,
    _extract_principal,
    _is_automated_principal,
    attribute_finding,
)
from drifty.scanner import DriftFinding


def make_finding(
    resource_type: str,
    resource_id: str,
    changed_attributes: list[dict] | None = None,
    address: str | None = None,
) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name="test",
        resource_id=resource_id,
        changed_attributes=changed_attributes or [],
        address=address,
    )


# ---------------------------------------------------------------------------
# _candidate_resource_names
# ---------------------------------------------------------------------------


class TestCandidateResourceNames:
    def test_security_group_returns_id_and_arn(self):
        finding = make_finding("aws_security_group", "sg-0abc1234")
        values = _candidate_resource_names(finding)

        assert "sg-0abc1234" in values
        assert any("arn:aws:ec2:" in v and "security-group/sg-0abc1234" in v for v in values)

    def test_s3_bucket_returns_id_and_arn(self):
        finding = make_finding("aws_s3_bucket", "my-bucket")
        values = _candidate_resource_names(finding)

        assert "my-bucket" in values
        assert "arn:aws:s3:::my-bucket" in values

    def test_lambda_returns_id_and_arn_patterns(self):
        finding = make_finding("aws_lambda_function", "my-func")
        values = _candidate_resource_names(finding)

        assert "my-func" in values
        assert "arn:aws:lambda:*:*:function:my-func" in values
        assert "arn:aws:lambda:*:*:function:my-func:*" in values

    def test_no_duplicate_values(self):
        finding = make_finding("aws_instance", "i-123")
        values = _candidate_resource_names(finding)

        assert len(values) == len(set(values))

    def test_result_is_capped(self):
        finding = make_finding("aws_lambda_function", "my-func")
        values = _candidate_resource_names(finding)

        assert len(values) <= 3


# ---------------------------------------------------------------------------
# _event_match_score
# ---------------------------------------------------------------------------


class TestEventMatchScore:
    def test_prefers_relevant_sg_ingress_event(self):
        finding = make_finding(
            "aws_security_group",
            "sg-123",
            changed_attributes=[{"attribute": "ingress", "before": [], "after": ["rule"]}],
            address="aws_security_group.test",
        )

        ingress = {
            "EventName": "AuthorizeSecurityGroupIngress",
            "EventTime": datetime(2026, 6, 8, 11, 50, tzinfo=timezone.utc),
            "Username": "arn:aws:iam::123:user/test",
            "ReadOnly": False,
            "Resources": [{"ResourceName": "sg-123"}],
            "CloudTrailEvent": json.dumps(
                {
                    "eventSource": "ec2.amazonaws.com",
                    "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
                    "requestParameters": {"groupId": "sg-123"},
                }
            ),
        }

        egress = {
            "EventName": "AuthorizeSecurityGroupEgress",
            "EventTime": datetime(2026, 6, 8, 11, 51, tzinfo=timezone.utc),
            "Username": "arn:aws:iam::123:user/test",
            "ReadOnly": False,
            "Resources": [{"ResourceName": "sg-123"}],
            "CloudTrailEvent": json.dumps(
                {
                    "eventSource": "ec2.amazonaws.com",
                    "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
                    "requestParameters": {"groupId": "sg-123"},
                }
            ),
        }

        assert _event_match_score(ingress, finding)[0] >= _event_match_score(egress, finding)[0]


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
# _is_automated_principal
# ---------------------------------------------------------------------------


class TestIsAutomatedPrincipal:
    def test_service_role_is_automated(self):
        assert (
            _is_automated_principal("arn:aws:sts::123:assumed-role/aws-service-role/something")
            is True
        )

    def test_autoscaling_service_is_automated(self):
        assert _is_automated_principal("autoscaling.amazonaws.com") is True

    def test_human_user_is_not_automated(self):
        assert _is_automated_principal("arn:aws:iam::123:user/john.doe") is False

    def test_ops_role_is_not_automated(self):
        assert _is_automated_principal("arn:aws:iam::123:role/ops-team") is False


# ---------------------------------------------------------------------------
# attribute_finding
# ---------------------------------------------------------------------------


@mock_aws
def test_attribute_finding_handles_missing_profile():
    finding = make_finding("aws_security_group", "sg-0abc1234")
    result = attribute_finding(finding, profile="nonexistent-profile")
    assert result is None


@mock_aws
def test_attribute_finding_returns_none_when_no_events():
    with patch("drifty.cloudtrail.boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = iter([{"Events": []}])

        finding = make_finding("aws_security_group", "sg-0abc1234")
        result = attribute_finding(finding, profile="default")

    assert result is None


@mock_aws
def test_attribute_finding_returns_best_ranked_event():
    with patch("drifty.cloudtrail.boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator

        events = [
            {
                "EventName": "RunInstances",
                "EventTime": datetime(2026, 6, 8, 11, 56, tzinfo=timezone.utc),
                "Username": "arn:aws:iam::123:user/test",
                "ReadOnly": False,
                "Resources": [{"ResourceName": "i-123"}],
                "CloudTrailEvent": json.dumps(
                    {
                        "eventSource": "ec2.amazonaws.com",
                        "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
                        "responseElements": {"instancesSet": {"items": [{"instanceId": "i-123"}]}},
                    }
                ),
            },
            {
                "EventName": "CreateTags",
                "EventTime": datetime(2026, 6, 8, 11, 55, tzinfo=timezone.utc),
                "Username": "arn:aws:iam::123:user/test",
                "ReadOnly": False,
                "Resources": [{"ResourceName": "i-123"}],
                "CloudTrailEvent": json.dumps(
                    {
                        "eventSource": "ec2.amazonaws.com",
                        "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
                        "requestParameters": {"resourcesSet": {"items": [{"resourceId": "i-123"}]}},
                    }
                ),
            },
        ]
        mock_paginator.paginate.return_value = iter([{"Events": events}])

        finding = make_finding(
            "aws_instance",
            "i-123",
            changed_attributes=[
                {
                    "attribute": "tags",
                    "before": {"Env": "test"},
                    "after": {"Env": "test", "X": "1"},
                },
                {
                    "attribute": "tags_all",
                    "before": {"Env": "test"},
                    "after": {"Env": "test", "X": "1"},
                },
            ],
            address="aws_instance.test",
        )

        result = attribute_finding(finding, profile="default")

    assert result is not None
    assert result["action"] == "CreateTags"
    assert result["principal"] == "arn:aws:iam::123:user/test"
