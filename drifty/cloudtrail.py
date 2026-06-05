"""
cloudtrail.py — boto3 CloudTrail attribution for DriftFinding instances.

Given a DriftFinding, queries CloudTrail LookupEvents to find the most recent
API call that touched that resource. Returns a dict with:
  {
    "principal": "arn:aws:iam::123456789:user/john.doe",
    "timestamp": "2026-06-03T14:22:11+00:00",
    "action":    "ModifySecurityGroupRules",
  }

CloudTrail LookupEvents constraints:
  - Max lookback: 90 days
  - Lookup by: ResourceName (resource ID or ARN), EventName, Username
  - Returns: up to 50 events per page, newest first
  - Only covers management events (not S3 data events unless enabled)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import boto3
import botocore.exceptions
from rich.console import Console

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding

console = Console()


# ---------------------------------------------------------------------------
# Resource type → CloudTrail event name patterns
# These help narrow the search to the most relevant API calls.
# ---------------------------------------------------------------------------

RESOURCE_EVENT_PREFIXES: dict[str, list[str]] = {
    "aws_security_group": [
        "AuthorizeSecurityGroup",
        "RevokeSecurityGroup",
        "ModifySecurityGroup",
        "CreateSecurityGroup",
    ],
    "aws_security_group_rule": ["AuthorizeSecurityGroup", "RevokeSecurityGroup"],
    "aws_iam_role": [
        "UpdateAssumeRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
    ],
    "aws_iam_role_policy": [
        "PutRolePolicy",
        "DeleteRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
    ],
    "aws_iam_policy": ["CreatePolicy", "CreatePolicyVersion", "DeletePolicyVersion"],
    "aws_instance": [
        "ModifyInstanceAttribute",
        "StartInstances",
        "StopInstances",
        "RebootInstances",
        "TerminateInstances",
    ],
    "aws_s3_bucket_policy": ["PutBucketPolicy", "DeleteBucketPolicy"],
    "aws_s3_bucket_public_access_block": ["PutPublicAccessBlock", "DeletePublicAccessBlock"],
    "aws_s3_bucket": [
        "PutBucketTagging",
        "DeleteBucketTagging",
        "PutBucketVersioning",
        "PutBucketAcl",
    ],
    "aws_rds_instance": ["ModifyDBInstance", "RebootDBInstance"],
    "aws_rds_cluster": ["ModifyDBCluster"],
    "aws_lambda_function": [
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
        "TagResource",
        "UntagResource",
    ],
    "aws_lb": ["ModifyLoadBalancerAttributes", "SetSecurityGroups", "ModifyListener"],
    "aws_alb": ["ModifyLoadBalancerAttributes", "SetSecurityGroups"],
    "aws_autoscaling_group": ["UpdateAutoScalingGroup", "SetDesiredCapacity"],
    "aws_cloudwatch_metric_alarm": ["PutMetricAlarm", "DeleteAlarms"],
    "aws_eks_cluster": ["UpdateClusterConfig", "UpdateClusterVersion"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def attribute_finding(
    finding: DriftFinding,
    profile: str = "default",
    lookback_days: int = 90,
) -> dict | None:
    """
    Query CloudTrail for the most recent API event touching the given resource.

    Returns:
        dict with keys: principal, timestamp, action
        None if no event found or CloudTrail is inaccessible.
    """
    try:
        session = boto3.Session(profile_name=profile)
        client = session.client("cloudtrail")
    except botocore.exceptions.ProfileNotFound:
        console.print(
            f"[yellow]⚠ AWS profile [bold]{profile!r}[/bold] not found. "
            "Skipping CloudTrail attribution.[/yellow]"
        )
        return None
    except Exception as e:
        console.print(f"[yellow]⚠ Could not create AWS session: {e}[/yellow]")
        return None

    resource_id = finding.resource_id
    resource_type = finding.resource_type

    # Build time window
    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(days=min(lookback_days, 90))

    # Try lookup by resource ID first, then by ARN pattern if needed
    lookup_values = _build_lookup_values(resource_type, resource_id)

    for lookup_value in lookup_values:
        event = _lookup_event(
            client=client,
            resource_name=lookup_value,
            start_time=start_time,
            end_time=end_time,
            resource_type=resource_type,
        )
        if event:
            return event

    return None


def _lookup_event(
    client,
    resource_name: str,
    start_time: datetime,
    end_time: datetime,
    resource_type: str,
) -> dict | None:
    """
    Call CloudTrail LookupEvents with a ResourceName filter.
    Pages through results and returns the most recent matching event.
    """
    lookup_attrs = [{"AttributeKey": "ResourceName", "AttributeValue": resource_name}]

    try:
        paginator = client.get_paginator("lookup_events")
        pages = paginator.paginate(
            LookupAttributes=lookup_attrs,
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": 50, "PageSize": 50},
        )

        for page in pages:
            events = page.get("Events", [])
            if not events:
                continue

            # Events are returned newest-first — take the first match
            # that isn't an automated AWS service action
            for event in events:
                principal = _extract_principal(event)
                if _is_automated_service_event(principal):
                    continue

                return {
                    "principal": principal,
                    "timestamp": event["EventTime"].isoformat(),
                    "action": event.get("EventName", "Unknown"),
                }

            # If all events were automated, return the newest one anyway
            if events:
                event = events[0]
                return {
                    "principal": _extract_principal(event),
                    "timestamp": event["EventTime"].isoformat(),
                    "action": event.get("EventName", "Unknown"),
                }

    except botocore.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidLookupAttributesException":
            # Resource name format not supported by CloudTrail lookup
            return None
        console.print(
            f"[yellow]⚠ CloudTrail lookup failed ({error_code}): "
            f"{e.response['Error']['Message']}[/yellow]"
        )
        return None
    except botocore.exceptions.EndpointResolutionError:
        console.print(
            "[yellow]⚠ Could not reach CloudTrail endpoint. " "Check AWS credentials.[/yellow]"
        )
    except Exception as e:
        console.print(f"[yellow]⚠ Unexpected CloudTrail error: {e}[/yellow]")
        return None

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_lookup_values(resource_type: str, resource_id: str) -> list[str]:
    """
    Build a prioritized list of values to try for CloudTrail ResourceName lookup.
    CloudTrail accepts: resource IDs, ARNs, resource names.
    We try the raw resource_id first, then common ARN patterns.
    """
    values = [resource_id]

    # Add ARN patterns for resource types where CloudTrail indexes by ARN
    arn_patterns = {
        "aws_s3_bucket": f"arn:aws:s3:::{resource_id}",
        "aws_s3_bucket_policy": f"arn:aws:s3:::{resource_id}",
        "aws_s3_bucket_public_access_block": f"arn:aws:s3:::{resource_id}",
        "aws_lambda_function": f"arn:aws:lambda:*:*:function:{resource_id}",
    }

    arn = arn_patterns.get(resource_type)
    if arn and arn not in values:
        values.append(arn)

    return values


def _extract_principal(event: dict) -> str:
    """
    Extract the IAM principal from a CloudTrail event.
    Returns the most specific identifier available.
    """
    username = event.get("Username", "")

    # CloudTrail Username field is the most direct — use it if it looks like an ARN
    if username.startswith("arn:aws"):
        return username

    # Fall back to CloudTrailEvent JSON for deeper principal info
    import json

    raw = event.get("CloudTrailEvent", "{}")
    try:
        ct_event = json.loads(raw)
        identity = ct_event.get("userIdentity", {})

        # Prefer ARN → assumed-role session → username → type
        arn = identity.get("arn")
        if arn:
            return arn

        session_context = identity.get("sessionContext", {})
        session_issuer = session_context.get("sessionIssuer", {})
        if session_issuer.get("arn"):
            return session_issuer["arn"]

        if username:
            return username

        return identity.get("type", "unknown")

    except (json.JSONDecodeError, AttributeError):
        return username or "unknown"


def _is_automated_service_event(principal: str) -> bool:
    """
    Return True if the principal looks like an automated AWS service call
    rather than a human or team automation action.
    Helps surface the human-initiated change first.
    """
    automated_patterns = [
        "elasticloadbalancing.amazonaws.com",
        "autoscaling.amazonaws.com",
        "ec2.amazonaws.com",
        "lambda.amazonaws.com",
        "rds.amazonaws.com",
        "AWSServiceRoleFor",
    ]
    return any(pattern in principal for pattern in automated_patterns)


def format_attribution(finding: DriftFinding) -> str:
    """
    Format attribution fields from a DriftFinding into a human-readable string.
    Used by reporter.py.
    """
    if finding.attributed_to:
        return (
            f"{finding.attributed_to} via {finding.attributed_action} "
            f"at {finding.attributed_at}"
        )
    return "attribution unavailable (event outside 90-day CloudTrail window)"
