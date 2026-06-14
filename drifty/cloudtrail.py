from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

RESOURCE_HINTS: dict[str, dict[str, list[str]]] = {
    "aws_lambda_function": {
        "event_prefixes": [
            "UpdateFunctionCode",
            "UpdateFunctionConfiguration",
            "PublishVersion",
            "DeleteFunctionConcurrency",
            "PutFunctionConcurrency",
            "TagResource",
            "UntagResource",
        ],
        "arn_templates": [
            "arn:aws:lambda:*:*:function:{id}",
            "arn:aws:lambda:*:*:function:{id}:*",
        ],
    },
    "aws_dynamodb_table": {
        "event_prefixes": [
            "UpdateTable",
            "UpdateContinuousBackups",
            "UpdateContributorInsights",
            "TagResource",
            "UntagResource",
            "UpdateTimeToLive",
        ],
        "arn_templates": [
            "arn:aws:dynamodb:*:*:table/{id}",
            "arn:aws:dynamodb:*:*:table/{id}/index/*",
        ],
    },
    "aws_instance": {
        "event_prefixes": [
            "ModifyInstanceAttribute",
            "StartInstances",
            "StopInstances",
            "RebootInstances",
            "CreateTags",
            "DeleteTags",
        ],
        "arn_templates": ["arn:aws:ec2:*:*:instance/{id}"],
    },
    "aws_security_group": {
        "event_prefixes": [
            "AuthorizeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "RevokeSecurityGroupIngress",
            "RevokeSecurityGroupEgress",
            "ModifySecurityGroupRules",
            "UpdateSecurityGroupRuleDescriptionsIngress",
            "UpdateSecurityGroupRuleDescriptionsEgress",
            "CreateTags",
            "DeleteTags",
        ],
        "arn_templates": ["arn:aws:ec2:*:*:security-group/{id}"],
    },
    "aws_db_instance": {
        "event_prefixes": [
            "ModifyDBInstance",
            "AddTagsToResource",
            "RemoveTagsFromResource",
            "StartDBInstance",
            "StopDBInstance",
        ],
        "arn_templates": ["arn:aws:rds:*:*:db:{id}"],
    },
    "aws_s3_bucket": {
        "event_prefixes": [
            "PutBucketAcl",
            "PutBucketVersioning",
            "PutBucketTagging",
            "DeleteBucketTagging",
            "PutBucketPolicy",
            "DeleteBucketPolicy",
            "PutBucketEncryption",
            "DeleteBucketEncryption",
            "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock",
        ],
        "arn_templates": ["arn:aws:s3:::{id}"],
    },
    "aws_cloudwatch_metric_alarm": {
        "event_prefixes": [
            "PutMetricAlarm",
            "DeleteAlarms",
            "TagResource",
            "UntagResource",
            "DisableAlarmActions",
            "EnableAlarmActions",
        ],
        "arn_templates": ["arn:aws:cloudwatch:*:*:alarm:{id}"],
    },
}


AUTOMATED_PRINCIPAL_PATTERNS = [
    "*aws-service-role*",
    "*assumed-role/aws-service-role/*",
    "*autoscaling*",
    "*cloudformation*",
    "*lambda.amazonaws.com*",
    "*ecs-tasks.amazonaws.com*",
    "*ec2.amazonaws.com*",
    "*rds.amazonaws.com*",
]


GENERIC_MUTATION_PATTERNS = [
    "Create*",
    "Put*",
    "Update*",
    "Modify*",
    "Delete*",
    "Tag*",
    "Untag*",
    "Attach*",
    "Detach*",
    "Associate*",
    "Disassociate*",
    "Enable*",
    "Disable*",
    "Start*",
    "Stop*",
    "Reboot*",
    "Set*",
]


READ_ONLY_PREFIXES = [
    "Get",
    "List",
    "Describe",
    "Lookup",
]


def attribute_finding(
    finding: Any, profile: str = "default", lookback_days: int = 90
) -> dict[str, str] | None:
    try:
        session = boto3.Session(profile_name=profile)
        client = session.client("cloudtrail")
    except (ProfileNotFound, BotoCoreError, ClientError):
        return None

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=min(max(lookback_days, 1), 90))

    lookup_values = _candidate_resource_names(finding)
    if not lookup_values:
        return None

    events = _lookup_candidate_events(client, lookup_values, start_time, end_time)
    if not events:
        return None

    ranked = sorted(events, key=lambda event: _event_match_score(event, finding), reverse=True)
    best = ranked[0]
    best_score, _ = _event_match_score(best, finding)
    if best_score <= 0:
        return None

    event_time = best.get("EventTime")
    timestamp = event_time.isoformat() if hasattr(event_time, "isoformat") else ""

    return {
        "principal": _extract_principal(best),
        "timestamp": timestamp,
        "action": best.get("EventName", "Unknown"),
    }


def _candidate_resource_names(finding: Any) -> list[str]:
    resource_type = str(getattr(finding, "resource_type", "") or "")
    resource_id = str(getattr(finding, "resource_id", "") or "")

    candidates: list[str] = []

    if resource_id:
        candidates.append(resource_id)

    hints = RESOURCE_HINTS.get(resource_type, {})
    for template in hints.get("arn_templates", []):
        if resource_id:
            candidates.append(template.format(id=resource_id))

    return list(dict.fromkeys(candidates))[:3]


def _extract_tokens(value: str) -> set[str]:
    if not value:
        return set()

    tokens = {value}

    for part in re.split(r"[:/]+", value):
        if part and part not in {"arn", "aws"}:
            tokens.add(part)

    if "." in value:
        tokens.add(value.split(".")[-1])

    return {token for token in tokens if token}


def _lookup_candidate_events(
    client: Any, lookup_values: list[str], start_time: datetime, end_time: datetime
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    paginator = client.get_paginator("lookup_events")

    for value in lookup_values:
        try:
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": value}],
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": 20, "PageSize": 20},
            )
            for page in pages:
                for event in page.get("Events", []):
                    event_id = event.get("EventId") or event.get("EventName", "") + str(
                        event.get("EventTime", "")
                    )
                    if event_id in seen_ids:
                        continue
                    seen_ids.add(event_id)
                    events.append(event)

                    if len(events) >= 20:
                        return events
        except (BotoCoreError, ClientError):
            continue

    return events


def _event_match_score(event: dict[str, Any], finding: Any) -> tuple[int, float]:
    score = 0
    resource_type = str(getattr(finding, "resource_type", "") or "")
    address = str(getattr(finding, "address", "") or "")
    hints = RESOURCE_HINTS.get(resource_type, {})
    event_name = event.get("EventName", "") or ""

    changed_attrs = {
        c.get("attribute")
        for c in getattr(finding, "changed_attributes", [])
        if isinstance(c, dict) and c.get("attribute")
    }
    tag_only = bool(changed_attrs) and changed_attrs.issubset({"tags", "tags_all"})

    candidates = set(_candidate_resource_names(finding))
    event_resource_names = _event_resource_names(event)

    for candidate in candidates:
        for event_name_value in event_resource_names:
            score += _resource_name_match_score(candidate, event_name_value)

    if tag_only:
        if event_name in {"CreateTags", "DeleteTags", "PutBucketTagging", "DeleteBucketTagging"}:
            score += 120
        if event_name == "RunInstances":
            score -= 80

    if any(
        event_name == prefix or event_name.startswith(prefix)
        for prefix in hints.get("event_prefixes", [])
    ):
        score += 60
    elif _looks_like_mutation(event_name):
        score += 20

    if event.get("ReadOnly") is False:
        score += 15
    if any(event_name.startswith(prefix) for prefix in READ_ONLY_PREFIXES):
        score -= 30

    principal = _extract_principal(event)
    if principal != "unknown":
        score += 10
    if not _is_automated_principal(principal):
        score += 20
    else:
        score -= 10

    raw_event = _parse_cloudtrail_event(event)
    if _request_parameters_contain_match(raw_event, candidates):
        score += 35

    if resource_type and _event_source_matches_resource(raw_event, resource_type):
        score += 20

    if address and address.split(".")[-1] in json.dumps(raw_event, default=str):
        score += 5

    ts = event.get("EventTime")
    timestamp = ts.timestamp() if hasattr(ts, "timestamp") else 0.0
    return (score, timestamp)


def _resource_name_match_score(candidate: str, event_value: str) -> int:
    if not candidate or not event_value:
        return 0

    if candidate == event_value:
        return 100
    if _wildcard_match(candidate, event_value) or _wildcard_match(event_value, candidate):
        return 80
    if event_value.endswith(f":{candidate}") or event_value.endswith(f"/{candidate}"):
        return 70
    if candidate.endswith(f":{event_value}") or candidate.endswith(f"/{event_value}"):
        return 60
    if candidate in event_value or event_value in candidate:
        return 40
    return 0


def _event_resource_names(event: dict[str, Any]) -> set[str]:
    names: set[str] = set()

    for resource in event.get("Resources", []) or []:
        for key in ("ResourceName", "ResourceType", "ARN"):
            value = resource.get(key)
            if value:
                names.add(str(value))
                names.update(_extract_tokens(str(value)))

    raw_event = _parse_cloudtrail_event(event)
    for resource in raw_event.get("resources", []) or []:
        for key in ("ARN", "accountId", "type"):
            value = resource.get(key)
            if value:
                names.add(str(value))
                names.update(_extract_tokens(str(value)))

    return names


def _parse_cloudtrail_event(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("CloudTrailEvent", "{}")
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}


def _request_parameters_contain_match(raw_event: dict[str, Any], candidates: set[str]) -> bool:
    blob = json.dumps(raw_event.get("requestParameters", {}), default=str)
    response_blob = json.dumps(raw_event.get("responseElements", {}), default=str)
    haystack = f"{blob} {response_blob}"
    return any(candidate and candidate in haystack for candidate in candidates)


def _event_source_matches_resource(raw_event: dict[str, Any], resource_type: str) -> bool:
    event_source = str(raw_event.get("eventSource", "") or "")
    mapping = {
        "aws_lambda_function": "lambda.amazonaws.com",
        "aws_dynamodb_table": "dynamodb.amazonaws.com",
        "aws_instance": "ec2.amazonaws.com",
        "aws_security_group": "ec2.amazonaws.com",
        "aws_db_instance": "rds.amazonaws.com",
        "aws_s3_bucket": "s3.amazonaws.com",
        "aws_cloudwatch_metric_alarm": "monitoring.amazonaws.com",
    }
    expected = mapping.get(resource_type)
    return bool(expected and event_source == expected)


def _looks_like_mutation(event_name: str) -> bool:
    if not event_name:
        return False
    if any(event_name.startswith(prefix) for prefix in READ_ONLY_PREFIXES):
        return False
    return any(fnmatchcase(event_name, pattern) for pattern in GENERIC_MUTATION_PATTERNS)


def _is_automated_principal(principal: str) -> bool:
    if not principal:
        return True
    lowered = principal.lower()
    return any(fnmatchcase(lowered, pattern.lower()) for pattern in AUTOMATED_PRINCIPAL_PATTERNS)


def _wildcard_match(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return fnmatchcase(left, right) or fnmatchcase(right, left)


def _extract_principal(event: dict[str, Any]) -> str:
    username = str(event.get("Username", "") or "")
    if username.startswith("arn:aws"):
        return username

    raw_event = _parse_cloudtrail_event(event)
    identity = raw_event.get("userIdentity", {}) or {}

    arn = identity.get("arn")
    if arn:
        return str(arn)

    issuer = (identity.get("sessionContext", {}) or {}).get("sessionIssuer", {}) or {}
    issuer_arn = issuer.get("arn")
    if issuer_arn:
        return str(issuer_arn)

    principal_id = identity.get("principalId")
    if username:
        return username
    if principal_id:
        return str(principal_id)
    if identity.get("type"):
        return str(identity.get("type"))
    return "unknown"
