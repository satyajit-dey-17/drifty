"""
scorer.py — assigns severity scores to DriftFinding instances.

Rules are applied in this order:
  1. Tag-only change overrides (aws_instance, aws_s3_bucket → Low)
  2. Exact resource_type match from SEVERITY_MAP
  3. Prefix match (e.g. "aws_iam_" → Critical)
  4. Default fallback → Medium

Users can override per-resource severity via .drifty/config.yaml:
  severity_overrides:
    aws_lambda_function: high
    aws_cloudwatch_metric_alarm: low
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drifty.scanner import DriftFinding


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


# ---------------------------------------------------------------------------
# Default severity map (resource_type → severity)
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[str, str] = {
    # --- Critical: security boundary resources ---
    "aws_iam_role_policy": CRITICAL,
    "aws_iam_policy": CRITICAL,
    "aws_iam_role": CRITICAL,
    "aws_iam_user_policy": CRITICAL,
    "aws_iam_group_policy": CRITICAL,
    "aws_security_group": CRITICAL,
    "aws_security_group_rule": CRITICAL,
    "aws_s3_bucket_policy": CRITICAL,
    "aws_s3_bucket_public_access_block": CRITICAL,
    "aws_vpc": CRITICAL,
    "aws_network_acl": CRITICAL,
    "aws_network_acl_rule": CRITICAL,
    # --- High: compute and data resources ---
    "aws_instance": HIGH,
    "aws_rds_instance": HIGH,
    "aws_rds_cluster": HIGH,
    "aws_lb": HIGH,
    "aws_alb": HIGH,
    "aws_elasticache_cluster": HIGH,
    "aws_eks_cluster": HIGH,
    "aws_ecs_service": HIGH,
    "aws_db_instance": HIGH,
    # --- Medium: operational resources ---
    "aws_lambda_function": MEDIUM,
    "aws_autoscaling_group": MEDIUM,
    "aws_cloudwatch_metric_alarm": MEDIUM,
    "aws_cloudwatch_log_group": MEDIUM,
    "aws_sns_topic": MEDIUM,
    "aws_sqs_queue": MEDIUM,
    "aws_route53_record": MEDIUM,
    "aws_elasticloadbalancingv2_listener": MEDIUM,
    # --- Low: non-critical metadata ---
    "aws_s3_bucket": LOW,
    "aws_subnet": LOW,
    "aws_route_table": LOW,
    "aws_internet_gateway": LOW,
    "aws_eip": LOW,
}


# ---------------------------------------------------------------------------
# Prefix-based fallback rules (applied when no exact match exists)
# ---------------------------------------------------------------------------

SEVERITY_PREFIX_MAP: list[tuple[str, str]] = [
    ("aws_iam_", CRITICAL),
    ("aws_security_", CRITICAL),
    ("aws_waf", CRITICAL),
    ("aws_kms_", CRITICAL),
    ("aws_rds_", HIGH),
    ("aws_eks_", HIGH),
    ("aws_ecs_", HIGH),
    ("aws_elb", HIGH),
    ("aws_lb", HIGH),
    ("aws_alb", HIGH),
    ("aws_lambda_", MEDIUM),
    ("aws_cloudwatch_", MEDIUM),
    ("aws_sns_", MEDIUM),
    ("aws_sqs_", MEDIUM),
]


# ---------------------------------------------------------------------------
# Tag-only change detection
# ---------------------------------------------------------------------------

# Attributes that are considered "tag-only" metadata changes
_TAG_ATTRIBUTE_NAMES = frozenset(
    {
        "tags",
        "tags_all",
        "labels",
    }
)

# Resource types where a tag-only change downgrades severity to Low
_TAG_ONLY_DOWNGRADE_TYPES = frozenset(
    {
        "aws_instance",
        "aws_s3_bucket",
        "aws_rds_instance",
        "aws_lambda_function",
        "aws_lb",
        "aws_alb",
    }
)


def _is_tag_only_change(finding: DriftFinding) -> bool:
    """
    Return True if ALL changed attributes are tag/label fields.
    e.g. only tags.LastModified changed → tag-only drift.
    """
    if not finding.changed_attributes:
        return False
    return all(
        # attribute name is a tag field, OR it's a dotted path under a tag field
        attr["attribute"].split(".")[0] in _TAG_ATTRIBUTE_NAMES
        for attr in finding.changed_attributes
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score(finding: DriftFinding, config_overrides: dict[str, str] | None = None) -> str:
    """
    Return a severity string for a DriftFinding.

    Resolution order:
      1. User config overrides (from .drifty/config.yaml severity_overrides)
      2. Tag-only change downgrade
      3. Exact match in SEVERITY_MAP
      4. Prefix match in SEVERITY_PREFIX_MAP
      5. Default: MEDIUM
    """
    resource_type = finding.resource_type.lower()

    # 1. User config overrides take highest priority
    if config_overrides:
        override = config_overrides.get(resource_type)
        if override and override in SEVERITY_ORDER:
            return override

    # 2. Tag-only change downgrade (before exact match so it overrides HIGH)
    if resource_type in _TAG_ONLY_DOWNGRADE_TYPES and _is_tag_only_change(finding):
        return LOW

    # 3. Exact match
    if resource_type in SEVERITY_MAP:
        return SEVERITY_MAP[resource_type]

    # 4. Prefix match (first match wins — list is ordered most-specific first)
    for prefix, severity in SEVERITY_PREFIX_MAP:
        if resource_type.startswith(prefix):
            return severity

    # 5. Default fallback
    return MEDIUM


def severity_color(severity: str) -> str:
    """Return a Rich color string for a given severity level."""
    return {
        CRITICAL: "bold red",
        HIGH: "bold orange1",
        MEDIUM: "bold yellow",
        LOW: "bold green",
    }.get(severity, "white")


def severity_emoji(severity: str) -> str:
    """Return an emoji badge for a given severity level."""
    return {
        CRITICAL: "🔴",
        HIGH: "🟠",
        MEDIUM: "🟡",
        LOW: "🟢",
    }.get(severity, "⚪")


def severity_badge(severity: str) -> str:
    """Return an uppercase label for a given severity level."""
    return severity.upper()


def meets_threshold(severity: str, threshold: str) -> bool:
    """
    Return True if `severity` is >= `threshold` in terms of criticality.
    e.g. meets_threshold("critical", "high") → True
         meets_threshold("low", "high")      → False
    """
    return SEVERITY_ORDER.get(severity, 3) <= SEVERITY_ORDER.get(threshold, 3)
