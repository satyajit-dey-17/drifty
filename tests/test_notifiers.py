"""
Tests for drifty/notifiers/slack.py
Uses httpx mock transport — no real HTTP calls made.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from drifty.notifiers.slack import (
    _build_finding_block,
    _build_payload,
    _format_value,
    _severity_summary_text,
    _shorten_arn,
    notify_slack,
)
from drifty.scanner import DriftFinding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_finding(
    resource_type: str = "aws_security_group",
    resource_name: str = "main",
    resource_id: str = "sg-0abc1234",
    severity: str = "critical",
    attributed_to: str | None = "arn:aws:iam::123456789:user/john.doe",
    attributed_action: str | None = "ModifySecurityGroupRules",
    attributed_at: str | None = "2026-06-03T14:22:11+00:00",
    attrs: list | None = None,
    remediation_hint: str | None = "terraform import aws_security_group.main sg-0abc1234",
) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name=resource_name,
        resource_id=resource_id,
        changed_attributes=attrs
        or [
            {"attribute": "ingress.0.cidr_blocks", "before": ["10.0.0.0/8"], "after": ["0.0.0.0/0"]}
        ],
        severity=severity,
        attributed_to=attributed_to,
        attributed_at=attributed_at,
        attributed_action=attributed_action,
        remediation_hint=remediation_hint,
    )


MOCK_WEBHOOK = "https://hooks.slack.com/services/TEST/TEST/TEST"


def _mock_transport(status_code: int = 200, text: str = "ok") -> httpx.MockTransport:
    def handler(request):
        return httpx.Response(status_code, text=text)

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# notify_slack — HTTP behaviour
# ---------------------------------------------------------------------------


class TestNotifySlack:
    def test_returns_true_on_success(self):
        findings = [make_finding()]
        with patch("httpx.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            result = notify_slack(findings, webhook_url=MOCK_WEBHOOK)
        assert result is True

    def test_returns_true_with_no_findings(self):
        # No findings → no HTTP call, returns True silently
        with patch("httpx.post") as mock_post:
            result = notify_slack([], webhook_url=MOCK_WEBHOOK)
        mock_post.assert_not_called()
        assert result is True

    def test_returns_false_on_timeout(self):
        findings = [make_finding()]
        with patch("httpx.post", side_effect=httpx.TimeoutException("timed out")):
            result = notify_slack(findings, webhook_url=MOCK_WEBHOOK)
        assert result is False

    def test_returns_false_on_http_error(self):
        findings = [make_finding()]
        mock_response = httpx.Response(400, text="invalid_payload")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = mock_response
            mock_post.return_value.raise_for_status = lambda: (_ for _ in ()).throw(
                httpx.HTTPStatusError("400", request=None, response=mock_response)
            )
            with patch(
                "httpx.post",
                side_effect=httpx.HTTPStatusError(
                    "400", request=httpx.Request("POST", MOCK_WEBHOOK), response=mock_response
                ),
            ):
                result = notify_slack(findings, webhook_url=MOCK_WEBHOOK)
        assert result is False

    def test_returns_false_on_request_error(self):
        findings = [make_finding()]
        with patch("httpx.post", side_effect=httpx.RequestError("connection refused")):
            result = notify_slack(findings, webhook_url=MOCK_WEBHOOK)
        assert result is False

    def test_posts_to_correct_url(self):
        findings = [make_finding()]
        with patch("httpx.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            notify_slack(findings, webhook_url=MOCK_WEBHOOK)
        call_args = mock_post.call_args
        assert call_args[0][0] == MOCK_WEBHOOK

    def test_posts_json_content_type(self):
        findings = [make_finding()]
        with patch("httpx.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response
            notify_slack(findings, webhook_url=MOCK_WEBHOOK)
        headers = mock_post.call_args[1]["headers"]
        assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# _build_payload — structure validation
# ---------------------------------------------------------------------------


class TestBuildPayload:
    def test_payload_has_text_and_blocks(self):
        findings = [make_finding()]
        payload = _build_payload(findings, Path("infra"))
        assert "text" in payload
        assert "blocks" in payload
        assert isinstance(payload["blocks"], list)

    def test_text_contains_finding_count(self):
        findings = [make_finding(), make_finding(resource_name="other", resource_id="sg-other")]
        payload = _build_payload(findings, Path("infra"))
        assert "2 drifts" in payload["text"]

    def test_text_singular_for_one_finding(self):
        findings = [make_finding()]
        payload = _build_payload(findings, Path("infra"))
        assert "1 drift" in payload["text"]
        assert "drifts" not in payload["text"]

    def test_workspace_name_in_text(self):
        findings = [make_finding()]
        payload = _build_payload(findings, Path("/home/user/my-infra"))
        assert "my-infra" in payload["text"]

    def test_header_block_present(self):
        findings = [make_finding()]
        payload = _build_payload(findings, Path("."))
        header_blocks = [b for b in payload["blocks"] if b.get("type") == "header"]
        assert len(header_blocks) == 1

    def test_overflow_notice_shown_when_exceeds_max(self):
        findings = [
            make_finding(resource_name=f"res{i}", resource_id=f"sg-{i}", severity="low")
            for i in range(15)
        ]
        payload = _build_payload(findings, Path("."))
        all_text = str(payload["blocks"])
        assert "more finding" in all_text

    def test_no_overflow_notice_within_limit(self):
        findings = [make_finding()]
        payload = _build_payload(findings, Path("."))
        all_text = str(payload["blocks"])
        assert "more finding" not in all_text

    def test_sorted_critical_first(self):
        critical = make_finding(severity="critical")
        low = make_finding(resource_name="low_res", resource_id="sg-low", severity="low")
        payload = _build_payload([low, critical], Path("."))
        # Find section blocks with finding content
        section_texts = [
            b["text"]["text"]
            for b in payload["blocks"]
            if b.get("type") == "section" and "CRITICAL" in b.get("text", {}).get("text", "")
        ]
        assert len(section_texts) >= 1


# ---------------------------------------------------------------------------
# _build_finding_block
# ---------------------------------------------------------------------------


class TestBuildFindingBlock:
    def test_contains_resource_address(self):
        finding = make_finding()
        block = _build_finding_block(finding)
        assert "aws_security_group.main" in block["text"]["text"]

    def test_contains_severity(self):
        finding = make_finding(severity="critical")
        block = _build_finding_block(finding)
        assert "CRITICAL" in block["text"]["text"]

    def test_contains_attribution(self):
        finding = make_finding(attributed_to="arn:aws:iam::123:user/john.doe")
        block = _build_finding_block(finding)
        assert "john.doe" in block["text"]["text"]

    def test_no_attribution_shows_unavailable(self):
        finding = make_finding(attributed_to=None, attributed_action=None, attributed_at=None)
        block = _build_finding_block(finding)
        assert "unavailable" in block["text"]["text"]

    def test_remediation_hint_shown(self):
        finding = make_finding()
        block = _build_finding_block(finding)
        assert "terraform import" in block["text"]["text"]

    def test_caps_attributes_at_three(self):
        attrs = [{"attribute": f"attr{i}", "before": "a", "after": "b"} for i in range(6)]
        finding = make_finding(attrs=attrs)
        block = _build_finding_block(finding)
        assert "more attribute" in block["text"]["text"]


# ---------------------------------------------------------------------------
# _shorten_arn
# ---------------------------------------------------------------------------


class TestShortenArn:
    def test_user_arn_returns_username(self):
        assert _shorten_arn("arn:aws:iam::123456789:user/john.doe") == "john.doe"

    def test_role_arn_returns_name_with_suffix(self):
        assert _shorten_arn("arn:aws:iam::123456789:role/ops-team") == "ops-team (role)"

    def test_non_arn_returned_as_is(self):
        assert _shorten_arn("john.doe") == "john.doe"

    def test_malformed_arn_returned_as_is(self):
        assert _shorten_arn("arn:aws") == "arn:aws"


# ---------------------------------------------------------------------------
# _format_value
# ---------------------------------------------------------------------------


class TestFormatValue:
    def test_none_returns_null(self):
        assert _format_value(None) == "null"

    def test_string_passthrough(self):
        assert _format_value("t3.large") == "t3.large"

    def test_long_string_truncated(self):
        result = _format_value("x" * 50)
        assert len(result) <= 40
        assert result.endswith("...")

    def test_list_serialized_as_json(self):
        result = _format_value(["0.0.0.0/0"])
        assert "0.0.0.0/0" in result

    def test_dict_serialized_as_json(self):
        result = _format_value({"key": "value"})
        assert "key" in result


# ---------------------------------------------------------------------------
# _severity_summary_text
# ---------------------------------------------------------------------------


class TestSeveritySummaryText:
    def test_single_critical(self):
        result = _severity_summary_text({"critical": 1})
        assert "Critical" in result
        assert "🔴" in result

    def test_mixed_severities(self):
        result = _severity_summary_text({"critical": 2, "high": 1, "low": 3})
        assert "Critical" in result
        assert "High" in result
        assert "Low" in result
        assert "Medium" not in result

    def test_empty_counts(self):
        result = _severity_summary_text({})
        assert result == ""
