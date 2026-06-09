"""
tests/test_github.py — Unit tests for drifty/github.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from drifty.github import (
    _build_comment,
    _build_finding_block,
    _fmt,
    _severity_summary,
    post_pr_comment,
)
from drifty.scanner import DriftFinding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(
    severity: str = "high",
    resource_type: str = "aws_instance",
    resource_name: str = "api_server",
    resource_id: str = "i-0abc1234",
    attributed_to: str | None = None,
    attributed_action: str | None = None,
    attributed_at: str | None = None,
    changed_attributes: list | None = None,
    remediation_hint: str | None = None,
) -> DriftFinding:
    return DriftFinding(
        resource_type=resource_type,
        resource_name=resource_name,
        resource_id=resource_id,
        severity=severity,
        changed_attributes=changed_attributes
        or [{"attribute": "instance_type", "before": "t3.medium", "after": "t3.large"}],
        attributed_to=attributed_to,
        attributed_action=attributed_action,
        attributed_at=attributed_at,
        remediation_hint=remediation_hint or "terraform import aws_instance.api_server i-0abc1234",
    )


ENV_BASE = {
    "GITHUB_TOKEN": "ghp_testtoken",
    "GITHUB_REPOSITORY": "acme/infra",
    "PR_NUMBER": "42",
}


def _mock_response(status_code: int = 201, text: str = "") -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.raise_for_status = MagicMock()
    if status_code >= 400:
        mock.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=mock,
        )
    return mock


# ---------------------------------------------------------------------------
# post_pr_comment — credential validation
# ---------------------------------------------------------------------------


def test_post_pr_comment_no_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    monkeypatch.setenv("PR_NUMBER", "42")
    assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_no_repo(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setenv("PR_NUMBER", "42")
    assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_no_pr(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    monkeypatch.delenv("PR_NUMBER", raising=False)
    assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_invalid_pr_number(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    monkeypatch.setenv("PR_NUMBER", "not-a-number")
    assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_pr_number_zero_is_invalid(monkeypatch):
    """PR number 0 should not be treated as falsy and fall through to env var."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    monkeypatch.delenv("PR_NUMBER", raising=False)

    with patch("httpx.post", return_value=_mock_response(201)) as mock_post:
        result = post_pr_comment([_finding()], pr_number=0)

    # With our fix, pr_number=0 is not falsy — it should be passed through
    # and the URL should contain /0/comments
    assert result is True
    assert "/0/comments" in mock_post.call_args[0][0]


# ---------------------------------------------------------------------------
# post_pr_comment — HTTP outcomes
# ---------------------------------------------------------------------------


def test_post_pr_comment_success(monkeypatch):
    for k, v in ENV_BASE.items():
        monkeypatch.setenv(k, v)

    with patch("httpx.post", return_value=_mock_response(201)):
        assert post_pr_comment([_finding()]) is True


def test_post_pr_comment_http_403(monkeypatch):
    for k, v in ENV_BASE.items():
        monkeypatch.setenv(k, v)

    with patch("httpx.post", return_value=_mock_response(403, "Forbidden")):
        assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_timeout(monkeypatch):
    for k, v in ENV_BASE.items():
        monkeypatch.setenv(k, v)

    with patch("httpx.post", side_effect=httpx.TimeoutException("timed out")):
        assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_request_error(monkeypatch):
    for k, v in ENV_BASE.items():
        monkeypatch.setenv(k, v)

    with patch("httpx.post", side_effect=httpx.RequestError("network error")):
        assert post_pr_comment([_finding()]) is False


def test_post_pr_comment_args_override_env(monkeypatch):
    """Explicit args take precedence over env vars."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("PR_NUMBER", raising=False)

    with patch("httpx.post", return_value=_mock_response(201)) as mock_post:
        result = post_pr_comment(
            [_finding()],
            github_token="ghp_explicit",
            repository="explicit/repo",
            pr_number=99,
        )
    assert result is True
    call_url = mock_post.call_args[0][0]
    assert "explicit/repo" in call_url
    assert "/99/" in call_url


# ---------------------------------------------------------------------------
# _build_comment
# ---------------------------------------------------------------------------


def test_build_comment_no_findings():
    result = _build_comment([], Path("infra"))
    assert "No Drift Detected" in result
    assert "clean" in result
    assert "drifty" in result


def test_build_comment_with_findings():
    findings = [_finding("critical"), _finding("low")]
    result = _build_comment(findings, Path("infra"))
    assert "2 Drifts Detected" in result
    assert "<details>" in result
    assert "CRITICAL" in result
    assert "LOW" in result


def test_build_comment_sorted_by_severity():
    """Critical findings should appear before low in the output."""
    findings = [_finding("low"), _finding("critical")]
    result = _build_comment(findings, Path("infra"))
    assert result.index("CRITICAL") < result.index("LOW")


def test_build_comment_overflow():
    """When findings exceed MAX, overflow notice is shown."""
    findings = [_finding() for _ in range(25)]
    result = _build_comment(findings, Path("infra"))
    assert "5 more findings" in result


def test_build_comment_footer():
    result = _build_comment([_finding()], Path("infra"))
    assert "pip install drifty" in result


# ---------------------------------------------------------------------------
# _build_finding_block
# ---------------------------------------------------------------------------


def test_build_finding_block_with_attribution():
    f = _finding(
        attributed_to="arn:aws:iam::123:user/john.doe",
        attributed_action="ModifyInstanceAttribute",
        attributed_at="2026-06-03 14:22:11 UTC",
    )
    result = _build_finding_block(f)
    assert "<details>" in result
    assert "john.doe" in result
    assert "ModifyInstanceAttribute" in result
    assert "2026-06-03" in result


def test_build_finding_block_no_attribution():
    f = _finding(attributed_to=None)
    result = _build_finding_block(f)
    assert "attribution unavailable" in result


def test_build_finding_block_attribute_cap():
    """Only 5 changed attributes shown, overflow noted."""
    f = _finding(
        changed_attributes=[
            {"attribute": f"attr_{i}", "before": "x", "after": "y"} for i in range(8)
        ]
    )
    result = _build_finding_block(f)
    assert "3 more" in result


def test_build_finding_block_remediation():
    f = _finding(remediation_hint="terraform import aws_instance.api_server i-0abc1234")
    result = _build_finding_block(f)
    assert "terraform import" in result
    assert "Fix" in result


# ---------------------------------------------------------------------------
# _severity_summary
# ---------------------------------------------------------------------------


def test_severity_summary_mixed():
    findings = [_finding("critical"), _finding("critical"), _finding("low")]
    result = _severity_summary(findings)
    assert "🔴" in result
    assert "2 Critical" in result
    assert "🟢" in result
    assert "1 Low" in result


def test_severity_summary_single():
    result = _severity_summary([_finding("high")])
    assert "🟠" in result
    assert "1 High" in result


# ---------------------------------------------------------------------------
# _fmt
# ---------------------------------------------------------------------------


def test_fmt_none():
    assert _fmt(None) == "null"


def test_fmt_short_string():
    assert _fmt("t3.large") == "t3.large"


def test_fmt_long_string_truncated():
    long_val = "x" * 60
    result = _fmt(long_val)
    assert len(result) <= 50
    assert result.endswith("...")


def test_fmt_dict():
    result = _fmt({"key": "value"})
    assert "key" in result


def test_fmt_long_dict_truncated():
    big = {f"key_{i}": f"value_{i}" for i in range(20)}
    result = _fmt(big)
    assert len(result) <= 50
    assert result.endswith("...")
