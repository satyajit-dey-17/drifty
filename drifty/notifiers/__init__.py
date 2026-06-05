"""
notifiers/ — pluggable notification backends for drifty.

Currently supported: slack
Planned: pagerduty, teams, email
"""

from __future__ import annotations

from drifty.notifiers.slack import notify_slack

__all__ = ["notify_slack"]
