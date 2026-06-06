"""
notifiers/ — pluggable notification backends for drifty.

Currently supported: slack
Planned: pagerduty, teams, email
"""

from __future__ import annotations

from drifty.notifiers.slack import notify_slack

__all__ = ["notify_slack"]


def get_notifier(name: str, **kwargs):
    from drifty.notifiers.slack import SlackNotifier

    registry = {"slack": SlackNotifier}
    if name not in registry:
        raise ValueError(f"Unknown notifier: '{name}'. Available: {list(registry)}")
    return registry[name](**kwargs)
