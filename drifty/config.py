"""
config.py — reads and writes .drifty/config.yaml in the active workspace.

Config file location: <workspace>/.drifty/config.yaml
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_DIR_NAME = ".drifty"
CONFIG_FILE_NAME = "config.yaml"

DEFAULT_CONFIG: dict[str, Any] = {
    "default_profile": "default",
    "default_severity": None,  # None means show all severities
    "default_output": "terminal",
    "slack_webhook": None,
    "cloudtrail_lookback_days": 90,
    "severity_overrides": {},  # e.g. {"aws_lambda_function": "high"}
}

VALID_KEYS = set(DEFAULT_CONFIG.keys())
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_OUTPUTS = {"terminal", "json", "markdown"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _config_path(workspace: Path) -> Path:
    return workspace / CONFIG_DIR_NAME / CONFIG_FILE_NAME


def _config_dir(workspace: Path) -> Path:
    return workspace / CONFIG_DIR_NAME


def _load_raw(workspace: Path) -> dict[str, Any]:
    """Load raw YAML from disk. Returns empty dict if file doesn't exist."""
    path = _config_path(workspace)
    if not path.exists():
        return {}
    with path.open("r") as fh:
        return yaml.safe_load(fh) or {}


def _save_raw(workspace: Path, data: dict[str, Any]) -> None:
    """Write data dict to .drifty/config.yaml."""
    config_dir = _config_dir(workspace)
    config_dir.mkdir(parents=True, exist_ok=True)
    with _config_path(workspace).open("w") as fh:
        yaml.dump(data, fh, default_flow_style=False, sort_keys=True)


def _merge_with_defaults(raw: dict[str, Any]) -> dict[str, Any]:
    """Merge loaded YAML with defaults so missing keys always have a value."""
    merged = DEFAULT_CONFIG.copy()
    merged.update(raw)
    return merged


# ---------------------------------------------------------------------------
# Public API (called from cli.py)
# ---------------------------------------------------------------------------


def init_workspace(workspace: Path) -> None:
    """
    Create .drifty/config.yaml in the given workspace with default values.
    Skips if the file already exists (idempotent).
    """
    path = _config_path(workspace)

    if path.exists():
        console.print(
            f"[yellow]⚠ Config already exists at [bold]{path}[/bold]. "
            "Nothing changed.[/yellow]\n"
            "  Run [cyan]drifty config show[/cyan] to view it, or "
            "[cyan]drifty config set KEY=VALUE[/cyan] to update it."
        )
        return

    _save_raw(workspace, DEFAULT_CONFIG)

    console.print(
        Panel(
            f"[green]✓ Initialized drifty config at:[/green]\n"
            f"  [bold cyan]{path}[/bold cyan]\n\n"
            f"[dim]Edit it directly or use [bold]drifty config set KEY=VALUE[/bold][/dim]",
            title="[bold green]drifty init[/bold green]",
            border_style="green",
        )
    )
    console.print("\n[dim]Default settings written:[/dim]")
    _print_config_table(_merge_with_defaults({}))


def load_config(workspace: Path = Path(".")) -> dict[str, Any]:
    """
    Load config for a workspace. Merges with defaults so callers always
    get a complete dict even if the config file is absent or partial.
    """
    raw = _load_raw(workspace)
    return _merge_with_defaults(raw)


def show_config(workspace: Path = Path(".")) -> None:
    """Pretty-print the current config as both a table and raw YAML."""
    path = _config_path(workspace)

    if not path.exists():
        console.print(
            f"[yellow]⚠ No config file found at [bold]{path}[/bold].[/yellow]\n"
            "  Run [cyan]drifty init[/cyan] to create one."
        )
        return

    config = load_config(workspace)

    console.print(f"\n[bold]Config file:[/bold] [cyan]{path}[/cyan]\n")
    _print_config_table(config)

    # Also show raw YAML for copy-paste convenience
    raw_yaml = yaml.dump(config, default_flow_style=False, sort_keys=True)
    console.print("\n[dim]Raw YAML:[/dim]")
    console.print(Syntax(raw_yaml, "yaml", theme="monokai", line_numbers=False))


def set_config_value(key: str, value: str, workspace: Path = Path(".")) -> None:
    """
    Write a single key=value into .drifty/config.yaml.
    Validates the key and value before writing.
    """
    # Key validation
    if key not in VALID_KEYS:
        console.print(
            f"[red]✗ Unknown config key:[/red] [bold]{key}[/bold]\n"
            f"  Valid keys: {', '.join(sorted(VALID_KEYS))}"
        )
        return

    # Value validation for constrained keys
    coerced = _coerce_value(key, value)
    if coerced is None and value.lower() not in ("none", "null", ""):
        # _coerce_value returned None as a validation failure signal
        # (the key has strict allowed values)
        _print_validation_error(key, value)
        return

    path = _config_path(workspace)
    if not path.exists():
        console.print(
            f"[yellow]⚠ No config found at [bold]{path}[/bold]. "
            "Run [cyan]drifty init[/cyan] first.[/yellow]"
        )
        return

    raw = _load_raw(workspace)
    raw[key] = coerced
    _save_raw(workspace, raw)

    display_value = repr(coerced) if coerced is not None else "null"
    console.print(
        f"[green]✓[/green] Set [bold cyan]{key}[/bold cyan] = [bold]{display_value}[/bold]"
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _coerce_value(key: str, value: str) -> Any:
    """
    Coerce a string value to the appropriate Python type for a given key.
    Returns None for null/empty. Raises ValueError for invalid constrained values.
    """
    # Null / clear semantics
    if value.lower() in ("none", "null", ""):
        return None

    # Integer keys
    if key == "cloudtrail_lookback_days":
        try:
            days = int(value)
            if not (1 <= days <= 90):
                console.print(
                    "[red]✗ [bold]cloudtrail_lookback_days[/bold] must be between 1 and 90.[/red]"
                )
                return None
            return days
        except ValueError:
            console.print("[red]✗ [bold]cloudtrail_lookback_days[/bold] must be an integer.[/red]")
            return None

    # Severity keys
    if key == "default_severity":
        if value.lower() not in VALID_SEVERITIES:
            console.print(
                f"[red]✗ Invalid severity:[/red] [bold]{value}[/bold]. "
                f"Choose from: {', '.join(sorted(VALID_SEVERITIES))}"
            )
            return None
        return value.lower()

    # Output format key
    if key == "default_output":
        if value.lower() not in VALID_OUTPUTS:
            console.print(
                f"[red]✗ Invalid output format:[/red] [bold]{value}[/bold]. "
                f"Choose from: {', '.join(sorted(VALID_OUTPUTS))}"
            )
            return None
        return value.lower()

    # Everything else is stored as a plain string
    return value


def _print_validation_error(key: str, value: str) -> None:
    console.print(f"[red]✗ Invalid value [bold]{value!r}[/bold] for key [bold]{key}[/bold].[/red]")


def _print_config_table(config: dict[str, Any]) -> None:
    """Render config as a Rich table."""
    table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_column("Description", style="dim")

    descriptions = {
        "default_profile": "AWS CLI profile for CloudTrail lookups",
        "default_severity": "Minimum severity filter (null = show all)",
        "default_output": "Output format: terminal | json | markdown",
        "slack_webhook": "Slack incoming webhook URL for --notify slack",
        "cloudtrail_lookback_days": "How far back to search CloudTrail (max 90)",
        "severity_overrides": "Per-resource severity overrides (YAML map)",
    }

    for key in sorted(config.keys()):
        val = config[key]
        display = (
            "[dim]null[/dim]"
            if val is None
            else (
                str(val)
                if not isinstance(val, dict)
                else yaml.dump(val, default_flow_style=True).strip()
            )
        )
        table.add_row(key, display, descriptions.get(key, ""))

    console.print(table)
