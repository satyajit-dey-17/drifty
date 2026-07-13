"""
discovery.py — recursively discovers runnable Terragrunt units from a root directory.

A unit is considered *runnable* when its terragrunt.hcl contains a terraform{} block,
which indicates it is a leaf/deployable unit rather than a shared root or generate-only
config.

Design rationale — why regex and not a Python HCL library:
  - pyhcl: last release 2021, largely unmaintained.
  - python-hcl2: more active but incomplete support for Terragrunt-specific expressions
    such as find_in_parent_folders() and dependency interpolations; adds a non-trivial
    dependency for a single boolean check.
  - For discovery purposes a single re.search for 'terraform {' is correct, fast,
    dependency-free, and covers all realistic formatting variants. The only edge case
    (a commented-out terraform block) is explicitly documented and tested.

Algorithm:
  1. Validate root exists and is a directory.
  2. os.walk with in-place dirs pruning to skip excluded directories.
  3. For each directory, look for terragrunt.hcl.
  4. Apply runnability heuristic via _is_runnable_unit().
  5. Infer environment hint from path segments.
  6. Deduplicate by resolved absolute path.
  7. Sort by rel_path for deterministic output.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from drifty.terragrunt.models import TerragruntUnit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HCL_FILENAME = "terragrunt.hcl"

DEFAULT_EXCLUDES: frozenset[str] = frozenset(
    {
        ".terragrunt-cache",
        ".git",
        ".terraform",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
    }
)

# Matches a terraform{} block at the start of a line, with optional leading
# whitespace and optional whitespace before the opening brace.
# Does NOT match commented-out blocks (# terraform {) by design.
_TERRAFORM_BLOCK_RE = re.compile(r"^\s*terraform\s*\{", re.MULTILINE)

# Common environment segment names used to infer env_hint from the path.
_ENV_SEGMENTS: frozenset[str] = frozenset(
    {
        "prod",
        "production",
        "staging",
        "stage",
        "dev",
        "development",
        "sandbox",
        "qa",
        "test",
        "uat",
        "preprod",
        "pre-prod",
    }
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def discover_units(
    root: Path,
    exclude: list[str] | None = None,
) -> list[TerragruntUnit]:
    """
    Recursively discover runnable Terragrunt units under *root*.

    Args:
        root:    Directory to start discovery from. Must exist.
        exclude: Directory names to skip entirely. Defaults to DEFAULT_EXCLUDES.
                 Values are matched against directory *names* (not full paths),
                 so ".terragrunt-cache" excludes any directory with that name
                 at any depth.

    Returns:
        Sorted list of TerragruntUnit instances (sorted by rel_path).

    Raises:
        ValueError:       root does not exist or is not a directory.
        FileNotFoundError: root path cannot be resolved.
    """
    root = root.resolve()

    if not root.exists():
        raise FileNotFoundError(f"Scan root does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"Scan root is not a directory: {root}")

    exclusion_set: frozenset[str] = (
        DEFAULT_EXCLUDES if exclude is None else DEFAULT_EXCLUDES | frozenset(exclude)
    )

    seen: set[Path] = set()
    units: list[TerragruntUnit] = []

    for dirpath_str, dirnames, filenames in os.walk(root, topdown=True):
        # Prune excluded directories in-place so os.walk never descends into them.
        dirnames[:] = [d for d in dirnames if d not in exclusion_set]

        if HCL_FILENAME not in filenames:
            continue

        dirpath = Path(dirpath_str)
        hcl_file = dirpath / HCL_FILENAME
        canonical = hcl_file.resolve()

        # Deduplicate via resolved path (handles symlinks).
        if canonical in seen:
            continue
        seen.add(canonical)

        if not _is_runnable_unit(hcl_file):
            continue

        rel_path = _rel_path_str(dirpath, root)

        units.append(
            TerragruntUnit(
                path=dirpath,
                rel_path=rel_path,
                hcl_file=hcl_file,
                is_runnable=True,
                env_hint=_infer_env_hint(dirpath, root),
            )
        )

    units.sort(key=lambda u: u.rel_path)
    return units


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_runnable_unit(hcl_file: Path) -> bool:
    """
    Return True if hcl_file contains a terraform{} block.

    Reads the file as UTF-8 with errors='replace' so binary/malformed content
    never raises an exception — it simply returns False (non-runnable).
    """
    try:
        content = hcl_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    return bool(_TERRAFORM_BLOCK_RE.search(content))


def _rel_path_str(dirpath: Path, root: Path) -> str:
    """
    Return the path of *dirpath* relative to *root* as a POSIX string.
    Returns '.' when dirpath == root (unit at the root level).
    """
    try:
        rel = dirpath.relative_to(root)
    except ValueError:
        return str(dirpath)

    posix = rel.as_posix()
    return posix if posix else "."


def _infer_env_hint(dirpath: Path, root: Path) -> str | None:
    """
    Walk path segments between root and dirpath and return the first segment
    that matches a known environment name, or None.

    Example: root=/infra, dirpath=/infra/envs/prod/networking → 'prod'
    """
    try:
        rel = dirpath.relative_to(root)
    except ValueError:
        return None

    for part in rel.parts:
        if part.lower() in _ENV_SEGMENTS:
            return part.lower()
    return None
