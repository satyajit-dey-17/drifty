"""
Tests for drifty/terragrunt/discovery.py

All tests in this file are pure filesystem operations — no subprocess,
no AWS credentials, no network access required.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# These imports will resolve in Commit 2 when the module exists.
# Collected by pytest now but ImportError deferred until test execution,
# so Commit 1 scaffolding does not break CI.
pytest.importorskip("drifty.terragrunt.discovery")

from drifty.terragrunt.discovery import DEFAULT_EXCLUDES, discover_units  # noqa: E402
from drifty.terragrunt.models import TerragruntUnit  # noqa: E402

MONOREPO = Path(__file__).parent / "fixtures" / "terragrunt_monorepo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def rel_paths(units: list[TerragruntUnit]) -> list[str]:
    return [u.rel_path for u in units]


# ---------------------------------------------------------------------------
# Basic discovery
# ---------------------------------------------------------------------------


class TestDiscoverUnits:
    def test_finds_exactly_three_runnable_units(self):
        units = discover_units(MONOREPO)
        assert len(units) == 3

    def test_runnable_unit_paths_correct(self):
        units = discover_units(MONOREPO)
        paths = rel_paths(units)
        assert "envs/prod/compute" in paths
        assert "envs/prod/networking" in paths
        assert "envs/staging/networking" in paths

    def test_all_discovered_units_are_runnable(self):
        units = discover_units(MONOREPO)
        assert all(u.is_runnable for u in units)

    def test_units_have_hcl_file_path(self):
        units = discover_units(MONOREPO)
        for unit in units:
            assert unit.hcl_file.name == "terragrunt.hcl"
            assert unit.hcl_file.exists()

    def test_units_have_absolute_paths(self):
        units = discover_units(MONOREPO)
        for unit in units:
            assert unit.path.is_absolute()


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


class TestExclusions:
    def test_excludes_terragrunt_cache(self):
        units = discover_units(MONOREPO)
        paths = rel_paths(units)
        assert not any(".terragrunt-cache" in p for p in paths)

    def test_excludes_custom_directory(self):
        units = discover_units(MONOREPO, exclude=["envs"])
        # No runnable units are outside envs/ in this fixture
        assert len(units) == 0

    def test_excludes_modules_directory(self):
        units = discover_units(MONOREPO, exclude=list(DEFAULT_EXCLUDES) + ["modules"])
        paths = rel_paths(units)
        assert not any("modules" in p for p in paths)

    def test_default_excludes_contains_git(self):
        assert ".git" in DEFAULT_EXCLUDES

    def test_default_excludes_contains_cache(self):
        assert ".terragrunt-cache" in DEFAULT_EXCLUDES

    def test_git_directory_excluded(self, tmp_path):
        # Create a minimal unit inside a .git subdirectory (edge case)
        git_unit = tmp_path / ".git" / "infra"
        git_unit.mkdir(parents=True)
        (git_unit / "terragrunt.hcl").write_text('terraform {\n  source = "."\n}\n')
        units = discover_units(tmp_path)
        paths = rel_paths(units)
        assert not any(".git" in p for p in paths)


# ---------------------------------------------------------------------------
# Root config not treated as runnable
# ---------------------------------------------------------------------------


class TestRunnabilityHeuristic:
    def test_root_config_not_runnable(self):
        units = discover_units(MONOREPO)
        paths = rel_paths(units)
        # The root terragrunt.hcl has only remote_state{}, no terraform{}
        assert "" not in paths
        assert "." not in paths

    def test_generate_only_not_runnable(self):
        units = discover_units(MONOREPO)
        paths = rel_paths(units)
        assert "modules/vpc" not in paths

    def test_terraform_block_makes_unit_runnable(self, tmp_path):
        unit_dir = tmp_path / "myunit"
        unit_dir.mkdir()
        (unit_dir / "terragrunt.hcl").write_text(
            'terraform {\n  source = "git::https://example.com/mod"\n}\n'
        )
        units = discover_units(tmp_path)
        assert len(units) == 1
        assert units[0].is_runnable

    def test_indented_terraform_block_is_runnable(self, tmp_path):
        unit_dir = tmp_path / "myunit"
        unit_dir.mkdir()
        # Ensure regex handles leading whitespace
        (unit_dir / "terragrunt.hcl").write_text(
            '  terraform   {\n  source = "git::https://example.com/mod"\n}\n'
        )
        units = discover_units(tmp_path)
        assert len(units) == 1

    def test_malformed_hcl_does_not_raise(self):
        # The malformed fixture exists — discovery should not crash
        units = discover_units(MONOREPO)
        # malformed/terragrunt.hcl has a partial terraform{ but is truncated/invalid
        # We just verify no exception is raised; whether it's detected as runnable
        # depends on whether the regex fires before the parse error
        assert isinstance(units, list)


# ---------------------------------------------------------------------------
# Determinism and deduplication
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_sorted_by_rel_path(self):
        units = discover_units(MONOREPO)
        paths = rel_paths(units)
        assert paths == sorted(paths)

    def test_stable_across_two_calls(self):
        units_a = discover_units(MONOREPO)
        units_b = discover_units(MONOREPO)
        assert rel_paths(units_a) == rel_paths(units_b)


# ---------------------------------------------------------------------------
# env_hint inference
# ---------------------------------------------------------------------------


class TestEnvHint:
    def test_prod_units_have_prod_env_hint(self):
        units = discover_units(MONOREPO)
        prod_units = [u for u in units if "prod" in u.rel_path]
        for unit in prod_units:
            assert unit.env_hint == "prod"

    def test_staging_unit_has_staging_env_hint(self):
        units = discover_units(MONOREPO)
        staging_units = [u for u in units if "staging" in u.rel_path]
        for unit in staging_units:
            assert unit.env_hint == "staging"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_root_returns_empty_list(self, tmp_path):
        units = discover_units(tmp_path)
        assert units == []

    def test_nonexistent_root_raises_value_error(self):
        with pytest.raises((ValueError, FileNotFoundError)):
            discover_units(Path("/nonexistent/path/xyz"))

    def test_single_unit_at_root_level(self, tmp_path):
        (tmp_path / "terragrunt.hcl").write_text(
            'terraform {\n  source = "git::https://example.com/m"\n}\n'
        )
        units = discover_units(tmp_path)
        assert len(units) == 1
        assert units[0].rel_path == "."