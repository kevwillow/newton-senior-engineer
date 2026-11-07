"""Locating ``profiles/openwrt/manifest.toml`` for an installed (non-editable)
``newton-mcp`` package.

The installed mode bug: ``probes.manifest_path()`` used to return
``Path(__file__).resolve().parents[2] / "profiles/openwrt/manifest.toml"``.
Inside an installed venv that resolves to a path that does not exist
(``/opt/newton/venv/lib/python3.12/profiles/...``) because the profile
tree lives next to ``scripts/`` at the install root, not under site-packages.
The launcher sets ``NEWTON_HOME`` to the install root, so we follow the
``server.script_path()`` pattern (server.py:173-178) and look there first.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import newton_mcp.probes as probes
import newton_mcp.tiers as tiers


REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_PROFILES = REPO_ROOT / "profiles" / "openwrt"


@pytest.fixture
def populated_home(tmp_path, monkeypatch):
    """A tmp dir that looks like ``NEWTON_HOME`` -- has a populated
    ``profiles/openwrt/`` with a manifest AND the three tier files, copied
    from the real ones in this repo.  Returns the path to the home dir."""
    home = tmp_path / "home"
    profiles_dir = home / "profiles" / "openwrt"
    profiles_dir.mkdir(parents=True)
    for name in ("manifest.toml", "standard.uci", "hardened.uci", "lockdown.uci", "intents.toml"):
        shutil.copy(REPO_PROFILES / name, profiles_dir / name)
    return home


def test_manifest_path_uses_newton_home_when_set(populated_home, monkeypatch):
    monkeypatch.delenv("NEWTON_MANIFEST", raising=False)
    monkeypatch.setenv("NEWTON_HOME", str(populated_home))
    assert probes.manifest_path() == populated_home / "profiles" / "openwrt" / "manifest.toml"


def test_newton_manifest_override_wins_over_newton_home(populated_home, monkeypatch, tmp_path):
    own_manifest = tmp_path / "my-manifest.toml"
    own_manifest.write_text("[[control]]\nid = 'X-1'\n")
    monkeypatch.setenv("NEWTON_MANIFEST", str(own_manifest))
    monkeypatch.setenv("NEWTON_HOME", str(populated_home))
    assert probes.manifest_path() == own_manifest


def test_manifest_path_without_newton_home_returns_the_package_relative_path(monkeypatch):
    monkeypatch.delenv("NEWTON_MANIFEST", raising=False)
    monkeypatch.delenv("NEWTON_HOME", raising=False)
    assert probes.manifest_path() == REPO_PROFILES / "manifest.toml"


def test_tier_loader_finds_uci_files_under_newton_home(populated_home, monkeypatch):
    """``tiers.split_tier`` resolves the .uci path via
    ``Path(probes.manifest_path()).parent`` -- so when ``NEWTON_HOME``
    moves the manifest it moves the tier files too.  Smoke-test that
    one active block in the real standard tier resolves end-to-end
    from the home-populated tree."""
    monkeypatch.delenv("NEWTON_MANIFEST", raising=False)
    monkeypatch.setenv("NEWTON_HOME", str(populated_home))
    info = tiers.split_tier("standard")
    # One of the standard tier's known blocks is wired to the manifest
    # and must therefore make it into the batches (not ``skipped``).
    assert info["batches"], "no batches were produced for the standard tier"
    assert all(b["probe_lines"] >= 1 for b in info["batches"])
