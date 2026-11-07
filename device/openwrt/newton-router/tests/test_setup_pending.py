"""The pending-apply detector of scripts/newton-router-setup.

OpenWrt's undo window is open while the router's snapshot directory
holds an entry: one file per changed config.  An EMPTY directory is
what a refused apply leaves behind, and it stays there for good
(measured on lab-r1).  The directory alone is therefore not a window,
so the no-install setup and the uninstall must not stop on it.

The detector is the host script's own function, run against a fake
router root: the script is sourced (its main is guarded) and the admin
lane is replaced by a local shell.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from conftest import REPO


SETUP = REPO / "scripts/newton-router-setup"


def _detector(root: Path) -> subprocess.CompletedProcess:
    """The setup script's detector, run against a fake router root."""
    body = f"""
set -uo pipefail
source "{SETUP}"
RR="{root}"
rsh_admin() {{ sh -c "$1"; }}
rpcd_apply_pending
"""
    return subprocess.run(
        ["bash", "-c", body], capture_output=True, text=True, timeout=60
    )


def test_a_missing_snapshot_directory_is_not_a_pending_apply(tmp_path: Path) -> None:
    """There is no directory and no window."""
    root = tmp_path / "router"
    (root / "var").mkdir(parents=True)
    result = _detector(root)
    assert result.returncode == 1, result.stderr


def test_an_empty_snapshot_directory_is_not_a_pending_apply(tmp_path: Path) -> None:
    """A refused apply leaves an empty directory behind, forever.

    The directory alone is not an undo window: the detector must say
    that no apply is pending, or the setup and the uninstall would stop
    for good on a router that has nothing pending.
    """
    root = tmp_path / "router"
    (root / "var/run/rpcd/snapshot-files").mkdir(parents=True)
    result = _detector(root)
    assert result.returncode == 1, result.stderr


def test_a_snapshot_directory_with_an_entry_is_a_pending_apply(tmp_path: Path) -> None:
    """A real undo window holds one file per changed config."""
    root = tmp_path / "router"
    snapshot = root / "var/run/rpcd/snapshot-files"
    snapshot.mkdir(parents=True)
    (snapshot / "dhcp").write_text("staged")
    result = _detector(root)
    assert result.returncode == 0, result.stderr


def test_the_detector_prints_the_mtime_of_the_newest_undo_file(
    tmp_path: Path
) -> None:
    """A window that is open says how old the undo file is.

    The mtime is what tells a live window from a leftover one: a
    restart of the router's web service forgets the window but leaves
    the undo file behind for good (measured, a4m-02).
    """
    root = tmp_path / "router"
    snapshot = root / "var/run/rpcd/snapshot-files"
    snapshot.mkdir(parents=True)
    undo = snapshot / "dhcp"
    undo.write_text("staged")
    mtime = int(undo.stat().st_mtime)
    result = _detector(root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(mtime), result.stdout
