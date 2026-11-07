"""newton-install --from-snapshot and the bootstrap installation."""
import os
import re
import shutil
import subprocess
from pathlib import Path
import pytest
from bootstrap_harness import FakeRoot, userns_ok

REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "newton-install"
ENV = {"SUDO_USER": "ci-test"}
needs_ns = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")


@pytest.fixture
def fr(tmp_path):
    return FakeRoot(tmp_path)


def required_paths():
    """(kind, path) rows from the installer's own required_snapshot_paths function."""
    r = subprocess.run(
        ["bash", "-c", f"source {INSTALL}; required_snapshot_paths"],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin"}, check=True,
    )
    return [tuple(line.split(" ", 1)) for line in r.stdout.splitlines() if line]


def make_snap(dst: Path, skip=None):
    """A snapshot directory with placeholder files for every required path and the REAL installer script.

    `skip` removes the matching required entry (file or directory). Files
    under a skipped directory are also skipped, and the real installer is
    NOT copied when `skip` removes its parent `scripts/` directory.
    The destination root is chmod 0755 so it passes the installer's
    `require_root_owned_chain` (the test runner's umask 0002 would
    otherwise leave it group-writable).
    """
    skipped_dirs = set()
    for kind, rel in required_paths():
        if rel == skip:
            if kind == "d":
                skipped_dirs.add(rel)
            continue
        p = dst / rel
        if kind == "d":
            p.mkdir(parents=True, exist_ok=True)
        else:
            parts = Path(rel).parent.parts
            if any(part in skipped_dirs for part in parts):
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# placeholder for %s\n" % rel)
    if skip != "scripts/newton-install" and "scripts" not in skipped_dirs:
        installer = dst / "scripts/newton-install"
        installer.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(INSTALL, installer)
    dst.chmod(0o755)
    return dst


def snap_run(fr, dirpath="/snap", pre="", env=None, installer="/snap/scripts/newton-install"):
    """Run run_from_snapshot_mode inside the fake root with check_root_programs stubbed.

    `pre` is shell run before the `source` line -- used to e.g. chmod a
    directory inside the namespace before the chain check sees it.
    `installer` is the path (inside the namespace) to source; default is
    `<dirpath>/scripts/newton-install` -- callers with non-default
    snapshot roots may override.
    """
    body = (
        f"{pre}"
        f"source {installer}; "
        f"check_root_programs() {{ :; }}; "
        f"run_from_snapshot_mode {dirpath}"
    )
    return fr.run(["bash", "-c", body], env=env or ENV)


# ---------------------------------------------------------------------------
# 1. usage
# ---------------------------------------------------------------------------

@needs_ns
def test_usage(fr):
    make_snap(fr.stage / "snap")
    rc1, _, err1 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot"], env=ENV,
    )
    assert rc1 == 2, err1
    assert "usage:" in err1

    rc2, _, err2 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "a", "b"], env=ENV,
    )
    assert rc2 == 2, err2
    assert "usage:" in err2

    rc3, _, err3 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--bogus"], env=ENV,
    )
    assert rc3 == 2, err3
    assert "usage:" in err3

    header = INSTALL.read_text()
    assert "--from-snapshot" in header
    assert re.search(r"first install", header, re.IGNORECASE), \
        "header comment must mention 'first install'"


# ---------------------------------------------------------------------------
# 2. non-root refused
# ---------------------------------------------------------------------------

@needs_ns
def test_not_root_is_refused(fr):
    rc, out, err = fr.run_nonroot(
        ["bash", str(INSTALL), "--from-snapshot", "/x"], env=ENV,
    )
    assert rc == 1, err
    assert "must run as root" in err


# ---------------------------------------------------------------------------
# 3. dirty env refused
# ---------------------------------------------------------------------------

@needs_ns
def test_dirty_env_is_refused(fr):
    make_snap(fr.stage / "snap")
    rc1, _, err1 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "/snap"],
        env={**ENV, "FOO": "1"},
    )
    assert rc1 == 1, err1
    assert "unexpected variable FOO" in err1

    rc2, _, err2 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "/snap"],
        env={**ENV, "LD_PRELOAD": "/x"},
    )
    assert rc2 == 1, err2
    assert "unexpected variable" in err2

    rc3, _, err3 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "/snap"],
        env={**ENV, "BASH_ENV": "/x"},
    )
    assert rc3 == 1, err3
    assert "unexpected variable" in err3


# ---------------------------------------------------------------------------
# 4. relative dir
# ---------------------------------------------------------------------------

@needs_ns
def test_relative_dir_is_refused(fr):
    make_snap(fr.stage / "snap")
    rc, out, err = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "snap"], env=ENV,
    )
    assert rc == 2, err
    assert "absolute" in err


# ---------------------------------------------------------------------------
# 5. combined with --check / NEWTON_INSTALL_ROOT
# ---------------------------------------------------------------------------

@needs_ns
def test_combined_with_check_or_test_seam(fr):
    make_snap(fr.stage / "snap")
    rc1, _, err1 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--check", "--from-snapshot", "/snap"],
        env=ENV,
    )
    assert rc1 == 2, err1
    assert "usage:" in err1

    rc2, _, err2 = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "/snap"],
        env={**ENV, "NEWTON_INSTALL_ROOT": "/tmp/x"},
    )
    assert rc2 == 2, err2
    assert "cannot be used with NEWTON_INSTALL_ROOT" in err2


# ---------------------------------------------------------------------------
# 6. program chain checked
# ---------------------------------------------------------------------------

@needs_ns
def test_program_chain_is_checked(fr):
    make_snap(fr.stage / "snap")
    rc, out, err = fr.run(
        ["bash", "/snap/scripts/newton-install", "--from-snapshot", "/snap"], env=ENV,
    )
    assert rc != 0
    assert "refusing to run it as root" in err


# ---------------------------------------------------------------------------
# 7a. dir not root owned
# ---------------------------------------------------------------------------

@needs_ns
def test_dir_not_root_owned(fr):
    snap = make_snap(fr.stage / "snap")
    abs_snap = str(snap.resolve())
    rc, out, err = fr.run_plain(
        ["bash", str(INSTALL), "--from-snapshot", abs_snap], env=ENV,
    )
    assert rc != 0
    assert "refusing to run it as root" in err


# ---------------------------------------------------------------------------
# 7b. dir writable by others
# ---------------------------------------------------------------------------

@needs_ns
def test_dir_writable_by_others(fr):
    make_snap(fr.stage / "snap")
    rc, out, err = snap_run(fr, "/snap", pre="chmod 777 /snap; ")
    assert rc != 0
    assert "writable by group or other" in err


@needs_ns
def test_parent_dir_writable_by_others(fr):
    make_snap(fr.stage / "outer" / "snap")
    rc, out, err = snap_run(
        fr, "/outer/snap", pre="chmod 777 /outer; ",
        installer="/outer/snap/scripts/newton-install",
    )
    assert rc != 0
    assert "writable by group or other" in err


# ---------------------------------------------------------------------------
# 7c. symlink inside snapshot
# ---------------------------------------------------------------------------

@needs_ns
def test_symlink_inside_snapshot(fr):
    snap = make_snap(fr.stage / "snap")
    link = snap / "link"
    if link.exists() or link.is_symlink():
        link.unlink()
    os.symlink("x", str(link))
    rc, out, err = snap_run(fr, "/snap")
    assert rc != 0
    assert "symlink or non-regular" in err


# ---------------------------------------------------------------------------
# 7d. missing required file/dir
# ---------------------------------------------------------------------------

@needs_ns
@pytest.mark.parametrize("kind,rel", required_paths())
def test_missing_required_file(fr, kind, rel):
    if rel == "scripts/newton-install":
        pytest.skip("the sourced install script must be present")
    if rel == "scripts":
        # The installer itself lives under scripts/newton-install; we
        # stage a copy at a sibling path so we can still source it.
        return _test_missing_required_dir_scripts(fr)
    make_snap(fr.stage / "snap", skip=rel)
    rc, out, err = snap_run(fr, "/snap")
    assert rc != 0, err
    assert "missing required" in err
    assert rel in err


def _test_missing_required_dir_scripts(fr):
    snap = fr.stage / "snap"
    # Create everything else required_snapshot_paths wants, EXCEPT the
    # `scripts` directory. The installer copy cannot live under
    # scripts/, so we drop it at a sibling path.
    make_snap(snap, skip="scripts")
    # Place installer at /snap/_installer.sh so the source can find it.
    shutil.copy2(INSTALL, snap / "_installer.sh")
    snap.chmod(0o755)
    rc, out, err = snap_run(fr, "/snap", installer="/snap/_installer.sh")
    assert rc != 0, err
    assert "missing required" in err
    assert "scripts" in err


# ---------------------------------------------------------------------------
# 7e. installer must live inside snapshot
# ---------------------------------------------------------------------------

@needs_ns
def test_installer_must_live_inside_the_snapshot_dir(fr):
    make_snap(fr.stage / "snap")
    # $0 is bash; the sourced script does NOT live inside /snap, so
    # require_root_owned_chain walks pass; the self_path check trips.
    rc, out, err = snap_run(fr, "/snap")
    assert rc != 0, err
    assert "must be inside --from-snapshot directory" in err
    # positive control: no earlier check tripped
    assert "missing required" not in err
    assert "symlink or non-regular" not in err
    assert "writable by group or other" not in err
