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


def required_paths():
    """(kind, path) rows from the installer's own required_snapshot_paths function."""
    r = subprocess.run(
        ["bash", "-c", f"source {INSTALL}; required_snapshot_paths"],
        capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin"}, check=True,
    )
    return [tuple(line.split(" ", 1)) for line in r.stdout.splitlines() if line]


def make_snap(dst: Path, skip=None):
    """A snapshot directory with placeholder files for every required path and the REAL installer script."""
    for kind, rel in required_paths():
        if rel == skip:
            continue
        p = dst / rel
        if kind == "d":
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# placeholder for %s\n" % rel)
    if skip != "scripts/newton-install":
        shutil.copy2(INSTALL, dst / "scripts/newton-install")
    return dst


def test_install_bootstrap_installs_atomically(tmp_path):
    if not userns_ok():
        pytest.skip("unshare -Ur unavailable")
    snap = make_snap(tmp_path / "snap")
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    snap_src = snap / "scripts" / "newton-bootstrap"
    snap_src.write_text("#!/bin/bash\n# boot\n")
    commit = "0123456789abcdef0123456789abcdef01234567"

    def run_install_bootstrap() -> subprocess.CompletedProcess:
        script = (
            f"source {INSTALL}; "
            f"BOOTSTRAP_DEST={sbin}/newton-bootstrap "
            f"BOOTSTRAP_SOURCE={sbin}/newton-bootstrap.source "
            f"SNAP={snap} "
            f"COMMIT_ID={commit} "
            f"install_bootstrap"
        )
        return subprocess.run(
            ["unshare", "-Ur", "bash", "-c", script],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
        )

    r = run_install_bootstrap()
    assert r.returncode == 0, (r.stdout, r.stderr)

    dest = sbin / "newton-bootstrap"
    src = sbin / "newton-bootstrap.source"
    assert dest.exists()
    assert oct(dest.stat().st_mode & 0o777) == "0o755"
    assert dest.read_text() == snap_src.read_text()
    assert src.exists()
    assert oct(src.stat().st_mode & 0o777) == "0o644"
    import hashlib
    assert src.read_text() == f"commit {commit}\nsha256 {hashlib.sha256(dest.read_bytes()).hexdigest()}\n"
    leftovers = list(sbin.glob("*.new.*"))
    assert leftovers == [], f"unexpected leftovers: {leftovers}"

    snap_src.write_text("#!/bin/bash\n# boot changed\n")
    r = run_install_bootstrap()
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert dest.read_text() == snap_src.read_text()
    leftovers = list(sbin.glob("*.new.*"))
    assert leftovers == [], f"unexpected leftovers on rerun: {leftovers}"


def test_plain_mode_refuses_when_the_bootstrap_exists():
    text = INSTALL.read_text()
    main_match = re.search(r"^main\(\) \{", text, re.MULTILINE)
    assert main_match is not None, "main() { not defined in installer"
    main_idx = main_match.start()
    plain = text[main_idx:]
    e_check = plain.find("-e $BOOTSTRAP_DEST")
    assert e_check >= 0, "BOOTSTRAP_DEST existence check (-e $BOOTSTRAP_DEST) not found in main()"
    after_check = re.search(r"^\tperform_install$", plain[e_check:], re.MULTILINE)
    assert after_check is not None, "perform_install call not found after BOOTSTRAP_DEST check in main()"
    perform_pos = e_check + after_check.start()
    assert e_check < perform_pos, (
        "-e $BOOTSTRAP_DEST existence check must come before perform_install in the plain path"
    )
    snippet = plain[e_check:e_check + 800]
    assert re.search(r"newton-bootstrap install", snippet), (
        "refusal near BOOTSTRAP_DEST check must mention 'newton-bootstrap install'"
    )


def test_check_preview_lists_the_bootstrap(tmp_path):
    root = tmp_path / "root"
    env = os.environ.copy()
    env.pop("NEWTON_INSTALL_ROOT", None)
    env.pop("SUDO_USER", None)
    env["NEWTON_INSTALL_ROOT"] = str(root)
    env["SUDO_USER"] = "agent"
    r = subprocess.run(
        ["bash", str(INSTALL), "--check"],
        capture_output=True, text=True, env=env, cwd=str(REPO),
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    out = r.stdout + ("\n" + r.stderr if r.stderr else "")
    assert "Would install: /usr/local/sbin/newton-bootstrap (root:root 0755)" in out, out
    assert "newton-bootstrap.source" in out, out
