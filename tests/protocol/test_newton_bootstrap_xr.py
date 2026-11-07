"""Cross-family review findings X-1..X-5."""
import hashlib
import os
import subprocess
from pathlib import Path
import pytest
from bootstrap_harness import FakeRoot, SCRIPT, userns_ok
from bootstrap_repo import make_repo
from test_newton_install_from_snapshot import make_snap

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}
REPO = Path(__file__).resolve().parents[2]
INSTALL = REPO / "scripts" / "newton-install"


def test_from_snapshot_refuses_world_writable_entries_inside(tmp_path):
    fr = FakeRoot(tmp_path)
    make_snap(fr.stage / "snap")
    boot = fr.install_bootstrap()

    body_a = (
        "chmod 666 /snap/SKILL.md; "
        "source /snap/scripts/newton-install; "
        "check_root_programs() { :; }; "
        "run_from_snapshot_mode /snap"
    )
    rc_a, _, err_a = fr.run(["bash", "-c", body_a], env=ENV)
    assert rc_a != 0
    assert "writable by others" in err_a

    body_b = (
        "chmod 777 /snap/mcp; "
        "source /snap/scripts/newton-install; "
        "check_root_programs() { :; }; "
        "run_from_snapshot_mode /snap"
    )
    rc_b, _, err_b = fr.run(["bash", "-c", body_b], env=ENV)
    assert rc_b != 0
    assert "writable by others" in err_b

    body_c = (
        "chmod 775 /snap/mcp; "
        "source /snap/scripts/newton-install; "
        "check_root_programs() { :; }; "
        "run_from_snapshot_mode /snap"
    )
    rc_c, out_c, err_c = fr.run(["bash", "-c", body_c], env=ENV)
    combined = out_c + err_c
    assert "must be inside --from-snapshot directory" in combined


def test_selfupdate_provenance_failure_is_reported_truthfully(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src", files={"scripts/newton-bootstrap": SCRIPT.read_text() + "# v2\n"})

    bind_cmd = (
        "cp /usr/bin/mv /tmp/mv.real; "
        "printf '#!/bin/sh\\nfor a; do l=$a; done\\ncase $l in *.source) exit 1;; esac\\nexec /tmp/mv.real \"$@\"\\n' > /tmp/fake-mv; "
        "chmod 755 /tmp/fake-mv; "
        "mount --bind /tmp/fake-mv /usr/bin/mv"
    )

    cmd = (
        f"{bind_cmd}; "
        f"{boot} self-update /src {cid}; echo rc=$?; "
        f"{boot} version"
    )
    typed = "update " + cid[:12]
    rc, out, err = fr.run(["bash", "-c", cmd], env=ENV, tty_input=typed + "\n")

    assert "rc=1" in out
    assert "nothing installed" not in err
    assert "provenance" in err
    assert "WARNING" in out


def test_version_warns_when_recorded_hash_differs(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    correct_hash = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()

    source_path = fr.stage / "usr" / "local" / "sbin" / "newton-bootstrap.source"
    source_path.parent.mkdir(parents=True, exist_ok=True)

    source_path.write_text(f"commit {'ab' * 20}\nsha256 {'0' * 64}\n")
    rc1, out1, err1 = fr.run(["bash", "-c", f"{boot} version"], env=ENV)
    combined1 = out1 + err1
    assert "WARNING" in combined1
    assert "provenance" in combined1

    source_path.write_text(f"commit {'ab' * 20}\nsha256 {correct_hash}\n")
    rc2, out2, err2 = fr.run(["bash", "-c", f"{boot} version"], env=ENV)
    combined2 = out2 + err2
    assert "WARNING" not in combined2

    source_path.write_text(f"commit {'ab' * 20}\n")
    rc3, out3, err3 = fr.run(["bash", "-c", f"{boot} version"], env=ENV)
    combined3 = out3 + err3
    assert "WARNING" not in combined3


def test_snapshot_listing_failure_is_fatal(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")

    bind_cmd = (
        "printf '#!/bin/sh\\nexit 1\\n' > /tmp/fake-sort; "
        "chmod 755 /tmp/fake-sort; "
        "mount --bind /tmp/fake-sort /usr/bin/sort"
    )

    cmd = f"{bind_cmd}; {boot} install /src {cid}; echo rc=$?"
    typed = "install " + cid[:12]
    rc, out, err = fr.run(["bash", "-c", cmd], env=ENV, tty_input=typed + "\n")

    assert "rc=1" in out, (out, err)  # rc of the bootstrap itself (bash -c reports the echo)
    assert "SNAPSHOT-INSTALLER" not in out


def test_marker_pass_requires_the_fixed_path_and_home(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()

    env1 = {**ENV, "_NEWTON_BOOTSTRAP_CLEAN": "1", "PATH": "/snap/bin:/usr/bin:/bin"}
    rc1, _, err1 = fr.run(["bash", "-c", f"{boot} version"], env=env1)
    assert rc1 == 1
    assert "PATH" in err1

    env2 = {**ENV, "_NEWTON_BOOTSTRAP_CLEAN": "1", "HOME": "/home/x"}
    rc2, _, err2 = fr.run(["bash", "-c", f"{boot} version"], env=env2)
    assert rc2 == 1
    assert "HOME" in err2

    env3 = {
        **ENV,
        "_NEWTON_BOOTSTRAP_CLEAN": "1",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
    }
    rc3, _, _ = fr.run(["bash", "-c", f"{boot} version"], env=env3)
    assert rc3 == 0


@pytest.mark.parametrize("x", ["ALL", "FOO_BAR", "A1"])
def test_sudoers_keyword_user_is_refused(tmp_path, x):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, _, err = fr.run(["bash", "-c", f"{boot} version"], env={"SUDO_USER": x})
    assert rc == 1
    assert "SUDO_USER" in err


def test_sudoers_keyword_user_install_refused(tmp_path):
    result = subprocess.run(
        [str(INSTALL), "--check"],
        env={
            "SUDO_USER": "ALL",
            "NEWTON_INSTALL_ROOT": str(tmp_path / "root"),
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "LANG": "C.UTF-8",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert "SUDO_USER must name" in result.stderr


def test_sudoers_keyword_lowercase_passes(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, _, _ = fr.run(["bash", "-c", f"{boot} version"], env={"SUDO_USER": "alice"})
    assert rc == 0