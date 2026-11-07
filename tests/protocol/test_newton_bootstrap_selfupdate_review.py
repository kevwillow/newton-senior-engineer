import hashlib
import subprocess

import pytest
from bootstrap_harness import FakeRoot, SCRIPT, userns_ok
from bootstrap_repo import GIT_ENV, make_repo

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}
OLD = SCRIPT.read_text()
INST = "/usr/local/sbin/newton-bootstrap"
SHOW = f"echo rc=$?; sha256sum {INST}; ls -A /usr/local/sbin"


def update(tmp_path, new_bytes, typed_ok=True, prefix=""):
    """Run self-update to a repo whose scripts/newton-bootstrap holds new_bytes (bytes). Returns (cid, rc_of_bootstrap, out, err)."""
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")
    (fr.stage / "src" / "scripts" / "newton-bootstrap").write_bytes(new_bytes)
    subprocess.run(["git", "-C", str(fr.stage / "src"), "add", "-A"], check=True, env=GIT_ENV)
    subprocess.run(["git", "-C", str(fr.stage / "src"), "commit", "-q", "-m", "second"], check=True, env=GIT_ENV)
    cid = subprocess.run(
        ["git", "-C", str(fr.stage / "src"), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        env=GIT_ENV,
    ).stdout.decode().strip()
    cmd = f"{prefix}{boot} self-update /src {cid}; {SHOW}"
    rc, out, err = fr.run(["bash", "-c", cmd], env=ENV, tty_input="update " + cid[:12] + "\n")
    return cid, rc, out, err


def _assert_refused(out, err):
    assert "rc=1" in out, f"expected bootstrap rc=1 in stdout; got:\n{out}"
    assert "nothing installed" in err, f"expected 'nothing installed' in stderr; got:\n{err}"
    old_hash = hashlib.sha256(OLD.encode()).hexdigest()
    line = f"{old_hash}  {INST}"
    assert line in out, f"expected installed sha256 unchanged; got:\n{out}"
    listing = out.strip().splitlines()[-1]
    assert listing == "newton-bootstrap", f"expected only newton-bootstrap in listing; got: {listing!r}"


def test_nul_byte_is_refused(tmp_path):
    new = OLD.encode() + b"# hidden\0 exec /tmp/x\n"
    _, _, out, err = update(tmp_path, new)
    _assert_refused(out, err)
    assert "outside TAB/LF/printable-ASCII" in err
    assert "Binary files" not in out


@pytest.mark.parametrize(
    "bad",
    [
        b"\r",
        b"\x1b[2J",
        b"\x7f",
        "caf\xc3\xa9".encode(),
    ],
)
def test_other_unprintable_bytes_are_refused(tmp_path, bad):
    new = OLD.encode() + b"# " + bad + b"\n"
    _, _, out, err = update(tmp_path, new)
    _assert_refused(out, err)
    assert "outside TAB/LF/printable-ASCII" in err


def test_overlong_line_is_refused(tmp_path):
    new = OLD.encode() + b"# " + (b"x" * 250) + b"\n"
    _, _, out, err = update(tmp_path, new)
    _assert_refused(out, err)
    assert "longer than 200 bytes" in err


def test_huge_diff_is_refused(tmp_path):
    body = "".join(f"echo line {i}\n" for i in range(900))
    new = ("#!/bin/bash\n" + body).encode()
    _, _, out, err = update(tmp_path, new)
    _assert_refused(out, err)
    assert "diff too long to review" in err


def test_ordinary_update_still_passes_the_gates(tmp_path):
    new = OLD.encode() + b"# ok\n"
    _, _, out, err = update(tmp_path, new)
    assert "rc=0" in out, f"expected bootstrap rc=0 in stdout; got:\n{out}"
    new_hash = hashlib.sha256(new).hexdigest()
    line = f"{new_hash}  {INST}"
    assert line in out, f"expected installed sha256 == sha256(new); got:\n{out}"


def test_diff_command_failure_is_not_ignored(tmp_path):
    setup = (
        "printf '#!/bin/sh\\nexit 2\\n' > /tmp/fd && "
        "chmod 755 /tmp/fd && "
        "for d in /usr/bin/diff /bin/diff; do "
        "[ -e \"$d\" ] && mount --bind /tmp/fd \"$d\"; "
        "done && "
    )
    new = OLD.encode() + b"# ok\n"
    _, _, out, err = update(tmp_path, new, prefix=setup)
    assert "rc=1" in out, f"expected bootstrap rc=1 on diff failure; got:\n{out}"
    assert "diff tool failed" in err, f"expected 'diff tool failed' in stderr; got:\n{err}"
    assert "nothing installed" in err
    old_hash = hashlib.sha256(OLD.encode()).hexdigest()
    line = f"{old_hash}  {INST}"
    assert line in out, f"expected installed sha256 unchanged after diff failure; got:\n{out}"
