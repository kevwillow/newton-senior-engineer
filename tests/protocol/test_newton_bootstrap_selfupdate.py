"""newton-bootstrap self-update."""
import hashlib
import pytest

from bootstrap_harness import FakeRoot, SCRIPT, userns_ok
from bootstrap_repo import make_repo

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}
OLD = SCRIPT.read_text()
NEW = OLD + "# self-update test marker v2\n"
INST = "/usr/local/sbin/newton-bootstrap"
SHOW = (
    f"echo rc=$?; sha256sum {INST}; "
    f"stat -c '%a %n' {INST}.prev 2>&1; "
    f"cat {INST}.prev 2>/dev/null | sha256sum; "
    f"cat {INST}.source 2>&1; "
    f"ls -A /usr/local/sbin"
)
PREFIX_6 = (
    "printf '#!/bin/sh\\nkill -9 $PPID\\n' > /tmp/fake-sync && "
    "chmod 755 /tmp/fake-sync && "
    "{ for d in /usr/sbin /usr/bin /sbin /bin; do "
    "if [ -f \"$d/sync\" ]; then mount --bind /tmp/fake-sync \"$d/sync\" || true; fi; "
    "done; } && "
)


def update(tmp_path, new_text=NEW, typed=None, prefix=""):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src", files={"scripts/newton-bootstrap": new_text})
    typed = "update " + cid[:12] if typed is None else typed
    cmd = f"{prefix}{boot} self-update /src {cid}; {SHOW}"
    rc, out, err = fr.run(["bash", "-c", cmd], env=ENV, tty_input=typed + "\n")
    return cid, rc, out, err


def _rc_idx(out_lines, rc_str):
    for i, l in enumerate(out_lines):
        if l == rc_str:
            return i
    raise AssertionError(f"{rc_str!r} not in output lines")


def test_update_shows_the_diff_and_replaces_atomically_with_prev(tmp_path):
    cid, rc, out, err = update(tmp_path)
    h_old = hashlib.sha256(OLD.encode()).hexdigest()
    h_new = hashlib.sha256(NEW.encode()).hexdigest()

    out_lines = out.splitlines()

    assert "rc=0" in out_lines
    assert "+# self-update test marker v2" in out
    assert "--- /usr/local/sbin/newton-bootstrap" in out
    assert "Commit:  " + cid in out
    assert "sha256 installed: " + h_old in out
    assert "sha256 snapshot:  " + h_new in out

    idx = _rc_idx(out_lines, "rc=0")
    assert out_lines[idx + 1] == f"{h_new}  {INST}"

    assert any(l.startswith("644 ") for l in out_lines)
    assert f"{h_old}  -" in out_lines
    assert f"commit {cid}" in out_lines

    assert out_lines[-3:] == [
        "newton-bootstrap",
        "newton-bootstrap.prev",
        "newton-bootstrap.source",
    ]
    assert "newton-bootstrap.new" not in out_lines
    assert "newton-bootstrap.prev.tmp" not in out_lines
    assert "newton-bootstrap.source.new" not in out_lines


@pytest.mark.parametrize(
    "typed",
    [
        "",
        "yes",
        "install " + "0" * 12,
        "update " + "0" * 12,
    ],
)
def test_wrong_confirmation_changes_nothing(tmp_path, typed):
    cid, rc, out, err = update(tmp_path, typed=typed)
    h_old = hashlib.sha256(OLD.encode()).hexdigest()

    out_lines = out.splitlines()
    assert "rc=1" in out_lines
    assert "confirmation did not match" in err
    assert "nothing changed" in err

    idx = _rc_idx(out_lines, "rc=1")
    assert out_lines[idx + 1] == f"{h_old}  {INST}"

    assert "newton-bootstrap" in out_lines
    assert "newton-bootstrap.prev" not in out_lines
    assert "newton-bootstrap.source" not in out_lines
    assert "newton-bootstrap.new" not in out_lines


def test_identical_copy_is_up_to_date(tmp_path):
    cid, rc, out, err = update(tmp_path, new_text=OLD)
    out_lines = out.splitlines()
    assert "rc=0" in out_lines
    assert "already up to date" in out

    assert "newton-bootstrap" in out_lines
    assert "newton-bootstrap.prev" not in out_lines
    assert "newton-bootstrap.source" not in out_lines
    assert "newton-bootstrap.new" not in out_lines


def test_diff_output_is_terminal_safe(tmp_path):
    new_text = OLD + "# esc \x1b]0;pwn\x07 bell\n"
    cid, rc, out, err = update(tmp_path, new_text=new_text, typed="")
    # since round b4 the control bytes are refused before any diff is shown (see ..._selfupdate_review.py)
    assert "\x1b" not in out and "\x1b" not in err
    assert "\x07" not in out and "\x07" not in err
    assert "outside TAB/LF/printable-ASCII" in err


def test_new_script_that_does_not_parse_is_refused_and_old_stays(tmp_path):
    new_text = "#!/bin/bash\nif then fi (\n"
    cid, rc, out, err = update(tmp_path, new_text=new_text)
    h_old = hashlib.sha256(OLD.encode()).hexdigest()

    out_lines = out.splitlines()
    assert "rc=1" in out_lines
    assert "bash -n" in err or "nothing installed" in err

    idx = _rc_idx(out_lines, "rc=1")
    assert out_lines[idx + 1] == f"{h_old}  {INST}"

    assert "newton-bootstrap.prev" not in out_lines
    assert "newton-bootstrap.source" not in out_lines
    assert "newton-bootstrap.new" not in out_lines


def test_crash_between_write_and_rename_leaves_the_old_bootstrap_working(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src", files={"scripts/newton-bootstrap": NEW})
    typed = "update " + cid[:12]
    cmd = f"{PREFIX_6}{boot} self-update /src {cid}; {SHOW}; {INST} version"
    rc, out, err = fr.run(["bash", "-c", cmd], env=ENV, tty_input=typed + "\n")
    h_old = hashlib.sha256(OLD.encode()).hexdigest()

    out_lines = out.splitlines()
    assert "rc=137" in out_lines

    idx = _rc_idx(out_lines, "rc=137")
    assert out_lines[idx + 1] == f"{h_old}  {INST}"

    assert f"sha256 {h_old}" in out_lines

    assert "newton-bootstrap.prev" not in out_lines
    assert "newton-bootstrap.source" not in out_lines


def test_second_update_keeps_the_latest_previous_copy(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid_a, _ = make_repo(fr.stage / "src", files={"scripts/newton-bootstrap": NEW})
    new_b = NEW + "# v3\n"
    cid_b, _ = make_repo(fr.stage / "src2", files={"scripts/newton-bootstrap": new_b})
    typed = f"update {cid_a[:12]}\nupdate {cid_b[:12]}\n"
    cmd = f"{boot} self-update /src {cid_a}; {boot} self-update /src2 {cid_b}; {SHOW}"
    rc, out, err = fr.run(["bash", "-c", cmd], env=ENV, tty_input=typed)

    h_new = hashlib.sha256(NEW.encode()).hexdigest()
    h_b = hashlib.sha256(new_b.encode()).hexdigest()

    out_lines = out.splitlines()
    assert "rc=0" in out_lines

    idx = _rc_idx(out_lines, "rc=0")
    assert out_lines[idx + 1] == f"{h_b}  {INST}"

    assert f"{h_new}  -" in out_lines
    assert f"commit {cid_b}" in out_lines

    assert out_lines[-3:] == [
        "newton-bootstrap",
        "newton-bootstrap.prev",
        "newton-bootstrap.source",
    ]
