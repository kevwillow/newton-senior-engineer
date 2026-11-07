"""The post-restore file fingerprint (PHYSICAL_FINGERPRINT_CMD +
archive_fingerprint) covers every path it claims to, but nothing else: a
leftover from a scenario that landed somewhere unexpected, or a file in the
covered set that a scenario changed, must shift the digest; an extra file
elsewhere, approve.key, or the guard's lock file, must not.

We reproduce the body of the command with `sh -c \"cd <tmp> && \" +
PHYSICAL_FINGERPRINT_BODY` (argv list, never shell=True with interpolation)
and compare it against `archive_fingerprint` on the same archive, so a real
busybox ash or a real sh, whichever is /bin/sh, can run it as-is. No router,
no ssh, no PVE."""
from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
from pathlib import Path

import newton_lab_test as nl


SH = "/bin/sh"
ARCHIVE_PATH = "/tmp/newton-baseline.tar.gz"


def _cp(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr)


BASELINE = {
    "etc/config/network": b"config interface 'lan'\n",
    "etc/config/system": b"config system\n",
    "etc/config/firewall": b"config defaults\n",
    "etc/config/dropbear": b"config dropbear\n",
    "etc/dropbear/authorized_keys": b"ssh-ed25519 AAAA\n",
    "etc/newton/state": b"n1\n",
    "etc/newton/device-id": b"pulsar\n",
    "etc/newton/profile": b"lab\n",
    "etc/passwd": b"root:x:0:0\n",          # not part of the fingerprint
}

# The paths the body reaches through its named loop rather than through
# `find`: any regular file under etc/crontabs and these three top-level files
# (with etc/dropbear/authorized_keys, already in BASELINE). Distinct bytes,
# one per name, so a digest shift can only come from the name moving in or
# out of the archive side.
NAMED = {
    "etc/crontabs/root": b"* * * * * /bin/true\n",
    "etc/firewall.user": b"iptables -t nat -A prerouting_rule -j ACCEPT\n",
    "etc/rc.local": b"exit 0\n",
    "etc/sysupgrade.conf": b"# keep\n",
}


def _make_archive(path: Path, files=None) -> str:
    files = BASELINE if files is None else files
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _extract_archive(archive: Path, dest: Path) -> None:
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf:
            if not m.isreg():
                continue
            target = dest / m.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tf.extractfile(m).read())


def _run_body(tmp: Path) -> str:
    """Run PHYSICAL_FINGERPRINT_BODY inside `tmp` (as the fake root) with an
    argv list, no shell interpolation. Returns the stdout digest."""
    argv = [SH, "-c", f"cd {tmp} && {nl.PHYSICAL_FINGERPRINT_BODY}"]
    res = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, (res.returncode, res.stderr)
    return res.stdout.strip()


def test_body_and_archive_fingerprint_agree_on_a_baseline_tree(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    body = _run_body(tree)
    assert body == nl.archive_fingerprint(str(archive))


def test_body_and_archive_fingerprint_agree_when_the_archive_holds_every_named_file(tmp_path):
    """The agreement test on a baseline tree proves nothing about the paths no
    baseline archive happens to carry. Build one that carries all of them:
    etc/crontabs/root and the three named top-level files. A `_in_fingerprint`
    that forgot one of them (say etc/crontabs/) would drop its line from the
    archive digest while the body still hashes it, and the two must still
    match here."""
    files = dict(BASELINE)
    files.update(NAMED)
    archive = tmp_path / "full.tar.gz"
    _make_archive(archive, files)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    assert _run_body(tree) == nl.archive_fingerprint(str(archive))


def test_a_named_file_missing_from_the_archive_only_splits_the_two_values(tmp_path):
    """The other half of the same gap, from the archive side: the tree keeps
    the file, the archive does not, so the body hashes a line the archive
    digest has not got and the values must differ. Without this, an archive
    that quietly stopped counting a path would still agree with a tree that
    counts it whenever no test archive holds that path."""
    files = dict(BASELINE)
    files.update(NAMED)
    full = tmp_path / "full.tar.gz"
    _make_archive(full, files)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(full, tree)
    body = _run_body(tree)
    assert body == nl.archive_fingerprint(str(full))
    for name in NAMED:
        cut = tmp_path / (name.replace("/", "_") + ".tar.gz")
        _make_archive(cut, {n: d for n, d in files.items() if n != name})
        # The file is still on the tree: only the archive lost it.
        assert (tree / name).is_file(), name
        assert nl.archive_fingerprint(str(cut)) != body, name


def test_extra_file_under_etc_config_breaks_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "config" / "extra").write_bytes(b"x\n")
    assert _run_body(tree) != base


def test_extra_file_under_etc_newton_breaks_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "newton" / "guard.log").write_bytes(b"x\n")
    assert _run_body(tree) != base


def test_firewall_user_leftover_breaks_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "firewall.user").write_bytes(
        "iptables -t nat -A prerouting_rule -j ACCEPT\n".encode())
    assert _run_body(tree) != base


def test_crontabs_root_leftover_breaks_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "crontabs").mkdir(exist_ok=True)
    (tree / "etc" / "crontabs" / "root").write_bytes(b"* * * * * /bin/true\n")
    assert _run_body(tree) != base


def test_changed_rc_local_breaks_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    files = dict(BASELINE)
    files["etc/rc.local"] = b"exit 0\n"
    _make_archive(archive, files)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "rc.local").write_bytes(b"exit 1\n")
    assert _run_body(tree) != base


def test_changed_sysupgrade_conf_breaks_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    files = dict(BASELINE)
    files["etc/sysupgrade.conf"] = b"\n"
    _make_archive(archive, files)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "sysupgrade.conf").write_bytes(b"# keep\n")
    assert _run_body(tree) != base


def test_approve_key_present_does_not_change_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "newton" / "approve.key").write_bytes(b"secret\n")
    assert _run_body(tree) == base


def test_guard_lock_present_does_not_change_the_fingerprint(tmp_path):
    """The 1.1.0 guard holds an empty /etc/newton/guard.lock open for its whole
    life and re-creates it after every restore, so a tree that has it and a
    tree that does not are the same device state. sysupgrade -b never archives
    it (newton-router-setup keeps it out), so the archive side cannot have it
    either: counting it would make every post-restore check fail."""
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    (tree / "etc" / "newton" / "guard.lock").write_bytes(b"")
    assert _run_body(tree) == base
    assert base == nl.archive_fingerprint(str(archive))


def test_another_etc_newton_file_still_breaks_the_fingerprint(tmp_path):
    """The guard.lock exclusion must not widen: any other file a scenario left
    under /etc/newton still has to move the digest, on both sides."""
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    assert base == nl.archive_fingerprint(str(archive))
    (tree / "etc" / "newton" / "last_revert").write_bytes(b"1700000000\n")
    assert _run_body(tree) != base
    files = dict(BASELINE)
    files["etc/newton/last_revert"] = b"1700000000\n"
    other = tmp_path / "other.tar.gz"
    _make_archive(other, files)
    assert nl.archive_fingerprint(str(other)) != base


def test_uncovered_file_does_not_change_the_fingerprint(tmp_path):
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    base = _run_body(tree)
    for path in ("etc/hosts", "tmp/runner.log", "var/log/dnsmasq.log"):
        target = tree / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"x\n")
    assert _run_body(tree) == base


def test_body_runs_on_a_real_shell_not_bash(tmp_path):
    """The body must run on busybox ash (no bashisms). Anything more exotic
    than sh's own syntax fails here before the scenarios do."""
    archive = tmp_path / "base.tar.gz"
    _make_archive(archive)
    tree = tmp_path / "tree"
    tree.mkdir()
    _extract_archive(archive, tree)
    argv = [SH, "-c", f"cd {tree} && {nl.PHYSICAL_FINGERPRINT_BODY}"]
    res = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, (res.returncode, res.stderr)
    assert hashlib.sha256(bytes.fromhex(
        nl.archive_fingerprint(str(archive)))).hexdigest() == (
        hashlib.sha256(bytes.fromhex(res.stdout.strip())).hexdigest())


def test_archive_fingerprint_ignores_approve_key(tmp_path):
    with_key = dict(BASELINE)
    with_key["etc/newton/approve.key"] = b"secret\n"
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    _make_archive(a)
    _make_archive(b, with_key)
    assert nl.archive_fingerprint(str(a)) == nl.archive_fingerprint(str(b))
    assert "approve.key" in nl.PHYSICAL_FINGERPRINT_BODY
    assert "etc/newton" in nl.PHYSICAL_FINGERPRINT_BODY
    assert "etc/crontabs" in nl.PHYSICAL_FINGERPRINT_BODY


def test_archive_fingerprint_ignores_guard_lock(tmp_path):
    """Archive side of the same rule: a baseline archive that somehow carries
    /etc/newton/guard.lock hashes to the same digest as one without it. The
    exclusion is by name, so an empty lock and a lock with bytes in it are both
    out."""
    plain = tmp_path / "a.tar.gz"
    empty = tmp_path / "b.tar.gz"
    written = tmp_path / "c.tar.gz"
    with_empty = dict(BASELINE)
    with_empty["etc/newton/guard.lock"] = b""
    with_written = dict(BASELINE)
    with_written["etc/newton/guard.lock"] = b"lock bytes\n"
    _make_archive(plain)
    _make_archive(empty, with_empty)
    _make_archive(written, with_written)
    want = nl.archive_fingerprint(str(plain))
    assert nl.archive_fingerprint(str(empty)) == want
    assert nl.archive_fingerprint(str(written)) == want
    assert "guard.lock" in nl.PHYSICAL_FINGERPRINT_BODY


def test_in_fingerprint_classifier_matches_the_body():
    pos = [
        "etc/config/network", "etc/newton/state", "etc/newton/profile",
        "etc/crontabs/root",  # any regular file below etc/crontabs
        "etc/dropbear/authorized_keys", "etc/firewall.user", "etc/rc.local",
        "etc/sysupgrade.conf"]
    neg = [
        "etc/newton/approve.key", "etc/newton/guard.lock", "etc/passwd",
        "etc/hosts", "tmp/verify-observer.log", "var/state/dnsmasqsec",
    ]
    for n in pos:
        assert nl._in_fingerprint(n), n
    for n in neg:
        assert not nl._in_fingerprint(n), n
