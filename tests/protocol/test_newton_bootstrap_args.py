"""Bootstrap argument, id, tty and version behaviour."""
import hashlib
import os
import subprocess
import sys

import pytest
from bootstrap_harness import FakeRoot, SCRIPT, userns_ok

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}
GOOD = "a" * 40


@pytest.fixture(autouse=True)
def _coax_umask():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


@pytest.mark.parametrize("args", [[], ["bogus"], ["install"], ["install", "r"], ["install", "r", GOOD, "extra"],
                                   ["self-update", "r"], ["self-update"], ["version", "extra"]])
def test_usage_errors(tmp_path, args):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run([boot, *args], env=ENV)
    assert rc == 2, (rc, out, err)
    assert "usage" in err


@pytest.mark.parametrize("sub", ["install", "self-update"])
@pytest.mark.parametrize("commit_id", [GOOD.upper(), "a" * 39, "a" * 41, "HEAD", "abc; rm -rf /", ""])
def test_bad_ids_are_refused_before_any_work(tmp_path, sub, commit_id):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(FakeRoot.RUN_THEN_LIST + [boot, sub, "/nonexistent", commit_id],
                          env=ENV, tty_input="x\n")
    assert rc == 2, (rc, out, err)
    assert "40 lowercase hex" in err
    assert ".newton-bootstrap." not in out


@pytest.mark.parametrize("sub", ["install", "self-update"])
def test_no_tty_is_refused_before_any_work(tmp_path, sub):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(FakeRoot.RUN_THEN_LIST + [boot, sub, "/nonexistent", GOOD],
                          env=ENV, tty_input=None)
    assert rc == 1, (rc, out, err)
    assert "must be a tty" in err
    assert ".newton-bootstrap." not in out


def test_version_prints_own_hash_and_unknown_commit(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run([boot, "version"], env=ENV)
    lines = out.splitlines()
    assert lines[0] == "sha256 " + hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
    assert lines[1] == "commit unknown"


def test_version_prints_recorded_commit(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    target = fr.stage / "usr/local/sbin/newton-bootstrap.source"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("commit " + "ab" * 20 + "\n")
    rc, out, err = fr.run([boot, "version"], env=ENV)
    lines = out.splitlines()
    assert lines[1] == "commit " + "ab" * 20


def test_repo_problems_are_refused_with_nothing_run(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()

    cases = []

    # 1. does not exist
    cases.append(("missing", "/r1"))

    # 2. exists but empty directory
    (fr.stage / "r2").mkdir()
    cases.append(("empty", "/r2"))

    # 3. .git is a file
    r3 = fr.stage / "r3"
    r3.mkdir()
    (r3 / ".git").write_text("gitdir: /elsewhere\n")
    cases.append(("gitfile", "/r3"))

    # 4. .git is a symlink to a directory
    r4 = fr.stage / "r4"
    r4.mkdir()
    real_git = fr.stage / "r4_real_git"
    real_git.mkdir()
    (r4 / ".git").symlink_to(real_git)
    cases.append(("symlink", "/r4"))

    # 5. directory name with ':'
    p = tmp_path / "a:b"
    subprocess.run(["git", "init", "-q", str(p)], check=True)
    target = fr.stage / "repo-colon"
    dropped = False
    try:
        cdf = subprocess.run(
            ["tar", "-C", str(p.parent), "-cf", "-",
             "--transform", f"s|^{p.name}|{target.name}|", p.name],
            stdout=subprocess.PIPE, check=True
        )
        subprocess.run(
            ["tar", "-C", str(fr.stage), "-xf", "-"],
            input=cdf.stdout, check=True
        )
        cases.append(("colon", "/repo-colon"))
    except (subprocess.CalledProcessError, OSError):
        dropped = True
        cases.append(("colon_dropped", None))

    if dropped:
        print("NOTE: dropped colon-in-name case (tar staging failed)", file=sys.stderr)

    for label, repo_path in cases:
        if label == "colon_dropped":
            continue
        rc, out, err = fr.run(FakeRoot.RUN_THEN_LIST + [boot, "install", repo_path, GOOD],
                              env=ENV, tty_input="install " + GOOD[:12] + "\n")
        assert rc == 1, (label, rc, out, err)
        assert "nothing installed" in err, (label, err)
        assert "Commit:" not in out, (label, out)
