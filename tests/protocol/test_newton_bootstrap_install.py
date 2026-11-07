"""Bootstrap install happy-path and refusal tests."""
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

from bootstrap_harness import FakeRoot, userns_ok
from bootstrap_repo import SNAP_STUB, git, make_repo

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}


def go(fr, boot, repo_in_root, cid, typed, extra_env=None):
    """Run `boot install <repo> <cid>` inside the fake root with a typed confirmation.

    The harness's RUN_THEN_LIST appends `ls -A /root` to stdout so we can confirm
    that the bootstrap cleaned up its private work directory before exiting.
    """
    return fr.run(
        FakeRoot.RUN_THEN_LIST + [boot, "install", repo_in_root, cid],
        env={**ENV, **(extra_env or {})},
        tty_input=typed + "\n",
    )


_WORKDIR_RE = re.compile(r"^\.newton-bootstrap\.[A-Za-z0-9]+$")


def _root_leftovers(out):
    """Return any line in `out` that looks like a leftover bootstrap work dir."""
    return [l for l in out.splitlines() if _WORKDIR_RE.match(l)]


def test_good_install_runs_the_snapshot_installer(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, tid = make_repo(fr.stage / "src")
    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 0, (rc, out, err)
    assert "SNAPSHOT-INSTALLER" in out
    assert "Commit:  " + cid in out
    assert "Tree:    " + tid in out
    assert "Author:  Test Author <author@example.test>" in out
    assert "Subject: fixture commit" in out
    expected_sha = hashlib.sha256(SNAP_STUB.encode()).hexdigest()
    assert "sha256 of snap/scripts/newton-install: " + expected_sha in out, out
    assert re.search(r"ARGV:--from-snapshot /root/\.newton-bootstrap\.[A-Za-z0-9]{8}/snap\b", out), out
    assert re.search(r"SELF:/root/\.newton-bootstrap\.[A-Za-z0-9]+/snap/scripts/newton-install\b", out), out
    assert re.search(r"CWD:/root/\.newton-bootstrap\.[A-Za-z0-9]+/empty\b", out), out
    assert "CWD-ENTRIES:0" in out, out

    # ENVNAMES: exactly the env the installer was launched with (PATH/HOME/LANG/SUDO_USER
    # from the bootstrap, plus PWD/SHLVL/_ added by bash). Compare as sets so the
    # trailing space from `tr '\n' ' '` and the `_`-style variants don't matter.
    m = re.search(r"^ENVNAMES:([^\n]+)$", out, re.MULTILINE)
    assert m, out
    got_names = set(m.group(1).split()) - {"_"}
    expected_names = {"HOME", "LANG", "PATH", "PWD", "SHLVL", "SUDO_USER"}
    assert got_names == expected_names, (got_names, expected_names)

    assert "SUDO_USER:ci-test" in out, out
    assert not _root_leftovers(out), out


def test_working_tree_installer_is_not_run(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    installer_with_ls = SNAP_STUB + "ls $(dirname $0)\n"
    cid, _ = make_repo(fr.stage / "src", installer=installer_with_ls)
    wt = fr.stage / "src" / "scripts" / "newton-install"
    wt.write_text("#!/bin/bash\necho WORKTREE-INSTALLER-RAN\n")
    os.chmod(wt, 0o755)
    (fr.stage / "src" / "scripts" / "evil.sh").write_text("#!/bin/bash\necho EVIL\n")
    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 0, (rc, out, err)
    assert "SNAPSHOT-INSTALLER" in out
    assert "WORKTREE-INSTALLER-RAN" not in out
    assert "evil.sh" not in out
    assert not _root_leftovers(out), out


def test_wrong_confirmation_installs_nothing(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")
    cases = [
        "install " + cid[:11],
        "install " + cid,
        "",
        "yes",
    ]
    for typed in cases:
        rc, out, err = go(fr, boot, "/src", cid, typed)
        assert rc == 1, (typed, rc, out, err)
        assert "confirmation did not match" in err, (typed, err)
        assert "SNAPSHOT-INSTALLER" not in out, (typed, out)
        assert not _root_leftovers(out), (typed, out)


@pytest.mark.parametrize("cid", ["0" * 40, "ab" * 20])
def test_unknown_commit_id(tmp_path, cid):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    make_repo(fr.stage / "src")
    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 1, (rc, out, err)
    assert "nothing installed" in err, err
    assert "SNAPSHOT-INSTALLER" not in out, out
    assert not _root_leftovers(out), out


def test_tree_id_given_as_commit_id_is_refused(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    _, tid = make_repo(fr.stage / "src")
    rc, out, err = go(fr, boot, "/src", tid, "install " + tid[:12])
    assert rc == 1, (rc, out, err)
    assert "nothing installed" in err, err
    assert "SNAPSHOT-INSTALLER" not in out, out
    assert not _root_leftovers(out), out


def test_installer_exit_status_is_propagated(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    installer_exit_7 = SNAP_STUB.replace("${STUB_EXIT:-0}", "7")
    cid, _ = make_repo(fr.stage / "src", installer=installer_exit_7)
    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 7, (rc, out, err)
    assert not _root_leftovers(out), out


def test_hostile_repo_config_is_not_honoured(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")
    cfg = fr.stage / "src" / ".git" / "config"
    cfg.write_text(cfg.read_text() + (
        "[core]\n"
        "\tfsmonitor = touch /fsmonitor_ran\n"
        "\thooksPath = /hooks\n"
        "\tattributesFile = /attrs\n"
        "[filter \"x\"]\n"
        "\tclean = touch /filter_ran\n"
        "\tsmudge = touch /filter_ran\n"
        "[uploadpack]\n"
        "\tpackObjectsHook = touch /hook_ran\n"
        "[include]\n"
        "\tpath = /evil.cfg\n"
    ))
    (fr.stage / "src" / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (fr.stage / "src" / ".git" / "info" / "attributes").write_text("* filter=x\n")
    hook = fr.stage / "src" / ".git" / "hooks" / "post-checkout"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/bash\ntouch /hook_ran\n")
    os.chmod(hook, 0o755)

    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 0, (rc, out, err)
    assert "SNAPSHOT-INSTALLER" in out, out
    assert not _root_leftovers(out), out

    # Same namespace, separate command: re-run the bootstrap and check that none of
    # the touch files were created. Each fr.run is a fresh tmpfs root, so this
    # only catches touches triggered by *this* run.
    rc2, out2, err2 = fr.run(
        ["bash", "-c",
         f"{boot} install /src {cid}; echo rc=$?; "
         "ls /fsmonitor_ran /filter_ran /hook_ran 2>&1"],
        env=ENV,
        tty_input="install " + cid[:12] + "\n",
    )
    assert "rc=0" in out2, out2
    assert out2.count("No such file") == 3, out2


def test_packed_repo_works(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")
    repo = fr.stage / "src"
    git(repo, "gc", "-q", "--aggressive")
    git(repo, "repack", "-ad")
    loose = [p for p in repo.glob(".git/objects/[0-9a-f][0-9a-f]/*") if p.is_file()]
    assert not loose, (loose,)

    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 0, (rc, out, err)
    assert "SNAPSHOT-INSTALLER" in out, out
    assert not _root_leftovers(out), out


def test_bare_repo_install_works(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")
    subprocess.run(
        ["git", "clone", "-q", "--bare",
         str(fr.stage / "src"), str(fr.stage / "bare.git")],
        check=True,
    )
    rc, out, err = go(fr, boot, "/bare.git", cid, "install " + cid[:12])
    assert rc == 0, (rc, out, err)
    assert "SNAPSHOT-INSTALLER" in out, out
    assert not _root_leftovers(out), out


def test_identity_block_escapes_non_ascii_bidi_and_zero_width_l1(tmp_path):
    """L-1: sanitize_text must escape every byte outside 0x20-0x7e.

    Under LANG=C.UTF-8, the [:print:] class in the old code treated U+202E
    (RIGHT-TO-LEFT OVERRIDE) and U+200B (ZERO WIDTH SPACE) as printable, so
    the commit author/subject that contained them was rendered raw in the
    identity block. The fix escapes every byte outside 0x20-0x7e as \\xNN.
    """
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    cid, _ = make_repo(fr.stage / "src")
    # U+202E (RIGHT-TO-LEFT OVERRIDE) and U+200B (ZERO WIDTH SPACE) in UTF-8 are
    # E2 80 AE and E2 80 8B respectively. Plant them in both the author name
    # and the commit subject so the identity block exercises them twice.
    author = "Eve\u202eRoot\u200bX"
    subject = "subj\u202eect\u200b"
    # --reset-author is needed so GIT_AUTHOR_NAME actually takes effect on --amend.
    git(fr.stage / "src", "commit", "--amend", "-q", "--allow-empty",
        "--reset-author", "-m", subject,
        env={"GIT_AUTHOR_NAME": author, "GIT_COMMITTER_NAME": author})
    cid = git(fr.stage / "src", "rev-parse", "HEAD")
    rc, out, err = go(fr, boot, "/src", cid, "install " + cid[:12])
    assert rc == 0, (rc, out, err)

    # The escaped sequences must appear as literal backslash-x text in stdout.
    assert "\\xe2\\x80\\xae" in out, out
    assert "\\xe2\\x80\\x8b" in out, out

    # The raw UTF-8 characters themselves must not appear anywhere in the output.
    assert "\u202e" not in out, out
    assert "\u200b" not in out, out

    # The identity lines must contain no byte above 0x7e.
    identity_lines = [
        l for l in out.splitlines()
        if l.startswith("Commit:") or l.startswith("Tree:")
        or l.startswith("Author:") or l.startswith("Date:")
        or l.startswith("Subject:")
    ]
    assert identity_lines, out
    for line in identity_lines:
        assert all(b <= 0x7e for b in line.encode()), (line, line.encode())