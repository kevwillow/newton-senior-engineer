"""Bootstrap refuses tampered or malicious snapshots: every case ends rc 1, 'nothing installed', installer never ran."""
import subprocess
import zlib
import pytest
from bootstrap_harness import FakeRoot, userns_ok
from bootstrap_repo import make_repo, git, loose_object_path, GIT_ENV

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}


def run_install(tmp_path, repo, cid, typed=None):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(FakeRoot.RUN_THEN_LIST + [boot, "install", "/src", cid], env=ENV,
                          tty_input=(typed if typed is not None else "install " + cid[:12]) + "\n")
    return rc, out, err


def assert_refused(res, text):
    rc, out, err = res
    assert rc == 1, (rc, out, err)
    assert "nothing installed" in err, err
    assert text in err, err
    assert "SNAPSHOT-INSTALLER" not in out
    assert ".newton-bootstrap." not in out


def rewrite_loose(repo, oid, fn):
    p = loose_object_path(repo, oid)
    raw = zlib.decompress(p.read_bytes())
    p.chmod(0o644)
    p.write_bytes(zlib.compress(fn(raw)))


def raw_tree(entries):
    return b"".join(m.encode() + b" " + n + b"\0" + bytes.fromhex(o) for m, n, o in entries)


def put(repo, kind, data):
    r = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--literally", "-t", kind, "--stdin"],
                       input=data, capture_output=True, check=True, env=GIT_ENV)
    return r.stdout.decode().strip()


def commit_of(repo, tree_oid):
    return git(repo, "commit-tree", tree_oid, "-m", "crafted")


def test_tampered_commit_object(tmp_path):
    repo = tmp_path / "stage" / "src"
    cid, _ = make_repo(repo)
    rewrite_loose(repo, cid, lambda raw: raw.replace(b"fixture commit", b"evil  commit"))
    assert_refused(run_install(tmp_path, repo, cid), "commit object does not match its id")


def test_tampered_blob_in_tree(tmp_path):
    repo = tmp_path / "stage" / "src"
    cid, _ = make_repo(repo)
    boot_blob = git(repo, "rev-parse", "HEAD:scripts/newton-bootstrap")
    rewrite_loose(repo, boot_blob, lambda raw: raw.replace(b"fixture", b"EVIL!!!"))
    assert_refused(run_install(tmp_path, repo, cid), "do not match tree")


def test_tampered_tree_object_swaps_a_blob(tmp_path):
    repo = tmp_path / "stage" / "src"
    cid, _ = make_repo(repo)
    boot_blob = git(repo, "rev-parse", "HEAD:scripts/newton-bootstrap")
    readme_blob = git(repo, "rev-parse", "HEAD:README")
    scripts_tree = git(repo, "rev-parse", "HEAD:scripts")
    rewrite_loose(repo, scripts_tree,
                  lambda raw: raw.replace(bytes.fromhex(boot_blob), bytes.fromhex(readme_blob)))
    assert_refused(run_install(tmp_path, repo, cid), "do not match tree")


def test_unknown_commit(tmp_path):
    repo = tmp_path / "stage" / "src"
    make_repo(repo)
    assert_refused(run_install(tmp_path, repo, "0" * 40), "not found")
    blob_id = git(repo, "rev-parse", "HEAD:README")
    rc, out, err = run_install(tmp_path, repo, blob_id)
    assert rc == 1, (rc, out, err)
    assert "nothing installed" in err, err
    assert "SNAPSHOT-INSTALLER" not in out
    assert ".newton-bootstrap." not in out


@pytest.mark.parametrize("case_id, primary, alt", [
    ("symlink", "non-regular", None),
    ("dotdot", "escapes", "git archive failed"),
    ("dot-git-file", ".git", "git archive failed"),
    ("dot-git-dir", ".git", "git archive failed"),
    ("gitattributes", ".gitattributes", None),
    ("gitlink", None, None),
    ("duplicate-name", None, None),
])
def test_malicious_crafted_tree(tmp_path, case_id, primary, alt):
    repo = tmp_path / "stage" / "src"
    make_repo(repo)
    b = put(repo, "blob", b"x\n")
    ib = git(repo, "rev-parse", "HEAD:scripts/newton-install")
    bb = git(repo, "rev-parse", "HEAD:scripts/newton-bootstrap")
    scripts_entries = sorted(
        [("100755", b"newton-install", ib), ("100644", b"newton-bootstrap", bb)],
        key=lambda e: e[1],
    )
    st = put(repo, "tree", raw_tree(scripts_entries))

    if case_id == "symlink":
        link_blob = put(repo, "blob", b"/etc/passwd")
        extra = [("120000", b"link", link_blob)]
    elif case_id == "dotdot":
        extra = [("100644", b"..", b)]
    elif case_id == "dot-git-file":
        extra = [("100644", b".git", b)]
    elif case_id == "dot-git-dir":
        cfg_tree = put(repo, "tree", raw_tree([("100644", b"config", b)]))
        extra = [("40000", b".git", cfg_tree)]
    elif case_id == "gitattributes":
        extra = [("100644", b".gitattributes", b)]
    elif case_id == "gitlink":
        extra = [("160000", b"sub", "1" * 40)]
    elif case_id == "duplicate-name":
        y = put(repo, "blob", b"y\n")
        extra = [("100644", b"dup", b), ("100644", b"dup", y)]

    sorted_entries = sorted(
        [("40000", b"scripts", st)] + extra,
        key=lambda e: e[1],
    )
    root_bytes = raw_tree(sorted_entries)
    root_oid = put(repo, "tree", root_bytes)
    cid = commit_of(repo, root_oid)

    rc, out, err = run_install(tmp_path, repo, cid)
    assert rc == 1, (case_id, rc, out, err)
    assert "nothing installed" in err, (case_id, err)
    assert "SNAPSHOT-INSTALLER" not in out, (case_id, out)
    assert ".newton-bootstrap." not in out, (case_id, out)

    if primary is not None:
        ok = primary in err or (alt is not None and alt in err)
        assert ok, (case_id, err)


def test_good_crafted_tree_control(tmp_path):
    repo = tmp_path / "stage" / "src"
    make_repo(repo)
    ib = git(repo, "rev-parse", "HEAD:scripts/newton-install")
    bb = git(repo, "rev-parse", "HEAD:scripts/newton-bootstrap")
    scripts_entries = sorted(
        [("100755", b"newton-install", ib), ("100644", b"newton-bootstrap", bb)],
        key=lambda e: e[1],
    )
    st = put(repo, "tree", raw_tree(scripts_entries))
    root_oid = put(repo, "tree", raw_tree(sorted([("40000", b"scripts", st)], key=lambda e: e[1])))
    cid = commit_of(repo, root_oid)
    rc, out, err = run_install(tmp_path, repo, cid)
    assert rc == 0, (rc, out, err)
    assert "SNAPSHOT-INSTALLER" in out