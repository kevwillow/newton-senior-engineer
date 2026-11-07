"""Build throw-away git repositories for the bootstrap tests (host git, run as the test user, no global config)."""
import os
import subprocess
from pathlib import Path

GIT_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Test Author", "GIT_AUTHOR_EMAIL": "author@example.test",
    "GIT_COMMITTER_NAME": "Test Author", "GIT_COMMITTER_EMAIL": "author@example.test",
    "GIT_AUTHOR_DATE": "2026-01-02T03:04:05 +0000", "GIT_COMMITTER_DATE": "2026-01-02T03:04:05 +0000",
}
SNAP_STUB = """#!/bin/bash
echo SNAPSHOT-INSTALLER
echo "ARGV:$*"
echo "SELF:$0"
echo "CWD:$(pwd)"
echo "CWD-ENTRIES:$(ls -A | wc -l)"
echo "ENVNAMES:$(env | cut -d= -f1 | sort | tr '\n' ' ')"
echo "SUDO_USER:${SUDO_USER-unset}"
exit ${STUB_EXIT:-0}
"""


def git(repo, *args, input=None, env=None):
    e = dict(GIT_ENV, **(env or {}))
    r = subprocess.run(["git", "-C", str(repo), *args], env=e, input=input, capture_output=True, check=True)
    return r.stdout.decode().strip() if input is None or isinstance(input, str) else r.stdout


def make_repo(path, files=None, installer=SNAP_STUB):
    """Create <path> with one commit; returns (commit_id, tree_id). files: {relpath: text}."""
    path = Path(path)
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    base = {"scripts/newton-install": installer, "scripts/newton-bootstrap": "#!/bin/bash\n# fixture\n", "README": "x\n"}
    base.update(files or {})
    for rel, text in base.items():
        f = path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    os.chmod(path / "scripts/newton-install", 0o755)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "fixture commit")
    return git(path, "rev-parse", "HEAD"), git(path, "rev-parse", "HEAD^{tree}")


def loose_object_path(repo, oid):
    return Path(repo) / ".git" / "objects" / oid[:2] / oid[2:]