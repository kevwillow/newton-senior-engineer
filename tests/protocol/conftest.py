"""Autouse state-dir isolation for every protocol test.

The protocol suite spawns subprocesses that drive scripts/newton-router-setup
and approve.py.  Two paths inside those tools write a host-side state file:

* `wan-health-restart-pending/<device>` is written by the bash helper
  `wan_health_restart_pending_write`, whose state dir is `NEWTON_STATE_DIR`
  when set, else `$(home_dir)/.local/state/newton`.  home_dir reads
  `getent passwd` (NOT `$HOME`), so setting $HOME alone does not isolate.
* `approval-fp/<device>` is written by an inline Python helper inside
  approval_fingerprint_write; that helper falls back to `Path.home()`
  (~/.local/state/newton) when NEWTON_STATE_DIR is unset.

If a test forgets to set NEWTON_STATE_DIR (or a test sets it but lets HOME
leak to the real user), these helpers write into the real home of the user
who is running the suite.

This conftest isolates every test:

* autouse fixture `_isolate_state_dir` sets NEWTON_STATE_DIR to a
  per-test tmp dir (mode 0700) and HOME to a per-test tmp dir, so the
  bash home_dir() and the python Path.home() both resolve inside the
  tmp tree.
* autouse fixture `_guard_real_state_subtrees` snapshots, BEFORE and
  AFTER each test, the two named subtrees under the real user's
  `<getent home>/.local/state/newton/` (names, sizes and mtimes; the
  home path is read from `pwd.getpwuid(os.getuid()).pw_dir`, not
  $HOME), and fails the test if either changed.  Only those two
  subtrees are guarded: a real dev MCP server may legitimately write
  elsewhere under `~/.local/state/newton` at the same time.  The guard
  never deletes or modifies anything in the real home.

The guard home path is overridable by a module-level variable
(`GUARDED_HOME_FOR_TESTS`) that the self-test in
`test_state_isolation.py` patches; a normal test run cannot change it
because the conftest does not export an environment variable for it.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

GUARDED_SUBTREES = (
    "approval-fp",
    "wan-health-restart-pending",
)

# Module-level knob so the self-test can point the guard at a fake home.
# Not settable through an environment variable (a normal run cannot reach
# it; only the self-test imports and patches this symbol).
GUARDED_HOME_FOR_TESTS = None


def _real_user_home():
    """The running user's home directory read from the password
    database, never from $HOME (the bash helper `home_dir` does the
    same)."""
    if GUARDED_HOME_FOR_TESTS is not None:
        return Path(GUARDED_HOME_FOR_TESTS)
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _snapshot_subtree(root):
    """A snapshot of every regular file under `root` keyed by a
    `(relative path, size, mtime)` triple.  Missing root -> empty."""
    if not root.exists():
        return []
    entries = [(".", 0, root.stat().st_mtime)]
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            try:
                st = path.stat()
            except OSError:
                continue
            rel = Path(path).relative_to(root).as_posix()
            entries.append((rel, st.st_size, st.st_mtime))
    entries.sort()
    return entries


def _diff_snapshots(before, after, root):
    """Return a list of human-readable differences between two
    snapshots of the same subtree.  A change is one of: added, removed,
    size-changed, mtime-changed.  All paths are relative to `root`."""
    bset = {e[0]: (e[1], e[2]) for e in before}
    aset = {e[0]: (e[1], e[2]) for e in after}
    diffs = []
    for name in sorted(aset.keys() - bset.keys()):
        diffs.append("added: %s" % name)
    for name in sorted(bset.keys() - aset.keys()):
        diffs.append("removed: %s" % name)
    for name in sorted(aset.keys() & bset.keys()):
        bs, bm = bset[name]
        as_, am = aset[name]
        if bs != as_:
            diffs.append("size-changed: %s (%d -> %d)" % (name, bs, as_))
        if bm != am:
            diffs.append("mtime-changed: %s (mtime %s -> %s)"
                         % (name, bm, am))
    return diffs


@pytest.fixture(autouse=True)
def _isolate_state_dir(tmp_path, monkeypatch):
    """Set NEWTON_STATE_DIR to a per-test tmp dir (mode 0700) and HOME
    to a per-test tmp dir.  The two env vars cover both writers: the
    bash helper that ignores $HOME (reads getent) and the python
    helper that ignores getent (reads Path.home()).  The fixture runs
    in autouse so a test cannot opt out by accident."""
    # Use a uniquely-named subdir under tmp_path so the conftest does
    # not collide with the per-test fixtures (e.g. SetupEnv.home at
    # `tmp_path / "home"`).  The dirs are mode 0700 so the guard can
    # detect any write that escapes the tmp tree.
    state_dir = tmp_path / "conftest_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    home_dir = tmp_path / "conftest_home"
    home_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state_dir))
    monkeypatch.setenv("HOME", str(home_dir))
    yield


@pytest.fixture(autouse=True)
def _guard_real_state_subtrees(request, tmp_path):
    """Snapshot the two named state subtrees under the real user's
    home before and after the test, fail the test when either changed.
    Only the named subtrees are guarded; a dev MCP server is allowed
    to write elsewhere under ~/.local/state/newton.  A missing subtree
    snapshots as empty, so the guard never skips a test."""
    real_home = _real_user_home()
    real_root = real_home / ".local" / "state" / "newton"

    before = {name: _snapshot_subtree(real_root / name)
              for name in GUARDED_SUBTREES}
    try:
        yield
    finally:
        after = {name: _snapshot_subtree(real_root / name)
                 for name in GUARDED_SUBTREES}
        for name in GUARDED_SUBTREES:
            diffs = _diff_snapshots(before[name], after[name],
                                    real_root / name)
            if diffs:
                # We do not delete anything in the real home; we only
                # read the snapshot.  Surface every changed entry so
                # the test author can clean up manually.
                pytest.fail(
                    "test wrote into the real user state dir under "
                    "%s (NEWTON_STATE_DIR isolation is broken; do "
                    "NOT delete the stray files -- the test author "
                    "must clean them up by hand): %s"
                    % (real_root / name, "; ".join(diffs)))


@pytest.fixture
def tmp_state_dir(tmp_path):
    """A per-test state dir that the calling test may pass into
    subprocess envs (handy when the test builds its own env by hand
    instead of going through the SetupEnv fixture)."""
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    return state
