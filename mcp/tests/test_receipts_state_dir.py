"""MV-4: receipts state directory must be safe to write into.

A new state directory this code just created is mode 0700 (mkdir's mode
is masked by umask only downward; we chmod explicitly to match the audit
log's pattern in ``server.write_audit``). When the state directory
already exists, it must be a real directory owned by the user running
the MCP server, it must not be a symlink, and it must not be group- or
world-writable. As the ``receipts`` module says: every failure is
returned as False; callers must not let a receipt problem fail a read.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from newton_mcp import receipts


@pytest.fixture
def umask_zero():
    """Run the body of this test with a 0 umask so mkdir applies the
    requested mode verbatim.  Restored on teardown; the autouse
    ``_restrict_default_umask`` in conftest.py brought it to 022 and
    is then responsible for restoring the original value."""
    old = os.umask(0)
    try:
        yield
    finally:
        os.umask(old)


def _record(state: Path) -> bool:
    return receipts.record(state, "junos", "interfaces", "ok", "matched", "1.0")


def test_new_dir_is_mode_0700_even_under_umask_0(tmp_path: Path, umask_zero) -> None:
    """A new state dir is 0700 even when the umask would not block anything."""
    state = tmp_path / "newstate"
    assert _record(state) is True
    assert stat.S_IMODE(state.lstat().st_mode) == 0o700
    assert (state / receipts.RECEIPT_FILE).exists()
    assert stat.S_IMODE((state / receipts.RECEIPT_FILE).stat().st_mode) == 0o600


def test_existing_0700_dir_ok_and_receipt_written(tmp_path: Path) -> None:
    """A pre-existing 0700 state dir is accepted and the receipt is written; the dir mode is not changed."""
    state = tmp_path / "good"
    state.mkdir(mode=0o700)
    assert _record(state) is True
    assert stat.S_IMODE(state.lstat().st_mode) == 0o700
    assert (state / receipts.RECEIPT_FILE).exists()
    assert stat.S_IMODE((state / receipts.RECEIPT_FILE).stat().st_mode) == 0o600


@pytest.mark.parametrize("bad_mode", [0o775, 0o777])
def test_existing_world_or_group_writable_dir_refused(
    tmp_path: Path, bad_mode: int
) -> None:
    """An existing group- or world-writable state dir is refused; nothing is written; its mode is unchanged."""
    state = tmp_path / "loose"
    state.mkdir(mode=0o700)
    os.chmod(state, bad_mode)
    assert _record(state) is False
    assert not (state / receipts.RECEIPT_FILE).exists()
    assert not (state / receipts.LOCK_FILE).exists()
    assert stat.S_IMODE(state.lstat().st_mode) == bad_mode


def test_symlink_state_path_is_refused(tmp_path: Path) -> None:
    """A symlink where the state dir should be is refused and the real dir behind it is not used."""
    real = tmp_path / "good"
    real.mkdir(mode=0o700)
    link = tmp_path / "linkstate"
    link.symlink_to(real)
    assert _record(link) is False
    assert not (real / receipts.RECEIPT_FILE).exists()
    assert not (real / receipts.LOCK_FILE).exists()
    assert stat.S_IMODE(real.lstat().st_mode) == 0o700


def test_regular_file_state_path_is_refused(tmp_path: Path) -> None:
    """A regular file in place of the state dir is refused and is not modified."""
    state = tmp_path / "not-a-dir"
    state.write_text("x")
    state.chmod(0o600)
    assert _record(state) is False
    assert stat.S_IMODE(state.lstat().st_mode) == 0o600
    assert state.read_text() == "x"


def test_foreign_owner_state_dir_refused(tmp_path: Path, monkeypatch) -> None:
    """A state dir owned by another uid is refused and the record is not written."""
    state = tmp_path / "foreign"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(receipts, "_effective_uid", lambda: state.stat().st_uid + 1)
    assert _record(state) is False
    assert not (state / receipts.RECEIPT_FILE).exists()
    assert not (state / receipts.LOCK_FILE).exists()


# ---- check_state_dir: a leaf, lstat-based helper -----------------------------


def test_check_state_dir_accepts_missing(tmp_path: Path) -> None:
    """A missing path returns ``None`` so the caller can create it."""
    assert receipts.check_state_dir(tmp_path / "no-such-dir") is None


def test_check_state_dir_accepts_0700(tmp_path: Path) -> None:
    state = tmp_path / "good"
    state.mkdir(mode=0o700)
    assert receipts.check_state_dir(state) is None


def test_check_state_dir_accepts_0755(tmp_path: Path) -> None:
    """Group/world-readable but not writable is fine -- only group/other writable bits are refused."""
    state = tmp_path / "readable"
    state.mkdir()
    os.chmod(state, 0o755)
    assert receipts.check_state_dir(state) is None


def test_check_state_dir_refuses_symlink(tmp_path: Path) -> None:
    real = tmp_path / "good"
    real.mkdir(mode=0o700)
    link = tmp_path / "lnk"
    link.symlink_to(real)
    msg = receipts.check_state_dir(link)
    assert msg is not None
    assert "symlink" in msg


def test_check_state_dir_refuses_regular_file(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_text("")
    msg = receipts.check_state_dir(f)
    assert msg is not None
    assert "directory" in msg


@pytest.mark.parametrize("bad_mode", [0o775, 0o777])
def test_check_state_dir_refuses_world_or_group_writable(
    tmp_path: Path, bad_mode: int
) -> None:
    state = tmp_path / "loose"
    state.mkdir(mode=0o700)
    os.chmod(state, bad_mode)
    msg = receipts.check_state_dir(state)
    assert msg is not None
    assert f"chmod go-w {state}" in msg


def test_check_state_dir_refuses_foreign_owner(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "foreign"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(receipts, "_effective_uid", lambda: state.stat().st_uid + 1)
    msg = receipts.check_state_dir(state)
    assert msg is not None
    assert "owned" in msg


def test_check_state_dir_lstat_error_becomes_a_message(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "boom"
    state.mkdir(mode=0o700)

    def boom(self: Path) -> os.stat_result:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "lstat", boom)
    msg = receipts.check_state_dir(state)
    assert msg is not None
    assert "cannot be inspected" in msg


def test_new_dir_is_mode_0700_when_umask_strips_owner_bits(tmp_path: Path) -> None:
    """mkdir's mode can only be narrowed by the umask; the explicit chmod is what
    makes a dir created under umask 0277 usable (0700) instead of 0500."""
    old = os.umask(0o277)
    try:
        state = tmp_path / "state"
        assert _record(state) is True
        assert stat.S_IMODE(state.lstat().st_mode) == 0o700
    finally:
        os.umask(old)


# ---- check_state_dir_parent: a follows-link helper for the parent only -----


def test_check_state_dir_parent_accepts_missing(tmp_path: Path) -> None:
    """A missing parent returns None so the caller can create it."""
    assert receipts.check_state_dir_parent(tmp_path / "no-such-dir") is None


def test_check_state_dir_parent_accepts_0755(tmp_path: Path) -> None:
    """A 0755 parent (no group/other write) is fine."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o755)
    state = parent / "state"
    assert receipts.check_state_dir_parent(state) is None


def test_check_state_dir_parent_accepts_1777(tmp_path: Path) -> None:
    """A 1777 parent (group/other writable WITH sticky bit) is fine."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o777)
    os.chmod(parent, 0o1777)
    state = parent / "state"
    assert receipts.check_state_dir_parent(state) is None


@pytest.mark.parametrize("bad_mode", [0o775, 0o777])
def test_check_state_dir_parent_refuses_group_or_world_writable_without_sticky(
    tmp_path: Path, bad_mode: int
) -> None:
    """A 0775/0777 parent (group/other writable, no sticky) is refused."""
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o755)
    os.chmod(parent, bad_mode)
    state = parent / "state"
    msg = receipts.check_state_dir_parent(state)
    assert msg is not None
    assert f"parent {parent}" in msg
    assert "sticky bit" in msg


def test_check_state_dir_parent_follows_symlink_parent(tmp_path: Path) -> None:
    """A symlinked parent pointing at a 0755 dir is accepted (link followed)."""
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o755)
    link_parent = tmp_path / "link-parent"
    link_parent.symlink_to(real_parent)
    state = link_parent / "state"
    assert receipts.check_state_dir_parent(state) is None


def test_check_state_dir_parent_does_not_follow_symlinked_state(tmp_path: Path) -> None:
    """The parent check fires on the resolved parent only; it does not let a
    symlinked state dir trick the check (the state dir itself is lstat-checked
    by ``check_state_dir``)."""
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o777)
    os.chmod(real_parent, 0o777)
    link_state = tmp_path / "state"
    link_state.symlink_to(tmp_path / "elsewhere")
    # the parent of the symlink (tmp_path) is 0o755, so the parent check
    # accepts regardless of the symlink's eventual target.
    assert receipts.check_state_dir_parent(link_state) is None
