"""A correct passphrase clears the wrong-answer count.

Wrong passphrases are counted where the lock is on (the in-client dialog,
`newton-rpcd owner-check`, `newton-approve ad-change`).  A correct one must
clear that count, or typos weeks apart add up to a lock for the life of the
install.  The TOTP branch already did this; the passphrase paths did not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from newton_mcp import approval_proof, approve


DEVICE = "lab-r1"


@pytest.fixture(autouse=True)
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _misses(device: str) -> int:
    record, unreadable = approval_proof._load_lockout(device)
    assert not unreadable
    return 0 if record is None else record["misses"]


def _ask(monkeypatch: pytest.MonkeyPatch, status: str, *, lockout: bool) -> tuple[str | None, str | None]:
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "some passphrase")
    key = "ab" * 32 if status == approval_proof.PASS_OK else None
    monkeypatch.setattr(
        approval_proof, "verify_passphrase", lambda *args: (status, key)
    )
    return approve._ask_proof(DEVICE, approve.LEVEL_PASSPHRASE, None, lockout)


def test_a_correct_passphrase_clears_the_count_where_the_lock_is_on(monkeypatch):
    for _ in range(2):
        key, refusal = _ask(monkeypatch, approval_proof.PASS_WRONG, lockout=True)
        assert key is None and refusal is not None
    assert _misses(DEVICE) == 2

    key, refusal = _ask(monkeypatch, approval_proof.PASS_OK, lockout=True)
    assert refusal is None and key == "ab" * 32
    assert _misses(DEVICE) == 0

    # two more typos after the success do not lock
    for _ in range(2):
        _ask(monkeypatch, approval_proof.PASS_WRONG, lockout=True)
    assert approval_proof.lock_remaining(DEVICE) == 0
    assert _misses(DEVICE) == 2


def test_the_terminal_path_without_the_lock_still_counts_nothing(monkeypatch):
    _ask(monkeypatch, approval_proof.PASS_WRONG, lockout=False)
    assert _misses(DEVICE) == 0


def test_a_correct_passphrase_on_the_terminal_path_clears_the_count(monkeypatch):
    """Two dialog typos, then a correct answer at the newton-approve terminal
    (no lock there): the count is cleared, so one more typo does not lock."""
    for _ in range(2):
        _ask(monkeypatch, approval_proof.PASS_WRONG, lockout=True)
    assert _misses(DEVICE) == 2
    key, refusal = _ask(monkeypatch, approval_proof.PASS_OK, lockout=False)
    assert refusal is None and key == "ab" * 32
    assert _misses(DEVICE) == 0
