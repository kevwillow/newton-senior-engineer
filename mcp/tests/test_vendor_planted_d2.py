"""The test the vendor suite was missing for the planted defect.

It was missed by every other test in ``mcp/tests`` (all green with the
defect planted): the apply script may carry a plain ``commit`` before the
``commit-confirm``.  A plain commit commits the candidate with no revert
armed, so the commit-confirm that follows reverts nothing: a change that
fails its verification stays on the device.

"""

from __future__ import annotations

import pytest

from newton_mcp.adapters import vendor_write as vw


STAGE_STATEMENTS = [
    ["set", "system", "host-name", "p11-test"],
    ["set", "interfaces", "ethernet", "eth1", "description", "lab uplink"],
]


def _apply_script_lines() -> list[str]:
    """The lines of the apply script the builder emits."""
    return vw.apply_script(STAGE_STATEMENTS, 3).stdin.splitlines()


def _assert_revert_armed_before_any_commit(lines: list[str]) -> None:
    """The only commit in the apply script is the commit-confirm.

    A plain ``commit`` commits the candidate with no revert armed.  The
    commit-confirm that arms the revert has to be the first thing that
    commits, so no plain commit may sit in front of it.
    """
    commits = [
        (index, line)
        for index, line in enumerate(lines)
        if line.split(" ", 1)[0] == "commit"
    ]
    assert commits == [], (
        f"the apply script commits with no revert armed: {commits}"
    )
    assert "commit-confirm 3 no-prompt" in lines, lines


def test_vpa6_d2_the_apply_script_arms_the_revert_before_it_commits() -> None:
    """the commit-confirm is the only commit in the apply script."""
    _assert_revert_armed_before_any_commit(_apply_script_lines())


def test_vpa6_d2_meta_the_check_catches_a_script_that_commits_first() -> None:
    """the check fails on a script with a plain commit in it.

    The assertion is a function so it can run twice: once on the real
    script and once on a script whose plain ``commit`` was planted.  The
    second run must raise, or the test proves nothing.
    """
    lines = _apply_script_lines()
    lines.insert(lines.index("commit-confirm 3 no-prompt"), "commit")
    assert "commit" in [line.split(" ", 1)[0] for line in lines]
    with pytest.raises(AssertionError):
        _assert_revert_armed_before_any_commit(lines)
