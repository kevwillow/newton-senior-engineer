"""The undo task the Windows write helper registers on the DC.

The undo of a Windows DC is a scheduled task that runs at the change's
undo_at.  ``StartWhenAvailable`` makes a task whose start time passed while
the DC was off or busy run as soon as it can: without it, a DC that was
down at undo_at never puts the change back.  These tests run the REAL
``Register`` method of ``New-NewtonSchedulerAdapter`` with the COM
scheduler replaced by a local object (``win_write_undo_task_probe.ps1``)
and pin what the task definition holds.  No host is contacted.

This is a release gate like the parity tests: a missing PowerShell 7.4
fails it, and only ``NEWTON_PWSH_SKIP=1`` on a dev box skips it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from pwsh_path import PWSH, require_pwsh


PROBE = Path(__file__).resolve().parent / "win_write_undo_task_probe.ps1"


def _pwsh() -> str:
    """The shell of the tests, or a failure (a skip only with NEWTON_PWSH_SKIP=1)."""
    return require_pwsh(PWSH, "the undo task of the Windows write helper")


@pytest.fixture(scope="module")
def registered() -> list[dict[str, Any]]:
    """The task definitions the real Register method registered."""
    finished = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(PROBE)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr[:2000]
    document = json.loads(finished.stdout)
    tasks = document["registered"]
    if isinstance(tasks, dict):
        tasks = [tasks]
    return tasks


def test_the_probe_registers_exactly_one_task(registered: list[dict[str, Any]]) -> None:
    assert [task["name"] for task in registered] == ["NewtonUndo-probe"]


def test_the_undo_task_starts_when_available(registered: list[dict[str, Any]]) -> None:
    """A DC that was off or busy at undo_at still runs the undo once it can."""
    assert registered[0]["start_when_available"] is True


def test_the_undo_task_is_enabled_with_one_time_trigger_at_undo_at(
    registered: list[dict[str, Any]],
) -> None:
    task = registered[0]
    assert task["enabled"] is True
    assert task["trigger_types"] == [1]
    assert task["start_boundary"] == ["2027-01-01T00:10:00Z"]
