"""Every lab run that touches the lab holds /tmp/newton-lab.lock.

The README said both lab runs must hold the lock and never overlap, but the
runner took none, so a second run's run-start reset rolled VMs back under a
live run.  The runner now takes the lock (fcntl.flock, non-blocking) before
anything touches a device and refuses when another run holds it; --list
needs no lock.  The tests point the lock at a temp file (conftest), never at
the real /tmp/newton-lab.lock.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl
from test_runner import fake_lab  # noqa: F401


SCENARIO = ('name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
            'expect = "none"\ntimeout = 60\nbatch = ""\n'
            'description = "x"\n')


def _argv(fake_lab, tmp_path: Path, *extra: str) -> list[str]:
    lab_toml, scen_dir = fake_lab
    (scen_dir / "01-x.toml").write_text(SCENARIO)
    return ["--lab", str(lab_toml), "--scenarios", str(scen_dir),
            "--lane", "password", "--results", str(tmp_path / "res" / "r.json"),
            *extra]


def _hold(path: Path) -> int:
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def _is_free(path: Path) -> bool:
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


def test_the_lock_path_is_the_shared_lab_lock() -> None:
    assert nl.DEFAULT_LAB_LOCK == Path("/tmp/newton-lab.lock")


def test_a_run_refuses_while_another_run_holds_the_lock(
        fake_lab, tmp_path, capsys) -> None:
    held = _hold(nl.LAB_LOCK_PATH)
    try:
        with mock.patch.object(nl, "_reset_lab_at_run_start") as reset, \
             mock.patch.object(nl, "run_scenario") as run:
            rc = nl.main(_argv(fake_lab, tmp_path))
    finally:
        os.close(held)
    assert rc == 2
    err = capsys.readouterr().err
    assert (f"ERROR: another lab run holds {nl.LAB_LOCK_PATH}; wait for it "
            "to finish (nothing was touched)") in err
    reset.assert_not_called()
    run.assert_not_called()


def test_list_needs_no_lock(fake_lab, tmp_path, capsys) -> None:
    held = _hold(nl.LAB_LOCK_PATH)
    try:
        rc = nl.main(_argv(fake_lab, tmp_path, "--list"))
    finally:
        os.close(held)
    assert rc == 0
    assert "01-x" in capsys.readouterr().out


def test_a_run_holds_the_lock_while_it_runs_and_releases_it(
        fake_lab, tmp_path) -> None:
    seen: list[bool] = []

    def fake_reset(*a, **k):
        seen.append(_is_free(nl.LAB_LOCK_PATH))
        return True

    def fake_run(*a, **k):
        seen.append(_is_free(nl.LAB_LOCK_PATH))
        raise RuntimeError("stop here")

    with mock.patch.object(nl, "_reset_lab_at_run_start", side_effect=fake_reset), \
         mock.patch.object(nl, "run_scenario", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="stop here"):
            nl.main(_argv(fake_lab, tmp_path))
    # held during the reset and the scenario, released even on an error
    assert seen == [False, False], seen
    assert _is_free(nl.LAB_LOCK_PATH)


def test_a_lock_file_created_by_another_run_in_between_is_opened(tmp_path):
    """Two first runs race: the loser's O_EXCL create meets the winner's file.
    It opens that file and takes (or waits for) the flock like any run,
    instead of reporting that the lock cannot be opened."""
    path = nl.LAB_LOCK_PATH
    assert not path.exists()
    real_open = os.open
    calls = []

    def racing_open(name, flags, *args):
        calls.append(flags)
        if len(calls) == 1:
            # the other run creates the file right after our first look
            os.close(real_open(name, os.O_RDONLY | os.O_CREAT, 0o644))
            raise FileNotFoundError(2, "No such file or directory")
        return real_open(name, flags, *args)

    with mock.patch.object(nl.os, "open", racing_open):
        fd, reason = nl.take_lab_lock()
    assert reason == "" and fd is not None
    os.close(fd)
