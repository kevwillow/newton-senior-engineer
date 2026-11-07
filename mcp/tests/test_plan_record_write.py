"""APR-04: the plan record is written the way approve.py writes a record.

The old code wrote the record to a fixed temporary name
(``<session_id>.json.tmp``) and chmod'ed it afterwards, so the file
existed under the process umask (0644 with the usual mask) for a moment,
and a planted symlink at that fixed name was written through.

The record now goes through a fresh ``mkstemp`` file (mode 0600 from the
start), an fsync and an ``os.replace`` into place, and the temporary file
is removed when anything fails.  The record holds the raw uci_batch, so
its mode matters.

All values here are synthetic; the staged device output is a fixture.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from exhelp import explained

import newton_mcp.server as server


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
BATCH = "set dhcp.skilltest=host"

PLAN_OUTPUT = (
    "BACKUP /tmp/skilltest.tar.gz (2 config files)\n"
    f"STAGED session={SID} from /tmp/changes.uci diff={'1' * 64}\n"
    f"BASEHASH {BASE_HASH}\n"
    f"PROBES 0 {'a' * 64}\n"
    "PROFILE lab\n"
    "LEASH wan-rule firewall.wan_rule.src\n"
    "SECTION dhcp skilltest host-reservation skilltest\n"
    "APPROVAL not-required\n"
    f"PLANDIGEST {'d' * 64}\n"
    "----- diff -----\n"
    "dhcp.skilltest='host'\n"
    "----------------\n"
)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """An inventory with one lab device and a state dir this code may write."""
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'profile = "lab"\nlab = true\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    return tmp_path


def _drive_planner(monkeypatch):
    """Stub the staged-router script so a real plan call returns a record."""

    def fake_script(self, device, *args, **kwargs):
        return subprocess.CompletedProcess(args, 0, PLAN_OUTPUT, "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_script)


def _plan():
    return server.newton_plan_change("quasar", BATCH, **explained(BATCH))


def _plans_dir(lab):
    return lab / "state" / "plans"


def _record_path(lab):
    return _plans_dir(lab) / f"{SID}.json"


def test_the_record_is_written_with_mode_0600_under_umask_0(lab, monkeypatch):
    """The record never exists with a mode the umask would give it."""
    _drive_planner(monkeypatch)
    old = os.umask(0)
    try:
        result = _plan()
    finally:
        os.umask(old)
    assert "error" not in result, result
    record = _record_path(lab)
    assert record.exists()
    assert stat.S_IMODE(record.stat().st_mode) == 0o600


def test_no_temporary_file_is_left_behind(lab, monkeypatch):
    _drive_planner(monkeypatch)
    assert "error" not in _plan()
    plans = _plans_dir(lab)
    assert list(plans.glob("*.json.tmp")) == []
    assert list(plans.glob(".*")) == []
    assert [path.name for path in plans.iterdir()] == [f"{SID}.json"]


def test_a_planted_tmp_symlink_is_not_written_through(lab, monkeypatch):
    """A symlink at the old fixed temporary name is never followed."""
    _drive_planner(monkeypatch)
    plans = _plans_dir(lab)
    plans.mkdir(mode=0o700, parents=True, exist_ok=True)
    victim = lab / "victim.txt"
    victim.write_text("original\n", encoding="utf-8")
    planted = plans / f"{SID}.json.tmp"
    planted.symlink_to(victim)

    result = _plan()

    assert "error" not in result, result
    assert victim.read_text(encoding="utf-8") == "original\n"
    record = _record_path(lab)
    assert record.exists()
    assert json.loads(record.read_text(encoding="utf-8"))["session_id"] == SID


def test_a_failed_write_leaves_no_temporary_file(lab, monkeypatch):
    """A failure in the middle of the write cleans the temporary file up."""
    _drive_planner(monkeypatch)

    def boom(*args, **kwargs):
        raise OSError("replace refused for the test")

    monkeypatch.setattr(server.os, "replace", boom)

    with pytest.raises(OSError):
        server.NewtonService().plan("quasar", BATCH, **explained(BATCH))

    plans = _plans_dir(lab)
    assert list(plans.iterdir()) == []


def test_the_write_uses_a_fresh_temporary_name(lab, monkeypatch):
    """The record is renamed into place from a file of its own, not from a
    fixed name an attacker could plant before the write."""
    _drive_planner(monkeypatch)
    seen = {}
    original = server.os.replace

    def spy(source, destination, *args, **kwargs):
        seen["source"] = Path(source).name
        return original(source, destination, *args, **kwargs)

    monkeypatch.setattr(server.os, "replace", spy)
    assert "error" not in _plan()

    assert seen["source"] != f"{SID}.json.tmp"
    assert seen["source"].startswith(f".{SID}.json.")


def test_a_symlink_at_the_record_name_is_replaced_not_written_through(
    lab, monkeypatch
):
    _drive_planner(monkeypatch)
    plans = _plans_dir(lab)
    plans.mkdir(mode=0o700, parents=True, exist_ok=True)
    victim = lab / "victim.txt"
    victim.write_text("original\n", encoding="utf-8")
    planted = plans / f"{SID}.json"
    planted.symlink_to(victim)

    result = _plan()

    assert "error" not in result, result
    assert victim.read_text(encoding="utf-8") == "original\n"
    record = _record_path(lab)
    assert record.is_file()
    assert not record.is_symlink()
    assert json.loads(record.read_text(encoding="utf-8"))["session_id"] == SID



def test_a_failed_chmod_closes_the_descriptor_and_removes_the_file(lab, monkeypatch):
    """A failure right after mkstemp neither leaks the descriptor nor leaves
    the temporary file behind."""
    _drive_planner(monkeypatch)
    fds_before = set(os.listdir("/proc/self/fd"))

    original = server.os.fchmod

    def boom(descriptor, mode):
        # fail only for the record's temporary file; other code uses fchmod too
        if Path(os.readlink(f"/proc/self/fd/{descriptor}")).name.startswith(f".{SID}"):
            raise OSError("fchmod refused for the test")
        return original(descriptor, mode)

    monkeypatch.setattr(server.os, "fchmod", boom)

    with pytest.raises(OSError, match="fchmod refused"):
        server.NewtonService().plan("quasar", BATCH, **explained(BATCH))

    assert list(_plans_dir(lab).iterdir()) == []
    assert set(os.listdir("/proc/self/fd")) - fds_before == set()
