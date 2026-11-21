"""A confirmed change whose undo record could not be kept says so.

The server stores the config hashes right after a confirm (the undo record)
at three places: the apply, the confirm of a held apply, and the status,
abort or confirm that learns of a confirm whose answer was lost.  When that
store fails (no usable hashes, a record that cannot be written, an
exception), the server appends a ``NO UNDO RECORD session=<sid>: ...`` line
to the wrapper's audit log, so ``newton_plan_undo`` names that reason
instead of "confirmed before undo records were kept"; the apply and confirm
results say it too.  Everything is local: a fake script runner, no device.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from newton_mcp import server
from newton_mcp import undo_plan
from test_server import SID, _record, _write_plan, configured_lab  # noqa: F401

HASHES = f"CONFIGHASH {'a' * 32} dhcp\nCONFIGHASH {'b' * 32} network\n"
APPLY = f"APPLYING session={SID}\n{{hashes}}CONFIRMED session={SID} (3 consecutive passes)\n"
CONFIRM = f"{{hashes}}CONFIRMED session={SID} (held apply: 3 consecutive passes, then one more round)\n"
STATUS = (f"confirmed sid={SID} guard=idle rpcd=- config=other boot=-\n{{hashes}}"
          f"CONFIRMED session={SID} (reconciled: the router's status says confirmed)\n")
NO_UNDO = f"NO UNDO RECORD session={SID}: "


@pytest.fixture(autouse=True)
def _own_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))


def _fake(stdout: str):
    def run(self, device, *args, **kwargs):
        return subprocess.CompletedProcess(list(args), 0, stdout, "")
    return run


def _call(tool: str, hashes: str, monkeypatch):
    shape = {"apply": APPLY, "confirm": CONFIRM, "status": STATUS}[tool]
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(shape.format(hashes=hashes)))
    if tool == "apply":
        return server.newton_apply_change("quasar", SID)
    if tool == "confirm":
        return server.newton_confirm_change("quasar", SID)
    return server.newton_change_status("quasar", SID)


def _no_undo_lines(root: Path) -> list[str]:
    audit = root / "audit.log"
    if not audit.exists():
        return []
    return [line for line in audit.read_text().splitlines() if NO_UNDO in line]


def _returns_false(*args, **kwargs):
    return False


def _raises(*args, **kwargs):
    raise RuntimeError("storage failed")


TOOLS = ["apply", "confirm", "status"]


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("failure", ["no-hashes", "returns-false", "raises"])
def test_a_confirm_whose_undo_record_was_not_kept_logs_no_undo_record(
        configured_lab, monkeypatch, tool, failure):
    _write_plan(configured_lab, _record())
    hashes = HASHES
    if failure == "no-hashes":
        hashes = ""
    elif failure == "returns-false":
        monkeypatch.setattr(undo_plan, "record_after_hash", _returns_false)
    else:
        monkeypatch.setattr(undo_plan, "record_after_hash", _raises)
    result = _call(tool, hashes, monkeypatch)
    lines = _no_undo_lines(configured_lab)
    assert len(lines) == 1, lines
    # the line has the wrapper's shape: stamp, router, message
    stamp, router, message = lines[0].split(" ", 2)
    assert stamp and router == "quasar"
    assert message.startswith(NO_UNDO)
    assert "newton_plan_change" in message
    assert "OUTCOME UNKNOWN" not in message
    if tool in ("apply", "confirm"):
        assert result["result"] == "confirmed"
        assert "newton_plan_undo cannot undo" in result["undo_record"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_kept_undo_record_logs_nothing(configured_lab, monkeypatch, tool):
    _write_plan(configured_lab, _record())
    result = _call(tool, HASHES, monkeypatch)
    assert _no_undo_lines(configured_lab) == []
    assert "undo_record" not in result


def test_the_wrappers_own_no_undo_record_line_is_not_repeated(configured_lab, monkeypatch):
    """The wrapper already logged that it could not read the config: one line is enough."""
    _write_plan(configured_lab, _record())
    (configured_lab / "audit.log").write_text(
        f"2026-11-21T10:00:00+00:00 root@192.0.2.1 {NO_UNDO}the router's config could not be read\n")
    result = _call("apply", "", monkeypatch)
    assert len(_no_undo_lines(configured_lab)) == 1
    assert "newton_plan_undo cannot undo" in result["undo_record"]


def test_the_undo_then_names_the_reason_not_the_old_one(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(undo_plan, "record_after_hash", _returns_false)
    _call("apply", HASHES, monkeypatch)
    with pytest.raises(undo_plan.UndoRefused) as excinfo:
        undo_plan._require_after_hash(_record(), SID)
    assert str(excinfo.value) == undo_plan.NO_AFTER_HASH_UNREAD
    assert "before undo records were kept" not in str(excinfo.value)
