"""A confirm the router has but this host never logged.

When the link drops after the router confirmed a change but before its
answer reached the host, the apply (or confirm) ends OUTCOME UNKNOWN.  A
later status, abort or confirm that finds the router's status saying
confirmed prints a ``CONFIRMED session=<sid> (reconciled: ...)`` line;
the server then writes the confirmed receipt (and an after-hash when the
wrapper printed config hashes; the current wrapper prints none, and the
undo planner refuses a reconciled change).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from newton_mcp import server
from test_server import SID, _record, _write_plan, configured_lab  # noqa: F401

HASHES = f"CONFIGHASH {'a' * 32} dhcp\nCONFIGHASH {'b' * 32} network\n"
STATUS_LINE = f"confirmed sid={SID} guard=idle rpcd=- config=other boot=-\n"
RECONCILED = f"CONFIRMED session={SID} (reconciled: the router's status says confirmed)\n"
REFUSED = (f"ERROR: abort refused: session {SID} was already confirmed; the change stays live. "
           "To undo it, plan the reverse change (newton_plan_undo)\n")
CONFIRM_REFUSED = (f"ERROR: session {SID} is already confirmed on the router; nothing confirmed by "
                   "this run; the router's status says it is confirmed\n")


@pytest.fixture(autouse=True)
def _own_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))


def _fake(stdout: str, rc: int):
    def run(self, device, *args, **kwargs):
        return subprocess.CompletedProcess(list(args), rc, stdout, "")
    return run


def _receipts(root: Path) -> list[Path]:
    d = root / "state" / "receipts"
    return sorted(d.glob("*.md")) if d.is_dir() else []


def _stored(root: Path) -> dict:
    return json.loads((root / "state" / "plans" / f"{SID}.json").read_text())


def _call(tool: str):
    if tool == "status":
        return server.newton_change_status("quasar", SID)
    if tool == "abort":
        return server.newton_abort_change("quasar", SID)
    return server.newton_confirm_change("quasar", SID)


@pytest.mark.parametrize("tool,out,rc", [
    ("status", STATUS_LINE + HASHES + RECONCILED, 0),
    ("abort", HASHES + RECONCILED.replace("the router's status says confirmed",
                                          "the router refused the abort: it says confirmed") + REFUSED, 1),
    ("abort", STATUS_LINE + HASHES + RECONCILED + REFUSED, 1),
    ("confirm", STATUS_LINE + HASHES + RECONCILED + CONFIRM_REFUSED, 1),
], ids=["status", "abort-refused", "abort-gone", "confirm"])
def test_a_reconciled_confirm_writes_the_confirmed_receipt_and_after_hash(
        configured_lab, monkeypatch, tool, out, rc):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(out, rc))
    result = _call(tool)
    receipts = _receipts(configured_lab)
    assert len(receipts) == 1, result
    assert "Outcome: CONFIRMED" in receipts[0].read_text()
    assert _stored(configured_lab)["after_hash"] == {"dhcp": "a" * 32, "network": "b" * 32}
    if tool == "confirm":
        assert "already confirmed on the router" in result["error"]
    else:
        assert "CONFIGHASH" not in result["log"]["text"]


@pytest.mark.parametrize("out", [
    STATUS_LINE,
    f"confirmed sid={SID} CONFIRMED session={SID} (reconciled: x)\n",
    RECONCILED.replace(SID, "f" * 32),
    f"NOTE CONFIRMED session={SID} (reconciled: x)\n",
], ids=["status-line-only", "mid-line", "other-session", "not-at-line-start"])
def test_no_reconciled_line_writes_no_receipt(configured_lab, monkeypatch, out):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(out, 0))
    server.newton_change_status("quasar", SID)
    assert _receipts(configured_lab) == []
    assert "after_hash" not in _stored(configured_lab)


def test_a_reconciled_line_for_another_device_writes_no_receipt(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record(device="other"))
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(STATUS_LINE + HASHES + RECONCILED, 0))
    server.newton_change_status("quasar", SID)
    assert _receipts(configured_lab) == []


def test_the_confirm_refusal_for_a_session_already_confirmed_on_the_router_is_a_refusal():
    final = CONFIRM_REFUSED.strip()
    assert server._host_confirm_refusal_re(SID).match(final)
    assert not server._host_confirm_refusal_re(SID).match(final.replace(SID, "f" * 32))
