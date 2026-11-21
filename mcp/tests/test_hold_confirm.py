"""newton_apply_change(hold=True) and newton_confirm_change.

The installed-mode apply confirmed on its own after three passing rounds, and
newton_apply_change blocked until it had, so the owner could never test from a
client inside the window as the docs said.  With hold=True the apply runs the
same rounds and returns `held` with the rollback still armed; the agent then
calls newton_confirm_change (or newton_abort_change) before the window closes.
hold defaults to False, and then nothing changes.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import notice, server
from test_server import SID, _record, _write_plan, configured_lab  # noqa: F401

HELD = (f"APPLYING session={SID}\nAPPLIED session={SID} rollback=90s\n"
        f"HELD session={SID} until=1794000000 (3 consecutive passes; NOT confirmed) "
        f"confirm: owrt-change.sh confirm root@192.0.2.1 {SID} abort: owrt-change.sh "
        f"abort root@192.0.2.1 {SID}\n")


def _fake(calls: list, stdout: str, rc: int = 0):
    def run(self, device, *args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(list(args), rc, stdout, "")
    return run


def _receipts(root: Path) -> list[Path]:
    d = root / "state" / "receipts"
    return sorted(d.glob("*.md")) if d.is_dir() else []


def test_hold_passes_the_flag_and_returns_held(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    calls: list = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(calls, HELD))
    result = server.newton_apply_change("quasar", SID, hold=True)
    assert calls[0] == ("apply", "root@192.0.2.1", SID, "90", "--hold")
    assert result["result"] == "held"
    assert result["confirm_by"] == 1794000000
    assert "newton_confirm_change" in result["next_step"]
    assert "newton_abort_change" in result["next_step"]
    # a receipt now, outcome unknown: if nobody confirms, the trail still
    # holds the change (the confirm adds its own receipt)
    receipts = _receipts(configured_lab)
    assert len(receipts) == 1
    assert "UNKNOWN" in receipts[0].read_text().upper()


def test_without_hold_the_arguments_are_unchanged(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    calls: list = []
    monkeypatch.setattr(server.NewtonService, "run_script",
                        _fake(calls, f"CONFIRMED session={SID}"))
    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    assert calls[0] == ("apply", "root@192.0.2.1", SID, "90")


def test_a_held_line_without_hold_is_unknown(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], HELD))
    assert server.newton_apply_change("quasar", SID)["result"] == "unknown"


@pytest.mark.parametrize("bad", ["yes", 1, None])
def test_hold_must_be_a_boolean(configured_lab, monkeypatch, bad):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script",
                        lambda *a, **k: pytest.fail("must not run"))
    result = server.newton_apply_change("quasar", SID, hold=bad)
    assert "hold must be true or false" in result["error"]


CONFIRMED = (f"CONFIGHASH {'a' * 32} dhcp\nCONFIGHASH {'b' * 32} network\n"
             f"CONFIRMED session={SID} (held apply: 3 consecutive passes, then one more round)\n")


def test_confirm_runs_the_confirm_subcommand_and_records_the_result(
        configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    calls: list = []
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(calls, CONFIRMED))
    result = server.newton_confirm_change("quasar", SID)
    assert calls[0] == ("confirm", "root@192.0.2.1", SID)
    assert result["result"] == "confirmed"
    assert result["newton_result"].startswith("NEWTON RESULT: CONFIRMED  quasar")
    assert "CONFIGHASH" not in result["log"]["text"]
    assert len(_receipts(configured_lab)) == 1
    stored = json.loads((configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert stored["after_hash"] == {"dhcp": "a" * 32, "network": "b" * 32}


def test_a_refused_confirm_is_not_confirmed(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    out = ("ERROR: confirm refused: error too-late; not confirmed: the router rolls "
           "the change back on its own\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert result["result"] == "not_confirmed"
    assert "rolls the change back" in result["next_step"]
    assert result["newton_result"].startswith("NEWTON RESULT: NOT CONFIRMED")
    assert _receipts(configured_lab) == []


def test_a_confirm_with_no_answer_is_unknown(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    out = (f"CONFIRM DID NOT REPORT SUCCESS session={SID} — OUTCOME UNKNOWN; "
           "run: owrt-change.sh status\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert result["result"] == "unknown"
    assert len(_receipts(configured_lab)) == 1


def test_confirm_checks_the_session_id(configured_lab, monkeypatch):
    monkeypatch.setattr(server.NewtonService, "run_script",
                        lambda *a, **k: pytest.fail("must not run"))
    assert "session_id" in server.newton_confirm_change("quasar", "nope")["error"]


def test_the_tools_are_listed_with_the_hold_argument():
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(server.mcp._mcp_server) as session:
            await session.initialize()
            return await session.list_tools()

    tools = {t.name: t for t in asyncio.run(listed()).tools}
    assert "newton_confirm_change" in server.TOOL_NAMES
    assert "newton_confirm_change" in tools
    assert set(tools["newton_confirm_change"].inputSchema["properties"]) == {"device", "session_id"}
    assert "hold" in tools["newton_apply_change"].inputSchema["properties"]


def test_the_notice_words_for_held_and_not_confirmed():
    held = notice.result_line({"result": "held"}, "quasar", SID, "a change")
    assert held.startswith("NEWTON RESULT: APPLIED, NOT CONFIRMED YET  quasar")
    assert "Confirm or abort it before the window closes." in held
    nc = notice.result_line({"result": "not_confirmed"}, "quasar", SID, "a change")
    assert nc.startswith("NEWTON RESULT: NOT CONFIRMED  quasar")
    assert "Check the router before doing anything else." in nc


@pytest.mark.parametrize("platform,access", [("vyos", "installed"), ("openwrt", "no-install")])
def test_hold_is_refused_where_nothing_can_stay_armed(configured_lab, monkeypatch, platform, access):
    _write_plan(configured_lab, _record())
    device = server.Device(name="quasar", platform=platform, host="192.0.2.1", user="root",
                           access=access)
    monkeypatch.setattr(server.NewtonService, "device_for", lambda self, tool, name: device)
    monkeypatch.setattr(server.NewtonService, "run_script",
                        lambda *a, **k: pytest.fail("must not run"))
    monkeypatch.setattr(server.vendor_flow, "apply",
                        lambda *a, **k: pytest.fail("must not run"))
    result = server.newton_apply_change("quasar", SID, hold=True)
    assert "hold is available only for an installed OpenWrt router" in result["error"]


def test_a_confirm_refused_before_the_router_is_an_error(configured_lab, monkeypatch):
    """No hold record on this host, or the session was already confirmed:
    the router was not asked, so the result claims nothing about it."""
    _write_plan(configured_lab, _record())
    out = (f"ERROR: session {SID} was already confirmed; nothing confirmed "
           f"(run: owrt-change.sh status root@192.0.2.1 {SID})\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert "already confirmed; nothing confirmed" in result["error"]
    assert "newton_result" not in result and "result" not in result
    assert _receipts(configured_lab) == []


def test_hold_is_refused_for_a_plan_with_client_checks(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server._client_checks, "client_claims",
                        lambda expect: [(0, {"zone": "lan"})])
    monkeypatch.setattr(server.NewtonService, "run_script",
                        lambda *a, **k: pytest.fail("must not run"))
    result = server.newton_apply_change("quasar", SID, hold=True)
    assert "hold cannot be used for a plan with client checks" in result["error"]


def test_router_text_cannot_pass_for_a_host_refusal(configured_lab, monkeypatch):
    """The host-refusal shapes are anchored: a router reason that happens to
    say '; nothing confirmed' is still a not_confirmed result."""
    _write_plan(configured_lab, _record())
    out = ("ERROR: confirm refused: error confirm-incomplete; nothing confirmed; not confirmed: "
           "the router rolls the change back on its own\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert "error" not in result
    assert result["result"] == "not_confirmed"


def test_an_aborted_held_apply_gets_a_rolled_back_receipt(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    out = (f"ABORTED session={SID} (restored)\nHELD APPLY ABORTED session={SID}\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out))
    server.newton_abort_change("quasar", SID)
    receipts = _receipts(configured_lab)
    assert len(receipts) == 1
    assert "ROLLED BACK" in receipts[0].read_text().upper().replace("_", " ")


def test_an_abort_that_found_a_held_apply_rolled_back_gets_a_rolled_back_receipt(configured_lab, monkeypatch):
    """The router answered gone and its status says rolled-back: the
    wrapper writes the HELD APPLY ROLLED BACK line, never ABORTED, and the
    receipt follows that line."""
    _write_plan(configured_lab, _record())
    out = (f"rolled-back sid={SID} guard=restored:deadline rpcd=rolled-back config=base boot=same\n"
           f"HELD APPLY ROLLED BACK session={SID} (the abort found the session gone; the router's "
           "status says rolled-back)\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out))
    server.newton_abort_change("quasar", SID)
    receipts = _receipts(configured_lab)
    assert len(receipts) == 1
    assert "ROLLED BACK" in receipts[0].read_text().upper().replace("_", " ")


@pytest.mark.parametrize("status", ["gone", "inconsistent", "confirmed"])
def test_an_abort_answered_gone_writes_no_receipt_unless_the_router_says_rolled_back(
    configured_lab, monkeypatch, status
):
    """The router answered `aborted <SID> gone` and its status line does not
    say rolled-back: the wrapper prints no HELD APPLY line of its own (its
    protocol tests pin that) and fails, so no rolled_back receipt is written,
    even when the status line or the router text quotes the marker inside a
    line. A status that says confirmed is the confirmed refusal."""
    _write_plan(configured_lab, _record())
    marker = f"HELD APPLY ROLLED BACK session={SID}"
    status_line = {
        "gone": f"gone sid={SID} guard=idle rpcd=- config=other boot=- {marker}",
        "inconsistent": f"inconsistent sid={SID} guard=failed:x rpcd=- config=other boot=same",
        "confirmed": f"confirmed sid={SID} guard=idle rpcd=confirmed config=new boot=same",
    }[status]
    final = (
        f"ERROR: abort refused: session {SID} was already confirmed; the change stays live. "
        "To undo it, plan the reverse change (newton_plan_undo)"
        if status == "confirmed" else
        f"ERROR: the router no longer has session {SID}; this abort rolled nothing back, and "
        f"whether it was rolled back is not known from here: {marker} may not be assumed"
    )
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], f"{status_line}\n{final}\n", rc=1))
    result = server.newton_abort_change("quasar", SID)
    assert _receipts(configured_lab) == []
    assert (result.get("result") == "refused_confirmed") is (status == "confirmed"), result


def test_an_abort_that_was_not_held_writes_no_receipt(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    out = f"ABORTED session={SID} (restored) HELD APPLY ABORTED session={SID}\n"
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out))
    server.newton_abort_change("quasar", SID)
    assert _receipts(configured_lab) == []


ROLLED = (f"rolled-back sid={SID} guard=restored:deadline rpcd=rolled-back config=base boot=same\n"
          f"HELD APPLY ROLLED BACK session={SID} (its window ended unconfirmed; the router's "
          "status says rolled-back)\n")


def test_a_status_after_the_window_writes_the_rolled_back_receipt(configured_lab, monkeypatch):
    """The wrapper found the window closed and the router's status saying
    rolled-back: the unknown receipt of the held apply is followed by a
    rolled-back one."""
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], ROLLED))
    server.newton_change_status("quasar", SID)
    receipts = _receipts(configured_lab)
    assert len(receipts) == 1
    assert "ROLLED BACK" in receipts[0].read_text()


def test_a_confirm_after_the_window_writes_the_rolled_back_receipt(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    out = ROLLED + (f"ERROR: the window of session {SID} has closed; nothing confirmed: the "
                    "router rolled the change back (its status says rolled-back)\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert "has closed" in result["error"]
    receipts = _receipts(configured_lab)
    assert len(receipts) == 1
    assert "ROLLED BACK" in receipts[0].read_text()


@pytest.mark.parametrize("out", [
    f"gone sid={SID} guard=idle rpcd=- config=other boot=-\nNOTE session={SID}: the window of its held apply ended unconfirmed\n",
    f"rolled-back sid={SID} guard=x rpcd=- config=base boot=same HELD APPLY ROLLED BACK session={SID}\n",
    f"HELD APPLY ROLLED BACK session={'f' * 32} (x)\n",
])
def test_a_status_without_the_wrappers_line_writes_no_receipt(configured_lab, monkeypatch, out):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script", _fake([], out))
    server.newton_change_status("quasar", SID)
    assert _receipts(configured_lab) == []


def test_the_held_next_step_says_how_long_the_window_is_and_how_to_lengthen_it():
    """The hold window is the plan's timeout, part of it already spent on
    the verify rounds: the agent is told so, and how to get a longer one."""
    text = " ".join(server.HELD_NEXT_STEP.split())
    assert "the plan's timeout_s (90 s by default, 60 to 600)" in text
    assert "the verify rounds already used part of it" in text
    assert "plan the change again with a longer timeout_s" in text
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
    flat = " ".join(readme.split())
    assert "The hold window is the plan's timeout (90 s by default, 60 to 600 s)" in flat


def test_a_confirm_past_its_timeout_is_outcome_unknown_with_the_status_step(configured_lab, monkeypatch):
    """The wrapper run passed its timeout: the router may or may not have
    confirmed, so the answer is outcome-unknown with the status next step,
    never an internal error."""
    _write_plan(configured_lab, _record())

    def run(self, device, *args, **kwargs):
        # a real subprocess.run(text=True) timeout carries bytes
        raise subprocess.TimeoutExpired(cmd="owrt-change.sh", timeout=180,
                                        output=f"verify pass 1 for {SID}\n".encode(), stderr=b"")
    monkeypatch.setattr(server.NewtonService, "run_script", run)

    result = server.newton_confirm_change("quasar", SID)

    assert "error" not in result, result
    assert result["result"] == "unknown"
    assert "newton_change_status" in result["next_step"]
    assert "not known" in result["next_step"]
    assert "untrusted-device-data" in str(result["log"])
    # the partial log the timed-out run printed is kept
    assert f"verify pass 1 for {SID}" in result["log"]["text"]


def test_the_held_next_step_and_skill_warn_a_rollback_reverts_other_edits():
    """The rollback puts back every /etc/config file from its arm-time copy,
    so a setting the owner saves while testing is lost too: the agent is
    told so, in the result and in SKILL.md's held-apply text."""
    warning = (
        "also undoes any other setting saved during the window (in LuCI or with uci commit)"
    )
    text = " ".join(server.HELD_NEXT_STEP.split())
    assert warning in text
    assert "not to change other settings while testing" in text
    skill = (Path(__file__).resolve().parents[2] / "SKILL.md").read_text(encoding="utf-8")
    flat = " ".join(skill.split())
    assert warning in flat
    assert "not to change other settings while testing" in flat
