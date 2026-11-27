"""A held apply with client claims, and the confirm that runs them again.

A plan may claim something about a client inside a zone (that it resolves
a name through the zone router, that it gets a DHCP offer, that it
reaches the internet).  Newton asks a registered inside vantage to run
those checks from this host.  A held apply runs them in every round of
the apply; the confirm runs them once more, right before it asks the
router to confirm, so a check that fails there keeps the change
unconfirmed and the router puts it back at its deadline.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from newton_mcp import server
from newton_mcp.plan import compute_plan_hash
from test_client_checks_server import (  # noqa: F401
    SID, client_record, write_inventory, write_plan, write_script_directory,
)

UNREADABLE_RECORD = (
    "the plan record of this session cannot be read; the change was not "
    "confirmed and the router puts it back at its deadline"
)

HELD = (f"APPLYING session={SID}\nAPPLIED session={SID} rollback=90s\n"
        f"HELD session={SID} until=1794000000 (3 consecutive passes; NOT confirmed) "
        f"confirm: owrt-change.sh confirm root@192.0.2.1 {SID} abort: owrt-change.sh "
        f"abort root@192.0.2.1 {SID}\n")

CONFIRMED = (f"CONFIGHASH {'a' * 32} dhcp\nCONFIGHASH {'b' * 32} network\n"
             f"CONFIRMED session={SID} (held apply: 3 consecutive passes, then one more round)\n")


def _spec(tmp_path) -> Path:
    return tmp_path / "state" / "vantage-runs" / f"{SID}.json"


def _fake_run(seen: dict, stdout: str, rc: int = 0):
    """A fake of the change script that records what it was run with."""

    def run(self, device, *args, **kwargs):
        seen["args"] = args
        seen["extra_env"] = kwargs.get("extra_env")
        return subprocess.CompletedProcess(list(args), rc, stdout, "")

    return run


def _held_apply(tmp_path, monkeypatch, record=None) -> dict:
    """Apply a held plan with client claims; the script run is faked."""
    seen: dict = {}
    record = record if record is not None else client_record()
    write_plan(tmp_path, record)
    monkeypatch.setattr(
        server.NewtonService, "run_script", _fake_run(seen, HELD)
    )
    service = server.NewtonService()
    result = service.apply("quasar", SID, hold=True)
    assert result["result"] == "held", result
    return seen


def test_a_held_apply_with_a_client_claim_is_applied_and_keeps_its_spec(
    tmp_path, monkeypatch
):
    """The hold is not refused for the client claims: the apply runs, and
    the spec of the client checks stays on disk for the confirm."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    seen = _held_apply(tmp_path, monkeypatch)
    assert seen["args"] == ("apply", "root@192.0.2.1", SID, "180", "--hold")
    assert seen["extra_env"]["OWRT_LOCAL_CHECK"].endswith(f"' {SID}")
    assert _spec(tmp_path).is_file()


def test_the_confirm_passes_the_client_check_and_removes_the_spec(
    tmp_path, monkeypatch
):
    """The confirm runs the same client checks: the sealed spec is what the
    vantage runner reads, and it is removed after the confirm."""
    write_inventory(tmp_path, monkeypatch)
    scripts = write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    seen: dict = {}
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run(seen, CONFIRMED))
    result = server.NewtonService().confirm("quasar", SID)
    assert result["result"] == "confirmed", result
    assert seen["args"] == ("confirm", "root@192.0.2.1", SID)
    assert seen["extra_env"]["OWRT_LOCAL_CHECK"] == (
        f"'{scripts / 'newton-vantage-run'}' {SID}"
    )
    assert seen["extra_env"]["NEWTON_VANTAGE_SPEC_DIR"] == str(
        tmp_path / "state" / "vantage-runs"
    )
    assert not _spec(tmp_path).exists()


def test_a_confirm_whose_local_check_failed_is_not_confirmed(tmp_path, monkeypatch):
    """The host does not confirm when the client check fails: the change is
    not confirmed and the router puts it back at its deadline."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    out = (f"ERROR: the local check failed before the confirm (exit 1); not confirmed: "
           f"the router rolls the change back when its window ends, or abort now: "
           f"owrt-change.sh abort root@192.0.2.1 {SID}\n")
    seen: dict = {}
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run(seen, out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert result["result"] == "not_confirmed", result
    assert "rolls the change back" in result["next_step"]
    assert not _spec(tmp_path).exists()


def test_a_confirm_refused_for_another_client_check_is_a_refusal(tmp_path, monkeypatch):
    """The host refused the confirm before the router was asked: the check
    of the held apply is not the check of the confirm, so the server
    reports it as a refusal and claims nothing about the change."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    out = (f"ERROR: the held apply of session {SID} ran a client check; run the confirm "
           "with the same OWRT_LOCAL_CHECK as the apply; nothing confirmed; to see where "
           f"session {SID} stands, run: owrt-change.sh status root@192.0.2.1 {SID}; to "
           f"roll it back now: owrt-change.sh abort root@192.0.2.1 {SID}\n")
    seen: dict = {}
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run(seen, out, rc=1))
    result = server.newton_confirm_change("quasar", SID)
    assert "ran a client check" in result["error"]
    assert "result" not in result and "newton_result" not in result


def test_the_apply_and_the_confirm_pass_the_same_client_check(tmp_path, monkeypatch):
    """The apply and the confirm of a held change run the same client
    checks: the OWRT_LOCAL_CHECK they pass is byte for byte the same, so
    the digest the hold record carries is the digest of the check the
    confirm runs, and the confirm is never refused for another one."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    applied = _held_apply(tmp_path, monkeypatch)
    seen: dict = {}
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run(seen, CONFIRMED))
    server.NewtonService().confirm("quasar", SID)
    assert seen["extra_env"]["OWRT_LOCAL_CHECK"] == applied["extra_env"]["OWRT_LOCAL_CHECK"]


def test_a_vantage_that_is_gone_refuses_the_confirm(tmp_path, monkeypatch):
    """The vantage that served the zone is gone: the confirm is refused
    before the router is asked, and the change is not confirmed."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    write_inventory(tmp_path, monkeypatch, include_vantage=False)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not ask the router"),
    )
    result = server.newton_confirm_change("quasar", SID)
    assert result["error"] == (
        "the client check vantage is gone; the change was not confirmed "
        "and the router puts it back at its deadline"
    )
    # the confirm never reached the router, so the window is still open and
    # the spec stays: the owner can register the vantage again and confirm
    assert _spec(tmp_path).is_file()


def test_a_confirm_without_the_plan_record_is_refused(tmp_path, monkeypatch):
    """The record of the held change is gone: the confirm cannot say which
    claims the change was sealed with, so it is refused before the router
    is asked and the change is not confirmed."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    (tmp_path / "state" / "plans" / f"{SID}.json").unlink()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not ask the router"),
    )
    result = server.newton_confirm_change("quasar", SID)
    assert result["error"] == UNREADABLE_RECORD


def test_a_confirm_with_a_tampered_plan_record_is_refused(tmp_path, monkeypatch):
    """The claim of the held change was taken out of the record on disk (a
    router claim took its place, so the record still reads) and the hash was
    left as it was: the record no longer says what the change was sealed
    with, so the confirm is refused before the router is asked and the
    change is not confirmed."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    path = tmp_path / "state" / "plans" / f"{SID}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["explanation"]["expect"][0]["kind"] == "client_dns"
    record["explanation"]["expect"] = [
        {"kind": "probe", "probe": ["iface-absent", "guestx"]}
    ]
    path.write_text(json.dumps(record), encoding="utf-8")
    # the hash was not recomputed: the record on disk is not the one that
    # was sealed
    assert compute_plan_hash(record) != record["plan_hash"]
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not ask the router"),
    )
    result = server.newton_confirm_change("quasar", SID)
    assert result["error"] == UNREADABLE_RECORD


def test_a_confirm_with_the_record_of_another_session_is_refused(tmp_path, monkeypatch):
    """The record of another session, copied into this session's file, is
    sealed and validly hashed, but it is not this session's record: the
    confirm is refused before the router is asked and the change is not
    confirmed."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    path = tmp_path / "state" / "plans" / f"{SID}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["session_id"] = "f" * 32
    record["plan_hash"] = compute_plan_hash(record)
    path.write_text(json.dumps(record), encoding="utf-8")
    # the record on disk is the one that was sealed: its hash matches
    assert compute_plan_hash(record) == record["plan_hash"]
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not ask the router"),
    )
    result = server.newton_confirm_change("quasar", SID)
    assert result["error"] == UNREADABLE_RECORD


def test_a_confirm_with_the_record_of_another_host_is_refused(tmp_path, monkeypatch):
    """The record names another host: the device's host is not the one the
    change was planned for, so the confirm is refused before the router is
    asked and the change is not confirmed."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    path = tmp_path / "state" / "plans" / f"{SID}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["host"] = "198.51.100.9"
    record["plan_hash"] = compute_plan_hash(record)
    path.write_text(json.dumps(record), encoding="utf-8")
    assert compute_plan_hash(record) == record["plan_hash"]
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not ask the router"),
    )
    result = server.newton_confirm_change("quasar", SID)
    assert result["error"] == UNREADABLE_RECORD


def test_a_status_that_finds_the_session_ended_removes_the_spec(tmp_path, monkeypatch):
    """The window passed unconfirmed and the router put the change back:
    the session is over, so the spec of its client checks goes with it."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    out = (f"rolled-back sid={SID} guard=restored:deadline rpcd=rolled-back config=base boot=same\n"
           f"HELD APPLY ROLLED BACK session={SID} (its window ended unconfirmed; the router's "
           "status says rolled-back)\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run({}, out))
    result = server.newton_change_status("quasar", SID)
    assert result["exit_code"] == 0, result
    assert not _spec(tmp_path).exists()


def test_a_status_that_finds_the_session_confirmed_removes_the_spec(tmp_path, monkeypatch):
    """The router confirmed the change and this host learned it from the
    status: the session is over, so the spec of its client checks goes with
    it, like it does after a rolled-back session."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    out = (f"confirmed sid={SID} guard=idle rpcd=- config=other boot=-\n"
           f"CONFIRMED session={SID} (reconciled: the router's status says confirmed)\n")
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run({}, out))
    result = server.newton_change_status("quasar", SID)
    assert result["exit_code"] == 0, result
    assert not _spec(tmp_path).exists()


def test_an_abort_removes_the_spec(tmp_path, monkeypatch):
    """The abort ends the session: the spec of its client checks goes with
    it, like it does after a confirm."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    _held_apply(tmp_path, monkeypatch)
    out = f"ABORTED session={SID} (restored)\nHELD APPLY ABORTED session={SID}\n"
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run({}, out))
    server.newton_abort_change("quasar", SID)
    assert not _spec(tmp_path).exists()


def test_a_plan_without_client_claims_passes_no_client_check(tmp_path, monkeypatch):
    """A plan with no client claim needs no vantage and no local check:
    the confirm is what it was."""
    write_inventory(tmp_path, monkeypatch)
    write_script_directory(tmp_path, monkeypatch)
    record = client_record(expect=[{"kind": "probe", "probe": ["iface-absent", "guestx"]}])
    record["probes"] = [["iface-absent", "guestx"]]
    record["plan_hash"] = compute_plan_hash(record)
    seen = _held_apply(tmp_path, monkeypatch, record)
    assert "OWRT_LOCAL_CHECK" not in seen["extra_env"]
    assert "NEWTON_VANTAGE_SPEC_DIR" not in seen["extra_env"]
    seen = {}
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_run(seen, CONFIRMED))
    result = server.NewtonService().confirm("quasar", SID)
    assert result["result"] == "confirmed", result
    assert not seen["extra_env"]
    assert not _spec(tmp_path).exists()
