"""the apply of a no-install auto plan.

ADR-021 point 4 and point 6: a change of an allowlisted class is
planned on a no-install router and applied by Newton itself, over the
router's own web API, with the same rules the installed apply has:

  * the plan record is loaded and verified (the plan hash), and the
    router digest is recomputed from the record's own ops, so a record
    whose ops were edited on disk is refused BEFORE the router is
    contacted;
  * the approval is consumed and settled, whether the apply succeeds
    or not;
  * the router is read again: a router that changed since the plan is
    refused, and nothing is applied;
  * the change is staged and applied in one session; a busy or refused
    router is a plain message and nothing is applied; a lost answer is
    resolved by reading the values back, and only a change that is
    provably ours is confirmed;
  * every mandatory check of every class runs, and then the plan's
    claims: a check that failed or could not run gives no confirm;
  * only a CONFIRMED change is a success; anything else is read back
    from the router, never inferred from the clock;
  * an owner-script record is never applied by Newton: the refusal
    names the command the owner runs.

No router is contacted: the whole flow runs over a fake rpcd router
that records every call.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import owner_records
from newton_mcp import noinstall_flow
from newton_mcp import noinstall_read
from newton_mcp import server as _server

import noinstall_answers
from noinstall_fakes import ApplyRouter

from test_inventory_noinstall import _no_install_body, _write_inventory


#: The measured dhcp config of lab-r1.
DHCP = noinstall_answers.data("uci.get.dhcp")["values"]

#: A DHCP reservation: the class Newton may apply itself.
RESERVATION = (
    "set dhcp.laptop=host\n"
    "set dhcp.laptop.mac='02:00:00:00:10:01'\n"
    "set dhcp.laptop.ip='10.109.0.55'\n"
)

#: A Wi-Fi name: never auto-applied on a no-install router.
WIFI_NAME = "set wireless.default_radio0.ssid='newname'\n"

#: A DNS server of the section the router already holds: the class of
#: this change needs the type the router holds.
DNS_SERVER = "set dhcp.cfg01411c.server='1.1.1.1'\n"


class Clock:
    """The clock of the test: the router and the settle read it."""

    def __init__(self) -> None:
        self.value = time.time()

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _explanation_for(batch: str) -> dict[str, Any]:
    """A valid explanation for one batch: one step per change line."""
    lines = [line for line in batch.splitlines() if line.strip()]
    return {
        "intent": "change one setting of the router",
        "steps": ["one change for the owner to read"] * len(lines),
        "expect": [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}],
        "risk": "the router's own settings change",
    }


def _setup(tmp_path: Path, monkeypatch) -> tuple[ApplyRouter, Clock]:
    """The inventory, the state dir and the fake router."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    router = ApplyRouter({"dhcp": DHCP})
    clock = Clock()
    router.now = clock
    monkeypatch.setattr(
        noinstall_read, "default_client_factory", lambda _device: router
    )
    return router, clock


def _state(tmp_path: Path) -> Path:
    return Path(os.environ["NEWTON_STATE_DIR"])


def _plan(
    tmp_path: Path, monkeypatch, batch: str = RESERVATION
) -> dict[str, Any]:
    """The plan of the DHCP reservation, over the fake router."""
    result = _server.newton_plan_change(
        "lab-r1",
        batch,
        explanation=_explanation_for(batch),
        owner_confirmed_in_chat=True,
    )
    assert "error" not in result, result
    return result


def _record(state: Path, sid: str) -> dict[str, Any]:
    return json.loads(
        (state / "plans" / f"{sid}.json").read_text(encoding="utf-8")
    )


def _approve(state: Path, sid: str, record: dict[str, Any]) -> None:
    """The approval the owner made in their own terminal."""
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=30)
    payload = {
        "plan_id": sid,
        "plan_hash": record["plan_hash"],
        "device": record["device"],
        "base_hash": record["base_hash"],
        "approved_by": "owner",
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "not_before": int(created.timestamp()),
        "not_after": int(expires.timestamp()),
        "token": "ab" * 32,
    }
    approvals = state / "approvals"
    approvals.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = approvals / f"{sid}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)


def _apply(
    tmp_path: Path,
    monkeypatch,
    router: ApplyRouter,
    clock: Clock,
    sid: str,
) -> dict[str, Any]:
    """The apply of a no-install plan, with the test's clock."""
    service = _server.NewtonService()
    return noinstall_flow.apply(
        service,
        "lab-r1",
        sid,
        now=clock,
        sleep=clock.advance,
    )


def _apply_error(
    tmp_path: Path,
    monkeypatch,
    router: ApplyRouter,
    clock: Clock,
    sid: str,
) -> str:
    """The apply of a plan that is refused, as the error it says."""
    with pytest.raises(_server.NewtonError) as caught:
        _apply(tmp_path, monkeypatch, router, clock, sid)
    return str(caught.value)


# ---- the happy path --------------------------------------------------------


def test_the_auto_plan_is_applied_and_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """One apply, one confirm: the change is on the router and stays."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "confirmed", result
    assert router.count("uci", "apply") == 1, router.calls
    assert router.count("uci", "confirm") == 1, router.calls
    # the reservation is on the router
    assert router.sections[("dhcp", "laptop")] == (
        "host",
        {"mac": "02:00:00:00:10:01", "ip": "10.109.0.55"},
    )


def test_the_apply_of_a_no_install_device_never_reaches_ssh(
    tmp_path: Path, monkeypatch
) -> None:
    """The apply goes to the router's own web API, never to ssh."""
    import subprocess

    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    ran: list = []
    original_run = subprocess.run

    def guarded_run(argv, *args, **kwargs):
        ran.append(argv)
        return original_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "confirmed", result
    assert ran == [], "the apply of a no-install device must not reach ssh"


# ---- the refusals before the router is touched -----------------------------


def test_the_router_changed_since_the_plan_is_refused_before_the_apply(
    tmp_path: Path, monkeypatch
) -> None:
    """A router that changed since the plan is refused: nothing applied."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    # the router's own settings change after the plan
    router.sections[("dhcp", "lan")] = (
        "dhcp",
        {"interface": "lan", "limit": "150", "start": "200"},
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "changed since the plan" in message
    assert router.count("uci", "apply") == 0, router.calls
    assert router.count("uci", "confirm") == 0, router.calls


def test_the_record_ops_are_bound_by_the_router_digest(
    tmp_path: Path, monkeypatch
) -> None:
    """The ops of a record are bound by the router digest.

    The plan hash does not cover the ops, so the digest is what binds
    them: a record whose ops were edited on disk is refused before the
    router is contacted at all.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    record = _record(state, sid)
    _approve(state, sid, record)

    # the ops are edited on disk; the plan hash still verifies
    record["ops"] = [["set", "dhcp.laptop", "host"]]
    (state / "plans" / f"{sid}.json").write_text(
        json.dumps(record, sort_keys=True), encoding="utf-8"
    )
    assert _server.compute_plan_hash(record) == record["plan_hash"]

    router.calls.clear()
    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "digest" in message or "modified" in message
    assert router.calls == [], "the router must not be contacted at all"
    assert router.count("uci", "apply") == 0


def test_the_apply_of_an_owner_script_record_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """An owner script is the owner's own bytes: Newton never applies it."""
    router, clock = _setup(tmp_path, monkeypatch)
    router.sections[("wireless", "default_radio0")] = (
        "wifi-iface",
        {"device": "radio0", "ssid": "labnet"},
    )
    plan = _plan(tmp_path, monkeypatch, WIFI_NAME)
    sid = plan["session_id"]
    assert plan["mode"] == "owner-script"
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "owner-run" in message
    assert router.count("uci", "apply") == 0


def test_the_apply_without_an_approval_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """No approval, no apply."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "approval" in message
    assert router.count("uci", "apply") == 0


# ---- the transaction -------------------------------------------------------


def test_a_refused_apply_leaves_the_router_alone(
    tmp_path: Path, monkeypatch
) -> None:
    """A router that refuses the apply is a plain message."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.apply_code = 6

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "not_applied", result
    assert router.count("uci", "confirm") == 0
    assert ("dhcp", "laptop") not in router.sections


def test_the_status_of_a_refused_apply_says_why(
    tmp_path: Path, monkeypatch
) -> None:
    """A refused apply leaves a run record, so the status says why.

    The status answers for a no-install plan: the notes of the run are
    the notes the apply gave.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.apply_code = 6

    answer = _apply(tmp_path, monkeypatch, router, clock, sid)

    status = _server.newton_change_status("lab-r1", sid)
    assert status["result"] == "not_applied", status
    # the run record carries the notes the apply gave
    assert answer["notes"], answer
    assert status["notes"] == answer["notes"], (status, answer)


def test_a_lost_answer_is_resolved_and_confirmed_when_it_is_ours(
    tmp_path: Path, monkeypatch
) -> None:
    """The answer was lost, but the values prove the change is ours."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.lose_apply_answer = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "confirmed", result
    assert router.count("uci", "confirm") == 1


def test_a_lost_answer_that_applied_nothing_is_never_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """The values do not hold the change: nothing is confirmed."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.lose_apply_answer = True
    router.lose_apply_answer_applies = False

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "not_applied", result
    assert router.count("uci", "confirm") == 0


# ---- the checks ------------------------------------------------------------


def test_a_failing_mandatory_check_gives_no_confirm_and_the_router_rolls_it_back(
    tmp_path: Path, monkeypatch
) -> None:
    """A check that fails blocks the confirm, and the router undoes it."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_running = False

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert router.count("uci", "confirm") == 0, router.calls
    # the router put the change back
    assert ("dhcp", "laptop") not in router.sections


def test_a_check_that_cannot_run_is_listed_and_gives_no_confirm(
    tmp_path: Path, monkeypatch
) -> None:
    """A check that could not run is not verified, and it blocks."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_refused = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert router.count("uci", "confirm") == 0, router.calls
    assert result["not_verified"], result


def test_a_rolled_back_created_section_is_a_revert_and_not_an_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    """A missing unit is absent: the read-back proves the rollback.

    The router answers a missing section with [0] and no data (the
    measured answer), so the settle can say the change was put back
    instead of saying it cannot tell.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    router.absence_answers_empty = True
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_running = False

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert router.count("uci", "confirm") == 0, router.calls
    assert ("dhcp", "laptop") not in router.sections


def test_a_window_that_never_closes_gives_unknown_and_the_restart_note(
    tmp_path: Path, monkeypatch
) -> None:
    """A window the router forgot says the change stayed.

    After a restart of the router's web service the window is gone but
    the undo file stays (measured, a4m-02): the change stays on the
    router and Newton can no longer confirm or undo it.  It says so
    instead of saying it cannot tell.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    router.never_close = True
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_running = False

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "unknown", result
    assert (
        "the window did not close on the router: its web service most likely "
        "restarted, so the change stayed (see the reboot line)"
    ) in result["notes"], result
    assert router.count("uci", "confirm") == 0, router.calls


# ---- the status and the abort ---------------------------------------------


def test_the_status_of_a_no_install_plan_answers(
    tmp_path: Path, monkeypatch
) -> None:
    """The status answers for a no-install plan id."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    planned = _server.newton_change_status("lab-r1", sid)
    assert "error" not in planned, planned
    assert planned["result"] == "not_applied", planned

    _apply(tmp_path, monkeypatch, router, clock, sid)

    after = _server.newton_change_status("lab-r1", sid)
    assert "error" not in after, after
    assert after["result"] == "confirmed", after


def test_the_abort_of_a_no_install_plan_drops_the_plan(
    tmp_path: Path, monkeypatch
) -> None:
    """Before an apply, an abort drops the plan and changes nothing."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert not (state / "plans" / f"{sid}.json").exists()
    assert router.count("uci", "apply") == 0


def test_the_abort_during_an_apply_says_the_router_undoes_it(
    tmp_path: Path, monkeypatch
) -> None:
    """During an apply there is nothing to abort: the router undoes it."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    # an apply is in flight: the approval is claimed
    (state / "approvals" / f"{sid}.claimed").write_text("{}", encoding="utf-8")

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert "undoes it unless Newton confirms" in result["message"]
    assert (state / "plans" / f"{sid}.json").exists()


# ---- the receipt -----------------------------------------------------------


def test_the_apply_writes_a_receipt(tmp_path: Path, monkeypatch) -> None:
    """A confirmed change leaves a receipt, as an installed one does."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    _apply(tmp_path, monkeypatch, router, clock, sid)

    receipts = sorted((state / "receipts").glob(f"*-{sid}.md"))
    assert len(receipts) == 1, list((state / "receipts").glob("*"))
    text = receipts[0].read_text(encoding="utf-8")
    assert "CONFIRMED" in text


# ---- the grant --------------------------------------------------------


def test_a_grant_never_approves_an_owner_script_plan(
    tmp_path: Path, monkeypatch
) -> None:
    """A live grant never writes the approval of an owner script.

    An owner script is the owner's own bytes: the owner is asked for it
    at the owner-run, in their own terminal.  An approval written here
    would skip that question, so a grant never writes one.
    """
    import asyncio

    from newton_mcp import elicit_approval, grants

    router, clock = _setup(tmp_path, monkeypatch)
    state = _state(tmp_path)
    grants.open_grant("lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32)
    # a new section with no settings of its own: the class a grant
    # covers, but a change Newton cannot apply itself
    batch = "set dhcp.newhost=host\n"
    planned = _server.newton_plan_change(
        "lab-r1",
        batch,
        explanation=_explanation_for(batch),
        owner_confirmed_in_chat=True,
    )
    assert "error" not in planned, planned
    sid = planned["session_id"]
    assert _record(state, sid)["router_leash"] == "owner-script"

    outcome = asyncio.run(
        elicit_approval.collect_approval(None, "lab-r1", sid)
    )

    assert outcome.grant_used is False, outcome
    assert outcome.status != "approved", outcome
    assert not (state / "approvals" / f"{sid}.json").exists()


def test_a_grant_covers_an_auto_apply(tmp_path: Path, monkeypatch) -> None:
    """A live grant is the owner's consent: the apply needs no chat yes."""
    from newton_mcp import grants

    router, clock = _setup(tmp_path, monkeypatch)
    state = _state(tmp_path)
    grants.open_grant("lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32)
    result = _server.newton_plan_change(
        "lab-r1",
        RESERVATION,
        explanation=_explanation_for(RESERVATION),
        owner_confirmed_in_chat=False,
    )
    assert "error" not in result, result
    assert result["consent_basis"] == "grant"
    sid = result["session_id"]
    _approve(state, sid, _record(state, sid))

    applied = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert applied["result"] == "confirmed", applied


# ---- the exceptions -----------------------------------------


def _run_record(state: Path, sid: str) -> dict[str, Any]:
    """The run record of a plan: what the status answers with."""
    return json.loads(
        (
            state / "owner-scripts" / sid / "run.json"
        ).read_text(encoding="utf-8")
    )


def test_a_lost_answer_the_router_cannot_reach_gives_unknown_and_a_run_record(
    tmp_path: Path, monkeypatch
) -> None:
    """The answer to the apply was lost and the router went away.

    The change may be live on the router: the approval is consumed, the
    run record and the receipt are written, and the owner is told the
    outcome is unknown.  Newton never says "not applied" for a change
    it cannot read back.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.lose_apply_answer = True
    router.unreachable_after_apply = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "unknown", result
    assert _run_record(state, sid)["outcome"] == "unknown"
    # the receipt is written: the change may be on the router
    assert list((state / "receipts").glob(f"*-{sid}.md"))
    # the approval is consumed: it may have reached the router
    assert (state / "approvals" / f"{sid}.used").exists()
    assert not (state / "approvals" / f"{sid}.json").exists()


def test_a_check_that_cannot_log_in_is_not_verified_and_gives_no_confirm(
    tmp_path: Path, monkeypatch
) -> None:
    """The router cannot be reached for the checks: no check ran.

    A check that could not run is not a verified check: it is listed
    for the owner and it blocks the confirm.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.login_fails_after_apply = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "unknown", result
    assert result["not_verified"], result
    assert router.count("uci", "confirm") == 0, router.calls
    assert _run_record(state, sid)["outcome"] == "unknown"


def test_a_confirm_that_fails_gives_a_run_record_and_a_read_back(
    tmp_path: Path, monkeypatch
) -> None:
    """The confirm never came back: the change is read back, not guessed.

    The confirm is not a proof that it happened, so the router is read
    back after the window and the outcome is the one the router shows.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.confirm_fails = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert any("confirm" in note for note in result["notes"]), result
    assert _run_record(state, sid)["outcome"] == "rolled_back"
    assert list((state / "receipts").glob(f"*-{sid}.md"))


def test_a_settle_that_cannot_read_gives_unknown_and_a_run_record(
    tmp_path: Path, monkeypatch
) -> None:
    """The router cannot be read back: the outcome is unknown.

    An answer Newton cannot read is never an answer, and it never
    crashes the apply: the run record is written all the same.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.reads_fail_after_apply = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "unknown", result
    assert (
        "Newton cannot tell what the router did with the change"
        in result["notes"]
    ), result
    assert _run_record(state, sid)["outcome"] == "unknown"
    assert list((state / "receipts").glob(f"*-{sid}.md"))


# ---- the record must agree with itself ----------------------


def _rewrite(state: Path, sid: str, record: dict[str, Any]) -> None:
    """Write a record back, with its plan hash recomputed."""
    record["plan_hash"] = _server.compute_plan_hash(record)
    (state / "plans" / f"{sid}.json").write_text(
        json.dumps(record, sort_keys=True), encoding="utf-8"
    )


def _edited_record(
    tmp_path: Path, monkeypatch, *, batch: str = RESERVATION, **changes: Any
) -> tuple[ApplyRouter, Clock, str, Path, dict[str, Any]]:
    """A plan whose record was edited, with its hash recomputed."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch, batch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    record = _record(state, sid)
    record.update(changes)
    record["router_digest"] = noinstall_flow._router_digest(record)
    _rewrite(state, sid, record)
    _approve(state, sid, record)
    return router, clock, sid, state, record


def test_edited_ops_with_a_fresh_digest_and_hash_are_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """The ops of a record must be the ops of its own batch.

    A record whose ops were swapped for another change, with the digest
    and the plan hash recomputed to match, is refused before anything
    is written to the router.
    """
    router, clock, sid, state, _record = _edited_record(
        tmp_path, monkeypatch, ops=[["set", "dhcp.lan", "host"]]
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "its own change" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_whose_diff_is_not_the_diff_of_its_batch_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """The diff the owner reads must be the diff the change makes."""
    router, clock, sid, state, _record = _edited_record(
        tmp_path, monkeypatch, diff="dhcp.lan='other'"
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "its own change" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_with_another_leash_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """A no-install apply is for the rpcd leash and for no other."""
    router, clock, sid, state, _record = _edited_record(
        tmp_path, monkeypatch, router_leash="owner-script"
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "leash" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_with_another_profile_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """A no-install apply is for the no-install profile and for no other."""
    router, clock, sid, state, _record = _edited_record(
        tmp_path, monkeypatch, router_profile="installed"
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "profile" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_that_needs_no_approval_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """A change Newton applies itself always needs an approval."""
    router, clock, sid, state, _record = _edited_record(
        tmp_path, monkeypatch, requires_approval=False
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "approval" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_with_a_malformed_explanation_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """An explanation Newton cannot read is refused, never dropped.

    A malformed explanation used to be swallowed into an empty list of
    claims, which made the apply look verified when nothing had been
    checked.
    """
    router, clock, sid, state, _record = _edited_record(
        tmp_path, monkeypatch, explanation={"intent": "do a thing"}
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "explanation" in message, message
    assert router.count("uci", "apply") == 0, router.calls


# ---- the internet check ----------------------------------------------------


def test_an_apply_whose_ping_fails_is_not_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """The router's own internet check comes first: no internet, no confirm.

    The installed router program runs the same check before every
    confirm, so a router without the internet confirms nothing here
    either.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.exec_fails = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert router.count("uci", "confirm") == 0, router.calls
    assert "the internet check failed" in result["notes"], result


def test_an_apply_whose_ping_works_and_whose_dns_does_not_is_not_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """The ping is not the internet check: the name has to resolve too.

    The installed router program runs a ping and a lookup before every
    confirm, so a router that answers the ping and cannot resolve a
    name has no working internet: the change is not confirmed.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.exec_answers = {"/usr/bin/nslookup": {"code": 1}}

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert router.count("uci", "confirm") == 0, router.calls
    assert "the internet check failed" in result["notes"], result
def test_an_apply_whose_ping_fails_twice_and_then_works_is_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """The restore case: the internet comes back, and the change stays.

    The router's own network reload finishes after the apply returns,
    so the first probes can fail while the uplinks are still down.  The
    check retries, and a router that has the internet again confirms
    the change.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    pings = {"count": 0}

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        if obj == "file" and fn == "exec" and args.get("command") == "/bin/ping":
            pings["count"] += 1
            router.exec_fails = pings["count"] <= 2

    router.on_call = on_call
    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "confirmed", result
    assert router.count("uci", "confirm") == 1, router.calls


def test_an_apply_whose_ping_works_only_in_the_first_second_is_not_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """The measured case: the check ran before the uplinks were down.

    On the real router an owner script that took the uplinks down was
    confirmed 2.8 s after the run started, and the internet check ran
    about a second after the apply, while netifd had not taken the
    uplinks down yet.  The check waits for the reload, so the ping
    that still works in the first second is not the answer.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    applied_at = clock.value

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        # the router has the internet only in the first second
        router.exec_fails = (clock() - applied_at) > 1

    router.on_call = on_call
    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    assert router.count("uci", "confirm") == 0, router.calls
    assert "the internet check failed" in result["notes"], result


# ---- the status, the abort and the cleanup -------------------


def test_the_abort_of_an_applied_plan_refuses_and_keeps_the_plan(
    tmp_path: Path, monkeypatch
) -> None:
    """A change that ran cannot be aborted: it is on the router.

    The abort of a plan that has a run drops nothing: the run says the
    change is live, and a plan that says "nothing was applied" would be
    a lie.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    _apply(tmp_path, monkeypatch, router, clock, sid)

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert result["result"] == "not_aborted", result
    assert (state / "plans" / f"{sid}.json").exists()


def test_the_abort_drops_the_approval_of_an_unapplied_plan(
    tmp_path: Path, monkeypatch
) -> None:
    """A plan that never ran is dropped whole: the approval goes too.

    An approval left on disk is an approval the owner can still use, so
    dropping the plan drops it with it.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    assert (state / "approvals" / f"{sid}.json").exists()

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert result["result"] == "aborted", result
    assert not (state / "plans" / f"{sid}.json").exists()
    assert not (state / "approvals" / f"{sid}.json").exists()


# ---- the abort of a change that was never applied ------


def test_the_abort_of_a_change_that_was_never_applied_drops_the_plan(
    tmp_path: Path, monkeypatch
) -> None:
    """A run that PROVED the change was never applied may be dropped.

    The run says the change is not on the router, so there is nothing
    to abort and nothing to undo: the plan may go, and the approval
    with it.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    owner_records.write_run(
        state,
        sid,
        {"started_at": time.time(), "outcome": "not_applied"},
    )

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert result["result"] == "aborted", result
    assert not (state / "plans" / f"{sid}.json").exists()
    assert not (state / "approvals" / f"{sid}.json").exists()
    assert router.count("uci", "apply") == 0


def test_the_abort_of_an_owner_script_that_never_reached_the_router_drops_it(
    tmp_path: Path, monkeypatch
) -> None:
    """An owner script's run that proved NOT APPLIED may be dropped too.

    The verdict is the run's own word: the change never reached the
    router, so the plan may go.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    router.sections[("wireless", "default_radio0")] = (
        "wifi-iface",
        {"device": "radio0", "ssid": "labnet"},
    )
    plan = _plan(tmp_path, monkeypatch, WIFI_NAME)
    sid = plan["session_id"]
    assert plan["mode"] == "owner-script", plan
    state = _state(tmp_path)
    owner_records.write_run(
        state,
        sid,
        {
            "started_at": time.time(),
            "verdict": {
                "state": "NOT APPLIED",
                "notes": ["the change was never applied"],
                "not_verified": [],
            },
        },
    )

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert result["result"] == "aborted", result
    assert not (state / "plans" / f"{sid}.json").exists()


@pytest.mark.parametrize(
    "run",
    [
        {"outcome": "confirmed"},
        {"outcome": "rolled_back"},
        {"outcome": "unknown"},
        {"verdict": {"state": "CONFIRMED"}},
        {"verdict": {"state": "ROLLED BACK"}},
        {"verdict": {"state": "KEPT"}},
        {"verdict": {"state": "UNKNOWN"}},
    ],
)
def test_the_abort_of_a_change_that_ran_refuses(
    tmp_path: Path, monkeypatch, run: dict[str, Any]
) -> None:
    """Only a run that PROVED the change was never applied may be
    dropped.

    A confirmed, a rolled back, a kept and an unknown run all leave
    the change on the router (or leave it undecided), so the plan stays.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    owner_records.write_run(
        state, sid, {"started_at": time.time(), **run}
    )

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert result["result"] == "not_aborted", result
    assert (state / "plans" / f"{sid}.json").exists()


def test_the_abort_of_a_change_that_is_in_flight_refuses(
    tmp_path: Path, monkeypatch
) -> None:
    """An apply that is running is not aborted, not even when the run
    says the change was never applied.

    The run of an apply that is in flight may be written before the
    apply ends: the approval that is claimed is the truth here.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    owner_records.write_run(
        state,
        sid,
        {"started_at": time.time(), "outcome": "not_applied"},
    )
    (state / "approvals" / f"{sid}.claimed").write_text("{}", encoding="utf-8")

    result = _server.newton_abort_change("lab-r1", sid)

    assert "error" not in result, result
    assert result["result"] == "not_aborted", result
    assert "undoes it unless Newton confirms" in result["message"]
    assert (state / "plans" / f"{sid}.json").exists()


def test_the_status_of_an_owner_script_run_answers_its_verdict(
    tmp_path: Path, monkeypatch
) -> None:
    """The status of an owner script says what the run said.

    An owner script's verdict lives under "verdict", not under
    "outcome": a run that confirmed is a confirmed change, not a
    "not applied" one.
    """
    from newton_mcp import owner_records

    router, clock = _setup(tmp_path, monkeypatch)
    router.sections[("wireless", "default_radio0")] = (
        "wifi-iface",
        {"device": "radio0", "ssid": "labnet"},
    )
    plan = _plan(tmp_path, monkeypatch, WIFI_NAME)
    sid = plan["session_id"]
    assert plan["mode"] == "owner-script", plan
    state = _state(tmp_path)
    owner_records.write_run(
        state,
        sid,
        {
            "started_at": time.time(),
            "verdict": {
                "state": "CONFIRMED",
                "notes": ["the owner kept it"],
                "not_verified": [],
            },
        },
    )

    status = _server.newton_change_status("lab-r1", sid)

    assert "error" not in status, status
    assert status["result"] == "confirmed", status
    assert status["notes"] == ["the owner kept it"], status


def test_the_owner_cleanup_removes_the_auto_plans_of_the_device(
    tmp_path: Path, monkeypatch
) -> None:
    """The cleanup removes the auto plans too, not only the scripts.

    An auto plan leaves a plan record and a run directory behind, and
    an uninstall that leaves them is an uninstall that half happened.
    """
    from newton_mcp import rpcd_cli

    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    _apply(tmp_path, monkeypatch, router, clock, sid)
    assert (state / "plans" / f"{sid}.json").exists()
    assert (state / "owner-scripts" / sid).exists()

    code = rpcd_cli.main(["owner-cleanup", "lab-r1"])

    assert code == 0
    assert not (state / "plans" / f"{sid}.json").exists()
    assert not (state / "owner-scripts" / sid).exists()


def test_the_owner_cleanup_does_not_read_the_inventory(
    tmp_path: Path, monkeypatch
) -> None:
    """A bad entry of another device does not block this one's uninstall.

    The cleanup needs the state directory and the device name, and
    nothing else: one entry of another device that cannot be read must
    not stop this device from being cleaned up.
    """
    from newton_mcp import rpcd_cli

    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    _apply(tmp_path, monkeypatch, router, clock, sid)
    # a second device whose entry the inventory cannot read
    _write_inventory(
        tmp_path,
        monkeypatch,
        _no_install_body(
            tmp_path,
            extra=(
                '[devices.broken]\nplatform = "nonsense"\n'
                'host = "192.0.2.9"\nuser = "root"\n'
            ),
        ),
    )

    code = rpcd_cli.main(["owner-cleanup", "lab-r1"])

    assert code == 0
    assert not (state / "plans" / f"{sid}.json").exists()
    assert not (state / "owner-scripts" / sid).exists()


def test_the_owner_cleanup_keeps_the_records_of_another_device(
    tmp_path: Path, monkeypatch
) -> None:
    """The cleanup removes this device's plans and nobody else's."""
    from newton_mcp import rpcd_cli

    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    _apply(tmp_path, monkeypatch, router, clock, sid)
    other = "b" * 32
    other_record = _record(state, sid)
    other_record["device"] = "other-device"
    other_record["router_leash"] = "owner-script"
    (state / "plans" / f"{other}.json").write_text(
        json.dumps(other_record), encoding="utf-8"
    )

    code = rpcd_cli.main(["owner-cleanup", "lab-r1"])

    assert code == 0
    assert not (state / "plans" / f"{sid}.json").exists()
    assert (state / "plans" / f"{other}.json").exists()


def test_the_owner_cleanup_of_a_bad_device_name_fails(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A name that is not a device name is refused."""
    from newton_mcp import rpcd_cli

    _setup(tmp_path, monkeypatch)

    code = rpcd_cli.main(["owner-cleanup", "Not A Device"])

    assert code != 0
    assert "unknown device" in capsys.readouterr().out


def test_the_window_of_the_apply_is_the_clock_of_the_caller(
    tmp_path: Path, monkeypatch
) -> None:
    """The deadline and the settle are the caller's clock.

    The window of the apply is measured with the clock the caller
    gives: the settle gives up when ITS deadline is reached, not when
    the wall clock says so.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    clock.value = 0.0
    router.never_close = True
    # a settle that never gives up would spin for ever: the router
    # stops answering instead
    router.call_limit = 300
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_running = False

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "unknown", result
    assert (
        "the window did not close on the router: its web service most likely "
        "restarted, so the change stayed (see the reboot line)"
    ) in result["notes"], result


# ---- the status of a run in flight ----------------------------


def test_the_status_of_a_claimed_approval_says_in_progress(
    tmp_path: Path, monkeypatch
) -> None:
    """While the approval is claimed the change is being applied.

    The router undoes the change unless Newton confirms it, so the
    status must never say that nothing was applied.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    (state / "approvals" / f"{sid}.claimed").write_text("{}", encoding="utf-8")

    status = _server.newton_change_status("lab-r1", sid)

    assert "error" not in status, status
    assert status["result"] == "in_progress", status
    assert "undoes it unless Newton confirms" in " ".join(status["notes"])


def test_the_status_of_a_started_run_without_an_outcome_says_in_progress(
    tmp_path: Path, monkeypatch
) -> None:
    """A run that started and has not ended yet is in progress.

    The owner-run writes the start of the run before it sends the
    script: until the run ends, the change may be on the router.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    owner_records.write_run(state, sid, {"started_at": time.time()})

    status = _server.newton_change_status("lab-r1", sid)

    assert "error" not in status, status
    assert status["result"] == "in_progress", status
    assert "undoes it unless Newton confirms" in " ".join(status["notes"])


# ---- the types and the risk are bound -------------------------


def test_a_record_whose_section_types_are_not_the_types_the_router_holds_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """The types of the sections a change touches are the router's own.

    The types decide the class of the change, and the class decides
    what a grant covers, so a record whose types were edited on disk
    must not be applied: the apply reads the router again and compares
    the types with the ones the record carries.  A key that was
    stripped from the record is a mismatch too.
    """
    router, clock, sid, state, record = _edited_record(
        tmp_path,
        monkeypatch,
        batch=DNS_SERVER,
        section_types={},
    )
    assert record["section_types"] == {}, record

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "section types" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_whose_section_type_wrongs_the_router_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """A type the router does not hold is refused, even with a fresh hash."""
    router, clock, sid, state, record = _edited_record(
        tmp_path,
        monkeypatch,
        batch=DNS_SERVER,
        section_types={"dhcp.cfg01411c": "host"},
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "section types" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_record_whose_risk_is_not_the_risk_of_its_change_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """The risk of the record is the risk the policy gives the change.

    The policy judges the change from the diff and the router's own
    facts, so the apply judges it again and refuses a record that
    claims another risk.
    """
    router, clock, sid, state, record = _edited_record(
        tmp_path, monkeypatch, risk="high"
    )

    message = _apply_error(tmp_path, monkeypatch, router, clock, sid)

    assert "risk" in message, message
    assert router.count("uci", "apply") == 0, router.calls


def test_a_grant_covers_a_no_install_change_of_a_section_the_router_holds(
    tmp_path: Path, monkeypatch
) -> None:
    """The types of a no-install record are used, and the grant covers it.

    The class of a change of a section the router already holds needs
    the type the router holds, and the no-install record carries it.
    The digest binds those types to the record, so they are used.
    """
    import asyncio

    from newton_mcp import elicit_approval, grants

    router, clock = _setup(tmp_path, monkeypatch)
    state = _state(tmp_path)
    grants.open_grant("lab-r1", ["dns"], 1, "ab" * 32, "0" * 32)
    result = _server.newton_plan_change(
        "lab-r1",
        DNS_SERVER,
        explanation=_explanation_for(DNS_SERVER),
        owner_confirmed_in_chat=False,
    )
    assert "error" not in result, result
    assert result["consent_basis"] == "grant"
    sid = result["session_id"]
    assert _record(state, sid)["section_types"] == {"dhcp.cfg01411c": "dnsmasq"}

    outcome = asyncio.run(
        elicit_approval.collect_approval(None, "lab-r1", sid)
    )

    assert outcome.status == "approved", outcome
    assert outcome.grant_used is True, outcome
