"""the running state of a no-install router after its own rollback timer
put the old settings back (rule 9).

Rule 9 of the change protocol: after an automatic restore, the running
settings are shown to match, or Newton says plainly they may not and
prints the fix.

A no-install router runs no Newton program.  The change goes over
rpcd, and the router holds the revert in its own rollback window
(``uci apply`` with a rollback): when that window closes without a
confirm, the router puts the old settings back on its own.  Newton has
no program on the router and no snapshot of the services that ran
before the change, so it cannot show that the running network matches
the settings that are back.  It says so plainly and prints the fix,
the same way the installed mode says it (the ``unproven`` of the
installed contract, ``server.RUNNING_MISMATCH_NEXT_STEP``).

Every other state of a no-install session says nothing about the
running state: a confirmed change, a plan Newton dropped, a change
that is staged on the router, a change that was never applied and a
change whose outcome is unknown.  Nothing was restored in those, so
there is nothing to warn about.

The router is the fake of the no-install mode (``noinstall_fakes``): its
rollback window is its own timer, and the window closes when the clock
of the test passes it.  No router is contacted.
"""

from __future__ import annotations

import time
from pathlib import Path

from newton_mcp import owner_records
from newton_mcp import server as _server

from test_noinstall_apply import (
    WIFI_NAME,
    _apply,
    _approve,
    _plan,
    _record,
    _setup,
    _state,
)


#: The next step of the installed mode, word for word: the no-install
#: mode says the same thing about the same question.
NEXT_STEP = (
    "the router put the old settings back on its own, but Newton cannot show the running "
    "network matches them; on the router run: reload_config; /etc/init.d/firewall restart; "
    "wifi reload"
)

#: The running state of a router Newton cannot prove: the same word the
#: installed mode uses when it has no health snapshot of the session.
UNPROVEN = "unproven"

#: The section the change adds to the router.
RESERVATION_SECTION = ("dhcp", "laptop")


# ---- the change the router rolls back --------------------------------------


def test_a_change_the_rpcd_timer_rolled_back_says_the_running_state_is_unproven(
    tmp_path: Path, monkeypatch
) -> None:
    """The router's own timer put the old settings back: Newton says so
    and prints the fix.

    The check of the class fails, so nothing is confirmed: the rollback
    window of the router closes without a confirm and the router puts
    the change back on its own.  Newton has no program on the router
    and no snapshot of the services that ran before the change, so it
    cannot show that the running network matches the settings that are
    back: the status says ``unproven`` and names the fix.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_running = False

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "rolled_back", result
    # the router put the change back on its own
    assert RESERVATION_SECTION not in router.sections, router.sections

    status = _server.newton_change_status("lab-r1", sid)

    assert status["result"] == "rolled_back", status
    assert status["running"] == UNPROVEN, status
    assert status["next_step"] == _server.RUNNING_MISMATCH_NEXT_STEP, status
    assert status["next_step"] == NEXT_STEP, status


# ---- the states that say nothing about the running state -------------------


def test_a_confirmed_change_says_nothing_about_the_running_state(
    tmp_path: Path, monkeypatch
) -> None:
    """A confirmed change stays on the router: nothing was restored, so
    there is no running state to warn about."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "confirmed", result
    status = _server.newton_change_status("lab-r1", sid)
    assert status["result"] == "confirmed", status
    assert "running" not in status, status
    assert "next_step" not in status, status


def test_a_change_newton_aborted_says_nothing_about_the_running_state(
    tmp_path: Path, monkeypatch
) -> None:
    """A plan Newton dropped says nothing about the running state.

    Newton's abort of a no-install plan drops it: nothing was applied,
    so nothing was restored either.  The abort claims no running state
    and prints no fix, and the status of that session says the plan is
    gone instead of claiming anything about the router.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]

    aborted = _server.newton_abort_change("lab-r1", sid)

    assert aborted["result"] == "aborted", aborted
    assert "running" not in aborted, aborted
    assert "next_step" not in aborted, aborted
    assert router.count("uci", "apply") == 0, router.calls

    status = _server.newton_change_status("lab-r1", sid)
    assert "running" not in status, status
    assert "next_step" not in status, status
    # the plan is gone: there is no session left to say anything
    assert status.get("error"), status


def test_a_change_that_is_staged_says_nothing_about_the_running_state(
    tmp_path: Path, monkeypatch
) -> None:
    """A change that is staged on the router, waiting for its window to
    close, says nothing about the running state.

    The apply is in flight: the approval is claimed, so the change may
    be on the router with the rollback window of the router open.  The
    router has not put anything back yet, so there is nothing to warn
    about.  When the window closes without a confirm, the router puts
    the change back and the status says so (the test above).
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    # an apply is in flight: the approval is claimed
    (state / "approvals" / f"{sid}.claimed").write_text("{}", encoding="utf-8")

    status = _server.newton_change_status("lab-r1", sid)

    assert status["result"] == "in_progress", status
    assert "undoes it unless Newton confirms" in " ".join(status["notes"]), status
    assert "running" not in status, status
    assert "next_step" not in status, status


def test_a_change_that_was_never_applied_says_nothing_about_the_running_state(
    tmp_path: Path, monkeypatch
) -> None:
    """A change that was never applied says nothing about the running
    state: the router was never touched."""
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]

    status = _server.newton_change_status("lab-r1", sid)

    assert status["result"] == "not_applied", status
    assert "running" not in status, status
    assert "next_step" not in status, status
    assert router.count("uci", "apply") == 0, router.calls


def test_an_unknown_change_says_nothing_about_the_running_state(
    tmp_path: Path, monkeypatch
) -> None:
    """A change whose outcome is unknown says nothing about the running
    state.

    The window of the router never closes (its web service restarted
    and forgot it), so Newton cannot tell what the router did with the
    change.  It says that instead of claiming anything about the
    running network.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.service_running = False
    router.never_close = True

    result = _apply(tmp_path, monkeypatch, router, clock, sid)

    assert result["result"] == "unknown", result
    status = _server.newton_change_status("lab-r1", sid)
    assert status["result"] == "unknown", status
    assert "running" not in status, status
    assert "next_step" not in status, status


# ---- the owner script of the same mode -------------------------------------


def test_an_owner_script_the_router_rolled_back_says_the_running_state_is_unproven(
    tmp_path: Path, monkeypatch
) -> None:
    """The owner's script applied the change and the router's own timer
    put it back: the running state is unproven.

    The owner script of a no-install router applies the change with the
    router's own rollback window, so the router's timer puts the change
    back when the window closes without a confirm.  Newton cannot show
    that the running network matches the settings that are back, so the
    status says ``unproven`` and names the fix.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    router.sections[("wireless", "default_radio0")] = (
        "wifi-iface",
        {"device": "radio0", "ssid": "newton-test"},
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
                "state": "ROLLED BACK",
                "notes": ["the router put the change back"],
                "not_verified": [],
            },
        },
    )

    status = _server.newton_change_status("lab-r1", sid)

    assert status["result"] == "rolled_back", status
    assert status["running"] == UNPROVEN, status
    assert status["next_step"] == _server.RUNNING_MISMATCH_NEXT_STEP, status
    assert status["next_step"] == NEXT_STEP, status


def test_a_restore_the_router_rolled_back_says_nothing_about_the_running_state(
    tmp_path: Path, monkeypatch
) -> None:
    """A restore that the router rolled back says nothing about the
    running state.

    The restore of a change is the other way round: the router put the
    *undo* back, so the change is still live on the router.  Saying that
    the old settings are back would be false, so the status says
    nothing about the running state.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    router.sections[("wireless", "default_radio0")] = (
        "wifi-iface",
        {"device": "radio0", "ssid": "newton-test"},
    )
    plan = _plan(tmp_path, monkeypatch, WIFI_NAME)
    restore_sid = plan["restore_session_id"]
    assert plan["mode"] == "owner-script", plan
    state = _state(tmp_path)
    owner_records.write_run(
        state,
        restore_sid,
        {
            "started_at": time.time(),
            "verdict": {
                "state": "ROLLED BACK",
                "notes": ["the router put the restore back"],
                "not_verified": [],
            },
        },
    )

    status = _server.newton_change_status("lab-r1", restore_sid)

    assert status["result"] == "rolled_back", status
    assert "running" not in status, status
    assert "next_step" not in status, status
