"""controller loss in the middle of a no-install change (rule 10).

Rule 10 of the change protocol: when the controller is lost in the
middle of a change, the device ends in the pre-change state or in the
confirmed state, never in between.

The controller of the no-install mode is the MCP process: it drives the
router over the router's own web API (rpcd), and the router holds the
revert while the change waits for the confirmation (its own rollback
window, opened by ``uci apply``).  Here the controller is LOST at an
exact point of one apply run: the fake router raises
``KeyboardInterrupt`` -- an exception that nothing catches -- at that
point, so the flow stops there with no clean-up of its own, the way the
process stops when it is killed.

Three points are proved, and the three are the three ends rule 10
allows:

  (a) right after the change is applied on the router, before the first
      verify: the router holds the change and its window is open, and
      the window closes by itself, so the router puts the change back;
  (b) after the verify passed, before the confirm was sent: the same,
      the confirm never reached the router and the window puts the
      change back;
  (c) after the confirm was sent and answered: the router confirmed, so
      the change stays and no revert is armed any more.

The router is the fake of the no-install mode (``noinstall_fakes``): its
rollback window is its own timer, and the window closes when the clock
of the test passes it.  No router is contacted.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import noinstall_flow
from newton_mcp import noinstall_read
from newton_mcp import rpcd_txn
from newton_mcp import server as _server
from newton_mcp.adapters import openwrt_rpcd as rpcd

from noinstall_fakes import ApplyRouter

from test_inventory_noinstall import _no_install_body, _write_inventory
from test_noinstall_apply import (
    DHCP,
    RESERVATION,
    Clock,
    _approve,
    _plan,
    _record,
)


#: The change the plan makes: a DHCP reservation the class of the change
#: lets Newton apply itself.
CHANGE = RESERVATION

#: The section the change adds, as the router holds it afterwards.
RESERVATION_SECTION = (
    "dhcp",
    "laptop",
)


class LossRouter(ApplyRouter):
    """The fake router that loses the controller at one exact point.

    The kill is an exception that nothing catches (``KeyboardInterrupt``)
    raised by the call the flow makes at that point:

    * ``kill_before`` is the call whose session never reaches the
      router: the router does not do that call at all;
    * ``kill_after`` is the call the router already answered: the router
      did that call, and the controller died before it could act on the
      answer.

    The flow stops at the raise and has no clean-up of its own, so the
    rollback window of the router is left open, the way a killed
    controller leaves it.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: the call that never reaches the router
        self.kill_before: tuple[str, str] | None = None
        #: the call the router answered before the controller died
        self.kill_after: tuple[str, str] | None = None

    def call(
        self,
        session: rpcd.RpcdSession,
        obj: str,
        fn: str,
        args: dict[str, Any] | None = None,
    ) -> Any:
        if self.kill_before == (obj, fn):
            raise KeyboardInterrupt(
                f"the controller was lost before {obj}.{fn}"
            )
        answer = super().call(session, obj, fn, args)
        if self.kill_after == (obj, fn):
            raise KeyboardInterrupt(
                f"the controller was lost after {obj}.{fn}"
            )
        return answer


def _setup(tmp_path: Path, monkeypatch) -> tuple[LossRouter, Clock]:
    """The inventory, the state dir and the fake router."""
    _write_inventory(tmp_path, monkeypatch, _no_install_body(tmp_path))
    router = LossRouter({"dhcp": DHCP})
    clock = Clock()
    router.now = clock
    monkeypatch.setattr(
        noinstall_read, "default_client_factory", lambda _device: router
    )
    return router, clock


def _state(tmp_path: Path) -> Path:
    """The state dir of the test."""
    return Path(os.environ["NEWTON_STATE_DIR"])


def _apply(router: LossRouter, clock: Clock, sid: str) -> dict[str, Any]:
    """The apply of a no-install plan, with the clock of the test."""
    service = _server.NewtonService()
    return noinstall_flow.apply(
        service,
        "lab-r1",
        sid,
        now=clock,
        sleep=clock.advance,
    )


def _let_the_router_revert(router: LossRouter, clock: Clock) -> None:
    """Let the rollback window of the router close and its timer fire.

    The window of the router is its own timer: the router puts the
    change back when the clock passes the end of the window.  The
    pending detector of Newton is what asks the router, the same read
    the settle of a finished apply does.
    """
    clock.advance(router.window_closes_at - clock() + 1)
    transaction = rpcd_txn.RpcdTransaction(router)
    session = router.login(rpcd.RPCD_USER, "synthetic-password", 60)
    try:
        entries = transaction.pending_entries(session)
    finally:
        session.mark_spent()
    # the window is closed: the router has nothing pending any more
    assert entries == [], entries


def _pending_is_open(router: LossRouter) -> bool:
    """Is a rollback window open on the router?"""
    transaction = rpcd_txn.RpcdTransaction(router)
    session = router.login(rpcd.RPCD_USER, "synthetic-password", 60)
    try:
        return bool(transaction.pending_entries(session))
    finally:
        session.mark_spent()


# =========================================================================
# TESTS
# =========================================================================


def test_a_controller_lost_after_the_apply_before_the_first_verify(
    tmp_path: Path, monkeypatch
) -> None:
    """The controller dies right after the change is applied.

    The change is on the router and the rollback window of the router is
    open.  Nothing verified it and nothing confirmed it, so the window
    closes by itself and the router puts the change back: the router is
    in the pre-change state, the state rule 10 allows.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch, CHANGE)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    before = dict(router.sections)
    router.kill_after = ("uci", "apply")

    with pytest.raises(KeyboardInterrupt):
        _apply(router, clock, sid)

    # the change is on the router and the window of the router is open
    assert router.sections[RESERVATION_SECTION] == (
        "host",
        {"mac": "02:00:00:00:10:01", "ip": "10.109.0.55"},
    )
    assert router.pending is True
    # the first verify never ran and no confirm was sent
    assert router.count("file", "exec") == 0, router.calls
    assert router.count("uci", "confirm") == 0, router.calls

    # the window of the router closes by itself
    _let_the_router_revert(router, clock)

    # the router is back in the pre-change state
    assert router.sections == before, router.sections
    assert router.pending is False


def test_a_controller_lost_after_the_verify_before_the_confirm(
    tmp_path: Path, monkeypatch
) -> None:
    """The controller dies after the verify and before the confirm.

    The verify passed: the flow only reaches the confirm when every
    check passed, so the loss at the confirm proves it.  The confirm
    never reached the router, so the change is not confirmed and the
    window of the router puts it back: the router is in the pre-change
    state.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch, CHANGE)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    before = dict(router.sections)
    router.kill_before = ("uci", "confirm")

    with pytest.raises(KeyboardInterrupt):
        _apply(router, clock, sid)

    # the verify ran: the internet check and the class checks
    assert router.count("file", "exec") >= 1, router.calls
    assert router.count("service", "list") >= 1, router.calls
    # the confirm never reached the router
    assert router.count("uci", "confirm") == 0, router.calls
    # the change is on the router and the window of the router is open
    assert RESERVATION_SECTION in router.sections
    assert router.pending is True

    # the window of the router closes by itself
    _let_the_router_revert(router, clock)

    # the router is back in the pre-change state
    assert router.sections == before, router.sections
    assert router.pending is False


def test_a_controller_lost_after_the_confirm_stays_confirmed(
    tmp_path: Path, monkeypatch
) -> None:
    """The controller dies after the confirm was sent and answered.

    The router confirmed the change, so the change is the confirmed
    state: the router holds it, no revert is armed any more, and the
    window that would have closed later changes nothing.
    """
    router, clock = _setup(tmp_path, monkeypatch)
    plan = _plan(tmp_path, monkeypatch, CHANGE)
    sid = plan["session_id"]
    state = _state(tmp_path)
    _approve(state, sid, _record(state, sid))
    router.kill_after = ("uci", "confirm")

    with pytest.raises(KeyboardInterrupt):
        _apply(router, clock, sid)

    # the confirm reached the router and was answered
    assert router.count("uci", "confirm") == 1, router.calls
    # the change is on the router
    assert router.sections[RESERVATION_SECTION] == (
        "host",
        {"mac": "02:00:00:00:10:01", "ip": "10.109.0.55"},
    )
    # no revert is armed any more
    assert router.pending is False
    assert _pending_is_open(router) is False

    # the window that closes later changes nothing
    clock.advance(1000)
    assert _pending_is_open(router) is False
    assert router.sections[RESERVATION_SECTION] == (
        "host",
        {"mac": "02:00:00:00:10:01", "ip": "10.109.0.55"},
    )
