"""The AD change apply, status and abort (DESIGN-1.4 section 1).

The apply sends the request of the plan to the domain controller of the
domain, and then reads the target back from **every** DC of the domain
that has a write entry in the inventory, over a fresh session.  The
confirm is sent only when each of those DCs shows the after-image.  A DC
of the domain without a write entry is never read: Newton does not list
the DCs of the directory itself.  A DC that has not caught up within the window is NOT
TESTED, and the abort goes out instead of the confirm: the DC puts the
before-image back itself.

A session that fails on the way to the DC (no answer, or not one JSON
object) is a result, never an exception: the receipt is written, the
result says which step was lost, and the owner reads the truth from the
DC with newton_ad_change_status.  A change that was written but never
confirmed is put back by the DC itself at its undo_at.

The receipt never holds the secret of a user-create, and the plan
record drops it once the apply has sent it.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ...adapters.ssh_cli import RunnerRefused
from . import inventory, plan as _plan, request, store, transport
from .errors import WriteError


#: The function that sends one request to one helper.
Send = Callable[[Any, Mapping[str, Any]], dict[str, Any]]

#: How often a DC is read again while it has not caught up.
POLL_S = 10.0

#: How long a DC may take to show the after-image.
TIMEOUT_S = 120.0

#: The state of a receipt.
STATE_CONFIRMED = "confirmed"
STATE_NOT_TESTED = "not_tested"
STATE_CONFLICT = "conflict"
STATE_REFUSED = "refused"
#: The session failed while the apply was sent: Newton does not know
#: whether the DC wrote the change.
STATE_APPLY_UNKNOWN = "apply_unknown"
#: Every DC showed the after-image, then the session failed while the
#: confirm was sent: Newton does not know whether the confirm arrived.
STATE_CONFIRM_UNKNOWN = "confirm_unknown"
#: The automatic abort did not run: the helper refused it, failed, or the
#: session failed while it was sent.
STATE_ABORT_FAILED = "abort_failed"

#: The failures of a session to a write helper.
LINK_ERRORS: tuple[type[Exception], ...] = (transport.TransportError, RunnerRefused)

#: What the owner is told for each state above.  The text is Newton's own.
APPLY_UNKNOWN_MESSAGE = (
    "The connection to the domain controller failed while the apply was "
    "sent, so Newton does not know whether the change was written. Run "
    "newton_ad_change_status to read it from the DC. A change that was "
    "written is armed and not confirmed, and the DC puts the before-image "
    "back itself at its undo_at."
)
CONFIRM_UNKNOWN_MESSAGE = (
    "Every domain controller showed the change, then the connection failed "
    "while the confirm was sent, so Newton does not know whether the confirm "
    "arrived. Run newton_ad_change_status to read it from the DC. A change "
    "that is not confirmed is put back by the DC itself at its undo_at."
)
ABORT_FAILED_MESSAGE = (
    "A domain controller did not show the change in time, and the automatic "
    "abort did not run (the DC refused it, or the connection failed). Run "
    "newton_ad_change_status to read the change from the DC. A change that "
    "is still armed is put back by the DC itself at its undo_at."
)
ABORT_LOST_MESSAGE = (
    "The connection to the domain controller failed while the abort was "
    "sent, so Newton does not know whether it arrived. Run "
    "newton_ad_change_status to read the change from the DC. A change that "
    "is still armed is put back by the DC itself at its undo_at."
)
#: The same states for an unlock, which arms no undo: it is confirmed once
#: written on the PDC emulator and stays written, so no rollback is promised.
UNLOCK_APPLY_UNKNOWN_MESSAGE = (
    "The connection to the domain controller failed while the unlock was "
    "sent, so Newton does not know whether it was written. Run "
    "newton_ad_change_status to read it from the DC. An unlock has no undo: "
    "if it was written, it stays written."
)
UNLOCK_CONFIRM_UNKNOWN_MESSAGE = (
    "Every domain controller showed the unlock, then the connection failed "
    "while the confirm was sent. Run newton_ad_change_status to read it from "
    "the DC. An unlock has no undo: it is confirmed once written on the PDC "
    "emulator and stays written."
)
UNLOCK_LAG_MESSAGE = (
    "A domain controller did not show the unlock in time. An unlock has no "
    "undo, so nothing was aborted: it stays written on the PDC emulator and "
    "reaches the other domain controllers by replication. Run "
    "newton_ad_change_status to read it from the DC."
)
STATUS_LOST_MESSAGE = (
    "The connection to the domain controller failed, so the status could "
    "not be read. Try newton_ad_change_status again."
)


def _try_send(sender: "Send", device: Any, payload: Mapping[str, Any]) -> dict[str, Any] | None:
    """One send, or None when the session to the helper failed."""
    try:
        return sender(device, payload)
    except LINK_ERRORS:
        return None


def _link_code(exc: BaseException | None) -> str:
    """The contract word of a failed session."""
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) else "unavailable"


def _load_plan(plan_id: str, domain: str | None = None) -> dict[str, Any]:
    """The plan of one change."""
    if not isinstance(plan_id, str) or not plan_id:
        raise WriteError("the plan id is not a name")
    try:
        plan = store.read_json(store.plan_path(plan_id))
    except (OSError, ValueError):
        raise WriteError("the plan record is not found or is invalid") from None
    if domain is not None and plan.get("device") != domain:
        raise WriteError("the plan belongs to another domain")
    if not isinstance(plan, dict) or plan.get("plan_id") != plan_id:
        raise WriteError("the plan record is not found or is invalid")
    return plan


def _load_approval(plan_id: str) -> dict[str, Any]:
    """The approval of one plan, beside the plan."""
    try:
        approval = store.read_json(store.approval_path(plan_id))
    except (OSError, ValueError):
        raise WriteError("the plan is not approved") from None
    if not isinstance(approval, dict):
        raise WriteError("the plan is not approved")
    for field in ("nbf", "exp", "token"):
        if field not in approval:
            raise WriteError("the plan is not approved")
    return approval


def _request_of(plan: Mapping[str, Any], approval: Mapping[str, Any]) -> dict[str, Any]:
    """The request of the apply: the plan, the window and the token."""
    payload: dict[str, Any] = {
        "v": 1,
        "mode": "apply",
        "device": plan["device"],
        "txid": plan["txid"],
        "verb": plan["verb"],
        "target": plan["target"],
        "before": plan["before"],
        "after": plan["after"],
        "window": plan["window"],
        "risk": plan["risk"],
        "nbf": approval["nbf"],
        "exp": approval["exp"],
        "token": approval["token"],
    }
    secret = plan.get("secret")
    if isinstance(secret, str):
        payload["secret"] = secret
    return payload


def _drop_secret(plan_id: str, plan: Mapping[str, Any]) -> None:
    """Drop the password of a user-create from the plan record.

    The password goes to the DC once.  After the apply has sent it, the
    txid is spent (a second apply is a replay), so nothing needs it
    again, and the plan record keeps every other field.  A record that
    cannot be rewritten keeps the password; the apply itself goes on.
    """
    if "secret" not in plan:
        return
    kept = {key: value for key, value in plan.items() if key != "secret"}
    try:
        store.write_json(store.plan_path(plan_id), kept)
    except OSError:
        pass


def _read_request(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The request of the verification read."""
    return {
        "v": 1,
        "mode": "read",
        "device": plan["device"],
        "verb": plan["verb"],
        "target": plan["target"],
    }


def _pdc_of(plan: Mapping[str, Any], devices: Mapping[str, Any]) -> Any:
    """The domain controller the plan was built against."""
    name = plan.get("pdc")
    if isinstance(name, str):
        device = devices.get(name)
        if device is not None and inventory.is_write_device(device):
            return device
    raise WriteError("the plan does not name the domain controller of its domain")


def _write_receipt(plan_id: str, receipt: Mapping[str, Any]) -> Path:
    """Write the receipt of one change."""
    path = store.receipt_path(plan_id)
    store.write_json(path, dict(receipt))
    return path


def apply_change(
    plan_id: str,
    *,
    domain: str | None = None,
    send: Send | None = None,
    devices: Mapping[str, Any] | None = None,
    poll_s: float = POLL_S,
    timeout_s: float = TIMEOUT_S,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply one approved change and verify it on every DC with a write entry.

    The DCs are the write entries of the inventory that name the domain: a
    DC of the domain without a write entry is never read.
    """
    plan = _load_plan(plan_id, domain)
    approval = _load_approval(plan_id)
    inventory_devices = _plan.load_devices(devices)
    dcs = inventory.domain_dcs(inventory_devices, str(plan["device"]))
    if not dcs:
        raise WriteError("the domain has no write entry")
    pdc = _pdc_of(plan, inventory_devices)
    sender = send if send is not None else transport.send

    payload = _request_of(plan, approval)
    try:
        request.parse_request(json.dumps(payload).encode("utf-8"))
    except request.RequestRefused as exc:
        raise WriteError(f"the request of the plan does not fit the contract: {exc}") from None

    created = datetime.now(timezone.utc) if now is None else now
    lost: BaseException | None = None
    try:
        answer = sender(pdc, payload)
    except LINK_ERRORS as exc:
        answer = None
        lost = exc
    finally:
        _drop_secret(plan_id, plan)
    unlock = plan.get("verb") == "unlock"
    if answer is None:
        code = _link_code(lost)
        apply_unknown = UNLOCK_APPLY_UNKNOWN_MESSAGE if unlock else APPLY_UNKNOWN_MESSAGE
        receipt = {
            "v": 1,
            "plan_id": plan_id,
            "txid": plan["txid"],
            "device": plan["device"],
            "verb": plan["verb"],
            "risk": plan.get("risk"),
            "window": plan.get("window"),
            "target": plan.get("target"),
            "before": plan.get("before"),
            "after": plan.get("after"),
            "state": STATE_APPLY_UNKNOWN,
            "code": code,
            "message": apply_unknown,
            "dcs": {},
            "created_at": created.isoformat(),
        }
        _write_receipt(plan_id, receipt)
        return {
            "result": "error",
            "plan_id": plan_id,
            "state": STATE_APPLY_UNKNOWN,
            "code": code,
            "message": apply_unknown,
            "dcs": {},
        }
    code = answer.get("code")
    if code != "ok":
        receipt = {
            "v": 1,
            "plan_id": plan_id,
            "txid": plan["txid"],
            "device": plan["device"],
            "verb": plan["verb"],
            "risk": plan.get("risk"),
            "window": plan.get("window"),
            "target": plan.get("target"),
            "before": plan.get("before"),
            "after": plan.get("after"),
            "state": STATE_CONFLICT if code == "conflict" else STATE_REFUSED,
            "code": code,
            "dcs": {},
            "created_at": created.isoformat(),
        }
        _write_receipt(plan_id, receipt)
        return {
            "result": "error",
            "plan_id": plan_id,
            "state": receipt["state"],
            "code": code,
            "dcs": {},
        }

    states = _verify(sender, dcs, plan, poll_s, timeout_s, sleep, clock)
    every = all(
        isinstance(one, dict) and one.get("state") == "matched"
        for one in states.values()
    )
    # The undo answer of an automatic abort: what it restored and what it
    # left changed, so the owner is told about the conflicts.
    undo: dict[str, Any] = {}
    message: str | None = None
    mode = "confirm" if every else "abort"
    lost = None
    sent: dict[str, Any] | None
    if unlock and not every:
        # An unlock arms no undo and is confirmed once written on the PDC
        # emulator, so there is nothing to abort: the helpers refuse it.
        sent = None
    else:
        try:
            sent = sender(
                pdc,
                {
                    "v": 1,
                    "mode": mode,
                    "device": plan["device"],
                    "txid": plan["txid"],
                },
            )
        except LINK_ERRORS as exc:
            sent = None
            lost = exc
    if unlock and not every:
        state = STATE_NOT_TESTED
        code = "ok"
        message = UNLOCK_LAG_MESSAGE
    elif every:
        if sent is None:
            state = STATE_CONFIRM_UNKNOWN
            code = _link_code(lost)
            message = UNLOCK_CONFIRM_UNKNOWN_MESSAGE if unlock else CONFIRM_UNKNOWN_MESSAGE
        else:
            state = STATE_CONFIRMED if sent.get("code") == "ok" else STATE_CONFLICT
            code = sent.get("code")
    elif sent is None or sent.get("code") != "ok":
        # The undo did not run: neither restored nor conflicts are known.
        state = STATE_ABORT_FAILED
        code = _link_code(lost) if sent is None else sent.get("code")
        message = ABORT_FAILED_MESSAGE
        undo = {"restored": None, "conflicts": None}
    else:
        state = STATE_NOT_TESTED
        code = sent.get("code")
        undo = {
            "restored": sent.get("restored"),
            "conflicts": sent.get("conflicts"),
        }
    said = {} if message is None else {"message": message}

    receipt = {
        "v": 1,
        "plan_id": plan_id,
        "txid": plan["txid"],
        "device": plan["device"],
        "verb": plan["verb"],
        "risk": plan.get("risk"),
        "window": plan.get("window"),
        "target": plan.get("target"),
        "before": plan.get("before"),
        "after": plan.get("after"),
        "state": state,
        "code": code,
        "dcs": states,
        **undo,
        **said,
        "created_at": created.isoformat(),
    }
    _write_receipt(plan_id, receipt)
    return {
        "result": "ok" if state == STATE_CONFIRMED else "error",
        "plan_id": plan_id,
        "state": state,
        "code": code,
        "dcs": states,
        **undo,
        **said,
    }


def _verify(
    sender: Send,
    dcs: list[Any],
    plan: Mapping[str, Any],
    poll_s: float,
    timeout_s: float,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> dict[str, dict[str, Any]]:
    """Read the target back from every DC until every one shows the after-image.

    The deadline is read from the clock, so a test that injects one
    waits exactly as long as the timeout and no longer.
    """
    deadline = clock() + timeout_s
    states: dict[str, dict[str, Any]] = {}
    read_request = _read_request(plan)
    after = plan["after"]
    for device in dcs:
        state = "not_tested"
        live: Any = None
        while True:
            try:
                answer = sender(device, read_request)
            except Exception:
                answer = {}
            if answer.get("code") == "ok":
                live = answer.get("live")
                if live == after:
                    state = "matched"
                    break
            remaining = deadline - clock()
            if remaining <= 0:
                break
            sleep(min(poll_s, remaining) if poll_s > 0 else 0)
        states[device.name] = {"state": state, "live": live}
    return states


def change_status(
    plan_id: str,
    *,
    domain: str | None = None,
    send: Send | None = None,
    devices: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The state of one change, as the domain controller holds it."""
    plan = _load_plan(plan_id, domain)
    inventory_devices = _plan.load_devices(devices)
    pdc = _pdc_of(plan, inventory_devices)
    sender = send if send is not None else transport.send
    try:
        answer = sender(
            pdc,
            {
                "v": 1,
                "mode": "status",
                "device": plan["device"],
                "txid": plan["txid"],
            },
        )
    except LINK_ERRORS as exc:
        return {
            "result": "error",
            "plan_id": plan_id,
            "txid": plan["txid"],
            "code": _link_code(exc),
            "state": None,
            "message": STATUS_LOST_MESSAGE,
        }
    return {
        "result": "ok" if answer.get("code") == "ok" else "error",
        "plan_id": plan_id,
        "txid": plan["txid"],
        "code": answer.get("code"),
        "state": answer.get("state"),
        "undo_at": answer.get("undo_at"),
        "restored": answer.get("restored"),
        "conflicts": answer.get("conflicts"),
    }


#: The answer to the abort of a confirmed change.  The text is Newton's
#: own, never the directory's.
CONFIRMED_ABORT_MESSAGE = (
    "This change is already confirmed, so abort cannot reverse it. Abort "
    "works only on an armed change (one whose confirm was lost). To reverse "
    "a confirmed change, plan the opposite change with newton_ad_plan_change "
    "and approve it (enable for disable, member-remove for member-add, the "
    "old value for enc-types, maq or move). A uac-clear and a user-create "
    "have no opposite verb: the owner reverses them with the admin tools."
)


#: The answer to the abort of an unlock: it has no undo and no opposite verb.
UNLOCK_ABORT_MESSAGE = (
    "An unlock has no undo: it is confirmed once written, so abort cannot "
    "reverse it."
)


def abort_change(
    plan_id: str,
    *,
    domain: str | None = None,
    send: Send | None = None,
    devices: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Abort one change: the domain controller puts the before-image back."""
    plan = _load_plan(plan_id, domain)
    inventory_devices = _plan.load_devices(devices)
    pdc = _pdc_of(plan, inventory_devices)
    sender = send if send is not None else transport.send
    try:
        answer = sender(
            pdc,
            {
                "v": 1,
                "mode": "abort",
                "device": plan["device"],
                "txid": plan["txid"],
            },
        )
    except LINK_ERRORS as exc:
        return {
            "result": "error",
            "plan_id": plan_id,
            "txid": plan["txid"],
            "code": _link_code(exc),
            "state": None,
            "restored": None,
            "conflicts": None,
            "message": ABORT_LOST_MESSAGE,
        }
    ok = answer.get("code") == "ok"
    message = None
    if answer.get("code") == "conflict":
        # Both helpers abort only an armed change.  A confirmed one is
        # reversed by a new plan of the opposite change.  A status that
        # cannot be read adds no message.
        status = _try_send(sender, pdc, {
            "v": 1,
            "mode": "status",
            "device": plan["device"],
            "txid": plan["txid"],
        }) or {}
        if status.get("code") == "ok" and status.get("state") == "confirmed":
            message = (
                UNLOCK_ABORT_MESSAGE
                if plan.get("verb") == "unlock"
                else CONFIRMED_ABORT_MESSAGE
            )
    restored = answer.get("restored")
    # The abort answer carries no state: both helpers record ``undone``
    # exactly when the undo restored the before-image, ``undo_failed``
    # otherwise, so the state is named by the same rule.  A refused
    # abort claims no state at all.
    state = ("undone" if restored is True else "undo_failed") if ok else None
    result: dict[str, Any] = {
        "result": "ok" if ok else "error",
        "plan_id": plan_id,
        "txid": plan["txid"],
        "code": answer.get("code"),
        "state": state,
        "restored": restored,
        "conflicts": answer.get("conflicts"),
    }
    if message is not None:
        result["message"] = message
    return result
