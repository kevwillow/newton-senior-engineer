"""apply.py tells the owner only outcomes some path of the code makes true.

A state, code or message the owner is shown must be one some path of the
code makes true.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import harness
import pytest

from newton_mcp.ad.write import apply as ad_apply, store, transport
from newton_mcp.ad.write.transport import TransportError

from test_write_apply import _approved_plan, _lab, _unlock_lab


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The state directory of the test."""
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _status(lab: harness.Lab, plan_id: str) -> dict[str, object]:
    plan = store.read_json(store.plan_path(plan_id))
    return lab.send(
        lab.devices["win-dc1"],
        {"v": 1, "mode": "status", "device": plan["device"], "txid": plan["txid"]},
    )


# ---- a confirm the DC did not record ---------------------------


@pytest.mark.parametrize("answer", ["conflict", "error"])
def test_a_confirm_the_dc_refuses_is_not_confirmed_and_says_it_is_armed(
    answer: str,
) -> None:
    """Every DC matched and the confirm came back non-ok.  The DC's record
    stays armed, so the owner is told the confirm was not recorded and the
    DC puts the before-image back at or after undo_at, never a bare
    conflict (which elsewhere means nothing was written)."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            return {"v": 1, "code": answer}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert all(one["state"] == "matched" for one in result["dcs"].values())
    assert result["state"] == ad_apply.STATE_NOT_CONFIRMED
    assert result["code"] == answer
    message = str(result["message"])
    assert "not recorded" in message
    assert "undo_at" in message
    assert "newton_ad_change_status" in message
    assert "during verify" in message
    assert "still armed" in message
    assert "The change is written" not in message
    assert result["dc_state"] == "armed"
    assert _status(lab, plan_id)["state"] == "armed"
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_NOT_CONFIRMED
    assert receipt["message"] == message


def test_an_unlock_confirm_the_dc_refuses_promises_no_undo() -> None:
    lab, plan_id = _unlock_lab()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            return {"v": 1, "code": "conflict"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_NOT_CONFIRMED
    message = str(result["message"])
    assert "no undo" in message
    assert "stays written" in message
    assert "undo_at" not in message


@pytest.mark.parametrize("answer", ["conflict", "error"])
def test_an_unlock_confirm_answered_non_ok_says_what_the_dc_holds(answer: str) -> None:
    """An unlock has no undo, so it stays written whatever the confirm got:
    the message never says the confirm was not recorded.  Neither message
    claims the DC's record reads confirmed (a Windows DC whose confirmed
    record could not be written keeps it armed and answers the apply ok),
    and a conflict never claims a new lockout: the helpers also answer it
    when the account or the record could not be read, or the record is not
    one a confirm accepts."""
    lab, plan_id = _unlock_lab()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            return {"v": 1, "code": answer}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    message = " ".join(str(result["message"]).split())
    assert "not recorded" not in message
    assert "The DC records an unlock confirmed" not in message
    assert "normally" in message
    assert "stays written" in message
    assert "newton_ad_change_status" in message
    assert "armed" in message
    if answer == "conflict":
        assert message == " ".join(ad_apply.UNLOCK_CONFIRM_CONFLICT_MESSAGE.split())
        assert "may have read the account locked again" in message
        assert "could not read" in message
        assert "it read the account locked again" not in message
        assert "another lockout reached it" not in message
    else:
        assert message == " ".join(ad_apply.UNLOCK_NOT_CONFIRMED_MESSAGE.split())
        assert "locked again" not in message


def test_the_unlock_confirm_comment_claims_no_record_the_code_does_not_guarantee() -> None:
    """The comment above the unlock confirm messages says what is
    guaranteed: an unlock stays written; the record normally reads
    confirmed, never always."""
    source = inspect.getsource(ad_apply)
    start = source.index("UNLOCK_NOT_CONFIRMED_MESSAGE = (")
    comment = source[source.rindex("\n\n", 0, start):start]
    assert "recorded confirmed when it is written (both helpers)" not in comment
    assert "stays written" in comment


# ---- a replay never overwrites the receipt ----------------------


def test_a_replay_keeps_the_receipt_of_the_earlier_apply() -> None:
    """The plan is confirmed; applying it again is a replay, which Newton
    now catches before it sends anything (code ``not_sent``).  The receipt
    of the confirmed change stays, and the replay answer has its own state,
    never the plain ``refused`` that means nothing changed."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    first = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)
    assert first["state"] == ad_apply.STATE_CONFIRMED

    again = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert again["code"] == "not_sent"
    assert again["state"] == ad_apply.STATE_REPLAY
    assert again["state"] != ad_apply.STATE_REFUSED
    assert "newton_ad_change_status" in str(again["message"])
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_CONFIRMED


@pytest.mark.parametrize("earlier_code", ["conflict", "not_pdc"])
def test_a_replay_keeps_an_earlier_refused_receipt(earlier_code: str) -> None:
    """An earlier apply left a final refused receipt and the DC holds a
    record of the txid, so a retry is sent and the DC answers replay.  The
    answer says the earlier receipt is kept, and it is: neither the pending
    receipt of this attempt nor a replay receipt is left over it."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    earlier = {"v": 1, "plan_id": plan_id, "state": ad_apply.STATE_REFUSED,
               "code": earlier_code, "message": "the earlier apply was refused", "dcs": {}}
    store.write_json(store.receipt_path(plan_id), earlier)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "replay"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REPLAY
    assert "kept" in " ".join(str(result["message"]).split())
    assert store.read_json(store.receipt_path(plan_id)) == earlier


def test_a_replay_with_no_receipt_writes_one_in_its_own_state() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "replay"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REPLAY
    assert store.read_json(store.receipt_path(plan_id))["state"] == ad_apply.STATE_REPLAY


def test_a_receipt_whose_presence_cannot_be_checked_is_taken_for_an_earlier_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check for an earlier receipt raises (the state directory turned
    unreadable): the receipt is taken for present, so the plan is refused
    on this host before anything is sent, and nothing is written over it."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    receipt = store.receipt_path(plan_id)
    real_exists = Path.exists
    calls: list[int] = []

    def exists(self: Path, *args: object, **kwargs: object) -> bool:
        if self == receipt:
            calls.append(1)
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "exists", exists)
    written: list[object] = []
    real_write = store.write_json

    def write_json(path: object, data: object) -> None:
        if path == receipt:
            written.append(path)
        real_write(path, data)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "write_json", write_json)
    seen: list[str] = []

    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert calls
    _assert_refused_locally(result, seen)
    assert written == []


def test_the_lost_apply_message_hedges_armed_with_an_undo_that_already_ran() -> None:
    """A written change is normally armed after a lost apply, but the DC
    runs the undo at once when it could not finish the apply after its
    write, so the record may already say undone or undo_failed."""
    text = " ".join(ad_apply.APPLY_UNKNOWN_MESSAGE.split())
    assert "written is armed" not in text
    assert "A change that was written is normally armed and not confirmed" in text
    assert "the DC may already have run the undo" in text
    assert "undone means the before-image is back" in text
    assert "undo_failed means the DC did not put it back" in text


# ---- the abort of an unlock --------------------------------


@pytest.mark.parametrize("answer", [{"code": "ok", "restored": False, "conflicts": []},
                                    {"code": "conflict"}])
@pytest.mark.parametrize("record", ["armed", "refused", "confirmed"])
def test_an_unlock_abort_never_names_an_undo_state(
    answer: dict[str, object], record: str
) -> None:
    """An unlock has no undo.  Whatever the helper answers to its abort (an
    older Samba helper answered ok), the result never names undone or
    undo_failed, it carries the no-undo message, and the state is the
    DC's own record."""
    lab, plan_id = _unlock_lab()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "abort":
            return {"v": 1, **answer}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": record}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.abort_change(plan_id, send=send, devices=lab.devices)

    assert result["state"] not in ("undone", "undo_failed")
    assert result["message"] == ad_apply.UNLOCK_ABORT_MESSAGE
    assert result["dc_state"] == record


# ---- the automatic abort ---------------------------


def test_abort_failed_does_not_claim_the_abort_did_not_run() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "abort":
            raise TransportError("unavailable", "the answer was lost")
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_ABORT_FAILED
    message = str(result["message"])
    assert "did not run" not in message
    assert "does not know whether the automatic abort ran" in message


@pytest.mark.parametrize("record", ["undone", "undo_failed"])
def test_an_abort_the_dc_answers_conflict_reports_the_dc_state(record: str) -> None:
    """The DC's own timer or sweep already ran the undo when the abort
    arrived, so the abort answered conflict.  The result reads the DC's
    record and reports what it holds, not abort_failed."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "abort":
            return {"v": 1, "code": "conflict"}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": record, "restored": record == "undone",
                    "conflicts": [] if record == "undone" else ["x"]}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_NOT_TESTED
    assert result["dc_state"] == record
    assert result["restored"] is (record == "undone")
    assert result["code"] == "conflict"


def test_an_abort_conflict_with_an_unreadable_record_is_abort_failed() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "abort":
            return {"v": 1, "code": "conflict"}
        if body["mode"] == "status":
            raise TransportError("unavailable", "lost")
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_ABORT_FAILED


# ---- the transport docstring -----------------------------------


def test_unavailable_does_not_claim_the_session_never_reached_the_helper() -> None:
    doc = " ".join(str(inspect.getdoc(transport.TransportError)).split())
    assert "never reached the helper" not in doc
    assert "may have acted" in doc


# ---- a DC error whose record could not be read -------------------


@pytest.mark.parametrize("unlock", [False, True])
def test_a_dc_error_with_no_readable_record_says_the_record_was_not_read(
    unlock: bool,
) -> None:
    if unlock:
        lab, plan_id = _unlock_lab()
    else:
        lab = _lab()
        plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "error"}
        if body["mode"] == "status":
            raise TransportError("unavailable", "lost")
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    message = str(result["message"])
    assert "could not read the DC's record" in message
    assert "does not show it refused" not in message


# ---- an answered write the DC could not record ---------------------------


@pytest.mark.parametrize("code", ["error", "denied", "not_found", "unavailable"])
@pytest.mark.parametrize("status_read", [True, False])
def test_an_unmarked_answer_says_the_undo_may_write_over_another_change(
    code: str, status_read: bool
) -> None:
    """The DC answered the write itself (nothing of Newton's was written),
    but its store took neither the mark nor the refused record: its record
    reads armed with no mark, so its undo may later write the before-image
    over somebody else's value.  Newton never says nothing changed, never
    promises the undo writes nothing, and tells the owner to read the target."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": code, "unmarked": True}
        if body["mode"] == "status":
            if not status_read:
                raise TransportError("unavailable", "lost")
            return {"v": 1, "code": "ok", "state": "armed", "undo_at": 1800000600,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert result["code"] == code
    assert result["message"] == ad_apply.UNMARKED_MESSAGE
    message = " ".join(str(result["message"]).split())
    assert "could not record" in message
    assert "somebody else" in message
    assert "nothing changed" not in message
    assert "writes nothing" not in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert receipt["message"] == result["message"]


@pytest.mark.parametrize("code", ["conflict", "schema"])
def test_an_unmarked_answer_is_never_reported_as_nothing_changed(code: str) -> None:
    """A conflict or a pre-write code says nothing was written and nothing is
    armed; an answer that also carries unmarked says the DC's record may
    still read armed, so its undo may run.  Newton reads the record and
    reports apply_unknown with the unmarked message, never conflict or
    refused."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": code, "unmarked": True}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": "armed", "undo_at": 1800000600,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert result["message"] == ad_apply.UNMARKED_MESSAGE


def test_the_unmarked_message_never_says_what_an_unread_record_reads() -> None:
    """The helper says unmarked when the record did not read refused or
    marked, which includes a record it could not read at all: the message
    says the record may still read armed, never that it reads armed."""
    message = " ".join(ad_apply.UNMARKED_MESSAGE.split())
    assert "its record of the change reads armed" not in message
    assert "its record of the change may still read armed" in message


def test_an_unmarked_answer_whose_record_reads_refused_is_refused() -> None:
    """The DC's record reads refused after all (a later write landed): the
    undo never runs over it, so the result is refused."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "error", "unmarked": True}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": "refused", "undo_at": 1800000600,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REFUSED


def test_an_unlock_answer_that_carries_unmarked_is_never_reported_unmarked() -> None:
    """An unlock has no undo: nothing of the DC's can write over anybody's
    change, so an unlock answer that carries unmarked never gets the
    message that says the undo may write over another change."""
    lab, plan_id = _unlock_lab()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "error", "unmarked": True}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": "armed", "undo_at": 1800000120,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert result["message"] != ad_apply.UNMARKED_MESSAGE
    assert result["message"] == ad_apply.UNLOCK_DC_ERROR_MESSAGE


# ---- the status of an armed unlock --------------------------------------


def test_the_status_of_an_armed_unlock_promises_no_undo() -> None:
    lab, plan_id = _unlock_lab()

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": "armed", "undo_at": 1800000120,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.change_status(plan_id, send=send, devices=lab.devices)

    assert result["state"] == "armed"
    message = str(result["message"])
    assert "no undo" in message
    assert "stays written" in message


def test_the_status_of_an_armed_change_with_an_undo_carries_no_unlock_caveat() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)
    plan = store.read_json(store.plan_path(plan_id))
    assert plan["verb"] != "unlock"

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": "armed", "undo_at": 1800000600,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.change_status(plan_id, send=send, devices=lab.devices)

    assert "message" not in result


# ---- no message promises the undo runs exactly at undo_at -----


@pytest.mark.parametrize(
    "name",
    ["APPLY_UNKNOWN_MESSAGE", "CONFIRM_UNKNOWN_MESSAGE", "ABORT_FAILED_MESSAGE",
     "ABORT_LOST_MESSAGE", "DC_ERROR_MESSAGE", "NOT_CONFIRMED_MESSAGE",
     "CONFIRM_NOT_SENT_MESSAGE", "ABORT_NOT_SENT_MESSAGE", "ABORT_TOOL_NOT_SENT_MESSAGE"],
)
def test_no_message_promises_the_undo_exactly_at_undo_at(name: str) -> None:
    text = getattr(ad_apply, name)
    assert "itself at its undo_at." not in text
    assert "back itself at its undo_at" not in text
    assert "at or after its undo_at" in text


def test_the_rendered_result_carries_the_dc_state_in_the_envelope() -> None:
    """dc_state is the DC's own word, so the model sees it wrapped."""
    from newton_mcp.ad.write import render as ad_render

    rendered = ad_render.applied({"result": "error", "state": None, "dc_state": "armed"})

    assert "dc_state" in rendered
    assert rendered["dc_state"] != "armed"
    assert "armed" in str(rendered["dc_state"])


# ---- the confirm after an undo -----------------------------------------


def test_a_confirm_refused_because_the_dc_already_undid_it_names_the_undo() -> None:
    """Every DC matched, then the confirm arrived after undo_at: the DC's
    own sweep ran the undo first and the confirm answered conflict.  The
    owner is told what the DC's record says, never that the change is
    still written and armed."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            undone = lab.send(target, {**body, "mode": "abort"})  # type: ignore[arg-type]
            assert undone["code"] == "ok"
            return {"v": 1, "code": "conflict"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert _status(lab, plan_id)["state"] == "undone"
    assert result["state"] == ad_apply.STATE_NOT_CONFIRMED
    assert result["dc_state"] == "undone"
    assert result["restored"] is True
    message = str(result["message"])
    assert "still armed" not in message
    assert "already" in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["dc_state"] == "undone"


def test_the_armed_unlock_status_never_claims_why_it_is_armed() -> None:
    """Windows also leaves an unlock armed when the write and its read
    were fine and only the confirmed record could not be written: the
    message does not claim the DC could not read the account."""
    assert "could not read the account" not in ad_apply.UNLOCK_ARMED_MESSAGE
    assert "no undo" in ad_apply.UNLOCK_ARMED_MESSAGE


# ---- a DC error whose re-read showed a third value --------------------------


@pytest.mark.parametrize("unlock", [False, True])
@pytest.mark.parametrize("status_read", [True, False])
def test_a_dc_error_with_a_third_value_says_another_change_reached_the_target(
    unlock: bool, status_read: bool
) -> None:
    """The DC answered the apply with an error and its re-read showed
    neither image: Newton does not know whether its write landed before the
    other change.  Never refused, never a promise that the before-image is
    put back."""
    if unlock:
        lab, plan_id = _unlock_lab()
    else:
        lab = _lab()
        plan_id = _approved_plan(lab)
    plan = store.read_json(store.plan_path(plan_id))
    key = next(iter(plan["after"]))
    third = {key: 987654}
    assert third not in (plan["before"], plan["after"])

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "error", "live": third}
        if body["mode"] == "status":
            if not status_read:
                raise TransportError("unavailable", "lost")
            return {"v": 1, "code": "ok", "state": "armed" if unlock else "undo_failed",
                    "undo_at": 1800000600, "restored": False, "conflicts": ["x"]}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert result["live"] == third
    message = str(result["message"])
    assert "another change" in message
    assert "does not know whether" in message
    assert "puts the before-image back" not in message
    if unlock:
        assert "no undo" in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert receipt["live"] == third
    assert receipt["message"] == message


def test_the_rendered_result_carries_the_live_value_of_a_third_value_wrapped() -> None:
    """The message points the owner at live, so the model sees it, wrapped
    the way the live values of every DC are."""
    from newton_mcp.ad.write import render as ad_render

    rendered = ad_render.applied({"result": "error", "state": "apply_unknown",
                                  "live": {"uac": 4096}})

    assert rendered["live"] == ad_render.values({"uac": 4096})



# ---- a confirm the DC did not record says only what the DC's record holds ---


@pytest.mark.parametrize("answer", ["conflict", "error"])
def test_a_refused_confirm_whose_record_cannot_be_read_never_says_still_armed(
    answer: str,
) -> None:
    """The status read after the refused confirm failed: the undo may
    already have run, so the owner is told Newton could not read the
    record, never that it is still armed."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            return {"v": 1, "code": answer}
        if body["mode"] == "status":
            raise TransportError("unavailable", "lost")
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_NOT_CONFIRMED
    message = str(result["message"])
    assert "still armed" not in message
    assert "could not read the DC's record" in message
    assert "newton_ad_change_status" in message


def test_a_confirm_answered_error_after_the_dc_ran_its_undo_names_the_undo() -> None:
    """The confirm answered error (not conflict) and the DC's record shows
    its undo already ran: the result carries that undo's dc_state."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            undone = lab.send(target, {**body, "mode": "abort"})  # type: ignore[arg-type]
            assert undone["code"] == "ok"
            return {"v": 1, "code": "error"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_NOT_CONFIRMED
    assert result["dc_state"] == "undone"
    assert "still armed" not in str(result["message"])


@pytest.mark.parametrize("answer", ["conflict", "error"])
def test_a_non_ok_confirm_whose_record_reads_confirmed_is_reported_confirmed(
    answer: str,
) -> None:
    """The DC recorded the confirm and then answered it with an error (a
    directory flush that failed after the record was replaced): its record
    reads confirmed and its timer finds it confirmed and does nothing, so
    the change is confirmed, never 'this confirm was not recorded'."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            return {"v": 1, "code": answer}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": "confirmed", "undo_at": 1800000600,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["result"] == "ok"
    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert result["dc_state"] == "confirmed"
    message = str(result["message"])
    assert "not recorded" not in message
    assert "answered the confirm with an error" in message
    assert "record shows it confirmed" in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_CONFIRMED


@pytest.mark.parametrize("state", ["refused"])
def test_a_refused_confirm_with_another_record_state_names_that_state(state: str) -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "confirm":
            return {"v": 1, "code": "conflict"}
        if body["mode"] == "status":
            return {"v": 1, "code": "ok", "state": state, "undo_at": 1800000600,
                    "restored": False, "conflicts": []}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_NOT_CONFIRMED
    assert result["dc_state"] == state
    message = str(result["message"])
    assert "still armed" not in message
    assert "dc_state" in message


def test_the_confirm_after_undo_message_names_the_abort_as_well_as_undo_at() -> None:
    """An owner's concurrent abort leaves the same record as the DC's own
    undo at undo_at: the message does not claim which one ran it."""
    message = ad_apply.CONFIRM_AFTER_UNDO_MESSAGE
    assert "already run the undo" in message
    assert "abort" in message
    assert "(its undo_at had passed)" not in message


def test_the_module_docstring_and_state_comment_carry_the_confirm_after_undo_case() -> None:
    doc = " ".join(str(ad_apply.__doc__).split())
    assert "leaves the change armed (``not_confirmed``)." not in doc
    assert "already ran" in doc
    source = inspect.getsource(ad_apply)
    start = source.index("STATE_NOT_CONFIRMED = ")
    comment = source[source.rindex("#: Every DC showed", 0, start):start]
    assert "so the change\n#: is still armed" not in comment
    assert "undo already ran" in " ".join(comment.replace("#:", " ").split())


@pytest.mark.parametrize("unlock", [False, True])
def test_an_apply_answered_conflict_with_the_after_image_is_a_conflict(unlock: bool) -> None:
    """A helper whose write the server refused finds the after-image there
    (somebody else made the same change): it records refused with the
    conflict and answers conflict with live.  Newton reports a conflict,
    never confirmed or apply_unknown, and sends no confirm or abort."""
    if unlock:
        lab, plan_id = _unlock_lab()
    else:
        lab = _lab()
        plan_id = _approved_plan(lab)
    plan = store.read_json(store.plan_path(plan_id))
    modes: list[str] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        modes.append(str(body["mode"]))
        if body["mode"] == "apply":
            return {"v": 1, "code": "conflict", "live": plan["after"]}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFLICT
    assert result["code"] == "conflict"
    assert "confirm" not in modes and "abort" not in modes
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_CONFLICT


# ---- a second apply of a plan whose earlier apply may have been written ----


def _first_apply(lab: harness.Lab, plan_id: str, ending: str) -> dict[str, object]:
    """The first apply of the plan, ending in ``ending``: its apply answer
    lost, its confirm answer lost, or confirmed."""

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        answer = lab.send(target, body)  # type: ignore[arg-type]
        if (ending, body["mode"]) in (("apply_unknown", "apply"), ("confirm_unknown", "confirm")):
            raise TransportError("unavailable", "the answer was lost")
        return answer

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)
    assert result["state"] == ending
    return store.read_json(store.receipt_path(plan_id))


def _second_apply(lab: harness.Lab, plan_id: str) -> tuple[dict[str, object], list[str]]:
    modes: list[str] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        modes.append(str(body["mode"]))
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)
    return result, modes


def _assert_refused_locally(result: dict[str, object], modes: list[str]) -> None:
    """Nothing was sent, the code is Newton's own, and the message never says
    nothing changed: it says the earlier apply may have been written and
    points to the change status."""
    assert modes == []
    assert result["code"] == "not_sent"
    assert result["state"] == ad_apply.STATE_REPLAY
    message = str(result["message"])
    assert message != ad_apply.DC_REFUSED_MESSAGE
    assert "nothing changed" not in message
    assert "earlier apply" in message
    assert "may already be written" in message
    assert "newton_ad_change_status" in message


@pytest.mark.parametrize("ending", ["apply_unknown", "confirm_unknown", "confirmed"])
def test_a_second_apply_of_a_plan_that_reached_the_dc_is_refused_before_it_is_sent(
    ending: str,
) -> None:
    """The earlier apply reached the DC, or may have: a second apply of the
    same plan is refused on the Newton host, sends nothing, and keeps the
    earlier receipt as it was."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    receipt = _first_apply(lab, plan_id, ending)

    result, modes = _second_apply(lab, plan_id)

    _assert_refused_locally(result, modes)
    assert store.read_json(store.receipt_path(plan_id)) == receipt


def test_a_second_apply_of_a_user_create_whose_apply_was_lost_is_never_refused_by_the_dc() -> None:
    """The secret of a user-create left the plan record when the first apply
    sent it.  A second apply would reach the DC without it and be refused
    with a pre-write code, which Newton would report as nothing changed and
    write over the apply_unknown receipt while the user may exist."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    receipt = _first_apply(lab, plan_id, "apply_unknown")

    result, modes = _second_apply(lab, plan_id)

    _assert_refused_locally(result, modes)
    assert store.read_json(store.receipt_path(plan_id)) == receipt


def test_a_user_create_whose_secret_was_sent_and_has_no_receipt_is_refused_before_send() -> None:
    """The plan record lost its secret to an apply that sent it, and no
    receipt was left (the host stopped before writing it): the apply may
    have been written, so the plan is refused on the Newton host."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    _first_apply(lab, plan_id, "apply_unknown")
    store.receipt_path(plan_id).unlink()

    result, modes = _second_apply(lab, plan_id)

    _assert_refused_locally(result, modes)
    assert not store.receipt_path(plan_id).exists()


def test_a_plan_whose_earlier_apply_was_refused_before_send_is_sent_again() -> None:
    """Control: a refused receipt says the DC wrote nothing, so the same plan
    is sent again once the cause is fixed."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab = _lab()
    plan_id = _approved_plan(lab)

    def refused(target: object, body: dict[str, object]) -> dict[str, object]:
        raise RunnerRefused("the inventory entry has no key file")

    first = ad_apply.apply_change(plan_id, send=refused, devices=lab.devices, timeout_s=0.0)
    assert first["state"] == ad_apply.STATE_REFUSED

    result, modes = _second_apply(lab, plan_id)

    assert modes[0] == "apply"
    assert result["state"] == ad_apply.STATE_CONFIRMED


def test_a_user_create_whose_secret_was_sent_after_a_refused_receipt_is_refused_before_send() -> None:
    """The first apply was refused before send and left a refused receipt.
    A later apply sent the secret and the host stopped before it wrote its
    own receipt, so the refused receipt still stands while the user may
    exist.  The secret is gone from the plan record, so the plan is refused
    on the Newton host and the refused receipt is never read as nothing
    written."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)

    def refused(target: object, body: dict[str, object]) -> dict[str, object]:
        raise RunnerRefused("the inventory entry has no key file")

    first = ad_apply.apply_change(plan_id, send=refused, devices=lab.devices, timeout_s=0.0)
    assert first["state"] == ad_apply.STATE_REFUSED
    refused_receipt = store.receipt_path(plan_id).read_bytes()
    _first_apply(lab, plan_id, "apply_unknown")
    store.receipt_path(plan_id).write_bytes(refused_receipt)

    result, modes = _second_apply(lab, plan_id)

    _assert_refused_locally(result, modes)
    assert store.receipt_path(plan_id).read_bytes() == refused_receipt


# ---- a confirm or an abort the SSH runner refuses before it is sent ------------


def _runner_refuses(lab: harness.Lab, mode: str):
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == mode:
            raise RunnerRefused("the inventory entry has no key file")
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


def _said(result: dict[str, object]) -> str:
    return " ".join(str(result["message"]).split())


def _assert_not_sent_hedge(message: str) -> None:
    """Nothing was sent and no record was read: the DC holds the change as
    it did, and only a change still armed is put back (a new user whose
    objectGUID was not recorded is left in place)."""
    assert "the change is still armed" not in message
    assert "the DC holds the change as it did" in message
    assert "a change still armed is put back by the DC itself at or after its undo_at" in message
    assert "a new user whose objectGUID the DC did not record" in message
    assert "newton_ad_change_status" in message


def test_a_confirm_the_runner_refuses_says_it_was_not_sent_and_the_dc_holds_it() -> None:
    """The SSH runner refused the confirm before it left this host: the code
    is not_sent, so the message never says the confirm may have arrived.
    No record is read on this path, so it never says the change is still
    armed: the DC holds it as it did, and a change still armed is put back
    at or after undo_at."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.apply_change(
        plan_id, send=_runner_refuses(lab, "confirm"), devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == ad_apply.STATE_CONFIRM_UNKNOWN
    assert result["code"] == "not_sent"
    message = _said(result)
    assert "does not know whether the confirm arrived" not in message
    assert "connection failed" not in message
    assert "was not sent" in message
    _assert_not_sent_hedge(message)
    assert _status(lab, plan_id)["state"] == "armed"
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["message"] == result["message"]


def test_an_unlock_confirm_the_runner_refuses_says_it_was_not_sent_and_stays_written() -> None:
    lab, plan_id = _unlock_lab()

    result = ad_apply.apply_change(
        plan_id, send=_runner_refuses(lab, "confirm"), devices=lab.devices, timeout_s=0.0
    )

    assert result["code"] == "not_sent"
    message = _said(result)
    assert "connection failed" not in message
    assert "was not sent" in message
    assert "stays written" in message
    assert "undo_at" not in message


def test_an_automatic_abort_the_runner_refuses_says_it_was_not_sent_and_the_dc_holds_it() -> None:
    """A DC lagged and the runner refused the automatic abort before it left
    this host: the abort did not run.  The verify waited out its timeout, so
    the DC's own undo may already have run: the message never says the
    change is still armed, only that the DC holds it as it did."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    result = ad_apply.apply_change(
        plan_id, send=_runner_refuses(lab, "abort"), devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == ad_apply.STATE_ABORT_FAILED
    assert result["code"] == "not_sent"
    message = _said(result)
    assert "does not know whether the automatic abort ran" not in message
    assert "was not sent" in message
    _assert_not_sent_hedge(message)
    assert _status(lab, plan_id)["state"] == "armed"


def test_an_abort_tool_call_the_runner_refuses_says_it_was_not_sent() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)
    from test_write_apply import _apply_now

    assert _apply_now(lab, plan_id)["code"] == "ok"

    result = ad_apply.abort_change(
        plan_id, send=_runner_refuses(lab, "abort"), devices=lab.devices
    )

    assert result["code"] == "not_sent"
    message = _said(result)
    assert "does not know whether it arrived" not in message
    assert "connection" not in message
    assert "was not sent" in message
    assert "undo_at" in message
    assert _status(lab, plan_id)["state"] == "armed"


def test_an_unlock_abort_tool_call_the_runner_refuses_says_it_was_not_sent() -> None:
    lab, plan_id = _unlock_lab()
    from test_write_apply import _apply_now

    assert _apply_now(lab, plan_id)["code"] == "ok"

    result = ad_apply.abort_change(
        plan_id, send=_runner_refuses(lab, "abort"), devices=lab.devices
    )

    assert result["code"] == "not_sent"
    message = _said(result)
    assert "connection" not in message
    assert "was not sent" in message
    assert "stays written" in message


def test_a_status_the_runner_refuses_says_it_was_not_sent() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.change_status(
        plan_id, send=_runner_refuses(lab, "status"), devices=lab.devices
    )

    assert result["code"] == "not_sent"
    message = _said(result)
    assert "connection" not in message
    assert "was not sent" in message


# ---- a receipt that cannot be written ------------------------------------------


def _receipt_write_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every write under the receipts directory raises (a full disk on the
    Newton host); the plan record is written as before."""
    real = store.write_json

    def write_json(path: Path, value: object) -> None:
        if path.parent == store.receipts_dir():
            raise OSError(28, "No space left on device")
        real(path, value)

    monkeypatch.setattr(store, "write_json", write_json)


def _final_receipt_write_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pending receipt is written; every later write under the receipts
    directory raises (the disk filled up while the apply ran)."""
    real = store.write_json

    def write_json(path: Path, value: object) -> None:
        if path.parent == store.receipts_dir() and not (
            isinstance(value, dict) and value.get("pending") is True
        ):
            raise OSError(28, "No space left on device")
        real(path, value)

    monkeypatch.setattr(store, "write_json", write_json)


def _assert_pending_kept(plan_id: str) -> None:
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert receipt["pending"] is True
    assert receipt["message"] == ad_apply.PENDING_MESSAGE


def _lost_apply(lab: harness.Lab):
    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            raise TransportError("unavailable", "the answer was lost")
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


def _lost_abort(lab: harness.Lab):
    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "abort":
            raise TransportError("unavailable", "the answer was lost")
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


def _dc_error(lab: harness.Lab):
    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            lab.send(target, body)  # type: ignore[arg-type]
            return {"v": 1, "code": "error"}
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


@pytest.mark.parametrize(
    "path, state, code",
    [
        ("apply_unknown", ad_apply.STATE_APPLY_UNKNOWN, "unavailable"),
        ("dc_error", ad_apply.STATE_APPLY_UNKNOWN, "error"),
        ("confirmed", ad_apply.STATE_CONFIRMED, "ok"),
        ("abort_failed", ad_apply.STATE_ABORT_FAILED, "unavailable"),
    ],
)
def test_a_receipt_that_cannot_be_written_never_replaces_the_dc_outcome(
    path: str, state: str, code: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A final receipt write that raises (a full disk on the Newton host)
    keeps the state, code and message of the AD result, and says the
    receipt was not written: the DC's record stays the source of truth, and
    the pending receipt written before the send stays on this host."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    send = {
        "apply_unknown": _lost_apply(lab),
        "dc_error": _dc_error(lab),
        "confirmed": lab.send,
        "abort_failed": _lost_abort(lab),
    }[path]
    if path == "abort_failed":
        lab.lag()
    _final_receipt_write_fails(monkeypatch)

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == state
    assert result["code"] == code
    if state != ad_apply.STATE_CONFIRMED:
        assert isinstance(result["message"], str) and result["message"]
    assert result["receipt_error"] == ad_apply.RECEIPT_ERROR_MESSAGE
    assert "newton_ad_change_status" in str(result["receipt_error"])
    _assert_pending_kept(plan_id)


@pytest.mark.parametrize("fails", ["every", "final"])
def test_a_receipt_that_cannot_be_written_after_a_runner_refusal_keeps_the_refusal(
    fails: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runner refuses the apply before it leaves this host.  With every
    receipt write failing the pending one is not written and nothing is
    tried; with only the refused receipt failing, the pending one stays
    (a retry reads the DC before it sends)."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab = _lab()
    plan_id = _approved_plan(lab)

    def refused(target: object, body: dict[str, object]) -> dict[str, object]:
        raise RunnerRefused("the inventory entry has no key file")

    if fails == "every":
        _receipt_write_fails(monkeypatch)
    else:
        _final_receipt_write_fails(monkeypatch)
    result = ad_apply.apply_change(plan_id, send=refused, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REFUSED
    assert result["code"] == "not_sent"
    assert "receipt_error" in result
    if fails == "final":
        assert result["message"] == ad_apply.REFUSED_BEFORE_SEND_MESSAGE
        assert result["receipt_error"] == ad_apply.RECEIPT_ERROR_MESSAGE
        _assert_pending_kept(plan_id)
    else:
        assert result["message"] == ad_apply.PENDING_REFUSED_MESSAGE
        assert not store.receipt_path(plan_id).exists()


def test_a_user_create_whose_receipt_could_not_be_written_is_never_sent_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The apply sent the password and its final receipt could not be
    written: the plan record no longer holds the password, so a second
    apply is refused on the Newton host as before."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    _final_receipt_write_fails(monkeypatch)

    first = ad_apply.apply_change(plan_id, send=_lost_apply(lab), devices=lab.devices, timeout_s=0.0)
    assert first["state"] == ad_apply.STATE_APPLY_UNKNOWN

    result, modes = _second_apply(lab, plan_id)

    _assert_refused_locally(result, modes)


def test_the_rendered_result_carries_the_receipt_error() -> None:
    """receipt_error is Newton's own text, so the model sees it as it is."""
    from newton_mcp.ad.write import render as ad_render

    rendered = ad_render.applied({
        "result": "ok", "state": "confirmed", "receipt_error": ad_apply.RECEIPT_ERROR_MESSAGE,
    })

    assert rendered["receipt_error"] == ad_apply.RECEIPT_ERROR_MESSAGE
    assert "receipt_error" not in ad_render.applied({"result": "ok", "state": "confirmed"})


# ---- the README's "covered by tests" marks ---------------------------------------

COMPUTER_CLASSES = ["top", "person", "organizationalPerson", "user", "computer"]


def _computer_lab(uac: int, **kwargs: object) -> harness.Lab:
    lab = harness.Lab(**kwargs)  # type: ignore[arg-type]
    lab.add_user(guid="c09619ff-8b86-d011-b42d-00c04fc964ff", sid="S-1-5-21-1-2-3-1120",
                 sam="ws01$", uac=uac, object_class=COMPUTER_CLASSES)
    return lab


def _computer_uac(lab: harness.Lab) -> int:
    return int(lab.objects["c09619ff-8b86-d011-b42d-00c04fc964ff"]["uac"])


@pytest.mark.parametrize("verb, before, after", [("disable", 4096, 4098), ("enable", 4098, 4096)])
def test_a_computer_account_is_disabled_or_enabled_and_confirmed_through_the_apply(
    verb: str, before: int, after: int,
) -> None:
    lab = _computer_lab(before)
    plan_id = _approved_plan(lab, verb, ["ws01$"], None)

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert _status(lab, plan_id)["state"] == "confirmed"
    assert _computer_uac(lab) == after


@pytest.mark.parametrize("verb, before", [("disable", 4096), ("enable", 4098)])
def test_a_computer_account_disable_or_enable_a_dc_did_not_show_is_undone(
    verb: str, before: int,
) -> None:
    lab = _computer_lab(before)
    plan_id = _approved_plan(lab, verb, ["ws01$"], None)
    lab.lag()

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_NOT_TESTED
    assert result["restored"] is True
    assert _status(lab, plan_id)["state"] == "undone"
    assert _computer_uac(lab) == before


def test_a_privileged_account_is_unlocked_through_the_apply_and_never_undone() -> None:
    """A privileged account (adminCount 1, privileged) may be unlocked: the
    plan is HIGH, the apply confirms it, and the abort tool never puts the
    lockout back."""
    lab = harness.Lab()
    lab.add_user(uac=512, lockout=5, privileged=True, admin_count=1)
    plan_id = _approved_plan(lab, "unlock", value=None)
    assert store.read_json(store.plan_path(plan_id))["risk"] == "HIGH"

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert lab.objects[harness.SEED_GUID]["lockout"] == 0
    aborted = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)
    assert aborted["message"] == ad_apply.UNLOCK_ABORT_MESSAGE
    assert lab.objects[harness.SEED_GUID]["lockout"] == 0
    assert _status(lab, plan_id)["state"] == "confirmed"


# ---- a status the DC answers with an error ------------------------------------


def test_a_status_the_dc_answers_with_an_error_says_the_record_could_not_be_read() -> None:
    """Both helpers answer a status with error when the record cannot be read
    (a read that throws): the result says the state could not be read and
    never names a state."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "status":
            return {"v": 1, "code": "error"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.change_status(plan_id, send=send, devices=lab.devices)

    assert result["result"] == "error"
    assert result["state"] is None
    message = _said(result)
    assert "could not be read" in message
    assert "newton_ad_change_status" in message


# ---- an apply refused because another change of the target is armed --------


def test_an_apply_refused_while_another_change_of_the_target_is_armed_says_so() -> None:
    """Both helpers refuse an apply with conflict and armed while another
    armed record names the same target (its undo could write over this
    change once confirmed).  Nothing was written: Newton reports a conflict,
    sends no confirm or abort, and tells the owner why and what to do."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    plan = store.read_json(store.plan_path(plan_id))
    modes: list[str] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        modes.append(str(body["mode"]))
        if body["mode"] == "apply":
            return {"v": 1, "code": "conflict", "live": plan["before"], "armed": True}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFLICT
    assert result["message"] == ad_apply.ARMED_CONFLICT_MESSAGE
    message = " ".join(str(result["message"]).split())
    assert "another change of the same target is still armed" in message
    assert "nothing was written" in message
    assert "confirm" not in modes and "abort" not in modes
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["message"] == result["message"]


# ---- a confirm answered with an error whose record cannot be read -----------


def test_the_not_confirmed_no_record_message_never_says_the_confirm_was_not_recorded() -> None:
    """The DC answered the confirm with an error and Newton could not read its
    record.  A helper can land the confirmed record and still answer error
    (the flush of its directory failed and its read-back failed too), so the
    message says Newton does not know whether the confirm was recorded and
    names confirmed among the states the record may read."""
    message = " ".join(ad_apply.NOT_CONFIRMED_NO_RECORD_MESSAGE.split())
    assert "the confirm was not recorded" not in message
    assert "does not know whether the confirm was recorded" in message
    assert "confirmed means" in message


# ---- a password the plan record could not drop is reported -----------------


def test_a_user_create_password_the_plan_record_cannot_drop_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The apply sent the password and the plan record cannot be rewritten
    without it: the password stays in the plan record, so the result says
    so in secret_error (Newton's own text) and the AD result stands."""
    from newton_mcp.ad.write import render

    import harness as _harness

    lab = _harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], _harness.DOMAIN_GUID)
    plan_path = store.plan_path(plan_id)
    real = store.write_json

    def failing(path: Path, value: object) -> None:
        if Path(path) == plan_path:
            raise OSError("the state directory is read-only")
        real(path, value)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "write_json", failing)

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert "secret" in store.read_json(plan_path)
    assert result["secret_error"] == ad_apply.SECRET_ERROR_MESSAGE
    assert "password" in ad_apply.SECRET_ERROR_MESSAGE
    assert render.applied(result)["secret_error"] == ad_apply.SECRET_ERROR_MESSAGE


def test_a_user_create_password_the_plan_record_drops_carries_no_secret_error() -> None:
    import harness as _harness

    lab = _harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], _harness.DOMAIN_GUID)

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert "secret_error" not in result
    assert "secret" not in store.read_json(store.plan_path(plan_id))


# ---- an apply that reached the DC but left no receipt -----------------------


class _HostDied(BaseException):
    """The Newton host stopped between the send and the receipt."""


def _member_add_lab() -> tuple[harness.Lab, str]:
    lab = harness.Lab()
    lab.add_group()
    lab.add_user()
    lab.add_other()
    return lab, _approved_plan(lab, "member-add", ["seed-group", "other"], None)


def _sent_without_receipt(
    verb: str, loss: str, monkeypatch: pytest.MonkeyPatch
) -> tuple[harness.Lab, str]:
    """A first apply that reached the DC and left no final receipt on this
    host: the host stopped right after the DC answered, or the final
    receipt write failed (both leave the pending receipt), or the receipt
    is gone from this host altogether (a state directory restored from an
    older copy, say)."""
    lab, plan_id = _unlock_lab() if verb == "unlock" else _member_add_lab()
    if loss == "host-died":
        _died_after_send(lab, plan_id)
    else:
        receipt_path = store.receipt_path(plan_id)
        real = store.write_json

        def failing(path: Path, value: object) -> None:
            if Path(path) == receipt_path and not (
                isinstance(value, dict) and value.get("pending") is True
            ):
                raise OSError("the state directory is full")
            real(path, value)  # type: ignore[arg-type]

        monkeypatch.setattr(store, "write_json", failing)
        first = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)
        assert first["receipt_error"] == ad_apply.RECEIPT_ERROR_MESSAGE
        monkeypatch.setattr(store, "write_json", real)
    if loss == "receipt-gone":
        store.receipt_path(plan_id).unlink()
        assert not store.receipt_path(plan_id).exists()
    else:
        _assert_pending_kept(plan_id)
    assert _status(lab, plan_id)["state"] in ("armed", "confirmed")
    return lab, plan_id


LOSSES = ["host-died", "receipt-write-failed", "receipt-gone"]


def _make_stale(lab: harness.Lab, retry: str) -> None:
    """The approval is over (expired), or the key of the DC changed since
    the approval (bad_token)."""
    for helper in lab.helpers.values():
        if retry == "expired":
            helper.now = harness.EXP + 1
        else:
            helper.key_hex = "22" * 32


def _assert_never_refused(lab: harness.Lab, plan_id: str, result: dict[str, object],
                          state_before: object) -> None:
    assert result["state"] != ad_apply.STATE_REFUSED
    assert "nothing changed" not in str(result["message"])
    assert "newton_ad_change_status" in str(result["message"])
    path = store.receipt_path(plan_id)
    if path.exists():
        assert store.read_json(path)["state"] != ad_apply.STATE_REFUSED
    assert _status(lab, plan_id)["state"] == state_before


@pytest.mark.parametrize("retry", ["expired", "bad_token"])
@pytest.mark.parametrize("loss", LOSSES)
@pytest.mark.parametrize("verb", ["unlock", "member-add"])
def test_a_retry_of_a_sent_apply_with_a_stale_approval_answers_replay(
    verb: str, loss: str, retry: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first apply reached the DC and left no final receipt.  With its
    pending receipt kept, the retry reads the DC's record by txid, finds
    it, and sends nothing.  With no receipt at all, Newton sends the plan
    again, and the helper looks for a record of the txid before the token
    and the window, so a stale approval still answers replay.  Either way
    the owner is sent to newton_ad_change_status, and no refused receipt is
    written over a change the DC holds."""
    lab, plan_id = _sent_without_receipt(verb, loss, monkeypatch)
    state_before = _status(lab, plan_id)["state"]
    _make_stale(lab, retry)
    seen: list[str] = []

    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REPLAY
    if loss == "receipt-gone":
        assert seen == ["apply"]
        assert result["code"] == "replay"
    else:
        assert seen == ["status"]
        assert result["code"] == "not_sent"
        _assert_pending_kept(plan_id)
    _assert_never_refused(lab, plan_id, result, state_before)


@pytest.mark.parametrize("retry", ["expired", "bad_token"])
@pytest.mark.parametrize("loss", LOSSES)
@pytest.mark.parametrize("verb", ["unlock", "member-add"])
def test_a_pre_write_code_for_a_txid_the_dc_holds_is_never_refused(
    verb: str, loss: str, retry: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A helper installed by an earlier release checks the token and the
    window before the replay, so it answers the retry expired or bad_token
    although it holds a record of the txid.  With the pending receipt kept,
    the retry reads that record first and sends nothing.  With no receipt,
    Newton reads that record by txid before it reports refused: the record
    is there, so the outcome is apply_unknown.  No refused receipt is
    written either way."""
    lab, plan_id = _sent_without_receipt(verb, loss, monkeypatch)
    state_before = _status(lab, plan_id)["state"]
    seen: list[str] = []

    def old_helper(target: object, body: dict[str, object]) -> dict[str, object]:
        seen.append(str(body["mode"]))
        if body["mode"] == "apply":
            return {"v": 1, "code": retry}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=old_helper, devices=lab.devices, timeout_s=0.0)

    if loss == "receipt-gone":
        assert seen == ["apply", "status"]
        assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
        assert result["code"] == retry
    else:
        assert seen == ["status"]
        _assert_refused_locally(result, [])
    _assert_never_refused(lab, plan_id, result, state_before)
    assert store.read_json(store.receipt_path(plan_id))["state"] == ad_apply.STATE_APPLY_UNKNOWN


@pytest.mark.parametrize("code", sorted(ad_apply.PRE_WRITE_CODES))
def test_a_pre_write_code_whose_status_read_fails_is_not_refused(code: str) -> None:
    """Newton reports refused on a pre-write code only when the DC's
    record by txid says not_found or refused: a status read that fails
    says neither."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": code}
        if body["mode"] == "status":
            raise TransportError("unavailable", "the session failed")
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert result["message"] == ad_apply.DC_ERROR_NO_RECORD_MESSAGE
    assert store.read_json(store.receipt_path(plan_id))["state"] == ad_apply.STATE_APPLY_UNKNOWN


# ---- a pending receipt is written before every apply is sent ----------------------


def _verb_lab(verb: str) -> tuple[harness.Lab, str]:
    """One approved plan of the verb, in its own lab."""
    if verb == "unlock":
        return _unlock_lab()
    if verb == "member-add":
        return _member_add_lab()
    if verb == "user-create":
        lab = harness.Lab()
        lab.add_user(uac=512)
        lab.add_domain_head()
        return lab, _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    lab = _lab()
    return lab, _approved_plan(lab)


PENDING_VERBS = ["uac-clear", "member-add", "unlock", "user-create"]


def _receipt(plan_id: str) -> dict[str, object]:
    return store.read_json(store.receipt_path(plan_id))


def _assert_pending(receipt: dict[str, object]) -> None:
    """A pending receipt: Newton was about to send, and does not know the
    outcome.  It never says nothing was sent or nothing changed."""
    assert receipt["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert receipt["pending"] is True
    message = " ".join(str(receipt["message"]).split())
    assert message == " ".join(ad_apply.PENDING_MESSAGE.split())
    assert "about to send" in message
    assert "does not yet know" in message
    assert "nothing was sent" not in message
    assert "nothing changed" not in message
    assert "newton_ad_change_status" in message


def _modes(lab: harness.Lab, seen: list[str]):
    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        seen.append(str(body["mode"]))
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


@pytest.mark.parametrize("verb", PENDING_VERBS)
def test_a_pending_receipt_is_written_and_synced_before_the_apply_is_sent(
    verb: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before the apply leaves this host, its receipt already reads
    apply_unknown (pending) on the disk, written through the store's
    fsync'd atomic write; the final receipt then replaces it."""
    lab, plan_id = _verb_lab(verb)
    written: list[dict[str, object]] = []
    real = store.write_json

    def spy(path: Path, value: object) -> None:
        real(path, value)
        if Path(path) == store.receipt_path(plan_id):
            written.append(dict(value))  # type: ignore[arg-type]

    monkeypatch.setattr(store, "write_json", spy)
    at_send: list[dict[str, object]] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            at_send.append(_receipt(plan_id))
            assert len(written) == 1
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert len(at_send) == 1
    _assert_pending(at_send[0])
    assert "secret" not in at_send[0]
    assert written[0] == at_send[0]
    final = _receipt(plan_id)
    assert final["state"] == ad_apply.STATE_CONFIRMED
    assert "pending" not in final


def test_the_store_write_of_a_receipt_is_synced_before_it_is_renamed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pending receipt reaches the disk before the send: the store
    flushes and fsyncs the file (with its bytes in it) before it renames it
    into place, then fsyncs the directory, so the rename survives a power
    cut too."""
    import os
    import stat

    order: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def spy_fsync(fd: int) -> None:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            order.append("fsync-dir")
        else:
            assert info.st_size > 0, "the file is synced before its bytes are flushed"
            order.append("fsync-file")
        real_fsync(fd)

    store.receipts_dir().mkdir(parents=True, exist_ok=True, mode=0o700)  # already there
    monkeypatch.setattr(os, "fsync", spy_fsync)
    monkeypatch.setattr(
        os, "replace", lambda a, b: (order.append("replace"), real_replace(a, b))[1]
    )
    store.write_json(store.receipt_path("a" * 32), {"state": "apply_unknown"})
    # ad-receipts and every directory above it to the root, on every write.
    depth = 1 + len(store.receipts_dir().parents)
    assert order == ["fsync-file", "replace", *["fsync-dir"] * depth]


@pytest.mark.parametrize("verb", PENDING_VERBS)
def test_a_pending_receipt_that_cannot_be_written_sends_nothing(
    verb: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pending receipt cannot be written (a full disk): Newton sends
    nothing, says so truthfully, and a user-create keeps its password."""
    lab, plan_id = _verb_lab(verb)
    _receipt_write_fails(monkeypatch)
    seen: list[str] = []

    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert seen == []
    assert result["state"] == ad_apply.STATE_REFUSED
    assert result["code"] == "not_sent"
    message = " ".join(str(result["message"]).split())
    assert message == " ".join(ad_apply.PENDING_REFUSED_MESSAGE.split())
    assert "nothing was sent" in message
    assert "could not record" in message
    assert result["receipt_error"] == ad_apply.PENDING_ERROR_MESSAGE
    assert not store.receipt_path(plan_id).exists()
    assert _status(lab, plan_id)["code"] == "not_found"
    if verb == "user-create":
        assert isinstance(store.read_json(store.plan_path(plan_id)).get("secret"), str)


def _died_before_send(lab: harness.Lab, plan_id: str) -> None:
    """The host stops right after the pending receipt reached the disk,
    before the apply leaves it (nothing after that write runs)."""
    real = store.write_json
    seen: list[str] = []

    def died(path: Path, value: object) -> None:
        real(path, value)
        if Path(path) == store.receipt_path(plan_id):
            raise _HostDied()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(store, "write_json", died)
        with pytest.raises(_HostDied):
            ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                  timeout_s=0.0)
    assert seen == []


def _died_after_send(lab: harness.Lab, plan_id: str) -> None:
    """The host stops after the DC answered the apply, before the final
    receipt is written."""

    def died(target: object, body: dict[str, object]) -> dict[str, object]:
        answer = lab.send(target, body)  # type: ignore[arg-type]
        if body["mode"] == "apply":
            raise _HostDied()
        return answer

    with pytest.raises(_HostDied):
        ad_apply.apply_change(plan_id, send=died, devices=lab.devices, timeout_s=0.0)


@pytest.mark.parametrize("verb", ["uac-clear", "member-add", "unlock"])
def test_a_host_that_died_after_the_pending_write_and_before_the_send(verb: str) -> None:
    """Nothing reached the DC.  The receipt says apply_unknown, never that
    nothing was sent; the status reads the DC, and its not_found is what
    says no apply reached the write.  A retry reads the DC by txid first,
    finds nothing and sends the apply."""
    lab, plan_id = _verb_lab(verb)
    _died_before_send(lab, plan_id)
    _assert_pending(_receipt(plan_id))

    status = ad_apply.change_status(plan_id, send=lab.send, devices=lab.devices)

    assert status["code"] == "not_found"
    message = " ".join(str(status["message"]).split())
    assert message == " ".join(ad_apply.PENDING_NOT_FOUND_MESSAGE.split())
    assert "holds no record" in message
    assert "had reached the DC's write when it was read" in message
    _assert_pending(_receipt(plan_id))

    seen: list[str] = []
    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert seen[:2] == ["status", "apply"]
    assert result["state"] == ad_apply.STATE_CONFIRMED
    assert _receipt(plan_id)["state"] == ad_apply.STATE_CONFIRMED


def test_a_user_create_whose_host_died_before_the_send_is_sent_again() -> None:
    """The password never left: the plan record keeps it, so a retry reads
    the DC, finds nothing and creates the user."""
    lab, plan_id = _verb_lab("user-create")
    _died_before_send(lab, plan_id)
    assert isinstance(store.read_json(store.plan_path(plan_id)).get("secret"), str)
    seen: list[str] = []

    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert seen[:2] == ["status", "apply"]
    assert result["state"] == ad_apply.STATE_CONFIRMED


@pytest.mark.parametrize("verb", PENDING_VERBS)
def test_a_host_that_died_after_the_send_before_the_final_receipt(verb: str) -> None:
    """The DC holds the change and the receipt is still pending: the status
    reads the DC's state and says nothing of not_found; a retry reads the DC
    (a user-create, whose password is gone, sends nothing at all), refuses
    on this host, and keeps the pending receipt."""
    lab, plan_id = _verb_lab(verb)
    _died_after_send(lab, plan_id)
    pending = _receipt(plan_id)
    _assert_pending(pending)
    held = _status(lab, plan_id)["state"]
    assert held in ("armed", "confirmed")

    status = ad_apply.change_status(plan_id, send=lab.send, devices=lab.devices)
    assert status["state"] == held
    assert "message" not in status or "holds no record" not in str(status["message"])

    seen: list[str] = []
    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert seen == ([] if verb == "user-create" else ["status"])
    _assert_refused_locally(result, [])
    assert _receipt(plan_id) == pending
    assert _status(lab, plan_id)["state"] == held


@pytest.mark.parametrize("verb", ["uac-clear", "member-add", "unlock"])
@pytest.mark.parametrize("where", ["preflight", "every-send"])
def test_a_runner_refusal_on_a_retry_after_a_lost_final_receipt_never_reads_refused(
    verb: str, where: str
) -> None:
    """The first apply reached the DC and the host stopped before its final
    receipt.  The retry meets a runner that refuses before anything leaves
    the host: the answer never says refused or nothing changed, the pending
    receipt stays, and the DC's change is untouched."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab, plan_id = _verb_lab(verb)
    _died_after_send(lab, plan_id)
    pending = _receipt(plan_id)
    held = _status(lab, plan_id)["state"]

    def refused(*args: object) -> dict[str, object]:
        raise RunnerRefused("the inventory entry has no key file")

    if where == "preflight":
        result = ad_apply.apply_change(plan_id, send=lab.send, preflight=refused,
                                       devices=lab.devices, timeout_s=0.0)
    else:
        result = ad_apply.apply_change(plan_id, send=refused, devices=lab.devices,
                                       timeout_s=0.0)

    assert result["state"] != ad_apply.STATE_REFUSED
    message = " ".join(str(result["message"]).split())
    assert "nothing changed" not in message
    assert "may already be written" in message
    assert "newton_ad_change_status" in message
    assert _receipt(plan_id) == pending
    assert _status(lab, plan_id)["state"] == held


def test_a_pre_flight_refusal_of_a_first_apply_writes_no_pending_receipt() -> None:
    """The pending receipt is written only once the pre-flight passed: a
    first apply the runner refuses there leaves the refused receipt alone,
    which truthfully says nothing was sent, and the plan can be applied
    again."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab, plan_id = _verb_lab("uac-clear")
    written: list[dict[str, object]] = []
    real = store.write_json

    def spy(path: Path, value: object) -> None:
        if Path(path) == store.receipt_path(plan_id):
            written.append(dict(value))  # type: ignore[arg-type]
        real(path, value)

    def refused(*args: object) -> None:
        raise RunnerRefused("the inventory entry has no key file")

    seen: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(store, "write_json", spy)
        result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), preflight=refused,
                                       devices=lab.devices, timeout_s=0.0)

    assert seen == []
    assert result["state"] == ad_apply.STATE_REFUSED
    assert result["code"] == "not_sent"
    assert result["message"] == ad_apply.REFUSED_BEFORE_SEND_MESSAGE
    assert [one["state"] for one in written] == [ad_apply.STATE_REFUSED]

    again = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)
    assert again["state"] == ad_apply.STATE_CONFIRMED


@pytest.mark.parametrize("where", ["preflight", "apply-send"])
def test_a_refusal_before_send_after_an_earlier_pending_receipt_keeps_it(where: str) -> None:
    """An earlier attempt left a pending receipt (the host stopped before
    its send) and the DC holds no record of the txid.  This attempt is
    refused before anything leaves the host: no refused receipt is written
    over the pending one, and the answer never says nothing changed."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab, plan_id = _verb_lab("uac-clear")
    _died_before_send(lab, plan_id)
    pending = _receipt(plan_id)

    def refuses_apply(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            raise RunnerRefused("ssh could not be started")
        return lab.send(target, body)  # type: ignore[arg-type]

    def refused(*args: object) -> None:
        raise RunnerRefused("the inventory entry has no key file")

    if where == "preflight":
        result = ad_apply.apply_change(plan_id, send=lab.send, preflight=refused,
                                       devices=lab.devices, timeout_s=0.0)
    else:
        result = ad_apply.apply_change(plan_id, send=refuses_apply, devices=lab.devices,
                                       timeout_s=0.0)

    assert result["code"] == "not_sent"
    message = " ".join(str(result["message"]).split())
    assert message == " ".join(ad_apply.EARLIER_PENDING_REFUSED_MESSAGE.split())
    assert "nothing changed" not in message
    receipt = _receipt(plan_id)
    assert receipt["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert receipt["pending"] is True
    if where == "preflight":
        assert receipt == pending
    assert _status(lab, plan_id)["code"] == "not_found"


def test_a_pending_retry_whose_status_read_fails_sends_nothing_more() -> None:
    """The DC's record cannot be read on the retry: Newton cannot tell a
    send that never left from one the DC holds, so it refuses on this host
    and keeps the pending receipt."""
    lab, plan_id = _verb_lab("uac-clear")
    _died_before_send(lab, plan_id)
    pending = _receipt(plan_id)
    seen: list[str] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        seen.append(str(body["mode"]))
        if body["mode"] == "status":
            raise TransportError("unavailable", "the session failed")
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert seen == ["status"]
    _assert_refused_locally(result, [])
    assert _receipt(plan_id) == pending


@pytest.mark.parametrize("answer", [{"code": "error"}, {"code": "ok", "state": "refused"}])
def test_a_pending_retry_sends_only_on_a_not_found(answer: dict[str, object]) -> None:
    """Only the DC's not_found says no apply of the txid reached its write:
    a status answered error, or a record in any state (refused included:
    the earlier send reached the DC), keeps the plan from being sent."""
    lab, plan_id = _verb_lab("uac-clear")
    _died_before_send(lab, plan_id)
    seen: list[str] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        seen.append(str(body["mode"]))
        if body["mode"] == "status":
            return {"v": 1, **answer}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert seen == ["status"]
    _assert_refused_locally(result, [])


def test_an_abort_with_a_pending_receipt_asks_the_dc() -> None:
    """The abort never reads the receipt: it asks the DC, which holds the
    armed change the lost final receipt never recorded."""
    lab, plan_id = _verb_lab("uac-clear")
    _died_after_send(lab, plan_id)
    assert _status(lab, plan_id)["state"] == "armed"

    result = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert result["code"] == "ok"
    assert result["state"] == "undone"


def test_the_apply_runs_the_transport_preflight_before_the_pending_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the real transport (no injected sender), the apply runs the
    transport's pre-flight first: a refusal there sends nothing and writes
    only the refused receipt, never a pending one."""
    from newton_mcp.adapters.ssh_cli import RunnerRefused

    lab, plan_id = _verb_lab("uac-clear")
    sent: list[object] = []
    written: list[dict[str, object]] = []
    real = store.write_json

    def spy(path: Path, value: object) -> None:
        if Path(path) == store.receipt_path(plan_id):
            written.append(dict(value))  # type: ignore[arg-type]
        real(path, value)

    def preflight(target: object, payload: object) -> None:
        raise RunnerRefused("the inventory entry has no key file")

    monkeypatch.setattr(store, "write_json", spy)
    monkeypatch.setattr(transport, "preflight", preflight)
    monkeypatch.setattr(transport, "send", lambda *args: sent.append(args) or {})

    result = ad_apply.apply_change(plan_id, devices=lab.devices, timeout_s=0.0)

    assert sent == []
    assert result["state"] == ad_apply.STATE_REFUSED
    assert result["message"] == ad_apply.REFUSED_BEFORE_SEND_MESSAGE
    assert [one.get("pending") for one in written] == [None]


def test_a_first_receipt_syncs_the_entry_of_every_directory_it_created(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first receipt of a host creates ad-receipts (and the state
    directory, when it is new).  Each created directory is an entry in its
    parent, so the parent of every directory the write created is fsynced
    too: else a power cut can lose the whole receipts directory."""
    import os

    state = store.state_dir()
    receipts = store.receipts_dir()
    assert not receipts.exists()
    synced: list[Path] = []
    names: dict[int, Path] = {}
    real_open, real_fsync = os.open, os.fsync

    def spy_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if flags & os.O_DIRECTORY:
            names[fd] = Path(str(path))
        return fd

    def spy_fsync(fd: int) -> None:
        if fd in names:
            synced.append(names[fd])
        real_fsync(fd)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    store.write_json(store.receipt_path("b" * 32), {"state": "apply_unknown"})

    assert receipts in synced
    assert state in synced, "the entry of ad-receipts in the state directory is never synced"


def test_a_second_apply_while_one_runs_is_refused_and_leaves_the_receipt() -> None:
    """Caller A has read no receipt and waits in the runner pre-flight
    while caller B applies the same plan.  B is refused on this host before
    it sends anything, so A's answer and the receipt on disk agree, and no
    result says a receipt was kept that was written over."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    inner: list[dict[str, object]] = []

    def preflight(target: object, payload: object) -> None:
        inner.append(ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices,
                                           timeout_s=0.0))

    outer = ad_apply.apply_change(plan_id, send=lab.send, preflight=preflight,
                                  devices=lab.devices, timeout_s=0.0)

    assert inner and inner[0]["code"] == "not_sent"
    assert "kept" not in " ".join(str(inner[0]["message"]).split())
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == outer["state"]
    assert outer["state"] == ad_apply.STATE_CONFIRMED


def test_the_pending_not_found_claim_allows_for_an_apply_still_on_its_way() -> None:
    """not_found says only that the DC held no record when it was read: an
    apply that left the host before Newton stopped can still be waiting on
    the DC.  The message and the status tool's description say so."""
    import newton_mcp.server as server

    message = " ".join(ad_apply.PENDING_NOT_FOUND_MESSAGE.split())
    assert "so nothing changed" not in message
    assert "still on its way" in message
    assert "status again" in message
    description = " ".join(inspect.getdoc(server.newton_ad_change_status).split()) if server.newton_ad_change_status.__doc__ else ""
    source = " ".join(inspect.getsource(server).split())
    assert "reached the DC's write, so nothing changed" not in source
    assert "still on its way" in source
    del description


def test_the_first_apply_of_a_host_syncs_the_receipts_entry_before_it_sends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Driven through apply_change from a state directory with no
    ad-receipts: whoever creates the directory (the apply lock does, before
    the receipt write), the state directory and its parent are fsynced
    before the apply leaves the host."""
    import os

    lab = _lab()
    plan_id = _approved_plan(lab)
    receipts = store.receipts_dir()
    if receipts.exists():
        for child in receipts.iterdir():
            child.unlink()
        receipts.rmdir()
    state = store.state_dir()
    synced: list[Path] = []
    names: dict[int, Path] = {}
    real_open, real_fsync = os.open, os.fsync
    synced_at_send: list[list[Path]] = []

    def spy_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if flags & os.O_DIRECTORY:
            names[fd] = Path(str(path))
        return fd

    def spy_fsync(fd: int) -> None:
        if fd in names:
            synced.append(names[fd])
        real_fsync(fd)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            synced_at_send.append(list(synced))
        return lab.send(target, body)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert synced_at_send, "the apply was never sent"
    assert receipts in synced_at_send[0]
    assert state in synced_at_send[0]
    assert state.parent in synced_at_send[0]


@pytest.mark.parametrize("fails", ["mkdir", "open"])
def test_a_lock_that_cannot_be_set_up_sends_nothing_and_says_so(
    fails: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-plan lock cannot be created (a read-only or full state
    directory): the apply is refused not_sent with the documented message,
    never an internal error, and nothing is sent."""
    import os

    lab = _lab()
    plan_id = _approved_plan(lab)
    seen: list[str] = []
    real_open = os.open

    if fails == "mkdir":
        def boom(*args: object, **kwargs: object) -> None:
            raise PermissionError("read-only state directory")
        monkeypatch.setattr(Path, "mkdir", boom)
    else:
        def spy_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            if str(path).endswith(".lock"):
                raise OSError(28, "No space left on device")
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        monkeypatch.setattr(os, "open", spy_open)

    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert seen == []
    assert result["code"] == "not_sent"
    assert result["state"] == ad_apply.STATE_REFUSED
    assert result["message"] == ad_apply.PENDING_REFUSED_MESSAGE


@pytest.mark.parametrize("code", sorted(ad_apply.PRE_WRITE_CODES))
def test_a_dc_refusal_of_a_retry_over_a_pending_receipt_keeps_it(code: str) -> None:
    """An earlier attempt left its pending receipt (the host died before
    the send).  The retry reads not_found, sends, and the DC refuses it
    before writing (not_pdc, say) while it still holds no record of the
    txid.  That says nothing about the earlier attempt, which may still be
    on its way: the receipt stays pending, and the answer never says
    nothing changed."""
    lab, plan_id = _verb_lab("uac-clear")
    _died_before_send(lab, plan_id)
    _assert_pending(_receipt(plan_id))

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": code}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    message = " ".join(str(result["message"]).split())
    assert "nothing changed" not in message
    assert "still be on its way" in message
    assert result["message"] == ad_apply.EARLIER_PENDING_DC_REFUSED_MESSAGE
    _assert_pending(_receipt(plan_id))


def test_a_receipt_write_syncs_the_parent_of_a_missing_ancestor_above_the_state_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEWTON_STATE_DIR names a path two levels below anything that exists
    (a missing ~/.local/state, say): mkdir creates them all, and the parent
    of the topmost one it created is synced too, since it holds that one's
    entry."""
    import os

    top = tmp_path / "local"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(top / "state" / "newton"))
    assert store.state_dir() == top / "state" / "newton"
    synced: list[Path] = []
    names: dict[int, Path] = {}
    real_open, real_fsync = os.open, os.fsync

    def spy_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if flags & os.O_DIRECTORY:
            names[fd] = Path(str(path))
        return fd

    def spy_fsync(fd: int) -> None:
        if fd in names:
            synced.append(names[fd])
        real_fsync(fd)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    store.write_json(store.receipt_path("d" * 32), {"state": "apply_unknown"})

    assert top / "state" in synced
    assert top in synced, "the entry of the new local/state in local is never synced"
    assert tmp_path in synced, "the entry of the new local in its parent is never synced"


def test_a_receipt_write_syncs_every_directory_up_to_the_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ancestors of the state directory already exist, made by an
    earlier step that synced none of them: a receipt write still syncs
    every directory from its own up to the root, whoever created them."""
    import os

    state = tmp_path / "local" / "state" / "newton"
    (state / "ad-receipts").mkdir(parents=True)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    synced: list[Path] = []
    names: dict[int, Path] = {}
    real_open, real_fsync = os.open, os.fsync

    def spy_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if flags & os.O_DIRECTORY:
            names[fd] = Path(str(path))
        return fd

    def spy_fsync(fd: int) -> None:
        if fd in names:
            synced.append(names[fd])
        real_fsync(fd)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    store.write_json(store.receipt_path("e" * 32), {"state": "apply_unknown"})

    receipts = state / "ad-receipts"
    for directory in (receipts, *receipts.parents):
        assert directory in synced, f"{directory} is never synced"


def _user_create_retry_refused(monkeypatch: pytest.MonkeyPatch, *, drop_fails: bool
                               ) -> tuple[str, dict[str, object]]:
    lab, plan_id = _verb_lab("user-create")
    _died_before_send(lab, plan_id)
    if drop_fails:
        real = store.write_json

        def write_json(path: Path, value: object) -> None:
            if path == store.plan_path(plan_id):
                raise OSError(28, "No space left on device")
            real(path, value)

        monkeypatch.setattr(store, "write_json", write_json)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "expired"}
        return lab.send(target, body)  # type: ignore[arg-type]

    return plan_id, ad_apply.apply_change(plan_id, send=send, devices=lab.devices,
                                          timeout_s=0.0)


def test_a_refused_user_create_retry_whose_password_stays_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry sent the password and the DC refused it before writing;
    dropping the password from the plan record failed: the answer warns
    that the password is still stored."""
    _, result = _user_create_retry_refused(monkeypatch, drop_fails=True)
    assert result["secret_error"] == ad_apply.SECRET_ERROR_MESSAGE


def test_a_refused_user_create_retry_says_to_plan_the_user_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry sent the password, so the plan is spent: every later apply
    is refused not_sent.  The answer says to plan the user again, never to
    apply the same plan again."""
    plan_id, result = _user_create_retry_refused(monkeypatch, drop_fails=False)
    message = " ".join(str(result["message"]).split())
    assert "apply the same plan again" not in message
    assert "plan the user again" in message
    assert "nothing changed" not in message


@pytest.mark.parametrize("fails", ["pending", "lock"])
def test_a_retry_that_cannot_record_itself_keeps_the_earlier_caveat(
    fails: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An earlier attempt left its pending receipt.  The retry cannot write
    its own pending receipt, or cannot set up the lock: it sends nothing,
    and its answer says the earlier apply may have reached the DC, never
    only that this apply changed nothing."""
    lab, plan_id = _verb_lab("uac-clear")
    _died_before_send(lab, plan_id)
    if fails == "pending":
        _receipt_write_fails(monkeypatch)
    else:
        def boom(*args: object, **kwargs: object) -> None:
            raise PermissionError("read-only state directory")
        monkeypatch.setattr(Path, "mkdir", boom)
    seen: list[str] = []

    result = ad_apply.apply_change(plan_id, send=_modes(lab, seen), devices=lab.devices,
                                   timeout_s=0.0)

    assert "apply" not in seen
    assert result["code"] == "not_sent"
    assert result["message"] == ad_apply.EARLIER_PENDING_NOT_SENT_MESSAGE
    _assert_pending(_receipt(plan_id))


def test_a_stale_before_image_conflict_names_the_cause_and_keeps_the_live_value() -> None:
    """Somebody changed the target between the plan and the apply: the DC
    answers conflict with its live value.  The owner is told the target
    changed since the plan and to plan again, and the live value reaches
    the result (and the receipt), never thrown away."""
    from newton_mcp.ad.write import render as ad_render

    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] = 512

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFLICT
    message = " ".join(str(result.get("message")).split())
    assert "changed since the plan" in message
    assert "plan the change again" in message
    assert "nothing was written" in message
    assert isinstance(result.get("live"), dict) and result["live"]
    assert "live" in ad_render.applied(result)
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["live"] == result["live"]
    assert receipt["message"] == result["message"]


@pytest.mark.parametrize(
    ("code", "step"),
    [
        ("expired", "approve the plan again"),
        ("bad_token", "approve the plan again"),
        ("risk_mismatch", "plan the change again"),
        ("not_pdc", "PDC emulator"),
        ("privileged", "privileged"),
        ("schema", "write setup"),
    ],
)
def test_a_pre_write_refusal_names_its_codes_next_step(code: str, step: str) -> None:
    """The DC refused before writing and has no record of the txid: the
    answer still says nothing changed, and adds the next step of the code
    the DC named."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": code}
        if body["mode"] == "status":
            return {"v": 1, "code": "not_found"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REFUSED
    message = " ".join(str(result["message"]).split())
    assert message.startswith(ad_apply.DC_REFUSED_MESSAGE)
    assert step in message
    assert message != ad_apply.DC_REFUSED_MESSAGE


def test_an_expired_user_create_says_plan_the_user_again() -> None:
    """A user-create's password left the plan record with the apply, so the
    same plan can never be applied again: the next step is a new plan."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": "expired"}
        if body["mode"] == "status":
            return {"v": 1, "code": "not_found"}
        return lab.send(target, body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_REFUSED
    message = " ".join(str(result["message"]).split())
    assert message.startswith(ad_apply.DC_REFUSED_MESSAGE)
    assert "plan the new user again" in message
    assert "approve the plan again" not in message


def test_a_conflict_whose_live_value_is_the_after_image_says_nothing_needs_applying() -> None:
    """Somebody made the planned change between the plan and the apply: the
    DC answers conflict with a live value equal to the plan's after-image.
    The owner is told the target already holds the planned value and that
    nothing needs applying, never to plan the same change again."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    record = store.read_json(store.plan_path(plan_id))
    lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] = 4260352 & ~4194304

    result = ad_apply.apply_change(plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == ad_apply.STATE_CONFLICT
    assert result.get("live") == record["after"], (result.get("live"), record["after"])
    message = " ".join(str(result.get("message")).split())
    assert "already holds the planned value" in message
    assert "nothing needs applying" in message
    assert "nothing was written" in message
    assert "plan the change again" not in message
    assert store.read_json(store.receipt_path(plan_id))["message"] == result["message"]
