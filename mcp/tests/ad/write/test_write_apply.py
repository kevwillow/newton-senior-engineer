"""The AD change apply, status and abort (DESIGN-1.4 section 1).

The confirm goes out only when every DC of the domain shows the
after-image.  A DC that does not is NOT TESTED, and the abort goes out
instead.  A conflict at the apply sends no confirm at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import harness
import pytest

from newton_mcp import approve
from newton_mcp.ad.write import apply as ad_apply, plan as ad_plan, request, store
from newton_mcp.ad.write import render as ad_render
from newton_mcp.ad.write.errors import WriteError


PASSPHRASE = "correct horse battery staple"
NBF = 1800000000
EXP = 1800000600


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The state directory of the test."""
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _approved_plan(lab: harness.Lab, verb: str = "uac-clear",
                   names: list[str] | None = None, value: object = 4194304,
                   send: object = None) -> str:
    """A plan of one change, with its approval."""
    result = ad_plan.plan_change(
        harness.DOMAIN,
        verb,
        ["seed-asrep"] if names is None else names,
        value,
        send=lab.send if send is None else send,
        devices=lab.devices,
    )
    plan_id = str(result["plan_id"])
    record = store.read_json(store.plan_path(plan_id))
    digest = request.digest(record)
    k_hex = harness.KEY_HEX
    store.write_json(
        store.approval_path(plan_id),
        {
            "plan_id": plan_id,
            "device": record["device"],
            "digest": digest,
            "nbf": NBF,
            "exp": EXP,
            "token": request.token(k_hex, digest, NBF, EXP),
        },
    )
    return plan_id


def _lab(**kwargs: object) -> harness.Lab:
    lab = harness.Lab(**kwargs)  # type: ignore[arg-type]
    lab.add_user(uac=4260352)
    return lab


def test_the_confirm_goes_out_only_when_every_dc_matches() -> None:
    """Every DC of the domain shows the after-image, so the change is confirmed."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == "confirmed"
    assert modes.count("confirm") == 1
    assert "abort" not in modes
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 66048


def test_a_change_reaches_the_second_dc_of_the_domain() -> None:
    """The second DC answers to the domain device's name.

    The setup of the second DC is run with ``--domain-device``: its
    helper is configured with the domain device's name and derives the
    key with it, so the plan's reads and the apply's verification reach
    it (SPEC-1.4-REQUEST section 1: ``device`` names the domain, and
    every DC of the domain holds the same K).
    """
    lab = _lab()
    reached: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        reached.append(str(target.name))  # type: ignore[attr-defined]
        return lab.send(target, request_body)  # type: ignore[arg-type]

    plan_id = _approved_plan(lab, send=send)
    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == "confirmed"
    assert set(reached) == {"win-dc1", "win-dc2"}
    for helper in lab.helpers.values():
        assert helper.objects[harness.SEED_GUID]["uac"] == 66048


def test_a_dc_configured_with_its_own_name_refuses_the_domain_device() -> None:
    """A DC whose device.txt holds its own name refuses the domain.

    That is what the setup wrote into the device file before it derived
    the name from ``--domain-device``: the request names the domain
    device, the helper of the second DC is configured with its own
    name, and no plan and no apply of the domain can be built.  The
    guard itself stays: the helper answers ``schema`` (SPEC-1.4-REQUEST
    section 1).
    """
    lab = _lab(dc2_configured="win-dc2")

    with pytest.raises(WriteError):
        ad_plan.plan_change(
            harness.DOMAIN,
            "uac-clear",
            ["seed-asrep"],
            4194304,
            send=lab.send,
            devices=lab.devices,
        )

    raw = json.dumps(
        {
            "v": 1,
            "mode": "read",
            "device": harness.DOMAIN,
            "verb": "uac-clear",
            "target": {"sam": "seed-asrep"},
        }
    ).encode("utf-8")
    assert lab.helpers["win-dc2"].handle(raw) == {"v": 1, "code": "schema"}
    assert lab.helpers["win-dc1"].handle(raw)["code"] == "ok"


def test_a_lagging_dc_gives_not_tested_and_an_abort() -> None:
    """A DC that does not catch up blocks the confirm."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    # the second DC keeps its own copy of the directory: it never sees the write
    lab.lag()
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == "not_tested"
    assert "confirm" not in modes
    assert modes.count("abort") == 1
    assert result["dcs"]["win-dc1"]["state"] == "matched"
    assert result["dcs"]["win-dc2"]["state"] == "not_tested"


def test_the_automatic_abort_carries_restored_and_conflicts() -> None:
    """A DC that does not catch up: the abort's restored and conflicts reach the owner.

    The apply aborts on its own, so the result, the receipt and the
    rendered answer must say what the undo left changed.
    """
    from newton_mcp.ad.write import render as ad_render

    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        if request_body["mode"] == "abort":
            return {"v": 1, "code": "ok", "restored": False,
                    "conflicts": [harness.SEED_GUID]}
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == "not_tested"
    assert result["restored"] is False
    assert result["conflicts"] == [harness.SEED_GUID]
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["restored"] is False
    assert receipt["conflicts"] == [harness.SEED_GUID]
    rendered = ad_render.applied(result)
    assert rendered["restored"] is False
    assert len(rendered["conflicts"]) == 1
    assert rendered["conflicts"][0]["kind"] == "untrusted-device-data"
    assert rendered["conflicts"][0]["text"].endswith(harness.SEED_GUID)


class FakeClock:
    """A clock a test drives: it moves only when the test sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_a_dc_that_never_matches_waits_the_whole_timeout_on_the_clock() -> None:
    """The deadline is the clock's, so the wait is exactly the timeout."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()
    clock = FakeClock()
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, sleep=clock.sleep, clock=clock
    )

    assert result["state"] == "not_tested"
    assert result["dcs"]["win-dc2"]["state"] == "not_tested"
    assert "confirm" not in modes
    assert modes.count("abort") == 1
    assert clock.now - 1000.0 == 120.0


def test_a_conflict_at_the_apply_sends_no_confirm() -> None:
    """A before-image that does not match is a conflict."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    # somebody else changed the account between the plan and the apply
    lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] = 512
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == "conflict"
    assert "confirm" not in modes
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 512


def test_the_receipt_never_holds_the_secret() -> None:
    """The receipt of a user-create holds no password."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    secret = store.read_json(store.plan_path(plan_id))["secret"]

    ad_apply.apply_change(
        plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0
    )

    receipt = store.receipt_path(plan_id)
    assert receipt.exists()
    text = receipt.read_text(encoding="utf-8")
    assert secret not in text
    assert "secret" not in text


def test_the_apply_drops_the_password_from_the_plan_record() -> None:
    """The password goes to the DC once and leaves the plan record after it."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    new_secret = store.read_json(store.plan_path(plan_id))["secret"]
    sent: list[dict[str, object]] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        sent.append(dict(request_body))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    applies = [one for one in sent if one["mode"] == "apply"]
    assert [one.get("secret") for one in applies] == [new_secret]
    record = store.read_json(store.plan_path(plan_id))
    assert "secret" not in record
    assert new_secret not in store.plan_path(plan_id).read_text(encoding="utf-8")
    assert record["txid"] and record["verb"] == "user-create"


def test_the_password_leaves_the_plan_record_when_the_send_fails() -> None:
    """A send that raises still drops the password, since the txid is spent."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    plan_id = _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        raise WriteError("the session to the domain controller failed")

    with pytest.raises(WriteError):
        ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert "secret" not in store.read_json(store.plan_path(plan_id))


def test_the_receipt_is_written_under_the_receipts_directory() -> None:
    """The receipt of a change lives in its own directory."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    ad_apply.apply_change(
        plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0
    )

    receipt = store.receipt_path(plan_id)
    assert receipt.parent.name == "ad-receipts"
    record = json.loads(receipt.read_text(encoding="utf-8"))
    assert record["state"] == "confirmed"
    assert record["txid"]


def test_an_unapproved_plan_is_refused() -> None:
    """A plan without an approval never reaches a device."""
    lab = _lab()
    result = ad_plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    with pytest.raises(ad_apply.WriteError) as caught:
        ad_apply.apply_change(
            str(result["plan_id"]), send=lab.send, devices=lab.devices
        )

    assert "not approved" in str(caught.value)


def test_the_status_sends_the_status_mode() -> None:
    """The status of a change comes from the domain controller."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )
    result = ad_apply.change_status(plan_id, send=send, devices=lab.devices)

    assert modes[-1] == "status"
    assert result["state"] == "confirmed"


def _apply_now(lab: harness.Lab, plan_id: str) -> dict[str, object]:
    """Apply the change on the DC, without the verification."""
    return lab.send(lab.devices["win-dc1"], _apply_body(plan_id))


def _apply_body(plan_id: str, **changes: object) -> dict[str, object]:
    """The request of an apply, as it goes to the helper."""
    plan = store.read_json(store.plan_path(plan_id))
    approval = store.read_json(store.approval_path(plan_id))
    body: dict[str, object] = {
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
    body.update(changes)
    return body


def _minted(body: dict[str, object]) -> dict[str, object]:
    """The request with the token minted over its own digest."""
    digest = request.digest(body)
    body["token"] = request.token(
        harness.KEY_HEX, digest, int(body["nbf"]), int(body["exp"])
    )
    return body


def _reapprove(plan_id: str, **changes: object) -> None:
    """Write the plan again with the changes, and mint the approval over it."""
    record = store.read_json(store.plan_path(plan_id))
    record.update(changes)
    store.write_json(store.plan_path(plan_id), record)
    digest = request.digest(record)
    store.write_json(
        store.approval_path(plan_id),
        {
            "plan_id": plan_id,
            "device": record["device"],
            "digest": digest,
            "nbf": NBF,
            "exp": EXP,
            "token": request.token(harness.KEY_HEX, digest, NBF, EXP),
        },
    )


def test_a_privileged_target_sent_as_med_is_refused() -> None:
    """The helper re-derives the risk and refuses a lowered one."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, privileged=True)
    plan_id = _approved_plan(lab)
    body = _minted(_apply_body(plan_id, risk="MED"))

    answer = lab.send(lab.devices["win-dc1"], body)

    assert answer["code"] == "risk_mismatch"
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 4260352


def test_a_normal_target_sent_as_high_is_refused() -> None:
    """The helper re-derives the risk and refuses a raised one."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    body = _minted(_apply_body(plan_id, risk="HIGH"))

    answer = lab.send(lab.devices["win-dc1"], body)

    assert answer["code"] == "risk_mismatch"
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 4260352


def test_a_matching_risk_is_accepted() -> None:
    """The risk the plan holds is the risk the helper derives."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    body = _minted(_apply_body(plan_id))

    answer = lab.send(lab.devices["win-dc1"], body)

    assert answer["code"] == "ok"
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 66048


def test_a_plan_whose_risk_was_lowered_is_refused_by_the_helper() -> None:
    """The token is minted over what the owner saw, so a lowered risk fails."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, privileged=True)
    plan_id = _approved_plan(lab)
    assert store.read_json(store.plan_path(plan_id))["risk"] == "HIGH"
    _reapprove(plan_id, risk="MED")

    result = ad_apply.apply_change(
        plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0
    )

    assert result["code"] == "risk_mismatch"
    assert result["state"] == "refused"
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 4260352


def test_the_abort_sends_the_abort_mode() -> None:
    """The abort of a change comes from the domain controller."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    # the apply arms the undo on the DC
    assert _apply_now(lab, plan_id)["code"] == "ok"

    result = ad_apply.abort_change(plan_id, send=send, devices=lab.devices)

    assert modes[-1] == "abort"
    assert result["code"] == "ok"
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 4260352


def test_the_undo_leaves_an_attribute_alone_when_it_changed_meanwhile() -> None:
    """The undo writes only when the version still matches."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    assert _apply_now(lab, plan_id)["code"] == "ok"
    # somebody else changed the account after the write
    lab.helpers["win-dc1"].touch(harness.SEED_GUID)

    result = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert result["conflicts"] == [harness.SEED_GUID]
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 66048


def test_the_abort_with_a_conflict_ends_undo_failed() -> None:
    """The abort answer carries no state: the result names it from restored."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    assert _apply_now(lab, plan_id)["code"] == "ok"
    lab.helpers["win-dc1"].touch(harness.SEED_GUID)

    result = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert result["state"] == "undo_failed"
    assert result["restored"] is False


def test_the_clean_abort_ends_undone() -> None:
    """An abort that restored the before-image ends undone."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    assert _apply_now(lab, plan_id)["code"] == "ok"

    result = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert result["state"] == "undone"
    assert result["restored"] is True


def test_the_abort_of_a_confirmed_change_says_how_to_reverse_it() -> None:
    """Abort reverses only an armed change (live 2026-11-13).

    Both helpers answer conflict to the abort of a confirmed record and
    restore nothing; apply_change confirms as soon as every DC matches, so
    a cleanly applied change is never armed.  The owner is told that a
    confirmed change is reversed by a new plan of the opposite change.
    """
    lab = _lab()
    plan_id = _approved_plan(lab)
    applied = ad_apply.apply_change(
        plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0
    )
    assert applied["state"] == "confirmed"

    result = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert result["code"] == "conflict"
    assert result["state"] is None
    assert "opposite change" in str(result["message"])
    # nothing was restored on the DC
    assert lab.helpers["win-dc1"].objects[harness.SEED_GUID]["uac"] == 66048
    # the message reaches the model
    assert ad_render.applied(result)["message"] == result["message"]


def test_the_abort_of_an_unlock_says_it_has_no_undo() -> None:
    """An unlock is confirmed once written and has no opposite verb."""
    lab = harness.Lab()
    lab.add_user(uac=512, lockout=5)
    plan_id = _approved_plan(lab, "unlock", value=None)
    applied = ad_apply.apply_change(
        plan_id, send=lab.send, devices=lab.devices, timeout_s=0.0
    )
    assert applied["state"] == "confirmed"

    result = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert result["code"] == "conflict"
    assert result["message"] == ad_apply.UNLOCK_ABORT_MESSAGE


def test_a_refused_abort_names_no_state() -> None:
    """An abort the DC refuses (not armed) claims no undo state."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    assert _apply_now(lab, plan_id)["code"] == "ok"
    assert ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)["code"] == "ok"

    again = ad_apply.abort_change(plan_id, send=lab.send, devices=lab.devices)

    assert again["code"] == "conflict"
    assert again["state"] is None


def _drops(mode: str, lab: harness.Lab, sent: list[str] | None = None,
           code: str = "unavailable"):  # type: ignore[no-untyped-def]
    """A send whose session fails for one mode, as the transport raises it."""
    from newton_mcp.ad.write.transport import TransportError

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        if sent is not None:
            sent.append(str(request_body["mode"]))
        if request_body["mode"] == mode:
            raise TransportError(code, "the write helper did not answer")
        return lab.send(target, request_body)  # type: ignore[arg-type]

    return send


def test_a_failed_session_at_the_apply_writes_a_receipt_and_says_what_is_known() -> None:
    """The connection fails while the apply is sent.

    Newton cannot tell whether the change reached the DC.  The apply
    still writes a receipt and returns a result that names the state and
    tells the owner to read the status; nothing else is sent.
    """
    lab = _lab()
    plan_id = _approved_plan(lab)
    modes: list[str] = []

    result = ad_apply.apply_change(
        plan_id, send=_drops("apply", lab, modes), devices=lab.devices, timeout_s=0.0
    )

    assert result["result"] == "error"
    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert result["code"] == "unavailable"
    assert "newton_ad_change_status" in str(result["message"])
    assert "undo_at" in str(result["message"])
    assert modes == ["apply"]
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_APPLY_UNKNOWN
    assert ad_render.applied(result)["message"] == result["message"]


def test_a_failed_session_at_the_confirm_writes_a_receipt_and_says_what_is_known() -> None:
    """Every DC matched, then the connection fails while the confirm is sent."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.apply_change(
        plan_id, send=_drops("confirm", lab, code="error"), devices=lab.devices,
        timeout_s=0.0,
    )

    assert result["result"] == "error"
    assert result["state"] == ad_apply.STATE_CONFIRM_UNKNOWN
    assert result["code"] == "error"
    assert result["dcs"]["win-dc1"]["state"] == "matched"
    assert "newton_ad_change_status" in str(result["message"])
    assert "undo_at" in str(result["message"])
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_CONFIRM_UNKNOWN


def test_a_failed_session_at_the_automatic_abort_gives_abort_failed() -> None:
    """A DC lags, and the connection fails while the automatic abort is sent."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    result = ad_apply.apply_change(
        plan_id, send=_drops("abort", lab), devices=lab.devices, timeout_s=0.0
    )

    assert result["result"] == "error"
    assert result["state"] == ad_apply.STATE_ABORT_FAILED
    assert result["code"] == "unavailable"
    assert "newton_ad_change_status" in str(result["message"])
    assert "undo_at" in str(result["message"])
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_ABORT_FAILED


@pytest.mark.parametrize("answer", ["error", "conflict"])
def test_an_automatic_abort_the_helper_refuses_gives_abort_failed(answer: str) -> None:
    """The helper answers the automatic abort with error or conflict.

    The undo did not run, so the result, the receipt and the rendered
    answer say so with their own state instead of not_tested.
    """
    lab = _lab()
    plan_id = _approved_plan(lab)
    lab.lag()

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        if request_body["mode"] == "abort":
            return {"v": 1, "code": answer}
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == ad_apply.STATE_ABORT_FAILED
    assert result["code"] == answer
    assert "newton_ad_change_status" in str(result["message"])
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_ABORT_FAILED
    rendered = ad_render.applied(result)
    assert rendered["state"] == ad_apply.STATE_ABORT_FAILED
    assert rendered["message"] == result["message"]


def test_a_failed_session_at_the_abort_tool_says_what_is_known() -> None:
    """The owner's abort: the connection fails while it is sent."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    assert _apply_now(lab, plan_id)["code"] == "ok"

    result = ad_apply.abort_change(
        plan_id, send=_drops("abort", lab), devices=lab.devices
    )

    assert result["result"] == "error"
    assert result["code"] == "unavailable"
    assert result["state"] is None
    assert "newton_ad_change_status" in str(result["message"])
    assert "undo_at" in str(result["message"])


def test_a_failed_session_at_the_status_says_so() -> None:
    """The status read: the connection fails while it is sent."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.change_status(
        plan_id, send=_drops("status", lab), devices=lab.devices
    )

    assert result["result"] == "error"
    assert result["code"] == "unavailable"
    assert result["state"] is None
    assert isinstance(result["message"], str)


def _unlock_lab() -> tuple[harness.Lab, str]:
    lab = harness.Lab()
    lab.add_user(uac=512, lockout=5)
    return lab, _approved_plan(lab, "unlock", value=None)


@pytest.mark.parametrize("mode", ["apply", "confirm"])
def test_a_lost_session_on_an_unlock_promises_no_undo(mode: str) -> None:
    """An unlock arms no undo, so a lost apply or confirm of one must not
    tell the owner the DC will put the before-image back."""
    lab, plan_id = _unlock_lab()

    result = ad_apply.apply_change(
        plan_id, send=_drops(mode, lab), devices=lab.devices, timeout_s=0.0
    )

    message = str(result["message"])
    assert "newton_ad_change_status" in message
    assert "undo_at" not in message
    assert "before-image back" not in message
    assert "no undo" in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["message"] == result["message"]


def test_an_unlock_a_dc_has_not_shown_yet_is_not_aborted() -> None:
    """A DC lags behind an unlock.  The unlock has nothing to abort, so
    Newton sends no abort and says the unlock stays written."""
    lab, plan_id = _unlock_lab()
    lab.lag()
    modes: list[str] = []

    def send(target: object, request_body: dict[str, object]) -> dict[str, object]:
        modes.append(str(request_body["mode"]))
        return lab.send(target, request_body)  # type: ignore[arg-type]

    result = ad_apply.apply_change(
        plan_id, send=send, devices=lab.devices, timeout_s=0.0
    )

    assert "abort" not in modes
    assert result["state"] == ad_apply.STATE_NOT_TESTED
    message = str(result["message"])
    assert "no undo" in message
    assert "undo_at" not in message
    assert "newton_ad_change_status" in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_NOT_TESTED
    assert ad_render.applied(result)["message"] == result["message"]
