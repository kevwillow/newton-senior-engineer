"""The next step of every refusal the DC records refused,
and of a user-create whose password left the plan with a refused apply."""

from __future__ import annotations

import harness
import pytest

from newton_mcp.ad.write import apply as ad_apply, store

from test_write_apply import _approved_plan, _lab


def _refusing(lab: harness.Lab, code: str, record: dict[str, object]):
    """A DC that refuses the apply with ``code`` and whose status answers ``record``."""

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            return {"v": 1, "code": code}
        if body["mode"] == "status":
            return dict(record)
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


def _user_create_lab() -> tuple[harness.Lab, str]:
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    return lab, _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)


RECORDED_REFUSED = {"v": 1, "code": "ok", "state": "refused"}


@pytest.mark.parametrize(
    ("code", "step"),
    [
        ("not_found", "plan the change again"),
        ("denied", "plan the change again"),
        ("unavailable", "write setup again"),
    ],
)
def test_a_refusal_the_dc_recorded_names_its_next_step(code: str, step: str) -> None:
    """denied, not_found and unavailable reach refused when the DC's record
    reads refused: the answer says nothing changed and adds a next step."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.apply_change(
        plan_id, send=_refusing(lab, code, RECORDED_REFUSED), devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == ad_apply.STATE_REFUSED
    message = " ".join(str(result["message"]).split())
    assert message.startswith(ad_apply.DC_REFUSED_MESSAGE)
    assert message != ad_apply.DC_REFUSED_MESSAGE
    assert step in message


def test_an_unavailable_refusal_says_plan_again_not_apply_again() -> None:
    """The DC kept a record of the refused txid, so the same plan is refused
    as replay: the step is the write setup, then a new plan, never the same
    plan applied again."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.apply_change(
        plan_id, send=_refusing(lab, "unavailable", RECORDED_REFUSED), devices=lab.devices, timeout_s=0.0
    )

    message = " ".join(str(result["message"]).split())
    assert "write setup again" in message
    assert "plan the change again" in message
    assert "apply the plan again" not in message


@pytest.mark.parametrize(
    ("code", "record"),
    [
        ("expired", {"v": 1, "code": "not_found"}),
        ("bad_token", {"v": 1, "code": "not_found"}),
        ("schema", {"v": 1, "code": "not_found"}),
        ("privileged", {"v": 1, "code": "not_found"}),
        ("risk_mismatch", {"v": 1, "code": "not_found"}),
        ("not_pdc", {"v": 1, "code": "not_found"}),
        ("denied", RECORDED_REFUSED),
        ("not_found", RECORDED_REFUSED),
        ("unavailable", RECORDED_REFUSED),
        ("odd_code", RECORDED_REFUSED),
    ],
)
def test_every_pre_write_refusal_of_a_user_create_says_plan_the_user_again(
    code: str, record: dict[str, object]
) -> None:
    """The password left the plan with this apply whatever the DC's code:
    the next step is always a new plan of the user, never the same plan."""
    lab, plan_id = _user_create_lab()

    result = ad_apply.apply_change(
        plan_id, send=_refusing(lab, code, record), devices=lab.devices, timeout_s=0.0
    )

    assert result["state"] == ad_apply.STATE_REFUSED
    message = " ".join(str(result["message"]).split())
    assert message.startswith(ad_apply.DC_REFUSED_MESSAGE)
    assert "plan the new user again" in message
    assert "apply it" not in message
    assert "apply the same plan" not in message
    assert "apply the plan again" not in message
    assert "approve the plan again" not in message
    assert "secret" not in store.read_json(store.plan_path(plan_id))


def test_a_retry_of_a_refused_user_create_never_says_it_may_be_written() -> None:
    """The DC refused the first apply before writing it and the password
    left the plan: a retry sends nothing and says the plan is spent,
    never that the change may already be written."""
    lab, plan_id = _user_create_lab()
    ad_apply.apply_change(
        plan_id,
        send=_refusing(lab, "privileged", {"v": 1, "code": "not_found"}),
        devices=lab.devices,
        timeout_s=0.0,
    )
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_REFUSED
    modes: list[str] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        modes.append(str(body["mode"]))
        return lab.send(target, body)  # type: ignore[arg-type]

    second = ad_apply.apply_change(plan_id, send=send, devices=lab.devices, timeout_s=0.0)

    assert modes == []
    assert second["state"] == ad_apply.STATE_REFUSED
    assert second["code"] == "not_sent"
    message = " ".join(str(second["message"]).split())
    assert "may already be written" not in message
    assert "password" in message
    assert "plan the new user again" in message
    assert store.read_json(store.receipt_path(plan_id)) == receipt
