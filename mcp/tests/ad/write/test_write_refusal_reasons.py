"""Every answer about an AD change that did not go through names its reason
and a next step that works: the helper's own install check, the status and
abort of a refused or unrecorded change, and a new user whose password left
the plan."""

from __future__ import annotations

from pathlib import Path

import harness
import pytest

from newton_mcp import server
from newton_mcp.ad.write import apply as ad_apply, plan as ad_plan, store
from newton_mcp.ad.write.errors import WriteError

from test_write_apply import _approved_plan, _lab


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _flat(text: object) -> str:
    return " ".join(str(text).split())


def _answering(lab: harness.Lab, answers: dict[str, dict[str, object]], sent: list[str] | None = None):
    """A DC that answers each mode named in ``answers`` with that answer."""

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        if sent is not None:
            sent.append(str(body["mode"]))
        mode = str(body["mode"])
        if mode in answers:
            return dict(answers[mode])
        return lab.send(target, body)  # type: ignore[arg-type]

    return send


def _user_create_lab() -> tuple[harness.Lab, str]:
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    return lab, _approved_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)


INSTALL = {"stage": "install"}


# ---- the helper's own install check ----------------------------------------


@pytest.mark.parametrize("code", ["unavailable", "denied"])
def test_an_install_check_refusal_is_refused_and_names_the_write_setup(code: str) -> None:
    """The helper refused before it read the request (its install check):
    nothing was written, so the answer is refused, never apply_unknown, and
    its step is the DC's write setup."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    answer = {"v": 1, "code": code, **INSTALL}

    result = ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": answer, "status": answer}),
        devices=lab.devices,
        timeout_s=0.0,
    )

    assert result["state"] == ad_apply.STATE_REFUSED
    assert result["code"] == code
    message = _flat(result["message"])
    assert message.startswith(ad_apply.DC_REFUSED_MESSAGE)
    assert "write setup again" in message
    assert "Do not apply the plan again" not in message
    assert "then apply the same plan" in message
    assert "holds no record of it" in message
    receipt = store.read_json(store.receipt_path(plan_id))
    assert receipt["state"] == ad_apply.STATE_REFUSED


def test_a_plan_refused_by_the_install_check_is_sent_again_once_set_up() -> None:
    """The DC holds no record of a request its install check refused, so
    the same plan goes out again once the write setup is fixed."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    answer = {"v": 1, "code": "unavailable", **INSTALL}
    ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": answer, "status": answer}),
        devices=lab.devices,
        timeout_s=0.0,
    )
    sent: list[str] = []

    second = ad_apply.apply_change(
        plan_id, send=_answering(lab, {}, sent), devices=lab.devices, timeout_s=0.0
    )

    assert "apply" in sent
    assert second["state"] == ad_apply.STATE_CONFIRMED


@pytest.mark.parametrize(
    "answer",
    [
        {"v": 1, "code": "unavailable"},
        {"v": 1, "code": "denied"},
        {"v": 1, "code": "unavailable", "stage": "install", "unmarked": True},
        {"v": 1, "code": "error", "stage": "install"},
        {"v": 1, "code": "unavailable", "stage": "other"},
    ],
)
def test_only_a_marked_install_check_refusal_skips_the_record(answer: dict[str, object]) -> None:
    """A bare unavailable or denied, an unmarked answer, another code or
    another stage says nothing about the install check: with no record
    read, Newton does not know whether the change was written."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": answer, "status": {"v": 1, "code": "unavailable"}}),
        devices=lab.devices,
        timeout_s=0.0,
    )

    assert result["state"] == ad_apply.STATE_APPLY_UNKNOWN


def test_a_user_create_refused_by_the_install_check_names_the_setup_and_a_new_plan() -> None:
    lab, plan_id = _user_create_lab()
    answer = {"v": 1, "code": "unavailable", **INSTALL}

    result = ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": answer, "status": answer}),
        devices=lab.devices,
        timeout_s=0.0,
    )

    assert result["state"] == ad_apply.STATE_REFUSED
    message = _flat(result["message"])
    assert "write setup again" in message
    assert "plan the new user again" in message
    assert "apply the plan again" not in message


@pytest.mark.parametrize("code", ["unavailable", "denied"])
def test_a_status_the_install_check_refuses_names_the_write_setup(code: str) -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)

    status = ad_apply.change_status(
        plan_id,
        send=_answering(lab, {"status": {"v": 1, "code": code}}),
        devices=lab.devices,
    )

    assert status["code"] == code
    assert "write setup again" in _flat(status.get("message", ""))


# ---- the status of a refused or unrecorded change --------------------------


def test_the_status_of_a_refused_change_carries_the_reason_of_its_receipt() -> None:
    """The DC's record says refused and nothing else: the receipt of the
    apply on this host kept the reason, and the status says it."""
    lab = _lab()
    plan_id = _approved_plan(lab)
    recorded = {"v": 1, "code": "ok", "state": "refused"}
    applied = ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": {"v": 1, "code": "privileged"}, "status": recorded}),
        devices=lab.devices,
        timeout_s=0.0,
    )

    status = ad_apply.change_status(
        plan_id, send=_answering(lab, {"status": recorded}), devices=lab.devices
    )

    assert status["state"] == "refused"
    assert _flat(status["message"]) == _flat(applied["message"])
    assert "privileged" in _flat(status["message"])


def test_the_status_of_a_refused_change_with_no_receipt_still_says_what_it_means() -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)

    status = ad_apply.change_status(
        plan_id,
        send=_answering(lab, {"status": {"v": 1, "code": "ok", "state": "refused"}}),
        devices=lab.devices,
    )

    message = _flat(status["message"])
    assert message.startswith(ad_apply.DC_REFUSED_MESSAGE)
    assert "receipt" in message


def test_a_not_found_status_after_a_lost_apply_never_says_apply_it() -> None:
    """The apply's session failed and its final receipt reads apply_unknown:
    the apply refuses a second send, so the status never says the plan can
    be applied, and it keeps the caveat that the apply may be on its way."""
    lab = _lab()
    plan_id = _approved_plan(lab)

    def lost(target: object, body: dict[str, object]) -> dict[str, object]:
        if body["mode"] == "apply":
            raise ad_apply.transport.TransportError("unavailable", "the link dropped")
        return lab.send(target, body)  # type: ignore[arg-type]

    first = ad_apply.apply_change(plan_id, send=lost, devices=lab.devices, timeout_s=0.0)
    assert first["state"] == ad_apply.STATE_APPLY_UNKNOWN

    status = ad_apply.change_status(
        plan_id, send=_answering(lab, {"status": {"v": 1, "code": "not_found"}}), devices=lab.devices
    )

    message = _flat(status["message"])
    assert "can be applied with newton_ad_apply_change" not in message
    assert "cannot be applied again" in message
    assert "on its way" in message
    assert "plan the change again" in message


def test_a_not_found_status_of_a_spent_user_create_says_plan_the_user_again() -> None:
    lab, plan_id = _user_create_lab()
    ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": {"v": 1, "code": "privileged"}, "status": {"v": 1, "code": "not_found"}}),
        devices=lab.devices,
        timeout_s=0.0,
    )

    status = ad_apply.change_status(
        plan_id, send=_answering(lab, {"status": {"v": 1, "code": "not_found"}}), devices=lab.devices
    )

    message = _flat(status["message"])
    assert "can be applied with newton_ad_apply_change" not in message
    assert "plan the new user again" in message


# ---- the abort --------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "words"),
    [
        ({"v": 1, "code": "not_found"}, "holds no record of this change"),
        ({"v": 1, "code": "error"}, "newton_ad_change_status"),
        ({"v": 1, "code": "unavailable"}, "write setup again"),
        ({"v": 1, "code": "denied"}, "write setup again"),
    ],
)
def test_an_abort_that_did_not_run_says_why(answer: dict[str, object], words: str) -> None:
    lab = _lab()
    plan_id = _approved_plan(lab)

    result = ad_apply.abort_change(
        plan_id, send=_answering(lab, {"abort": answer}), devices=lab.devices
    )

    assert result["result"] == "error"
    message = _flat(result.get("message", ""))
    if answer["code"] == "not_found":
        assert message.startswith("Nothing was aborted")
    assert words in message


# ---- the next steps ----------------------------------------------------------


def test_the_denied_step_names_the_delegation_and_the_write_setup() -> None:
    """denied also means the write account lacks the delegation (LDAP 50):
    a new plan gets the same refusal, so the step names the setup too."""
    step = _flat(ad_apply.DC_REFUSED_NEXT_STEPS["denied"])
    assert "delegation" in step
    assert "when a new plan is refused the same way, run the DC's write setup again" in step


def test_a_refused_user_create_says_the_new_plan_has_a_new_password() -> None:
    for text in (ad_apply.DC_REFUSED_USER_CREATE_STEP, ad_apply.SECRET_SPENT_MESSAGE):
        flat = _flat(text)
        assert "new password" in flat
        assert "discard" in flat


def test_an_unavailable_user_create_keeps_the_write_setup_step() -> None:
    lab, plan_id = _user_create_lab()

    result = ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {
            "apply": {"v": 1, "code": "unavailable"},
            "status": {"v": 1, "code": "ok", "state": "refused"},
        }),
        devices=lab.devices,
        timeout_s=0.0,
    )

    message = _flat(result["message"])
    assert "write setup again" in message
    assert "plan the new user again" in message


def test_a_retry_of_a_user_create_the_dc_refused_with_conflict_says_it_is_spent() -> None:
    """The DC answered conflict before writing (the name is taken): the
    password left with that apply, so a retry sends nothing and says the
    plan is spent, never that the change may be written."""
    lab, plan_id = _user_create_lab()
    first = ad_apply.apply_change(
        plan_id,
        send=_answering(lab, {"apply": {"v": 1, "code": "conflict", "live": {"object": "present"}}}),
        devices=lab.devices,
        timeout_s=0.0,
    )
    assert first["state"] == ad_apply.STATE_CONFLICT
    assert "plan the new user again" in _flat(first["message"])
    sent: list[str] = []

    second = ad_apply.apply_change(
        plan_id, send=_answering(lab, {}, sent), devices=lab.devices, timeout_s=0.0
    )

    assert sent == []
    assert second["state"] == ad_apply.STATE_REFUSED
    assert second["code"] == "not_sent"
    message = _flat(second["message"])
    assert "may already be written" not in message
    assert "plan the new user again" in message


# ---- the names of a target ---------------------------------------------------


def test_a_name_outside_the_sam_pattern_is_refused_with_the_pattern() -> None:
    lab = _lab()
    with pytest.raises(WriteError) as caught:
        ad_plan.plan_change(
            harness.DOMAIN, "disable", ["JSmith"], None, send=lab.send, devices=lab.devices
        )
    text = _flat(caught.value)
    assert "lowercase" in text
    assert "20" in text
    assert "space" in text


def test_the_plan_tool_description_names_the_sam_pattern() -> None:
    tool = server.mcp._tool_manager.get_tool("newton_ad_plan_change")
    flat = _flat(tool.description or "")
    assert "lowercase" in flat
    assert "20 characters" in flat


# ---- the skill ---------------------------------------------------------------

SKILL = Path(__file__).resolve().parents[4] / "SKILL.md"


def test_the_skill_says_a_spent_user_create_is_never_applied_again() -> None:
    """refused with code not_sent is also the answer to the retry of a new
    user whose password already left the plan: the skill must not promise
    that every refused not_sent plan can be applied again."""
    flat = _flat(SKILL.read_text(encoding="utf-8"))
    start = flat.index("an apply request Newton refuses before it leaves the Newton host")
    passage = flat[start:start + 900]
    assert "password already left the plan" in passage
    assert "plan the new user again" in passage


def test_the_skill_names_the_sam_pattern() -> None:
    flat = _flat(SKILL.read_text(encoding="utf-8"))
    start = flat.index("`sam_names` is a list of sAMAccountNames")
    assert "lowercase" in flat[start:start + 600]
