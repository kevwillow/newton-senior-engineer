"""Scoped grants and HIGH confirmation in the approval dialog."""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from typing import Any

import pytest

import newton_mcp.approve as approve
import newton_mcp.elicit_approval as elicit_approval
import newton_mcp.grants as grants
import newton_mcp.policy as policy
import newton_mcp.server as server
from newton_mcp.plan import compute_plan_hash
from test_elicit_approval import (  # noqa: E402  (tests dir is on sys.path)
    DEVICE,
    FORM_CAPABILITY,
    OTHER_SID,
    PASSPHRASE,
    SID,
    TOTP_K,
    TOTP_SEED,
    WRONG_PASSPHRASE,
    _approval_path,
    _audit_text,
    _derived_k,
    _plan,
    _write_fingerprint,
    _write_plan,
    clock,
    sdk_validate,
)


OTHER_DEVICE = "pulsar"
DHCP_BATCH = "\n".join(
    [
        "set dhcp.host1=host",
        "set dhcp.host1.mac='aa:bb:cc:dd:ee:01'",
        "set dhcp.host1.ip='192.0.2.20'",
    ]
)
HIGH_BATCH = "\n".join(
    [
        "set firewall.port=redirect",
        "set firewall.port.src='wan'",
        "set firewall.port.dest_port='443'",
    ]
)


class _ResponseContext:
    """A dialog context that answers a queued sequence of elicits."""

    def __init__(
        self,
        clock,
        responses: list[dict[str, Any]],
        *,
        capability: Any = FORM_CAPABILITY,
        delay: float = 5.0,
    ) -> None:
        self.clock = clock
        self.responses = list(responses)
        self.capability = capability
        self.delay = delay
        self.messages: list[str] = []
        self.schemas: list[type[Any]] = []
        self.session = SimpleNamespace(
            client_params=SimpleNamespace(
                capabilities=SimpleNamespace(elicitation=capability)
            )
        )

    async def elicit(self, message: str, schema: type[Any]) -> Any:
        self.messages.append(message)
        self.schemas.append(schema)
        sdk_validate(schema)
        response = self.responses.pop(0)
        if response.get("sleep_s"):
            await asyncio.sleep(response["sleep_s"])
        self.clock.advance(self.delay)
        action = response.get("action", "accept")
        if action != "accept":
            return SimpleNamespace(action=action, data=None)
        values: dict[str, Any] = {}
        for name in schema.model_fields:
            if name == "secret":
                values[name] = response.get("secret", PASSPHRASE)
            elif name == "device_name":
                values[name] = response.get("device_name", DEVICE)
            elif name == "grant_hours":
                values[name] = response.get("grant_hours", "0")
            elif name == "confirm":
                values[name] = response.get(
                    "confirm", f"{DEVICE} HIGH"
                )
        return SimpleNamespace(action=action, data=schema(**values))


def _grantable_plan(**kwargs: Any) -> dict[str, Any]:
    return _plan(uci_batch=DHCP_BATCH, **kwargs)


def _key() -> str:
    return _derived_k(PASSPHRASE.encode("utf-8"), DEVICE)


def _open_grant(
    *,
    device: str = DEVICE,
    classes: list[str] | None = None,
    hours: int = 4,
    now: float | None = None,
) -> str:
    key = _key()
    grants.open_grant(
        device,
        classes or ["dhcp-reservations"],
        hours,
        key,
        SID,
        now=now,
    )
    return key


def _run(ctx: _ResponseContext, device: str = DEVICE, session_id: str = SID):
    return asyncio.run(
        elicit_approval.collect_approval(ctx, device, session_id)
    )


def _dialog_ready() -> None:
    _write_fingerprint()
    elicit_approval.approval_proof.write_ack(DEVICE)


def test_a_live_grant_approves_without_a_dialog_or_client_capability(
    configured_newton, clock
):
    _grantable_plan_record = _grantable_plan()
    _write_plan(_grantable_plan_record)
    key = _open_grant()
    ctx = _ResponseContext(clock, [], capability=None)

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.message == "approved by your easy grant"
    assert outcome.grant_used is True
    assert outcome.grant_note.startswith("EASY GRANT: DHCP reservations until ")
    assert ctx.messages == []
    saved = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert saved["approved_by"] == "grant:dhcp-reservations"
    expected = approve.approval_token(
        key,
        _grantable_plan_record["router_digest"],
        saved["not_before"],
        saved["not_after"],
    )
    assert saved["token"] == expected
    consumed = server.NewtonService().consume_approval(
        DEVICE, SID, _grantable_plan_record
    )
    assert consumed.token == expected
    assert PASSPHRASE not in outcome.message
    assert key not in outcome.message
    assert key not in outcome.grant_note


def test_a_grant_approval_race_does_not_overwrite_another_approval(
    configured_newton, clock, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()
    calls = 0

    def approval_exists(session_id: str) -> bool:
        nonlocal calls
        calls += 1
        return calls > 1

    monkeypatch.setattr(
        elicit_approval, "_approval_exists", approval_exists
    )
    ctx = _ResponseContext(clock, [])

    outcome = _run(ctx)

    assert outcome.status == "skip"
    assert not _approval_path().exists()
    assert ctx.messages == []


def test_a_grant_never_approves_an_owner_script(clock):
    """A grant covers what Newton applies itself, never an owner script.

    An owner script is the owner's own bytes: the owner is asked for it
    at the owner-run, in their own terminal.  An approval written here
    would skip that question, so a grant never writes one.
    """
    _open_grant()
    record = _grantable_plan()
    record["router_leash"] = "owner-script"
    record["plan_hash"] = compute_plan_hash(record)
    _write_plan(record)

    ctx = _ResponseContext(clock, [])
    outcome = _run(ctx)

    assert outcome.grant_used is False, outcome
    assert outcome.status != "approved", outcome
    assert not ctx.messages, ctx.messages
    assert not _approval_path().exists()


def test_a_grant_never_approves_a_critical_plan(clock):
    """A critical change is never covered by a grant."""
    _open_grant()
    record = _grantable_plan()
    record["risk"] = "critical"
    _write_plan(record)

    ctx = _ResponseContext(clock, [])
    outcome = _run(ctx)

    assert outcome.grant_used is False, outcome
    assert outcome.status != "approved", outcome
    assert not _approval_path().exists()


CRITICAL_REASON = (
    "mgmt-zone: a change of the management zone requires approval: "
    "firewall.lan.input='ACCEPT'"
)


def test_a_grant_never_covers_a_record_whose_risk_was_edited_to_low(clock):
    """The risk word is outside the plan hash; the reasons are inside it.

    A record planned as critical whose ``risk`` was edited to ``low`` on
    disk still verifies, so the grant must read critical from the hashed
    reasons and refuse to cover it.
    """
    _open_grant()
    record = _grantable_plan()
    record["reasons"] = [policy.PROD_REASON, CRITICAL_REASON]
    record["risk"] = "critical"
    record["plan_hash"] = compute_plan_hash(record)
    record["risk"] = "low"
    assert compute_plan_hash(record) == record["plan_hash"]
    _write_plan(record)

    ctx = _ResponseContext(clock, [])
    outcome = _run(ctx)

    assert outcome.grant_used is False, outcome
    assert outcome.status != "approved", outcome
    assert not _approval_path().exists()


@pytest.mark.parametrize("reasons", [[], ["profile 'prod': every write requires approval"]])
def test_a_record_with_no_critical_reason_stays_grant_eligible(
    configured_newton, clock, reasons
):
    _open_grant()
    record = _grantable_plan()
    record["reasons"] = reasons
    record["risk"] = "low"
    record["plan_hash"] = compute_plan_hash(record)
    _write_plan(record)

    outcome = _run(_ResponseContext(clock, [], capability=None))

    assert outcome.status == "approved", outcome
    assert outcome.grant_used is True


@pytest.mark.parametrize(
    "reasons, critical",
    [
        ([], False),
        ([policy.PROD_REASON], False),
        ([policy.PROD_REASON, CRITICAL_REASON], True),
        ([CRITICAL_REASON], True),
        (["profile 'prod'"], True),
        ("not a list", True),
        (None, True),
        ([None], True),
    ],
)
def test_critical_is_read_from_the_reasons(reasons, critical):
    assert elicit_approval.critical_from_reasons(reasons) is critical


def test_a_grant_does_not_cover_a_plan_with_one_unlisted_line(clock):
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "set dhcp.host1.mac='aa:bb:cc:dd:ee:01'",
            "set network.lan.ipaddr='192.0.2.1'",
        ]
    )
    _write_plan(_plan(uci_batch=batch))
    _open_grant()
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.grant_used is False
    assert len(ctx.messages) == 1
    saved = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert saved["approved_by"].startswith("elicit:")


def test_a_grant_does_not_cover_a_delete(clock):
    _write_plan(_plan(uci_batch="delete dhcp.host1"))
    _open_grant()
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.grant_used is False
    assert len(ctx.messages) == 1


def test_an_expired_grant_does_not_cover_a_plan(clock):
    _write_plan(_grantable_plan())
    _open_grant(now=time.time() - 6 * 3600)
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.grant_used is False
    assert len(ctx.messages) == 1


def test_another_devices_grant_does_not_cover_a_plan(clock):
    _write_plan(_grantable_plan())
    _open_grant(device=OTHER_DEVICE)
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.grant_used is False
    assert len(ctx.messages) == 1


def test_easy_grants_can_be_disabled(clock, monkeypatch):
    _write_plan(_grantable_plan())
    _open_grant()
    _dialog_ready()
    monkeypatch.setenv("NEWTON_EASY_GRANTS", "0")
    ctx = _ResponseContext(clock, [{}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.grant_used is False
    assert len(ctx.messages) == 1


def test_a_lapsed_grant_basis_never_opens_a_dialog(clock):
    plan = _grantable_plan()
    plan["consent_basis"] = "grant"
    plan["plan_hash"] = compute_plan_hash(plan)
    _write_plan(plan)
    _open_grant(now=time.time() - 6 * 3600)
    ctx = _ResponseContext(clock, [{}])

    outcome = _run(ctx)

    assert outcome.status == "fallback"
    assert outcome.message == (
        "The easy grant for this kind of change has ended. "
        "Plan the change again and ask the owner first."
    )
    assert ctx.messages == []


def test_a_grantable_dialog_offers_the_grant_hours(clock):
    _write_plan(_grantable_plan())
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}])

    _run(ctx)

    field = ctx.schemas[0].model_fields["grant_hours"]
    assert field.default == "0"
    assert field.annotation is str
    assert field.json_schema_extra == {"enum": ["0", "1", "4", "8"]}
    assert field.title == (
        "Also allow more changes of this kind for how many hours? (0 = no)"
    )


def test_a_non_grantable_dialog_does_not_offer_grant_hours(clock):
    _write_plan(_plan())
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}])

    _run(ctx)

    assert "grant_hours" not in ctx.schemas[0].model_fields


def test_accepting_four_grant_hours_opens_a_private_grant(clock):
    _write_plan(_grantable_plan())
    _dialog_ready()
    ctx = _ResponseContext(clock, [{"grant_hours": "4"}])
    before = time.time()

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert outcome.grant_used is False
    assert outcome.grant_note.startswith("EASY GRANT OPENED: DHCP reservations until ")
    record = grants.load_live_grant(DEVICE)
    assert record is not None
    assert record["k"] == _key()
    assert 4 * 3600 - 30 <= record["until"] - before <= 4 * 3600 + 30
    path = elicit_approval.approve.state_dir() / "grants" / f"{DEVICE}.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert _key() not in outcome.message
    assert _key() not in outcome.grant_note


def test_every_schema_the_module_builds_passes_the_sdk_validator():
    for level in ("passphrase", "totp"):
        for offer in (False, True):
            sdk_validate(elicit_approval._approval_model(level, offer))
    sdk_validate(elicit_approval._high_confirmation_model("router"))


def test_the_grant_field_still_shows_the_client_four_choices():
    model = elicit_approval._approval_model("passphrase", True)
    prop = model.model_json_schema()["properties"]["grant_hours"]
    assert prop["enum"] == ["0", "1", "4", "8"]


@pytest.mark.parametrize("bad", ["2", "", "4 ", "x"])
def test_a_grant_answer_outside_the_offered_set_opens_no_grant(clock, bad):
    _write_plan(_grantable_plan())
    _dialog_ready()
    ctx = _ResponseContext(clock, [{"grant_hours": bad}])

    outcome = _run(ctx)

    assert outcome.status == "fallback"
    assert grants.load_live_grant(DEVICE) is None


def test_a_zero_grant_answer_approves_without_a_grant(clock):
    _write_plan(_grantable_plan())
    _dialog_ready()
    ctx = _ResponseContext(clock, [{"grant_hours": "0"}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert grants.load_live_grant(DEVICE) is None


def test_a_high_plan_needs_two_dialogs(clock):
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}, {}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert len(ctx.messages) == 2
    assert ctx.messages[0].startswith(
        f"NEWTON  HIGH RISK  APPROVAL  {DEVICE}  plan {SID[:8]}"
    )
    assert "WHY THIS IS HIGH RISK" in ctx.messages[0]
    assert "Exposes something to the internet." in ctx.messages[0]
    assert "grant_hours" not in ctx.schemas[0].model_fields
    assert set(ctx.schemas[1].model_fields) == {"confirm"}
    assert ctx.messages[1].startswith(
        "NEWTON  HIGH RISK  SECOND CONFIRMATION"
    )
    assert f"Type the words: {DEVICE} HIGH" in ctx.messages[1]
    assert grants.load_live_grant(DEVICE) is None


def test_the_second_dialog_says_it_is_not_a_password_prompt(clock):
    """The owner once typed his passphrase into this field: the title and
    the first lines must say it is a second question."""
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}, {}])

    _run(ctx)

    lines = ctx.messages[1].splitlines()
    assert lines[1] == "This is a second question, not a password prompt."
    assert "Do not type your passphrase" in lines[2]
    title = ctx.schemas[1].model_json_schema()["properties"]["confirm"]["title"]
    assert title == f"Type the words: {DEVICE} HIGH (not your passphrase)"


def test_a_high_plan_names_each_high_reason(clock):
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set uhttpd.main.listen_http='0.0.0.0:8080'",
        ]
    )
    _write_plan(_plan(uci_batch=batch))
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}, {}])

    _run(ctx)

    assert "Exposes something to the internet." in ctx.messages[0]
    assert "Changes who can manage the router." in ctx.messages[0]
    assert "Makes the router run commands." not in ctx.messages[0]


def test_a_policy_critical_plan_says_why(clock):
    plan = _plan()
    plan["risk"] = "critical"
    plan["plan_hash"] = compute_plan_hash(plan)
    _write_plan(plan)
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}, {}])

    outcome = _run(ctx)

    assert outcome.status == "approved"
    assert "Newton's policy marks this change as critical." in ctx.messages[0]
    assert len(ctx.messages) == 2


def test_a_wrong_second_confirmation_writes_nothing_and_counts_no_miss(clock):
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}, {"confirm": "wrong"}])

    outcome = _run(ctx)

    assert outcome.status == "declined"
    assert "second confirmation not given; nothing approved" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert not _approval_path().exists()
    assert elicit_approval.approval_proof.lock_remaining(DEVICE) == 0
    assert grants.load_live_grant(DEVICE) is None


def test_a_cancelled_second_confirmation_writes_nothing(clock):
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _dialog_ready()
    ctx = _ResponseContext(clock, [{}, {"action": "cancel"}])

    outcome = _run(ctx)

    assert outcome.status == "declined"
    assert "second confirmation not given; nothing approved" in outcome.message
    assert not _approval_path().exists()
    assert elicit_approval.approval_proof.lock_remaining(DEVICE) == 0


def test_a_timed_out_second_confirmation_writes_nothing(monkeypatch, clock):
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _dialog_ready()
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", "0.05")
    ctx = _ResponseContext(clock, [{}, {"sleep_s": 5.0}])

    outcome = _run(ctx)

    assert outcome.status == "declined"
    # The HIGH dialog's timeout says what the first dialog's
    # does: it timed out, and a late answer is ignored.
    assert (
        "second confirmation timed out after 0.05 seconds; nothing approved. "
        "An answer typed after that is ignored, even if the dialog is still "
        "on the screen"
    ) in outcome.message
    assert not _approval_path().exists()
    assert elicit_approval.approval_proof.lock_remaining(DEVICE) == 0


def test_a_wrong_first_secret_never_reaches_the_second_dialog(clock):
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _dialog_ready()
    ctx = _ResponseContext(clock, [{"secret": WRONG_PASSPHRASE}, {}])

    outcome = _run(ctx)

    assert outcome.status == "wrong"
    assert len(ctx.messages) == 1
    assert not _approval_path().exists()
    lockout = json.loads(
        (elicit_approval.approve.state_dir() / "lockout" / f"{DEVICE}.json").read_text(
            encoding="utf-8"
        )
    )
    assert lockout["misses"] == 1


#: The dialog's answer field (spelled once, as the schema names it).
ANSWER_FIELD = "secret"


def _totp_dialog_ready() -> str:
    """A TOTP device whose dialog is ready; the code it shows now."""
    proof = elicit_approval.approval_proof
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    proof.write_ack(DEVICE)
    return proof.totp_code(TOTP_SEED, proof.totp_counter())


def _misses() -> int:
    path = elicit_approval.approve.state_dir() / "lockout" / f"{DEVICE}.json"
    if not path.exists():
        return 0
    return int(json.loads(path.read_text(encoding="utf-8")).get("misses", 0))


def test_a_fumbled_high_confirmation_does_not_spend_the_totp_code(clock):
    """the code was spent before the second confirmation, so the
    natural retry with the same code was a replay, counted as a wrong
    answer toward the doubling lock.  The code is now spent only once
    the second confirmation was given."""
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    code = _totp_dialog_ready()

    first = _run(
        _ResponseContext(clock, [{ANSWER_FIELD: code}, {"confirm": "wrong"}])
    )
    second = _run(_ResponseContext(clock, [{ANSWER_FIELD: code}, {}]))

    assert first.status == "declined"
    assert second.status == "approved", second.message
    assert _misses() == 0
    saved = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert saved["approved_by"] == "elicit:totp"


def test_a_high_totp_code_is_still_spent_once_approved(clock):
    """The code that approved one HIGH plan does not approve another."""
    _write_plan(_plan(SID, uci_batch=HIGH_BATCH))
    _write_plan(_plan(OTHER_SID, uci_batch=HIGH_BATCH))
    code = _totp_dialog_ready()

    first = _run(_ResponseContext(clock, [{ANSWER_FIELD: code}, {}]))
    second = _run(
        _ResponseContext(clock, [{ANSWER_FIELD: code}, {}]), session_id=OTHER_SID
    )

    assert first.status == "approved"
    assert second.status == "wrong"
    assert not _approval_path(OTHER_SID).exists()


def test_a_code_spent_elsewhere_during_the_high_confirmation_is_no_miss(clock):
    """The code matched when it was typed; if another approval spent it
    while the second confirmation was open, nothing is approved and no
    miss is counted (the owner's code was right)."""
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    code = _totp_dialog_ready()
    proof = elicit_approval.approval_proof

    class _SpendDuringConfirm(_ResponseContext):
        async def elicit(self, message, schema):
            if "confirm" in schema.model_fields:
                assert proof.verify_totp(DEVICE, code) is not None
            return await super().elicit(message, schema)

    outcome = _run(_SpendDuringConfirm(clock, [{ANSWER_FIELD: code}, {}]))

    assert outcome.status == "fallback"
    assert "used by another approval" in outcome.message
    assert _misses() == 0
    assert not _approval_path().exists()


def test_a_wrong_totp_code_never_reaches_the_second_dialog(clock):
    _write_plan(_plan(uci_batch=HIGH_BATCH))
    _totp_dialog_ready()
    proof = elicit_approval.approval_proof
    current = proof.totp_counter()
    live = {proof.totp_code(TOTP_SEED, current + offset) for offset in (-1, 0, 1, 2)}
    wrong = next(c for c in ("000000", "111111", "222222", "333333", "444444") if c not in live)
    ctx = _ResponseContext(clock, [{ANSWER_FIELD: wrong}, {}])

    outcome = _run(ctx)

    assert outcome.status == "wrong"
    assert len(ctx.messages) == 1
    assert _misses() == 1
    assert not _approval_path().exists()


def test_the_apply_result_carries_a_newton_result_and_grant_notice(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "confirmed"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert result["newton_result"].startswith(
        f"NEWTON RESULT: CONFIRMED  {DEVICE}  {SID[:8]}"
    )
    assert result["grant_notice"] == (
        "EASY GRANT: DHCP reservations until 16:40"
    )
    assert grants.load_live_grant(DEVICE) is not None


def test_the_secret_and_grant_key_never_reach_a_result_or_audit(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    key = _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server.NewtonService,
        "apply",
        lambda self, device, session_id: {"result": "confirmed"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert PASSPHRASE not in json.dumps(result, default=str)
    assert key not in json.dumps(result, default=str)
    assert "tool=newton_apply_change" in _audit_text()
    assert PASSPHRASE not in _audit_text()
    assert key not in _audit_text()


@pytest.mark.parametrize("outcome", ["rolled_back", "unknown"])
def test_a_failed_grant_approved_apply_ends_the_grant(
    configured_newton, monkeypatch, outcome
):
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": outcome},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "EASY GRANT ENDED." in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


def test_a_failed_change_ends_a_grant_opened_by_the_dialog(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved in the client dialog",
            grant_note="EASY GRANT OPENED: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "rolled_back"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "EASY GRANT ENDED." in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


def test_an_error_after_a_grant_approval_ends_the_grant(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"error": "apply failed"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "NEWTON RESULT: NOT APPLIED" in result["newton_result"]
    assert "EASY GRANT ENDED." in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


def test_an_approval_error_still_carries_a_newton_result(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome("fallback", "approval needed")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert result["error"] == "approval needed"
    assert "NEWTON RESULT: NOT APPLIED" in result["newton_result"]
    assert "Reserves a fixed address for a device." in result["newton_result"]


def test_list_devices_shows_the_grant_without_its_key(configured_newton):
    key = _open_grant()

    listed = server.newton_list_devices()

    row = listed["devices"][0]
    assert row["easy_grant"] is not None
    assert row["easy_grant"]["classes"] == ["dhcp-reservations"]
    assert "k" not in row["easy_grant"]
    assert key not in json.dumps(listed)


def test_grant_off_ends_a_live_grant(configured_newton):
    _open_grant()

    result = server.newton_grant_off(DEVICE)

    assert result == {"result": "ok", "revoked": True}
    assert grants.load_live_grant(DEVICE) is None


def test_grant_off_without_a_grant_says_nothing_was_ended(configured_newton):
    result = server.newton_grant_off(DEVICE)

    assert result == {"result": "ok", "revoked": False}


def test_grant_off_refuses_an_invalid_device_name(configured_newton):
    result = server.newton_grant_off("../etc/passwd")

    assert result == {"error": "invalid device name"}


@pytest.mark.parametrize("status", ["skip", "approved"])
def test_a_failed_apply_on_a_pre_existing_approval_ends_the_grant(
    configured_newton, monkeypatch, status
):
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(status, "approval already on disk")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "rolled_back"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "EASY GRANT ENDED." in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


# ---- the result line must not claim a grant that was never open ----


def test_a_rolled_back_change_without_a_grant_does_not_claim_a_grant_ended(
    configured_newton, monkeypatch
):
    """The approval came from the terminal, the
    change was rolled back after a false claim and no grant was ever open
    in this session.  The result line must not say that a grant ended."""
    _write_plan(_grantable_plan())

    async def collect(ctx, device, session_id):
        # the terminal path: the approval was already on disk
        return elicit_approval.Outcome("skip", "approval already on disk")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "rolled_back"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "ROLLED BACK" in result["newton_result"]
    assert "EASY GRANT ENDED." not in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


def test_an_expired_grant_is_not_a_grant_that_ended(
    configured_newton, monkeypatch
):
    """A grant record whose deadline has passed was not open, so nothing
    ended and the result line must not say that it did."""
    _write_plan(_grantable_plan())
    _open_grant(hours=1, now=time.time() - 7200)

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome("skip", "approval already on disk")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "rolled_back"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "EASY GRANT ENDED." not in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


# ---- review fixes -------------------------------------------------


def test_a_grant_replaced_between_the_two_reads_does_not_approve(
    configured_newton, clock, monkeypatch
):
    """Another server process replaced the DHCP grant with a hostname-only
    one after this process found coverage: the plan must not be minted with
    the old grant's key."""
    _write_plan(_grantable_plan())
    _open_grant()
    real_covers = grants.covers

    def covers_then_replace(device, classification, now=None):
        key = real_covers(device, classification, now=now)
        grants.open_grant(device, ["hostname"], 4, "cd" * 32, "0" * 32)
        return key

    monkeypatch.setattr(grants, "covers", covers_then_replace)
    ctx = _ResponseContext(clock, [], capability=None)

    outcome = _run(ctx)

    assert outcome.status != "approved"
    assert not _approval_path().exists()


def test_a_grant_holding_the_key_of_an_older_passphrase_ends(
    configured_newton, clock
):
    """The passphrase changed after the grant opened: the grant's key no
    longer matches the fingerprint, so the grant ends and nothing is
    minted with the old key."""
    _write_plan(_grantable_plan())
    _open_grant()
    _write_fingerprint(k_hex="ef" * 32)
    ctx = _ResponseContext(clock, [], capability=None)

    outcome = _run(ctx)

    assert outcome.status != "approved"
    assert not _approval_path().exists()
    assert grants.load_live_grant(DEVICE) is None


def test_an_installed_plan_with_injected_section_types_is_not_grant_approved(
    configured_newton, clock
):
    """An installed plan is never grant-approved on injected types.

    The types of the sections a change touches are the router's own,
    and only a no-install record carries them: an installed record
    classifies without them.  A record whose types were written on
    disk therefore says nothing about the change, and the grant does
    not cover it: the owner is asked, in their own terminal.
    """
    record = _plan(uci_batch="set dhcp.host1.ip='192.0.2.21'")
    record["section_types"] = {"dhcp.host1": "host"}
    record["plan_hash"] = compute_plan_hash(record)
    _write_plan(record)
    _open_grant()
    ctx = _ResponseContext(clock, [], capability=None)

    outcome = _run(ctx)

    assert outcome.status != "approved", outcome
    assert outcome.grant_used is False, outcome
    assert not _approval_path().exists()


# ---- a held change has not failed: the grant ends only if it later does ----


def test_a_held_grant_approved_apply_keeps_the_grant(configured_newton, monkeypatch):
    """hold=true and verify passed returns `held`, which is not a
    failure, so the grant stays open and the line does not say it ended."""
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "held", "confirm_by": 1794000000},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object(), hold=True))

    assert "EASY GRANT ENDED." not in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is not None


def test_a_held_apply_whose_record_cannot_be_kept_says_the_grant_ended(
    configured_newton, monkeypatch
):
    """A held change with no confirm_by leaves nothing to settle later, so
    the grant ends now; the line says so and no grant notice is shown."""
    _write_plan(_grantable_plan())
    _open_grant()

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "held", "confirm_by": None},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object(), hold=True))

    assert grants.load_live_grant(DEVICE) is None
    assert "EASY GRANT ENDED." in result["newton_result"]
    assert "grant_notice" not in result


def _fake_script(stdout: str, rc: int = 0):
    import subprocess

    def run(self, device, *args, **kwargs):
        return subprocess.CompletedProcess(list(args), rc, stdout, "")

    return run


@pytest.mark.parametrize("out,rc", [
    ("ERROR: confirm refused: error too-late; not confirmed: the router rolls "
     "the change back on its own\n", 1),
    (f"CONFIRM DID NOT REPORT SUCCESS session={SID} — OUTCOME UNKNOWN; "
     "run: owrt-change.sh status\n", 1),
])
def test_a_held_change_that_does_not_confirm_ends_the_grant(
    configured_newton, monkeypatch, out, rc
):
    _write_plan(_grantable_plan())
    _open_grant()
    monkeypatch.setattr(server.NewtonService, "run_script", _fake_script(out, rc))

    result = server.newton_confirm_change(DEVICE, SID)

    assert result["result"] != "confirmed"
    assert result["easy_grant"] == "ended"
    assert "EASY GRANT ENDED." in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is None


def test_a_held_change_that_confirms_keeps_the_grant(configured_newton, monkeypatch):
    _write_plan(_grantable_plan())
    _open_grant()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(f"CONFIRMED session={SID} (verify passed)\n"),
    )

    result = server.newton_confirm_change(DEVICE, SID)

    assert result["result"] == "confirmed"
    assert "easy_grant" not in result
    assert "EASY GRANT ENDED." not in result["newton_result"]
    assert grants.load_live_grant(DEVICE) is not None


def test_a_confirm_without_a_grant_claims_no_grant_ended(configured_newton, monkeypatch):
    _write_plan(_grantable_plan())
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script("ERROR: confirm refused: error too-late; not confirmed\n", 1),
    )

    result = server.newton_confirm_change(DEVICE, SID)

    assert "easy_grant" not in result
    assert "EASY GRANT ENDED." not in result["newton_result"]


def test_an_aborted_held_change_ends_the_grant(configured_newton, monkeypatch):
    _write_plan(_grantable_plan())
    _open_grant()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(f"ABORTED session={SID} (restored)\nHELD APPLY ABORTED session={SID}\n"),
    )

    result = server.newton_abort_change(DEVICE, SID)

    assert result["easy_grant"] == "ended"
    assert grants.load_live_grant(DEVICE) is None


def test_a_held_change_the_router_rolled_back_ends_the_grant(configured_newton, monkeypatch):
    """The window ended unconfirmed and a status call learns it: that held
    change failed, so the grant ends."""
    _write_plan(_grantable_plan())
    _open_grant()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(
            f"rolled-back sid={SID} guard=restored:deadline rpcd=rolled-back config=base boot=same\n"
            f"HELD APPLY ROLLED BACK session={SID} (its window ended unconfirmed; the router's "
            "status says rolled-back)\n"
        ),
    )

    server.newton_change_status(DEVICE, SID)

    assert grants.load_live_grant(DEVICE) is None


def test_a_status_of_a_live_held_change_keeps_the_grant(configured_newton, monkeypatch):
    _write_plan(_grantable_plan())
    _open_grant()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(f"held sid={SID} guard=armed rpcd=pending config=new boot=same\n"),
    )

    server.newton_change_status(DEVICE, SID)

    assert grants.load_live_grant(DEVICE) is not None


# ---- a held change nobody looks at again still ends the grant when its window passes ----


def _held_apply_under_grant(monkeypatch, confirm_by: int) -> None:
    """An apply the grant approved that ends held, until confirm_by."""

    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved by your easy grant",
            grant_used=True,
            grant_note="EASY GRANT: DHCP reservations until 16:40",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id, hold=False: {"result": "held", "confirm_by": confirm_by},
    )
    asyncio.run(server._apply_change_tool(DEVICE, SID, object(), hold=True))


def test_a_held_change_whose_window_passed_unobserved_ends_the_grant_at_the_next_plan(
    configured_newton, monkeypatch
):
    """Nobody called status, confirm or abort: the router rolled the held
    change back on its own when its window ended.  The next plan under the
    grant learns the window passed unconfirmed and ends the grant."""
    _write_plan(_grantable_plan())
    _open_grant()
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) - 1)

    assert server._grant_can_waive_chat(DEVICE) is False
    assert grants.load_live_grant(DEVICE) is None


def test_a_held_change_whose_window_passed_unobserved_is_not_grant_waived(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) - 1)

    assert server._grant_waives_chat(DEVICE, "set dhcp.host1.ip='192.0.2.21'", False) is False
    assert grants.load_live_grant(DEVICE) is None


def test_a_held_change_whose_window_passed_unobserved_ends_the_grant_before_the_next_apply(
    configured_newton, monkeypatch
):
    """The approval of the next apply never sees the grant that the
    unobserved rollback ended."""
    _write_plan(_grantable_plan())
    _open_grant()
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) - 1)
    seen: list[Any] = []

    async def collect(ctx, device, session_id):
        seen.append(grants.load_live_grant(device))
        return elicit_approval.Outcome("fallback", "no approval")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server, "newton_apply_change",
        lambda device, session_id, hold=False: {"error": "not approved"},
    )
    asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert seen == [None]


def test_a_held_change_whose_window_passed_unobserved_is_not_shown_as_a_live_grant(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) - 1)

    devices = server.newton_list_devices()["devices"]

    assert [d["easy_grant"] for d in devices if d["name"] == DEVICE] == [None]


def test_a_held_change_still_in_its_window_keeps_the_grant(configured_newton, monkeypatch):
    _write_plan(_grantable_plan())
    _open_grant()
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) + 600)

    assert server._grant_can_waive_chat(DEVICE) is True
    assert grants.load_live_grant(DEVICE) is not None


def test_a_held_change_confirmed_in_its_window_keeps_the_grant_after_it(
    configured_newton, monkeypatch
):
    _write_plan(_grantable_plan())
    _open_grant()
    confirm_by = int(time.time()) + 600
    _held_apply_under_grant(monkeypatch, confirm_by=confirm_by)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(f"CONFIRMED session={SID} (verify passed)\n"),
    )
    assert server.newton_confirm_change(DEVICE, SID)["result"] == "confirmed"
    monkeypatch.setattr(server.time, "time", lambda: confirm_by + 60.0)

    assert server._grant_on_disk(DEVICE) is True


def test_a_held_change_under_an_earlier_grant_does_not_end_a_new_grant(
    configured_newton, monkeypatch
):
    """The held change ran under a grant that has since ended; a grant the
    owner opened after it is not ended by that change's window."""
    _write_plan(_grantable_plan())
    _open_grant(now=time.time() - 30)
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) - 1)
    grants.revoke_grant(DEVICE)
    _open_grant()

    assert server._grant_on_disk(DEVICE) is True


def test_a_held_change_the_router_confirmed_after_a_lost_answer_keeps_the_grant(
    configured_newton, monkeypatch
):
    """A status that reads the router's confirmed state (the confirm's answer
    was lost) clears the held change: its window passing is no failure."""
    _write_plan(_grantable_plan())
    _open_grant()
    confirm_by = int(time.time()) + 600
    _held_apply_under_grant(monkeypatch, confirm_by=confirm_by)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        _fake_script(f"CONFIRMED session={SID} (reconciled: the router's status says confirmed)\n"),
    )
    server.newton_change_status(DEVICE, SID)
    monkeypatch.setattr(server.time, "time", lambda: confirm_by + 60.0)

    assert server._grant_on_disk(DEVICE) is True


def test_an_unreadable_held_change_record_ends_the_grant(configured_newton, monkeypatch):
    """Whether the held change was confirmed cannot be read: unknown is not
    confirmed, so the grant ends."""
    _write_plan(_grantable_plan())
    _open_grant()
    _held_apply_under_grant(monkeypatch, confirm_by=int(time.time()) + 600)
    server._held_under_grant_path(DEVICE).write_text("{not json", encoding="utf-8")

    assert server._grant_on_disk(DEVICE) is False
    assert grants.load_live_grant(DEVICE) is None
