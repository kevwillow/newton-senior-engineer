from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from exhelp import record_fields, record_fields_display

import newton_mcp.approval_proof as proof
import newton_mcp.approve as approve
import newton_mcp.elicit_approval as elicit_approval
import newton_mcp.server as server
from newton_mcp.plan import compute_plan_hash


SID = "0123456789abcdef0123456789abcdef"
OTHER_SID = "fedcba9876543210fedcba9876543210"
DEVICE = "quasar"
DIGEST = "d" * 64
PASSPHRASE = "synthetic-dialog-passphrase"
WRONG_PASSPHRASE = "synthetic-wrong-passphrase"
TOTP_SEED = b"12345678901234567890"
TOTP_K = "ab" * 32
FORM_CAPABILITY = SimpleNamespace(form=None, url=None)


_DERIVED: dict[tuple[bytes, str], str] = {}


def _derived_k(passphrase: bytes, device: str = DEVICE) -> str:
    key = (passphrase, device)
    if key not in _DERIVED:
        _DERIVED[key] = approve.derive_k(passphrase, device)
    return _DERIVED[key]


def _plan(
    session_id: str = SID,
    *,
    device: str = DEVICE,
    requires_approval: bool = True,
    uci_batch: str = "set network.lan.proto='static'",
) -> dict[str, Any]:
    batch = uci_batch
    record: dict[str, Any] = {
        "device": device,
        "host": "192.0.2.1",
        "session_id": session_id,
        "uci_batch": batch,
        "diff": batch,
        "probes": [["log-has", "present", "made-up-marker"]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": requires_approval,
        "router_digest": DIGEST,
        "router_profile": "prod",
        "router_leash": ["mgmt-if"],
        "router_sections": ["network.lan"],
        "reasons": ["network configuration changes require approval"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "staged_at": datetime.now(timezone.utc).isoformat(),
    }
    record.update(record_fields(batch))
    record.update(record_fields_display())
    record["router_requires_approval"] = requires_approval
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _write_plan(record: dict[str, Any]) -> Path:
    path = approve.state_dir() / "plans" / f"{record['session_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _write_fingerprint(device: str = DEVICE, k_hex: str | None = None) -> Path:
    key = k_hex or _derived_k(PASSPHRASE.encode("utf-8"), device)
    path = approve.state_dir() / "approval-fp" / device
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"v1 {approve.approval_fingerprint(key)}\n", encoding="ascii")
    return path


def _approval_path(session_id: str = SID) -> Path:
    return approve.state_dir() / "approvals" / f"{session_id}.json"


def _lockout_record(device: str = DEVICE) -> dict[str, Any]:
    path = approve.state_dir() / "lockout" / f"{device}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _audit_text() -> str:
    """The audit log the server writes, without its timestamps.

    The timestamp of a line ends in microseconds, and six digits look
    exactly like a TOTP code: keeping it would make the "the code never
    reaches the log" test flaky.
    """
    path = approve.state_dir() / "mcp-audit.log"
    if not path.exists():
        return ""
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(" ", 1)
        lines.append(parts[1] if len(parts) == 2 else line)
    return "\n".join(lines)


class _Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def monotonic(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def sdk_validate(schema: type[Any]) -> None:
    """Run the pinned SDK's own elicitation-schema check, as ctx.elicit does."""
    from mcp.server.elicitation import _validate_elicitation_schema

    _validate_elicitation_schema(schema)


class _FakeContext:
    def __init__(
        self,
        clock: _Clock,
        *,
        secret: str = PASSPHRASE,
        action: str = "accept",
        delay: float = 5.0,
        typed_device: str = DEVICE,
        capability: Any = FORM_CAPABILITY,
        error: Exception | None = None,
        sleep_s: float = 0.0,
    ) -> None:
        self.clock = clock
        self.secret = secret
        self.action = action
        self.delay = delay
        self.typed_device = typed_device
        self.error = error
        self.sleep_s = sleep_s
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
        if self.error is not None:
            raise self.error
        if self.sleep_s:
            # a real wait, so the elicitation timeout can fire: the fake
            # clock only moves the dwell, it does not pass time
            await asyncio.sleep(self.sleep_s)
        self.clock.advance(self.delay)
        data = None
        if self.action == "accept":
            values: dict[str, Any] = {"secret": self.secret}
            if "device_name" in schema.model_fields:
                values["device_name"] = self.typed_device
            data = schema(**values)
        return SimpleNamespace(action=self.action, data=data)


class _GatedContext(_FakeContext):
    """A context whose dialog waits for an event before it answers.

    The gate is what lets a second call reach the lock while the first
    one is still inside its dialog: without a real await point the two
    calls would run one after the other and never overlap.
    """

    def __init__(self, clock: _Clock, gate: asyncio.Event, **kwargs: Any) -> None:
        super().__init__(clock, **kwargs)
        self.gate = gate

    async def elicit(self, message: str, schema: type[Any]) -> Any:
        self.messages.append(message)
        self.schemas.append(schema)
        sdk_validate(schema)
        await self.gate.wait()
        self.clock.advance(self.delay)
        data = None
        if self.action == "accept":
            values: dict[str, Any] = {"secret": self.secret}
            if "device_name" in schema.model_fields:
                values["device_name"] = self.typed_device
            data = schema(**values)
        return SimpleNamespace(action=self.action, data=data)


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    value = _Clock()
    monkeypatch.setattr(
        elicit_approval,
        "time",
        SimpleNamespace(monotonic=value.monotonic),
    )
    return value


def _collect_and_record(monkeypatch, outcomes: list[elicit_approval.Outcome]):
    """Wrap the real collect_approval so the outcome can be inspected."""
    real_collect = elicit_approval.collect_approval

    async def collect(ctx, device, session_id):
        outcome = await real_collect(ctx, device, session_id)
        outcomes.append(outcome)
        return outcome

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)


def _run_approval(
    ctx: _FakeContext,
    device: str = DEVICE,
    session_id: str = SID,
) -> elicit_approval.Outcome:
    return asyncio.run(
        elicit_approval.collect_approval(ctx, device, session_id)
    )


async def _gather_approvals(
    contexts: list[_FakeContext],
    device: str = DEVICE,
    session_id: str = SID,
) -> list[elicit_approval.Outcome]:
    """Run one approval per context in the same event loop."""
    return list(
        await asyncio.gather(
            *[
                elicit_approval.collect_approval(ctx, device, session_id)
                for ctx in contexts
            ]
        )
    )


def _run_two_gated(
    clock: _Clock,
    gate: asyncio.Event,
) -> tuple[list[elicit_approval.Outcome], list[_FakeContext]]:
    """Run two approvals whose dialogs wait for *gate*.

    The gate is released once one call is inside its dialog and the
    other has finished, so the two calls really overlap.
    """
    first = _GatedContext(clock, gate)
    second = _GatedContext(clock, gate)

    async def run() -> list[elicit_approval.Outcome]:
        task_one = asyncio.create_task(
            elicit_approval.collect_approval(first, DEVICE, SID)
        )
        task_two = asyncio.create_task(
            elicit_approval.collect_approval(second, DEVICE, SID)
        )
        for _ in range(200):
            shown = first.messages or second.messages
            if shown and (task_one.done() != task_two.done()):
                break
            await asyncio.sleep(0)
        gate.set()
        return list(await asyncio.gather(task_one, task_two))

    return asyncio.run(run()), [first, second]


def test_outcome_grant_fields_default_to_no_grant():
    outcome = elicit_approval.Outcome("approved", "approved")

    assert outcome.grant_used is False
    assert outcome.grant_note == ""


def test_env_zero_skips_without_elicit(monkeypatch, clock):
    _write_plan(_plan())
    monkeypatch.setenv("NEWTON_ELICIT_APPROVAL", "0")
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "skip"
    assert ctx.messages == []


def test_missing_plan_skips_without_elicit(clock):
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "skip"
    assert ctx.messages == []


def test_plan_not_requiring_approval_skips_without_elicit(clock):
    _write_plan(_plan(requires_approval=False))
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "skip"
    assert ctx.messages == []


def test_plan_for_another_device_skips_without_elicit(clock):
    _write_plan(_plan(device="another-device"))
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx, device=DEVICE)

    assert outcome.status == "skip"
    assert ctx.messages == []


@pytest.mark.parametrize("suffix", [".json", ".claimed", ".used"])
def test_an_existing_approval_state_skips_without_elicit(clock, suffix):
    _write_plan(_plan())
    path = approve.state_dir() / "approvals" / f"{SID}{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "skip"
    assert ctx.messages == []


def test_a_plan_refused_by_validation_falls_back_without_elicit(clock):
    plan = _plan()
    plan["router_digest"] = "not-a-digest"
    # the digest is part of the plan's identity: a record whose hash no
    # longer matches is a different plan, and the dialog must show that
    # refusal, not the edit
    plan["plan_hash"] = compute_plan_hash(plan)
    _write_plan(plan)
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "fallback"
    assert "no valid router digest" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert ctx.messages == []


@pytest.mark.parametrize(
    "capability",
    [None, SimpleNamespace(form=None, url=object())],
)
def test_a_client_without_form_elicitation_falls_back_without_elicit(clock, capability):
    _write_plan(_plan())
    ctx = _FakeContext(clock, capability=capability)

    outcome = _run_approval(ctx)

    assert outcome.status == "fallback"
    assert "cannot show an approval dialog" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert ctx.messages == []


def test_a_locked_device_is_locked_without_elicit(clock):
    _write_plan(_plan())
    for _ in range(3):
        proof.record_failure(DEVICE)
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "locked"
    assert "too many wrong answers" in outcome.message
    assert "5 min" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert ctx.messages == []


def test_passphrase_approval_writes_an_acceptable_approval(configured_newton, clock):
    plan = _plan()
    _write_plan(plan)
    _write_fingerprint()
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "approved"
    assert outcome.message == "approved in the client dialog"
    path = _approval_path()
    saved = json.loads(path.read_text(encoding="utf-8"))
    key = _derived_k(PASSPHRASE.encode("utf-8"), DEVICE)
    expected = approve.approval_token(
        key,
        DIGEST,
        saved["not_before"],
        saved["not_after"],
    )
    assert saved["token"] == expected
    assert saved["approved_by"] == "elicit:passphrase"
    assert path.stat().st_mode & 0o777 == 0o600
    grant = server.NewtonService().consume_approval(DEVICE, SID, plan)
    assert grant.token == expected


def test_wrong_passphrase_is_wrong_and_counts_a_miss(clock):
    _write_plan(_plan())
    _write_fingerprint()
    ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)

    outcome = _run_approval(ctx)

    assert outcome.status == "wrong"
    assert "wrong" in outcome.message.lower()
    assert "attempt" in outcome.message.lower()
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert not _approval_path().exists()
    assert _lockout_record()["misses"] == 1


def test_the_third_wrong_passphrase_locks_the_next_call(clock):
    _write_plan(_plan())
    _write_fingerprint()

    for _ in range(3):
        outcome = _run_approval(
            _FakeContext(clock, secret=WRONG_PASSPHRASE)
        )
        assert outcome.status == "wrong"

    ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    outcome = _run_approval(ctx)

    assert outcome.status == "locked"
    assert ctx.messages == []
    assert not _approval_path().exists()


def test_totp_approval_writes_the_same_approval_token(clock):
    _write_plan(_plan())
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    code = proof.totp_code(TOTP_SEED, proof.totp_counter())
    ctx = _FakeContext(clock, secret=code)

    outcome = _run_approval(ctx)

    assert outcome.status == "approved"
    saved = json.loads(_approval_path().read_text(encoding="utf-8"))
    expected = approve.approval_token(
        TOTP_K,
        DIGEST,
        saved["not_before"],
        saved["not_after"],
    )
    assert saved["token"] == expected
    assert saved["approved_by"] == "elicit:totp"


def test_a_totp_record_from_an_older_passphrase_falls_back(clock):
    """The passphrase was changed with ``approval-key`` after enrolment:
    the TOTP record still holds the old K, so an approval minted with it
    would only be refused by the router.  The dialog says to enrol again,
    writes no approval and counts no miss (the code itself was right)."""
    _write_plan(_plan())
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    _write_fingerprint()  # the fingerprint of the NEW passphrase, not TOTP_K
    code = proof.totp_code(TOTP_SEED, proof.totp_counter())

    outcome = _run_approval(_FakeContext(clock, secret=code))

    assert outcome.status == "fallback"
    assert "newton-enrol totp" in outcome.message
    assert not _approval_path().exists()
    assert not proof._lockout_path(DEVICE).exists()


def test_a_totp_record_matching_the_fingerprint_approves(clock):
    _write_plan(_plan())
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    _write_fingerprint(k_hex=TOTP_K)
    code = proof.totp_code(TOTP_SEED, proof.totp_counter())

    outcome = _run_approval(_FakeContext(clock, secret=code))

    assert outcome.status == "approved"


def test_a_replayed_totp_code_is_rejected(clock):
    first_plan = _plan(SID)
    second_plan = _plan(OTHER_SID)
    _write_plan(first_plan)
    _write_plan(second_plan)
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    code = proof.totp_code(TOTP_SEED, proof.totp_counter())

    first = _run_approval(_FakeContext(clock, secret=code), session_id=SID)
    second = _run_approval(
        _FakeContext(clock, secret=code),
        session_id=OTHER_SID,
    )

    assert first.status == "approved"
    assert second.status == "wrong"
    assert not _approval_path(OTHER_SID).exists()


def test_cancel_at_once_falls_back(clock):
    _write_plan(_plan())
    _write_fingerprint()
    ctx = _FakeContext(clock, action="cancel", delay=0.0)

    outcome = _run_approval(ctx)

    assert outcome.status == "fallback"
    assert "answered at once" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert not _approval_path().exists()


def test_cancel_after_the_dwell_declines(clock):
    _write_plan(_plan())
    _write_fingerprint()
    ctx = _FakeContext(clock, action="cancel", delay=5.0)

    outcome = _run_approval(ctx)

    assert outcome.status == "declined"
    assert "you declined" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert not _approval_path().exists()


def test_an_answer_at_once_falls_back_and_counts_a_miss(clock):
    _write_plan(_plan())
    _write_fingerprint()
    ctx = _FakeContext(clock, delay=0.1)

    outcome = _run_approval(ctx)

    assert outcome.status == "fallback"
    assert "too fast" in outcome.message
    assert outcome.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )
    assert _lockout_record()["misses"] == 1
    assert not _approval_path().exists()


def test_first_approval_warning_is_present_only_before_the_ack(clock):
    _write_plan(_plan())
    _write_fingerprint()

    first_ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    first_ctx_result = _run_approval(first_ctx)
    first_text = first_ctx.messages[0]
    assert first_ctx_result.status == "wrong"
    assert "FIRST APPROVAL ON THIS DEVICE" in first_text
    assert "live router" in first_text
    assert "auto-undoes" in first_text
    assert "only you can approve" in first_text.lower()
    assert "the agent can be wrong" in first_text.lower()
    # The first approval asks for the passphrase only; the warning
    # is shown, but no device name has to be typed.
    assert "type the device name" not in first_text.lower()
    assert "device_name" not in first_ctx.schemas[0].model_fields

    proof.write_ack(DEVICE)
    second_ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    second = _run_approval(second_ctx)

    assert second.status == "wrong"
    assert "FIRST APPROVAL ON THIS DEVICE" not in second_ctx.messages[0]
    assert "device_name" not in second_ctx.schemas[0].model_fields


def test_the_first_approval_warning_comes_back_after_a_failed_answer(clock):
    """A failed answer does not acknowledge the
    warning.

    The agent can send a failed answer of its own.  If that answered
    the warning, the owner's own dialog would carry no warning, and the
    agent would have made the owner approve blind.  The repetition is
    the protection, so the next dialog of the same approval shows the
    warning again.
    """
    _write_plan(_plan())
    _write_fingerprint()

    first_ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    first = _run_approval(first_ctx)

    assert first.status == "wrong"
    assert "FIRST APPROVAL ON THIS DEVICE" in first_ctx.messages[0]

    second_ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    second = _run_approval(second_ctx)

    assert second.status == "wrong"
    assert "FIRST APPROVAL ON THIS DEVICE" in second_ctx.messages[0]
    assert not proof.has_ack(DEVICE)


def test_a_forged_answer_does_not_acknowledge_the_first_approval_warning(
    clock,
):
    """The forged answer of the agent: a passphrase that is wrong.

    The owner sees the warning again, because the forged answer proved
    nothing.
    """
    _write_plan(_plan())
    _write_fingerprint()

    forged_ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    forged = _run_approval(forged_ctx)

    assert forged.status == "wrong"
    assert "FIRST APPROVAL ON THIS DEVICE" in forged_ctx.messages[0]

    owner_ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)
    owner = _run_approval(owner_ctx)

    assert owner.status == "wrong"
    assert "FIRST APPROVAL ON THIS DEVICE" in owner_ctx.messages[0]
    assert not proof.has_ack(DEVICE)


def test_the_dialog_begins_with_the_banner_and_puts_facts_first(clock):
    _write_plan(_plan())
    _write_fingerprint()
    ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)

    _run_approval(ctx)

    text = ctx.messages[0]
    assert text.startswith(f"NEWTON  APPROVAL  {DEVICE}  plan {SID[:8]}")
    assert text.index("Plan:") < text.index(approve.EXPLANATION_HEADING)
    assert approve.EXPLANATION_HEADING in text
    assert "unchecked" in text.lower()


def test_the_dialog_puts_plain_language_and_its_alternative_before_the_plan(clock):
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='DNAT'",
        ]
    )
    plan = _plan(uci_batch=batch)
    plan["explanation"]["intent"] = "guests are isolated from the other devices"
    plan["plan_hash"] = compute_plan_hash(plan)
    _write_plan(plan)
    _write_fingerprint()
    ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)

    _run_approval(ctx)

    lines = ctx.messages[0].splitlines()
    assert lines[0].startswith(
        f"NEWTON  HIGH RISK  APPROVAL  {DEVICE}  plan {SID[:8]}"
    )
    assert lines[1] == "WHAT THIS DOES"
    assert lines[2] == "Opens a port from the internet to a device on your network."
    assert lines[3] == (
        "Smaller alternative: reach it through a WireGuard/VPN connection instead "
        "of opening a public port."
    )
    assert lines[4].startswith("Plan:")
    assert "Gives a new, separate network internet access, with no new access to your other devices." not in ctx.messages[0]


def test_the_secret_never_appears_in_messages_or_logs(clock, caplog):
    _write_plan(_plan())
    _write_fingerprint()
    caplog.set_level(logging.DEBUG)
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    key = _derived_k(PASSPHRASE.encode("utf-8"), DEVICE)
    assert PASSPHRASE not in outcome.message
    assert PASSPHRASE not in "".join(ctx.messages)
    assert key not in outcome.message
    assert key not in "".join(ctx.messages)
    assert PASSPHRASE not in caplog.text
    assert key not in caplog.text


def test_only_one_dialog_opens_at_a_time_for_a_device(clock):
    """A second call for the same device must not open a second dialog.

    The agent can start many apply calls for one plan at once.  Without
    the device dialog lock every one of them would open a dialog, and a
    client that answers every dialog would hand the caller one
    passphrase guess per call before the first failure was counted.
    """
    _write_plan(_plan())
    _write_fingerprint()
    gate = asyncio.Event()

    outcomes, contexts = _run_two_gated(clock, gate)

    assert sum(len(ctx.messages) for ctx in contexts) == 1
    statuses = sorted(outcome.status for outcome in outcomes)
    assert statuses == ["approved", "fallback"]
    busy = next(outcome for outcome in outcomes if outcome.status == "fallback")
    assert "another approval dialog is already open for this device" in busy.message
    assert busy.message.endswith(
        f"sudo -u newton /usr/local/bin/newton-approve {SID}"
    )


def test_a_call_after_the_approval_was_written_skips(clock):
    """The winner's approval makes the next call a skip, not a dialog."""
    _write_plan(_plan())
    _write_fingerprint()
    gate = asyncio.Event()

    outcomes, _ = _run_two_gated(clock, gate)

    assert sorted(outcome.status for outcome in outcomes) == ["approved", "fallback"]
    third_ctx = _FakeContext(clock)
    third = _run_approval(third_ctx)

    assert third.status == "skip"
    assert third_ctx.messages == []


def test_five_concurrent_guesses_cannot_outrun_the_lockout(clock, monkeypatch):
    """Five parallel wrong answers must not buy five guesses.

    The lockout gives three tries and then a five-minute lock, so the
    number of passphrase checks can never pass the number of dialogs
    that were really shown.
    """
    _write_plan(_plan())
    _write_fingerprint()
    verified: list[str] = []
    failures: list[str] = []
    real_verify = proof.verify_passphrase
    real_failure = proof.record_failure

    def counting_verify(device, passphrase):
        verified.append(device)
        return real_verify(device, passphrase)

    def counting_failure(device, now=None):
        failures.append(device)
        return real_failure(device, now=now)

    monkeypatch.setattr(proof, "verify_passphrase", counting_verify)
    monkeypatch.setattr(proof, "record_failure", counting_failure)
    contexts = [_FakeContext(clock, secret=WRONG_PASSPHRASE) for _ in range(5)]

    outcomes = asyncio.run(_gather_approvals(contexts))

    dialogs = sum(len(ctx.messages) for ctx in contexts)
    assert len(verified) <= 3
    assert len(failures) <= dialogs
    assert len(verified) == dialogs
    statuses = [outcome.status for outcome in outcomes]
    assert statuses.count("wrong") == 3
    assert statuses.count("locked") == 2
    assert 299 <= proof.lock_remaining(DEVICE) <= 300


def test_a_failing_acknowledgement_still_leaves_a_valid_approval(clock, monkeypatch):
    """A broken acknowledgement is not a broken approval.

    The approval record is already on disk when the acknowledgement is
    written, so a failure there must not tell the owner that the
    approval itself failed.
    """
    _write_plan(_plan())
    _write_fingerprint()

    def refuse(device, now=None):
        raise OSError("no space left on device")

    monkeypatch.setattr(proof, "write_ack", refuse)
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "approved"
    assert "the first-approval acknowledgement could not be saved" in outcome.message
    assert "the approval record could not be written" not in outcome.message
    path = _approval_path()
    assert path.exists()
    saved = json.loads(path.read_text(encoding="utf-8"))
    key = _derived_k(PASSPHRASE.encode("utf-8"), DEVICE)
    expected = approve.approval_token(
        key,
        DIGEST,
        saved["not_before"],
        saved["not_after"],
    )
    assert saved["token"] == expected


def test_a_plan_whose_body_was_edited_skips_without_elicit(clock):
    """A plan record that no longer matches its hash is not shown.

    The approval token binds the plan hash, so a dialog over an edited
    record would ask the owner to approve something the token cannot
    prove.
    """
    plan = _plan()
    _write_plan(plan)
    edited = dict(plan)
    edited["uci_batch"] = "set network.lan.proto='dhcp'"
    _write_plan(edited)
    ctx = _FakeContext(clock)

    outcome = _run_approval(ctx)

    assert outcome.status == "skip"
    assert ctx.messages == []


def test_the_sync_apply_function_remains_importable_and_callable(
    configured_newton, monkeypatch
):
    monkeypatch.setattr(
        server.NewtonService,
        "apply",
        lambda self, device, session_id: {"result": "confirmed"},
    )

    result = server.newton_apply_change(DEVICE, SID)

    assert result == {"result": "confirmed"}


def test_the_registered_apply_tool_has_only_device_and_session_id():
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    tools = [tool for tool in response.tools if tool.name == "newton_apply_change"]
    assert len(tools) == 1
    tool = tools[0]
    assert set(tool.inputSchema["properties"]) == {"device", "session_id"}
    assert "ctx" not in tool.inputSchema["properties"]
    assert "approval" not in json.dumps(tool.inputSchema).lower()
    assert "secret" not in json.dumps(tool.inputSchema).lower()
    assert (
        "If approval is needed the owner is shown a dialog in their client and "
        "answers it; if the client cannot show one, tell the owner to run the "
        "newton-approve command in the error."
    ) in tool.description
    assert "session_id" in tool.description


def test_the_async_apply_tool_returns_an_approval_error_and_audits_it(
    configured_newton, monkeypatch
):
    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "fallback",
            f"cannot show an approval dialog; sudo -u newton /usr/local/bin/newton-approve {session_id}",
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id: pytest.fail("apply must not run"),
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert result == {
        "error": (
            f"cannot show an approval dialog; sudo -u newton /usr/local/bin/newton-approve {SID}"
        ),
        "newton_result": (
            f"NEWTON RESULT: NOT APPLIED  {DEVICE}  {SID[:8]}  (plan not available)"
        ),
    }
    audit = (
        approve.state_dir() / "mcp-audit.log"
    ).read_text(encoding="utf-8")
    assert "tool=newton_apply_change" in audit
    assert "result=error approval fallback" in audit


def test_the_async_apply_tool_runs_the_sync_apply_after_approval(
    configured_newton, monkeypatch
):
    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome("approved", "approved in the client dialog")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id: {"result": "confirmed"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert result == {
        "result": "confirmed",
        "newton_result": (
            f"NEWTON RESULT: CONFIRMED  {DEVICE}  {SID[:8]}  (plan not available)"
        ),
    }


def test_the_async_apply_tool_hides_an_unexpected_approval_error(
    configured_newton, monkeypatch
):
    """A crash in the dialog path is an internal error, not a crash.

    The model sees the same short error as any other unexpected failure
    of the tool; the real cause goes to the on-disk error log.
    """

    async def collect(ctx, device, session_id):
        raise RuntimeError("boom")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id: pytest.fail("apply must not run"),
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert result == {
        "error": "internal server error",
        "newton_result": (
            f"NEWTON RESULT: NOT APPLIED  {DEVICE}  {SID[:8]}  (plan not available)"
        ),
    }
    audit = (
        approve.state_dir() / "mcp-audit.log"
    ).read_text(encoding="utf-8")
    lines = [line for line in audit.splitlines() if "tool=newton_apply_change" in line]
    assert any("result=error" in line for line in lines)


# --- the bounded wait -------------------------------------------------------


def test_a_dialog_nobody_answers_times_out(monkeypatch, clock):
    """A dialog nobody answers must not hold the session for ever.

    The dialog is drawn by the client, and a client that cannot draw it
    never answers: without a bound the call would wait for ever and the
    session would look hung.  The wait is bounded, and the owner is
    told where to answer instead.
    """
    _write_plan(_plan())
    _write_fingerprint()
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", "0.05")
    ctx = _FakeContext(clock, sleep_s=5.0)

    outcome = _run_approval(ctx)

    assert outcome.status == "fallback"
    assert outcome.message == (
        "The approval dialog timed out after 0.05 seconds; nothing was "
        "approved. An answer typed after that is ignored, even if the dialog "
        "is still on the screen. Ask for the change again, or run "
        f"sudo -u newton /usr/local/bin/newton-approve {SID} in your terminal."
    )
    assert not _approval_path().exists()


def test_a_timeout_records_no_miss(monkeypatch, clock):
    """Nobody answering is not a wrong answer.

    A timeout must not count against the owner: the lockout is for
    wrong answers, and a client that cannot show a dialog must not lock
    the owner out of their own router.
    """
    _write_plan(_plan())
    _write_fingerprint()
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", "0.05")
    ctx = _FakeContext(clock, sleep_s=5.0)

    outcome = _run_approval(ctx)

    assert outcome.status == "fallback"
    assert not (approve.state_dir() / "lockout" / f"{DEVICE}.json").exists()
    assert proof.lock_remaining(DEVICE) == 0


def test_a_timeout_releases_the_dialog_lock(monkeypatch, clock):
    """The lock is released when the wait runs out.

    A lock that outlived the dialog would turn every later call into a
    fallback to the terminal, for ever.
    """
    _write_plan(_plan())
    _write_fingerprint()
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", "0.05")

    timed_out = _run_approval(_FakeContext(clock, sleep_s=5.0))
    assert timed_out.status == "fallback"

    second_ctx = _FakeContext(clock)
    second = _run_approval(second_ctx)

    assert second.status == "approved"
    assert len(second_ctx.messages) == 1


@pytest.mark.parametrize(
    "value",
    ["", "abc", "0", "-1", "1.5.2", "nan", "inf", "1e999"],
)
def test_a_bad_elicit_timeout_uses_the_default(monkeypatch, value):
    """Only a positive number is a timeout; anything else is the default."""
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", value)

    assert elicit_approval.ELICIT_TIMEOUT_S == 180.0
    assert elicit_approval._elicit_timeout_s() == 180.0


@pytest.mark.parametrize("value", ["0.25", "30", "30.5"])
def test_a_good_elicit_timeout_is_used(monkeypatch, value):
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", value)

    assert elicit_approval._elicit_timeout_s() == float(value)


def test_a_bad_elicit_timeout_does_not_cut_the_dialog_short(monkeypatch, clock):
    """A bad value must not turn into an instant timeout."""
    _write_plan(_plan())
    _write_fingerprint()
    monkeypatch.setenv("NEWTON_ELICIT_TIMEOUT_S", "not-a-number")
    ctx = _FakeContext(clock, sleep_s=0.2)

    outcome = _run_approval(ctx)

    assert outcome.status == "approved"


# --- the clear notice -------------------------------------------------------


def test_a_passphrase_approval_carries_the_clear_notice(clock):
    """The passphrase is shown as it is typed, so the owner is told to clear it.

    The notice names no product: the client may be anything, and a
    notice that names one product is a lie for the others.
    """
    _write_plan(_plan())
    _write_fingerprint()

    outcome = _run_approval(_FakeContext(clock))

    assert outcome.status == "approved"
    assert outcome.notice == elicit_approval.CLEAR_NOTICE
    assert "visible as you typed it" in outcome.notice
    assert "Termius" not in outcome.notice
    assert "phone" not in outcome.notice.lower()


def test_a_totp_approval_carries_no_notice(clock):
    """A TOTP code is not shown on the screen, so there is nothing to clear."""
    _write_plan(_plan())
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    code = proof.totp_code(TOTP_SEED, proof.totp_counter())

    outcome = _run_approval(_FakeContext(clock, secret=code))

    assert outcome.status == "approved"
    assert outcome.notice == ""


def test_the_apply_tool_adds_the_approval_notice(configured_newton, monkeypatch):
    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome(
            "approved",
            "approved in the client dialog",
            notice=elicit_approval.CLEAR_NOTICE,
        )

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id: {"result": "confirmed"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert result["approval_notice"] == elicit_approval.CLEAR_NOTICE


def test_the_apply_tool_adds_no_notice_when_there_is_none(configured_newton, monkeypatch):
    async def collect(ctx, device, session_id):
        return elicit_approval.Outcome("approved", "approved in the client dialog")

    monkeypatch.setattr(server.elicit_approval, "collect_approval", collect)
    monkeypatch.setattr(
        server,
        "newton_apply_change",
        lambda device, session_id: {"result": "confirmed"},
    )

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, object()))

    assert "approval_notice" not in result


# --- the secret never comes back --------------------------------------------


def test_the_typed_passphrase_never_reaches_the_agent(
    configured_newton, clock, caplog, monkeypatch
):
    """Nothing on the way out may hold the passphrase the owner typed."""
    _write_plan(_plan())
    _write_fingerprint()
    caplog.set_level(logging.DEBUG)
    outcomes: list[elicit_approval.Outcome] = []
    _collect_and_record(monkeypatch, outcomes)
    ctx = _FakeContext(clock)

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, ctx))

    assert outcomes[0].status == "approved"
    assert PASSPHRASE not in json.dumps(result, default=str)
    assert PASSPHRASE not in outcomes[0].message
    assert PASSPHRASE not in outcomes[0].notice
    # the audit log must really have a line, or "not in it" means nothing
    assert "tool=newton_apply_change" in _audit_text()
    assert PASSPHRASE not in _audit_text()
    assert PASSPHRASE not in caplog.text


def test_a_wrong_typed_passphrase_never_reaches_the_agent(
    configured_newton, clock, caplog, monkeypatch
):
    """A wrong answer is a secret too."""
    _write_plan(_plan())
    _write_fingerprint()
    caplog.set_level(logging.DEBUG)
    outcomes: list[elicit_approval.Outcome] = []
    _collect_and_record(monkeypatch, outcomes)
    ctx = _FakeContext(clock, secret=WRONG_PASSPHRASE)

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, ctx))

    assert outcomes[0].status == "wrong"
    assert WRONG_PASSPHRASE not in json.dumps(result, default=str)
    assert WRONG_PASSPHRASE not in outcomes[0].message
    assert WRONG_PASSPHRASE not in outcomes[0].notice
    assert "tool=newton_apply_change" in _audit_text()
    assert WRONG_PASSPHRASE not in _audit_text()
    assert WRONG_PASSPHRASE not in caplog.text


def test_the_typed_totp_code_never_reaches_the_agent(
    configured_newton, clock, caplog, monkeypatch
):
    """The code is a secret as much as the passphrase is."""
    _write_plan(_plan())
    proof.store_totp(DEVICE, TOTP_SEED, TOTP_K)
    proof.set_level(DEVICE, proof.LEVEL_TOTP)
    code = proof.totp_code(TOTP_SEED, proof.totp_counter())
    caplog.set_level(logging.DEBUG)
    outcomes: list[elicit_approval.Outcome] = []
    _collect_and_record(monkeypatch, outcomes)
    ctx = _FakeContext(clock, secret=code)

    result = asyncio.run(server._apply_change_tool(DEVICE, SID, ctx))

    assert outcomes[0].status == "approved"
    assert code not in json.dumps(result, default=str)
    assert code not in outcomes[0].message
    assert code not in outcomes[0].notice
    assert "tool=newton_apply_change" in _audit_text()
    assert code not in _audit_text()
    assert code not in caplog.text


def test_the_clear_notice_names_a_working_command_and_no_product():
    notice = elicit_approval.CLEAR_NOTICE
    assert "clear && printf '\\e[3J'" in notice
    assert "Termius" not in notice
