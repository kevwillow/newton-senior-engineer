"""The approve.py pieces the in-client approval dialog reuses.

The extraction is pure.  ``main()`` must print and refuse exactly what it
printed and refused before, and the extracted helpers must render and mint
the same bytes the terminal path does -- the dialog shows the owner the
same words the terminal shows, and mints the same approval token.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from exhelp import record_fields

import newton_mcp.approve as approve
from newton_mcp.plan import compute_plan_hash


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
BATCH = "set wireless.radio0.key='never-display-this'"
FROZEN = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)

NO_DIGEST_MESSAGE = (
    "plan record has no valid router digest "
    "(64 lowercase hex); there is nothing to bind an approval token to"
)
NOTHING_TO_APPROVE_MESSAGE = "nothing to approve: the plan does not require approval"
NO_CHAT_MESSAGE = (
    "plan record does not say the owner confirmed in chat; "
    "plan it again; approval not created"
)


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


class _FrozenDatetime(datetime):
    """Freeze ``approve.datetime.now()`` to a fixed UTC instant.

    Same trick as test_approve.py: patching ``approve.datetime`` swaps the
    implementation ``datetime.now(timezone.utc)`` resolves to inside the
    module, so the display time and the approval creation time are the
    same instant in every run of a test.
    """

    _fixed: datetime | None = None

    @classmethod
    def now(cls, tz=None):
        if cls._fixed is None:
            return super().now(tz)
        if tz is None:
            return cls._fixed.replace(tzinfo=None)
        return cls._fixed.astimezone(tz)


@pytest.fixture
def frozen_now(monkeypatch):
    """Freeze approve.datetime.now() to 2026-10-07T12:00:00+00:00."""
    monkeypatch.setattr(approve, "datetime", _FrozenDatetime)
    _FrozenDatetime._fixed = FROZEN
    yield FROZEN
    _FrozenDatetime._fixed = None


def plan_record(staged_at=None):
    """A plan record shaped like the one test_approve.py builds.

    ``staged_at`` defaults to the current UTC time so the stage is fresh
    for the tests that do not pin a frozen clock; the frozen-clock tests
    set it to the frozen instant so the stage window is deterministic.
    """
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": BATCH,
        "diff": BATCH,
        "check": "wifi status",
        "probes": [["log-has", "present", "made-up-marker"]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": DIGEST,
        **record_fields(BATCH),
        "router_profile": "prod",
        "router_leash": ["mgmt-if"],
        "router_sections": ["wireless.radio0"],
        "router_requires_approval": True,
        "reasons": ["wireless configuration changes require approval"],
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": (
            staged_at if staged_at is not None else datetime.now(timezone.utc).isoformat()
        ),
        "staged_check": {"fw4": "skipped-untouched", "reason": "", "not_checked": ["firewall"]},
    }
    record["plan_hash"] = compute_plan_hash(record)
    return record


def write_plan(tmp_path, monkeypatch, record=None):
    """Write the plan record where main() looks for it."""
    state = tmp_path / "state"
    plans = state / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    record = plan_record() if record is None else record
    (plans / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setenv("SUDO_USER", "labuser")
    return state, record


def refuse_getpass(prompt):
    raise AssertionError("getpass must not be called in this test")


# ---- validate_plan_for_approval ------------------------------------------------


def test_validate_refuses_a_record_without_a_valid_router_digest():
    record = plan_record()
    record["router_digest"] = "d" * 63
    with pytest.raises(approve.ApprovalRefused) as exc:
        approve.validate_plan_for_approval(record)
    assert str(exc.value) == NO_DIGEST_MESSAGE


def test_validate_refuses_a_plan_that_does_not_require_approval():
    record = plan_record()
    record["requires_approval"] = False
    record["router_requires_approval"] = False
    with pytest.raises(approve.ApprovalRefused) as exc:
        approve.validate_plan_for_approval(record)
    assert str(exc.value) == NOTHING_TO_APPROVE_MESSAGE


def test_validate_refuses_a_record_without_a_valid_explanation():
    record = plan_record()
    record["explanation"] = {
        "intent": "Change the wireless key.",
        "steps": [],
        "expect": [{"kind": "probe", "probe": ["iface-absent", "guestx"]}],
        "risk": "The owner would see the radio misbehave.",
    }
    with pytest.raises(approve.ApprovalRefused) as exc:
        approve.validate_plan_for_approval(record)
    message = str(exc.value)
    assert message.startswith("plan record has no valid explanation (")
    assert message.endswith(
        "plan it again with the owner's explanation; approval not created"
    )


def test_validate_refuses_a_record_without_the_owner_chat_yes():
    record = plan_record()
    record["owner_confirmed_in_chat"] = False
    with pytest.raises(approve.ApprovalRefused) as exc:
        approve.validate_plan_for_approval(record)
    assert str(exc.value) == NO_CHAT_MESSAGE


def test_validate_returns_the_parsed_explanation_and_the_router_digest():
    record = plan_record()
    explanation, digest = approve.validate_plan_for_approval(record)
    assert digest == DIGEST
    assert explanation["intent"] == record["explanation"]["intent"]
    assert explanation["steps"] == record["explanation"]["steps"]
    assert explanation["expect"] == record["explanation"]["expect"]
    assert explanation["risk"] == record["explanation"]["risk"]


def test_validate_accepts_a_plan_the_router_alone_marks_for_approval():
    """Only the router demanding it is enough (the terminal path allows it)."""
    record = plan_record()
    record["requires_approval"] = False
    record["router_requires_approval"] = True
    _explanation, digest = approve.validate_plan_for_approval(record)
    assert digest == DIGEST


# ---- render_plan_text ----------------------------------------------------------


def test_render_plan_text_shows_the_facts_the_explanation_and_the_plan_hash():
    record = plan_record()
    explanation, digest = approve.validate_plan_for_approval(record)
    text = approve.render_plan_text(SID, record, explanation, digest)
    assert f"Plan: {SID}" in text
    assert "Device: quasar" in text
    assert "Diff:" in text
    assert approve.EXPLANATION_HEADING in text
    assert "Plan hash:" in text
    # the prompt is the terminal path's job, not the rendered text's
    assert "to approve:" not in text


def test_render_plan_text_is_the_same_bytes_main_prints(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """The dialog shows what the terminal shows: the same bytes, up to the
    prompt."""
    record = plan_record(staged_at=frozen_now.isoformat())
    write_plan(tmp_path, monkeypatch, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    printed = capsys.readouterr().out
    shown = printed.split("Type 'approve")[0]

    explanation, digest = approve.validate_plan_for_approval(record)
    rendered = approve.render_plan_text(SID, record, explanation, digest, now=frozen_now)
    assert rendered == shown
    assert rendered.endswith(f"Plan hash: {record['plan_hash'][:12]}\n")


def test_render_plan_text_refuses_an_expired_stage(frozen_now):
    """An expired stage is refused with the terminal path's own words."""
    record = plan_record(staged_at=(frozen_now - timedelta(hours=2)).isoformat())
    explanation, digest = approve.validate_plan_for_approval(record)
    with pytest.raises(approve.ApprovalRefused) as exc:
        approve.render_plan_text(SID, record, explanation, digest, now=frozen_now)
    expired_local = (
        frozen_now - timedelta(hours=2) + timedelta(seconds=approve.STAGE_TOTAL_BUDGET_S
                                                    - record["timeout_s"]
                                                    - approve.STAGE_OVERHEAD_S)
    ).astimezone()
    assert str(exc.value) == (
        "the staged change has expired "
        f"(expired {expired_local.strftime('%H:%M:%S')}); "
        "plan it again; approval not created"
    )


def test_render_plan_text_escapes_control_characters_in_a_diff_line(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """The rendered text is sanitised exactly like the terminal's."""
    record = plan_record(staged_at=frozen_now.isoformat())
    record["diff"] = "network.lan.proto='static\x1b[2J'\r\nnetwork.lan.ipaddr='192.0.2.1'"
    record["plan_hash"] = compute_plan_hash(record)
    write_plan(tmp_path, monkeypatch, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    printed = capsys.readouterr().out
    shown = printed.split("Type 'approve")[0]

    explanation, digest = approve.validate_plan_for_approval(record)
    rendered = approve.render_plan_text(SID, record, explanation, digest, now=frozen_now)
    assert rendered == shown
    # the escape and the carriage return are rendered as escapes, the line
    # break stays a line break
    assert r"\x1b[2J'\r" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered


def test_main_refuses_an_expired_stage_with_the_same_bytes(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """The refusal the dialog raises is the refusal the terminal prints."""
    record = plan_record(staged_at=(frozen_now - timedelta(hours=2)).isoformat())
    write_plan(tmp_path, monkeypatch, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    expired_local = (
        frozen_now
        - timedelta(hours=2)
        + timedelta(
            seconds=approve.STAGE_TOTAL_BUDGET_S
            - record["timeout_s"]
            - approve.STAGE_OVERHEAD_S
        )
    ).astimezone()
    expected = (
        "newton-approve: the staged change has expired "
        f"(expired {expired_local.strftime('%H:%M:%S')}); "
        "plan it again; approval not created\n"
    )
    assert output.err == expected
    # the stage line is still printed before the refusal
    assert "Stage expires:" in output.out


# ---- mint_approval --------------------------------------------------------------


def test_mint_approval_mints_the_token_over_the_recorded_window(tmp_path, monkeypatch):
    _, record = write_plan(tmp_path, monkeypatch)
    k_hex = "a" * 64
    approval = approve.mint_approval(SID, record, DIGEST, k_hex, "labuser", now=FROZEN)
    assert approval["token"] == approve.approval_token(
        k_hex, DIGEST, approval["not_before"], approval["not_after"]
    )
    assert approval["not_before"] == int(
        datetime.fromisoformat(approval["created_at"]).timestamp()
    )
    assert approval["not_after"] == int(
        datetime.fromisoformat(approval["expires_at"]).timestamp()
    )
    assert type(approval["not_before"]) is int
    assert type(approval["not_after"]) is int
    assert approval["plan_id"] == SID
    assert approval["plan_hash"] == record["plan_hash"]
    assert approval["device"] == record["device"]
    assert approval["base_hash"] == record["base_hash"]
    assert approval["approved_by"] == "labuser"


def test_mint_approval_uses_a_thirty_minute_window_without_a_stage(
    tmp_path, monkeypatch
):
    _, record = write_plan(tmp_path, monkeypatch)
    # a record with no usable staged_at: the stage age cannot be computed,
    # so no clamp applies and the default 30-minute window stands.
    record.pop("staged_at")
    approval = approve.mint_approval(SID, record, DIGEST, "a" * 64, "labuser", now=FROZEN)
    created = datetime.fromisoformat(approval["created_at"])
    expires = datetime.fromisoformat(approval["expires_at"])
    assert (expires - created).total_seconds() == 30 * 60


def test_mint_approval_clamps_the_window_to_the_stage_expiry(tmp_path, monkeypatch):
    """A stage that expires sooner than 30 min shortens the window."""
    _, record = write_plan(tmp_path, monkeypatch)
    # timeout_s = 600 -> the router's age limit is 2040 s = 34 min; staged
    # 5 min ago -> the stage expires 29 min from now, sooner than 30 min.
    record["timeout_s"] = 600
    record["staged_at"] = (FROZEN - timedelta(minutes=5)).isoformat()
    record["plan_hash"] = compute_plan_hash(record)
    approval = approve.mint_approval(SID, record, DIGEST, "a" * 64, "labuser", now=FROZEN)
    expires = datetime.fromisoformat(approval["expires_at"])
    stage_expiry = (FROZEN - timedelta(minutes=5)) + timedelta(seconds=2040)
    assert expires == stage_expiry
    assert (expires - FROZEN).total_seconds() == 29 * 60


def test_mint_approval_refuses_when_the_clamped_window_is_not_after_created(
    tmp_path, monkeypatch
):
    """R8 (b-1): the stage can expire while the operator is typing."""
    _, record = write_plan(tmp_path, monkeypatch)
    # timeout_s = 2340 -> the stage window is 300 s = 5 min.
    record["timeout_s"] = 2340
    record["staged_at"] = FROZEN.isoformat()
    record["plan_hash"] = compute_plan_hash(record)
    with pytest.raises(approve.ApprovalRefused) as exc:
        approve.mint_approval(
            SID, record, DIGEST, "a" * 64, "labuser", now=FROZEN + timedelta(minutes=10)
        )
    assert str(exc.value) == (
        "the staged change expired while you typed; "
        "plan it again; approval not created"
    )


def test_mint_approval_writes_nothing(tmp_path, monkeypatch):
    state, record = write_plan(tmp_path, monkeypatch)
    approve.mint_approval(SID, record, DIGEST, "a" * 64, "labuser", now=FROZEN)
    assert not (state / "approvals").exists()


def test_mint_approval_records_the_approved_by_it_is_given(tmp_path, monkeypatch):
    _, record = write_plan(tmp_path, monkeypatch)
    approval = approve.mint_approval(SID, record, DIGEST, "a" * 64, "someone-else", now=FROZEN)
    assert approval["approved_by"] == "someone-else"


# ---- write_approval --------------------------------------------------------------


def test_write_approval_round_trip_and_mode(tmp_path, monkeypatch):
    state, record = write_plan(tmp_path, monkeypatch)
    approval = approve.mint_approval(SID, record, DIGEST, "a" * 64, "labuser", now=FROZEN)
    approve.write_approval(SID, approval)
    path = state / "approvals" / f"{SID}.json"
    assert json.loads(path.read_text()) == approval
    assert (Path(path).stat().st_mode & 0o777) == 0o600
    assert (path.parent.stat().st_mode & 0o777) == 0o700
