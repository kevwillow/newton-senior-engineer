import hashlib
import hmac
import io
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from exhelp import make_explanation, record_fields

import newton_mcp.approve as approve
from newton_mcp.plan import compute_plan_hash


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


class _FrozenDatetime(datetime):
    """Freeze ``approve.datetime.now()`` to a fixed UTC instant.

    ``approve`` imports ``datetime`` as a class.  Patching
    ``approve.datetime`` to this subclass swaps the implementation that
    ``datetime.now(timezone.utc)`` resolves to inside the module without
    any change to the source.  Used by the R2 stage-expiry tests so the
    print line, the refusal, and the 30-minute clamp are deterministic
    regardless of the wall clock the runner sees.
    """

    _fixed: datetime | None = None

    @classmethod
    def now(cls, tz=None):
        if cls._fixed is None:
            return super().now(tz)
        if tz is None:
            return cls._fixed.replace(tzinfo=None)
        return cls._fixed.astimezone(tz)


class _SequenceDatetime(datetime):
    """Frozen datetime that returns successive entries from a sequence
    on each ``datetime.now()`` call.  Used by the R8 (b-1) "expired
    while you typed" test: approve.main() calls ``datetime.now()``
    twice -- once for the display line (``now``) and once for the
    approval creation (``created``) -- so a sequence of two values lets
    a test drive the gap between the two calls.
    """

    _sequence: list = []

    @classmethod
    def now(cls, tz=None):
        if not cls._sequence:
            return super().now(tz)
        value = cls._sequence.pop(0)
        if tz is None:
            return value.replace(tzinfo=None)
        return value.astimezone(tz)


@pytest.fixture
def frozen_now(monkeypatch):
    """Freeze approve.datetime.now() to 2026-10-07T12:00:00+00:00.

    Yields the frozen instant so tests can stage ``staged_at`` relative
    to it without depending on the real wall clock.
    """
    monkeypatch.setattr(approve, "datetime", _FrozenDatetime)
    instant = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
    _FrozenDatetime._fixed = instant
    yield instant
    _FrozenDatetime._fixed = None


@pytest.fixture
def frozen_now_sequence(monkeypatch):
    """Replace approve.datetime with ``_SequenceDatetime``; the test
    must set ``_SequenceDatetime._sequence`` to a list of UTC
    datetimes (one per ``datetime.now()`` call)."""
    monkeypatch.setattr(approve, "datetime", _SequenceDatetime)
    _SequenceDatetime._sequence = []
    yield _SequenceDatetime
    _SequenceDatetime._sequence = []


def plan_record(staged_at=None):
    """Build a plan record whose staged_at defaults to the current UTC
    time so the stage is fresh for tests that don't pin a frozen clock.
    Tests using ``frozen_now`` overwrite ``staged_at`` (and the hash)
    to a deterministic instant before exercising approve.py."""
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set wireless.radio0.key='never-display-this'",
        "diff": "wireless.radio0.key='never-display-this'",
        "check": "wifi status",
        "probes": [["log-has", "present", "made-up-marker"]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": DIGEST,
        **record_fields("set wireless.radio0.key='never-display-this'"),
        "router_profile": "prod",
        "router_leash": ["mgmt-if"],
        "router_sections": ["wireless.radio0"],
        "router_requires_approval": True,
        "staged_check": {"fw4": "skipped-untouched", "reason": "", "not_checked": ["firewall"]},
        "reasons": ["wireless configuration changes require approval"],
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": staged_at if staged_at is not None else datetime.now(timezone.utc).isoformat(),
    }
    record["plan_hash"] = compute_plan_hash(record)
    return record


def write_plan(tmp_path, monkeypatch):
    state = tmp_path / "state"
    plans = state / "plans"
    plans.mkdir(parents=True)
    record = plan_record()
    (plans / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setenv("SUDO_USER", "labuser")
    return state, record


def write_record(state, record):
    record["plan_hash"] = compute_plan_hash(record)
    (state / "plans" / f"{SID}.json").write_text(json.dumps(record))


def plan_record_for_apply():
    """``plan_record()`` plus probes that carry the explanation's expect
    claim as the LAST sealed probe, so ``apply`` accepts it."""
    record = plan_record()
    record["probes"] = [
        ["log-has", "present", "made-up-marker"],
        ["iface-absent", "guestx"],
    ]
    record["plan_hash"] = compute_plan_hash(record)
    return record


def refuse_getpass(prompt):
    raise AssertionError("getpass must not be called in this test")


def approval_fingerprint_hex(k_hex):
    """The fingerprint approve.py compares against: HMAC-SHA256(K bytes,
    b"newton-approval-fingerprint-v1").hexdigest()."""
    return hmac.new(
        bytes.fromhex(k_hex),
        b"newton-approval-fingerprint-v1",
        hashlib.sha256,
    ).hexdigest()


def write_fingerprint(state, device, k_hex):
    """Seed state/approval-fp/<device> with the matching fingerprint."""
    fp_dir = state / "approval-fp"
    fp_dir.mkdir(parents=True, exist_ok=True)
    (fp_dir / device).write_text("v1 %s\n" % approval_fingerprint_hex(k_hex))


def write_bad_fingerprint(state, device, hex_value="0" * 64):
    """Seed state/approval-fp/<device> with a wrong fingerprint."""
    fp_dir = state / "approval-fp"
    fp_dir.mkdir(parents=True, exist_ok=True)
    (fp_dir / device).write_text("v1 %s\n" % hex_value)


def test_approve_refuses_without_terminal(tmp_path, monkeypatch, capsys):
    write_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(approve.sys, "stdin", io.StringIO(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 1
    assert "terminal" in capsys.readouterr().err


def test_approve_refuses_bad_id(monkeypatch, capsys):
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput())
    assert approve.main(["BAD"]) == 2
    assert "32 lowercase hexadecimal" in capsys.readouterr().err


def test_approve_requires_exactly_one_argument(monkeypatch, capsys):
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput())
    assert approve.main([]) == 2
    assert "usage:" in capsys.readouterr().err


def test_approve_refuses_wrong_confirmation(tmp_path, monkeypatch, capsys):
    state, _ = write_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("approve deadbeef\n"))
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert "confirmation did not match" in output.err
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_writes_bound_atomic_mode_0600_record_with_token(
    tmp_path, monkeypatch, capsys
):
    state, record = write_plan(tmp_path, monkeypatch)
    passphrase = "made-up-e2e-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    prompts = []
    monkeypatch.setattr(approve, "_getpass", lambda prompt: prompts.append(prompt) or passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    output = capsys.readouterr()
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    assert "never-display-this" not in output.out
    assert "<redacted:" in output.out
    path = state / "approvals" / f"{SID}.json"
    saved = json.loads(path.read_text())
    # SW2 Item 2: the token is minted over the window the record carries.
    expected_token = approve.approval_token(
        k, record["router_digest"], saved["not_before"], saved["not_after"]
    )
    # the passphrase, K and the token never reach the terminal
    assert passphrase not in output.out + output.err
    assert k not in output.out + output.err
    assert expected_token not in output.out + output.err
    # the no-echo prompt names the device and stays out of stdout
    assert prompts == [f"approval passphrase for quasar: "]
    assert saved["plan_id"] == SID
    assert saved["plan_hash"] == record["plan_hash"]
    assert saved["device"] == "quasar"
    assert saved["base_hash"] == "a" * 64
    assert saved["approved_by"] == "labuser"
    assert saved["token"] == expected_token
    assert re.fullmatch(r"[0-9a-f]{64}", saved["token"])
    assert (
        datetime.fromisoformat(saved["expires_at"])
        - datetime.fromisoformat(saved["created_at"])
    ).total_seconds() == 30 * 60
    assert (Path(path).stat().st_mode & 0o777) == 0o600
    # atomic write: nothing but the final record is left behind
    assert sorted(p.name for p in (state / "approvals").iterdir()) == [
        f"{SID}.json"
    ]


def test_approve_record_carries_the_window_floors_it_minted_over(
    tmp_path, monkeypatch, frozen_now
):
    """SW2 Item 2: ``not_before``/``not_after`` are the UNIX-second floors
    of ``created_at``/``expires_at``, stored as ints next to them, and the
    token is exactly the v2 HMAC over those two numbers."""
    state, record = write_plan(tmp_path, monkeypatch)
    passphrase = "made-up-floor-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    created = datetime.fromisoformat(saved["created_at"])
    expires = datetime.fromisoformat(saved["expires_at"])
    assert type(saved["not_before"]) is int and type(saved["not_after"]) is int
    assert saved["not_before"] == int(created.timestamp())
    assert saved["not_after"] == int(expires.timestamp())
    assert saved["not_after"] > saved["not_before"]
    # a token over any other window is a different token, so the router
    # could not be talked into accepting the record after an edit
    assert saved["token"] == approve.approval_token(
        k, record["router_digest"], saved["not_before"], saved["not_after"]
    )
    assert saved["token"] != approve.approval_token(
        k, record["router_digest"], saved["not_before"], saved["not_after"] + 1
    )
    # the window the router gets is one the router's own shape allows
    assert approve.APPROVAL_WINDOW_MIN_EPOCH <= saved["not_before"]
    assert saved["not_after"] <= approve.APPROVAL_WINDOW_MAX_EPOCH
    assert saved["not_after"] - saved["not_before"] <= 3600


def test_approve_refuses_empty_passphrase(tmp_path, monkeypatch, capsys):
    state, _ = write_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "")
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 1
    assert "passphrase must not be empty" in capsys.readouterr().err
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_refuses_when_nothing_to_approve(tmp_path, monkeypatch, capsys):
    state, record = write_plan(tmp_path, monkeypatch)
    record["requires_approval"] = False
    record["router_requires_approval"] = False
    write_record(state, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 1
    assert "nothing to approve" in capsys.readouterr().err
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_requires_approval_either_way(tmp_path, monkeypatch, capsys):
    """Only the router demanding it is enough: the same passphrase path runs."""
    state, record = write_plan(tmp_path, monkeypatch)
    record["requires_approval"] = True  # host policy alone would also work
    record["router_requires_approval"] = False
    write_record(state, record)
    passphrase = "router-said-required"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    assert saved["token"] == approve.approval_token(
        approve.derive_k(passphrase.encode("utf-8"), "quasar"),
        DIGEST,
        saved["not_before"],
        saved["not_after"],
    )


def test_approve_refuses_short_router_digest(tmp_path, monkeypatch, capsys):
    state, record = write_plan(tmp_path, monkeypatch)
    record["router_digest"] = "d" * 63
    write_record(state, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 1
    assert "nothing to bind an approval token to" in capsys.readouterr().err
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_refuses_missing_router_digest(tmp_path, monkeypatch, capsys):
    state, record = write_plan(tmp_path, monkeypatch)
    record.pop("router_digest")
    (state / "plans" / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 1
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_shows_router_facts_and_no_check_line(tmp_path, monkeypatch, capsys):
    state, _ = write_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert "Profile: prod" in lines
    assert "  - mgmt-if" in lines
    assert "  - wireless.radio0" in lines
    assert "  - log-has present made-up-marker" in lines
    assert "Timeout: 120s" in lines
    assert f"Digest: {DIGEST[:12]}" in lines
    assert "Check:" not in out
    # display order: profile, leash, sections before the risk reasons
    assert (
        lines.index("Profile: prod")
        < lines.index("  - mgmt-if")
        < lines.index("  - wireless.radio0")
        < lines.index("Risk reasons:")
        < lines.index("  - log-has present made-up-marker")
        < lines.index("Timeout: 120s")
        < lines.index(f"Digest: {DIGEST[:12]}")
    )
    assert re.search(r"Plan hash: [0-9a-f]{12}$", out, re.MULTILINE)


def test_approve_refuses_a_record_missing_one_hash_bound_router_field(
    tmp_path, monkeypatch, capsys
):
    """``router_profile``/``router_leash``/``router_sections`` are part of
    the canonical identity now.  A stored record that lacks one of them is
    refused by ``_load_plan`` (the same value that powers the "plan record
    was modified or is invalid" message), so the "Profile: unknown" /
    "Leash codes: unknown" / "Sections: unknown" display path no longer
    applies.  The refused branch is tested one field at a time so a future
    regression that drops only one of these still fails."""
    state, record = write_plan(tmp_path, monkeypatch)
    for field in ("router_profile", "router_leash", "router_sections"):
        # Drop the field by reading the record back and rewriting it.  We
        # cannot go through the plan_record/write_record helpers (which
        # call compute_plan_hash on the full record -- they would raise
        # ValueError the moment the field is gone), so we use plain JSON.
        on_disk = json.loads((state / "plans" / f"{SID}.json").read_text())
        del on_disk[field]
        (state / "plans" / f"{SID}.json").write_text(json.dumps(on_disk))
        monkeypatch.setattr(approve, "_getpass", refuse_getpass)
        monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
        assert approve.main([SID]) == 1
        err = capsys.readouterr().err
        assert "plan record was modified or is invalid" in err, (field, err)
        # nothing reached the display; the loader refused before printing.
        assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_escapes_terminal_controls_without_changing_output_shape(
    tmp_path, monkeypatch, capsys
):
    state, record = write_plan(tmp_path, monkeypatch)
    harmless = record.copy()
    harmless.update(
        device="quasar router",
        host="192.0.2.1 host",
        reasons=["first reason", "second reason"],
        diff="network.lan.proto='static'\nnetwork.lan.ipaddr='192.0.2.1'",
        router_sections=["wireless.radio0", "firewall.@zone[0]"],
        router_leash=["mgmt-if", "prod-profile"],
        probes=[["log-has", "present", "marker one"], ["uci-unset", "wireless.default_radio0"]],
    )
    write_record(state, harmless)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    harmless_output = capsys.readouterr()

    hostile = record.copy()
    hostile.update(
        device="quasar\x1b[2J\r\nrouter",
        host="192.0.2.1\u202e\nfake",
        reasons=[
            "first\x1b[H reason\r\nforged",
            "second\x7f\x85\u2066\u200b\ufeff reason",
        ],
        diff=(
            "network.lan.proto='static\x1b[2J'\r\n"
            "network.lan.ipaddr='192.0.2.1\u2029'"
        ),
        router_sections=[
            "wireless.radio0\x1b[2J\r\nforged",
            "firewall.@zone[0]\u202e\nfake",
        ],
        probes=[
            ["log-has", "present\x1b[2J", "marker\r\nforged"],
            ["uci-unset", "wireless.default_radio0\u2028"],
        ],
        router_leash=["mgmt-if\x1b[2J", "prod-profile\r"],
    )
    write_record(state, hostile)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    hostile_output = capsys.readouterr()

    # Newton's own facts keep their shape.  The agent block below them is excluded:
    # its mechanical check now reports control-split diff lines as "could not check"
    #, which is correct and depends on the diff content.
    def facts(text):
        return text.split(approve.EXPLANATION_HEADING)[0].splitlines()

    assert len(facts(hostile_output.out)) == len(facts(harmless_output.out))
    assert len(hostile_output.err.splitlines()) == len(harmless_output.err.splitlines())
    assert all(
        character == "\n" or character == " " or character.isprintable()
        for character in hostile_output.out + hostile_output.err
    )
    assert r"\x1b[2J\r\nforged" in hostile_output.out
    assert r"\u202e\nfake" in hostile_output.out
    assert r"  - wireless.radio0\x1b[2J\r\nforged" in hostile_output.out
    assert r"  - log-has present\x1b[2J marker\r\nforged" in hostile_output.out
    assert r"  - mgmt-if\x1b[2J" in hostile_output.out


def test_approve_refuses_edited_plan_record(tmp_path, monkeypatch, capsys):
    state, record = write_plan(tmp_path, monkeypatch)
    record["probes"] = [["fail"]]
    (state / "plans" / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 1
    assert "plan record was modified" in capsys.readouterr().err


def test_approve_distinguishes_a_typed_backslash_from_a_real_newline(
    tmp_path, monkeypatch, capsys
):
    """F1: a backslash renders as two, so `u\\ci`+newline and `u\\ci\\n` differ."""
    state, record = write_plan(tmp_path, monkeypatch)

    with_real_newline = record.copy()
    with_real_newline["router_sections"] = ["u\\ci\ntrue"]
    write_record(state, with_real_newline)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    first = capsys.readouterr().out

    with_typed_backslash_n = record.copy()
    with_typed_backslash_n["router_sections"] = ["u\\ci\\ntrue"]
    write_record(state, with_typed_backslash_n)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    second = capsys.readouterr().out

    assert "  - u\\\\ci\\ntrue" in first
    assert "  - u\\\\ci\\\\ntrue" in second
    assert first != second
    for output in (first, second):
        assert all(
            character == "\n" or character == " " or character.isprintable()
            for character in output
        )


def test_consume_approval_accepts_the_record_main_wrote(tmp_path, monkeypatch, capsys):
    """Round trip: plan -> newton-approve -> consume_approval returns the token."""
    state, record = write_plan(tmp_path, monkeypatch)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    from newton_mcp import server

    passphrase = "made-up-roundtrip-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    expected_token = approve.approval_token(
        approve.derive_k(passphrase.encode("utf-8"), "quasar"),
        DIGEST,
        saved["not_before"],
        saved["not_after"],
    )
    service = server.NewtonService()
    grant = service.consume_approval("quasar", SID, record)
    assert grant.token == expected_token
    assert grant.not_before == saved["not_before"]
    assert grant.not_after == saved["not_after"]
    # APR-05: consume_approval now CLAIMS the record by
    # renaming it to .claimed; settle_approval() is what turns the
    # claim into .used after the script reaches the router.
    assert not (state / "approvals" / f"{SID}.json").exists()
    assert (state / "approvals" / f"{SID}.claimed").exists()
    assert not (state / "approvals" / f"{SID}.used").exists()


# ---- SW2 Item 2: the approval window is bound into the token ---------------


OLD_APPROVE_MSG = "approval was made by an older newton-approve or edited; approve the plan again"


def _approve_plan(tmp_path, monkeypatch, passphrase="made-up-binding-pass"):
    """Run the real newton-approve over the fixture plan and return
    (state, plan record, saved approval record, K)."""
    state, _ = write_plan(tmp_path, monkeypatch)
    record = plan_record_for_apply()
    write_record(state, record)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    return state, record, saved, k


def _rewrite_approval(state, saved, **updates):
    saved = dict(saved)
    saved.update(updates)
    (state / "approvals" / f"{SID}.json").write_text(json.dumps(saved))
    return saved


def test_consume_approval_refuses_an_edited_expires_at(tmp_path, monkeypatch):
    """Repro, host half: only ``expires_at`` is moved later and the
    stored ``not_after`` stays, so the record no longer agrees with
    itself.  Refused BEFORE anything reaches the router, and the approval
    is left on disk for the user to inspect."""
    from newton_mcp import server

    state, record, saved, _k = _approve_plan(tmp_path, monkeypatch)
    later = datetime.fromisoformat(saved["expires_at"]) + timedelta(hours=6)
    _rewrite_approval(state, saved, expires_at=later.isoformat())
    service = server.NewtonService()
    with pytest.raises(server.NewtonError) as exc:
        service.consume_approval("quasar", SID, record)
    assert str(exc.value) == OLD_APPROVE_MSG
    assert (state / "approvals" / f"{SID}.json").exists()
    assert not (state / "approvals" / f"{SID}.claimed").exists()


def test_consume_approval_refuses_a_moved_created_at(tmp_path, monkeypatch):
    """The other half of the equality: ``created_at`` cannot be moved
    without moving ``not_before`` with it."""
    from newton_mcp import server

    state, record, saved, _k = _approve_plan(tmp_path, monkeypatch)
    earlier = datetime.fromisoformat(saved["created_at"]) - timedelta(days=1)
    _rewrite_approval(state, saved, created_at=earlier.isoformat())
    service = server.NewtonService()
    with pytest.raises(server.NewtonError) as exc:
        service.consume_approval("quasar", SID, record)
    assert str(exc.value) == OLD_APPROVE_MSG


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param({"not_before": None}, id="null-not-before"),
        pytest.param({"not_after": None}, id="null-not-after"),
        pytest.param({"not_before": "1790000000"}, id="string-not-before"),
        pytest.param({"not_after": "1790001800"}, id="string-not-after"),
        pytest.param({"not_before": 1790000000.0}, id="float-not-before"),
        pytest.param({"not_before": True, "not_after": True}, id="bool-window"),
        pytest.param({"not_after": 1000000000}, id="not-after-below-floor"),
    ],
)
def test_consume_approval_refuses_a_record_without_an_integer_window(
    tmp_path, monkeypatch, bad
):
    """A record whose window is missing, non-int or out of range is an
    old-format record (fail closed), refused with the old-approve message."""
    from newton_mcp import server

    state, record, saved, _k = _approve_plan(tmp_path, monkeypatch)
    _rewrite_approval(state, saved, **bad)
    service = server.NewtonService()
    with pytest.raises(server.NewtonError) as exc:
        service.consume_approval("quasar", SID, record)
    assert str(exc.value) == OLD_APPROVE_MSG
    assert (state / "approvals" / f"{SID}.json").exists()


def test_consume_approval_refuses_an_old_format_record_before_the_expiry_message(
    tmp_path, monkeypatch
):
    """A record with no ``not_before``/``not_after`` at all (what an old
    newton-approve wrote) is refused with the old-approve message even
    when it is ALSO expired: the old-format refusal runs first, so the
    operator is told to re-approve rather than that it expired."""
    from newton_mcp import server

    state, record, saved, _k = _approve_plan(tmp_path, monkeypatch)
    _rewrite_approval(
        state,
        saved,
        expires_at="2000-01-01T00:00:00+00:00",
        not_before=None,
        not_after=None,
    )
    service = server.NewtonService()
    with pytest.raises(server.NewtonError) as exc:
        service.consume_approval("quasar", SID, record)
    assert str(exc.value) == OLD_APPROVE_MSG
    assert "expired" not in str(exc.value)


def test_consume_approval_refuses_an_expired_record_whose_window_agrees(
    tmp_path, monkeypatch
):
    """The expiry refusal still stands when the window fields agree with
    ``created_at``/``expires_at``: the new check does not weaken it."""
    from newton_mcp import server

    state, record, saved, _k = _approve_plan(tmp_path, monkeypatch)
    created = datetime(2000, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    past = created + timedelta(minutes=30)
    _rewrite_approval(
        state,
        saved,
        created_at=created.isoformat(),
        expires_at=past.isoformat(),
        not_before=int(created.timestamp()),
        not_after=int(past.timestamp()),
    )
    service = server.NewtonService()
    with pytest.raises(server.NewtonError) as exc:
        service.consume_approval("quasar", SID, record)
    assert "approval expired" in str(exc.value)


def test_apply_sends_a_consistently_moved_window_and_the_router_still_refuses(
    tmp_path, monkeypatch
):
    """Both fields edited together: the host cannot tell, so it accepts
    and passes the EDITED window to the wrapper.  The token was minted
    over the original window, so the router recomputes a different HMAC
    and refuses with bad-approval -- the host stops trusting the file's
    expiry and the device stops trusting the file's token."""
    import subprocess as _sp

    from newton_mcp import server

    state, record, saved, k = _approve_plan(tmp_path, monkeypatch)
    moved_exp = int(datetime.fromisoformat(saved["expires_at"]).timestamp()) + 6 * 3600
    edited = _rewrite_approval(
        state,
        saved,
        not_after=moved_exp,
        expires_at=datetime.fromtimestamp(moved_exp, tz=timezone.utc).isoformat(),
    )
    assert edited["not_after"] == int(
        datetime.fromisoformat(edited["expires_at"]).timestamp()
    )
    calls = []

    def fake_run_script(self, device, script, *args, **kwargs):
        calls.append(kwargs.get("extra_env"))
        return _sp.CompletedProcess(args, 0, f"CONFIRMED session={SID}", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run_script)
    result = server.newton_apply_change("quasar", SID)
    assert result["result"] == "confirmed", result
    assert calls, "apply must reach the wrapper"
    env = calls[0]
    assert env["OWRT_APPROVAL_TOKEN"] == saved["token"]
    assert env["OWRT_APPROVAL_NBF"] == str(saved["not_before"])
    assert env["OWRT_APPROVAL_EXP"] == str(moved_exp)
    # the token the router will recompute over this window is NOT the one
    # in the file: the router answers bad-approval
    assert saved["token"] != approve.approval_token(
        k, record["router_digest"], saved["not_before"], moved_exp
    )


def test_apply_without_a_required_approval_passes_no_window(tmp_path, monkeypatch):
    """The lab carve-out path (no approval required) passes the token
    ``none`` and nothing else: the wrapper defaults NBF/EXP to 0 0."""
    import subprocess as _sp

    from newton_mcp import server

    record = plan_record_for_apply()
    record["requires_approval"] = False
    record["router_requires_approval"] = False
    record["device"] = "lab-r1"
    record["plan_hash"] = compute_plan_hash(record)
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True)
    (state / "plans" / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setenv(
        "NEWTON_INVENTORY",
        str(
            _lab_inventory(tmp_path)
        ),
    )
    calls = []

    def fake_run_script(self, device, script, *args, **kwargs):
        calls.append(kwargs.get("extra_env"))
        return _sp.CompletedProcess(args, 0, f"CONFIRMED session={SID}", "")

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run_script)
    result = server.newton_apply_change("lab-r1", SID)
    assert result["result"] == "confirmed", result
    env = calls[0]
    assert env["OWRT_APPROVAL_TOKEN"] == "none"
    assert "OWRT_APPROVAL_NBF" not in env
    assert "OWRT_APPROVAL_EXP" not in env


def _lab_inventory(tmp_path):
    inventory = tmp_path / "lab-devices.toml"
    inventory.write_text(
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\n'
        'user = "root"\nprofile = "lab"\nlab = true\n'
    )
    inventory.chmod(0o644)
    return inventory


# a wrong approval passphrase must be caught at approve time.
# tests/protocol/test_router_setup_approval.py is the protocol twin for
# the writing side (setup records the fingerprint on the host).


def test_approve_refuses_when_fingerprint_mismatches(
    tmp_path, monkeypatch, capsys
):
    """approval-fp/<device> holds a different fingerprint: refuse,
    print the wrong-passphrase line, do NOT write an approval file."""
    state, _ = write_plan(tmp_path, monkeypatch)
    write_bad_fingerprint(state, "quasar")
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "any-typed-pass")
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n")
    )
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert "wrong approval passphrase for quasar" in output.err
    assert "approval not created" in output.err
    assert not (state / "approvals" / f"{SID}.json").exists()
    # never prints the typed passphrase, the derived K, or the HMAC token
    assert "any-typed-pass" not in output.out + output.err


def test_approve_accepts_when_fingerprint_matches(
    tmp_path, monkeypatch, capsys
):
    """approval-fp/<device> holds the right fingerprint: the approval
    is recorded exactly as before, no mismatch and no notice."""
    state, record = write_plan(tmp_path, monkeypatch)
    passphrase = "made-up-match-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n")
    )
    assert approve.main([SID]) == 0
    output = capsys.readouterr()
    assert "wrong approval passphrase" not in output.err
    assert "could not check" not in output.err
    assert (state / "approvals" / f"{SID}.json").exists()
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    expected_token = approve.approval_token(
        k, record["router_digest"], saved["not_before"], saved["not_after"]
    )
    assert saved["token"] == expected_token


def test_approve_missing_fingerprint_refuses_with_setup_remediation(
    tmp_path, monkeypatch, capsys
):
    """APR-05: a missing approval fingerprint is a refusal,
    not a NOTICE.  The previous behaviour wrote an approval whose
    token the device then refused (bad-approval) and the human
    approval was burned; refuse here too, with a clear message that
    names the setup action the operator has to run to fix it."""
    state, _ = write_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "made-up-no-fp")
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n")
    )
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert (
        "newton-approve: no approval fingerprint on record for quasar; "
        "run newton-router-setup quasar approval-key first; approval not created"
    ) in output.err
    # No approval file is written when the fingerprint check cannot run.
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_treats_malformed_fingerprint_as_mismatch(
    tmp_path, monkeypatch, capsys
):
    """A truncated or non-v1 fingerprint file is treated like a
    mismatch (the right way to keep a broken file from disabling the
    new check): refuse without writing an approval."""
    state, _ = write_plan(tmp_path, monkeypatch)
    fp_dir = state / "approval-fp"
    fp_dir.mkdir(parents=True, exist_ok=True)
    (fp_dir / "quasar").write_text("not-a-fingerprint\n")
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "made-up-badfp")
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n")
    )
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert "wrong approval passphrase for quasar" in output.err
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_treats_non_ascii_fingerprint_as_mismatch(
    tmp_path, monkeypatch
):
    """R8 (a-1): a fingerprint file holding a non-ASCII byte does NOT
    crash with UnicodeDecodeError (a ValueError, not an OSError); it
    is treated as a mismatch, exactly like a truncated or non-v1 file.
    read_text(encoding='ascii') raises UnicodeDecodeError when the file
    holds a byte > 0x7F, so the OLD ``except OSError`` arm did not
    catch it and the operator saw a traceback AFTER the passphrase
    prompt."""
    state, _ = write_plan(tmp_path, monkeypatch)
    fp_dir = state / "approval-fp"
    fp_dir.mkdir(parents=True, exist_ok=True)
    (fp_dir / "quasar").write_bytes(b"v1 \xff\xfe\xfd some bytes\n")
    assert approve.check_approval_fingerprint(
        fp_dir / "quasar", "f" * 64
    ) == approve.APPROVAL_FP_MISMATCH


def test_approve_refuses_with_wrong_passphrase_message_when_fingerprint_is_non_ascii(
    tmp_path, monkeypatch, capsys
):
    """R8 (a-1) end-to-end: the full main path catches the non-ASCII
    fingerprint as a mismatch and prints the existing 'wrong approval
    passphrase' message; no traceback, no approval file."""
    state, _ = write_plan(tmp_path, monkeypatch)
    fp_dir = state / "approval-fp"
    fp_dir.mkdir(parents=True, exist_ok=True)
    (fp_dir / "quasar").write_bytes(b"v1 \xff\xfe\xfd some bytes\n")
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "any-typed-pass")
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n")
    )
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert "wrong approval passphrase for quasar" in output.err
    assert "approval not created" in output.err
    assert not (state / "approvals" / f"{SID}.json").exists()
    assert "Traceback" not in output.err


# the router refuses a stage older than ``2700 - t - 60`` seconds
# after staging (``device/openwrt/newton-router/newton-router`` near
# line :2477).  The host shows and enforces the same window at approve
# time so the operator does not type a passphrase for a plan the
# device will already reject.


def _stage_line(out: str) -> str | None:
    for line in out.splitlines():
        if line.startswith("Stage expires:"):
            return line
    return None


def test_approve_shows_stage_expires_when_staged_at_is_present(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """A fresh stage with timeout_s=120 shows an expiry ~42 min from now.

    The expected minutes come from ``2700 - 120 - 60 = 2520`` seconds,
    which is 42 minutes; ``(2700 - timeout_s - 60) / 60`` rounded down.
    """
    state, record = write_plan(tmp_path, monkeypatch)
    record["staged_at"] = frozen_now.isoformat()
    write_record(state, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    out = capsys.readouterr().out
    line = _stage_line(out)
    assert line is not None
    # HH:MM:SS in the operator's local timezone followed by a "(about N min from now)"
    match = re.fullmatch(
        r"Stage expires: (\d\d):(\d\d):(\d\d) \(about (\d+) min from now\)",
        line,
    )
    assert match, line
    remaining = int(match.group(4))
    assert remaining == 42
    # the printed local HH:MM:SS matches the UTC instant converted to local
    expected_expiry_utc = frozen_now + timedelta(seconds=2520)
    expected_local = expected_expiry_utc.astimezone()
    assert (int(match.group(1)), int(match.group(2)), int(match.group(3))) == (
        expected_local.hour,
        expected_local.minute,
        expected_local.second,
    )
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_refuses_when_stage_has_expired(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """A stage older than ``2700 - timeout_s - 60`` seconds is refused
    with a clear stderr line and a non-zero exit; nothing is written."""
    state, record = write_plan(tmp_path, monkeypatch)
    # timeout_s=60 -> age_limit = 2580s = 43 min.  staged_at two hours
    # before the frozen now is well past expiry.
    record["timeout_s"] = 60
    record["staged_at"] = (frozen_now - timedelta(hours=2)).isoformat()
    write_record(state, record)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    err = output.err
    assert "newton-approve: the staged change has expired" in err
    assert "expired" in err and "plan it again" in err and "approval not created" in err
    # local HH:MM:SS for the expired instant is included
    expired_local = (frozen_now - timedelta(hours=2) + timedelta(seconds=2580)).astimezone()
    expected_local = f"{expired_local.hour:02d}:{expired_local.minute:02d}:{expired_local.second:02d}"
    assert expected_local in err
    # the print line is still emitted BEFORE the refusal, so an
    # operator who aborts can still see what the device sees.
    line = _stage_line(output.out)
    assert line is not None
    assert "(about 0 min from now)" in line
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_clamps_expires_at_when_stage_expiry_is_sooner_than_thirty_minutes(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """If the stage expires sooner than 30 min from creation, the
    approval's expires_at is clamped to the stage expiry (the device
    will reject the apply first; the host mirrors that)."""
    state, record = write_plan(tmp_path, monkeypatch)
    # timeout_s=600 -> age_limit = 2040s = 34 min.  staged_at 5 min ago
    # -> expiry 29 min from now, sooner than the 30-min default.
    record["timeout_s"] = 600
    record["staged_at"] = (frozen_now - timedelta(minutes=5)).isoformat()
    write_record(state, record)
    passphrase = "made-up-clamp-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    created_at = datetime.fromisoformat(saved["created_at"])
    expires_at = datetime.fromisoformat(saved["expires_at"])
    thirty_min = created_at + timedelta(minutes=30)
    # the actual stage expiry is staged_at + (2700 - 600 - 60) = -5 min + 34 min = 29 min
    stage_expiry = (frozen_now - timedelta(minutes=5)) + timedelta(seconds=2040)
    # clamped to the sooner of the two
    assert expires_at == stage_expiry
    assert expires_at < thirty_min
    delta = (expires_at - created_at).total_seconds()
    # exactly 29 minutes, never the 30-minute default
    assert delta == 29 * 60


def test_approve_does_not_clamp_expires_at_when_stage_expiry_is_after_thirty_minutes(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """A fresh stage whose expiry is later than 30 min keeps the
    default 30-minute approval window (the device still has time)."""
    state, record = write_plan(tmp_path, monkeypatch)
    # timeout_s=60 -> age_limit = 2580s = 43 min; staged_at = now, so
    # expiry sits 43 min from now -- well past the 30-min default.
    record["timeout_s"] = 60
    record["staged_at"] = frozen_now.isoformat()
    write_record(state, record)
    passphrase = "made-up-noclamp-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    created_at = datetime.fromisoformat(saved["created_at"])
    expires_at = datetime.fromisoformat(saved["expires_at"])
    # unchanged 30 min from creation
    assert (expires_at - created_at).total_seconds() == 30 * 60


def test_approve_does_not_clamp_when_stage_expiry_is_well_after_thirty_minutes(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """A plan whose stage window is well beyond 30 min keeps the 30-min
    default (the clamp only shortens the host-side window when the
    router would otherwise reject the stage first)."""
    state, _ = write_plan(tmp_path, monkeypatch)
    passphrase = "made-up-unknown-stage-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    created_at = datetime.fromisoformat(saved["created_at"])
    expires_at = datetime.fromisoformat(saved["expires_at"])
    assert (expires_at - created_at).total_seconds() == 30 * 60


def test_stage_expiry_helper_computes_router_window():
    """The 2700/60 arithmetic lives in one place; if the router's
    ``age_limit=$(( 2700 - t - 60 ))`` changes, this is the one test
    that flags the drift."""
    plan = {
        "staged_at": "2026-10-07T12:00:00+00:00",
        "timeout_s": 120,
    }
    expiry = approve.stage_expiry(plan, now=datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc))
    assert expiry == datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=2520)
    # timeout_s=600 -> 2040s = 34 min
    plan["timeout_s"] = 600
    assert approve.stage_expiry(plan, now=datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)) == (
        datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=2040)
    )
    # missing or malformed staged_at -> None (caller prints 'unknown')
    assert approve.stage_expiry({"timeout_s": 120}, now=datetime.now(timezone.utc)) is None
    assert approve.stage_expiry(
        {"staged_at": "not-a-date", "timeout_s": 120}, now=datetime.now(timezone.utc)
    ) is None


# R8 (b-1): the stage can expire while the operator is typing the
# passphrase.  expires_at is clamped to stage_expiry; if that clamp
# leaves expires_at <= created (the time we wrote the approval), the
# approval would already be stale the moment it lands -- refuse instead
# of writing a doomed record.  The final "Approved plan ... for N
# minutes" line is truthful: it uses the real window (rounded down,
# at least 1) when the clamp shortened it, and keeps the exact old
# "for 30 minutes" text when the default 30-minute window applied.


def test_approve_refuses_when_clamped_expires_at_is_not_after_created(
    tmp_path, monkeypatch, capsys, frozen_now, frozen_now_sequence
):
    """R8 (b-1): the staged change expired while the operator typed
    the passphrase.  expires_at (= stage_expiry, computed from
    staged_at + 2700 - timeout_s - 60) falls between the display time
    (first datetime.now()) and the creation time (second
    datetime.now()), so the earlier ``expiry <= now`` check does NOT
    fire but the clamped expires_at is NOT strictly after created.
    Refuse with a clear stderr message, rc 1, no approval file."""
    state, record = write_plan(tmp_path, monkeypatch)
    # Stage window = 5 min: timeout_s = 2700 - 60 - 300 = 2340.
    # staged_at = frozen_now -> stage_expiry = frozen_now + 5 min.
    # Display-time now == frozen_now (5 min after now -> earlier
    # ``expiry <= now`` check does NOT fire).  Creation-time now ==
    # frozen_now + 10 min (typed for 10 min -> stage_expiry <= created).
    record["timeout_s"] = 2340
    record["staged_at"] = frozen_now.isoformat()
    write_record(state, record)
    # APR-05: approve now refuses when the fingerprint is
    # missing, so the test has to seed one to reach the clamped-expiry
    # branch it is actually exercising.
    passphrase = "any-typed-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    frozen_now_sequence._sequence = [
        frozen_now,
        frozen_now + timedelta(minutes=10),
    ]
    monkeypatch.setattr(approve, "_getpass", lambda prompt: "any-typed-pass")
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n")
    )
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert "newton-approve: the staged change expired while you typed" in output.err
    assert "plan it again" in output.err
    assert "approval not created" in output.err
    # match the style of the earlier expired-stage message
    assert "newton-approve:" in output.err
    assert not (state / "approvals" / f"{SID}.json").exists()


def test_approve_prints_real_minutes_when_window_is_shorter_than_thirty(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """R8 (b-1): the final 'Approved plan ... for N minutes' line is
    truthful.  When the clamp yields a window shorter than 30 minutes
    (here exactly 10 minutes), the printed minutes equal the real
    window minutes, not the default 30."""
    state, record = write_plan(tmp_path, monkeypatch)
    # Stage window = 10 min: timeout_s = 2700 - 60 - 600 = 2040.
    # staged_at = frozen_now -> stage_expiry = frozen_now + 10 min.
    # thirty_min = frozen_now + 30 min -> clamp to stage_expiry.
    record["timeout_s"] = 2040
    record["staged_at"] = frozen_now.isoformat()
    write_record(state, record)
    passphrase = "made-up-ten-min-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    output = capsys.readouterr()
    # the truthful minute count
    assert f"Approved plan {SID} for 10 minutes." in output.out
    # NOT the default 30-minute text in this shorter-window case
    assert "for 30 minutes." not in output.out
    # the saved record still carries the clamped window (10 min)
    saved = json.loads((state / "approvals" / f"{SID}.json").read_text())
    created_at = datetime.fromisoformat(saved["created_at"])
    expires_at = datetime.fromisoformat(saved["expires_at"])
    assert (expires_at - created_at).total_seconds() == 10 * 60


def test_approve_keeps_thirty_minute_text_when_window_is_thirty(
    tmp_path, monkeypatch, capsys, frozen_now
):
    """R8 (b-1): the exact old 'for 30 minutes' text is preserved on
    the default-window path (no staged_at -> no clamp -> 30 min)."""
    state, _ = write_plan(tmp_path, monkeypatch)
    passphrase = "made-up-default-pass"
    k = approve.derive_k(passphrase.encode("utf-8"), "quasar")
    write_fingerprint(state, "quasar", k)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput(f"approve {SID[:8]}\n"))
    assert approve.main([SID]) == 0
    output = capsys.readouterr()
    assert f"Approved plan {SID} for 30 minutes." in output.out


# ---- the note belongs to the platforms that can write ----------------
#
# The note says that the approval is checked by the host only.  That is
# true of the vendor write path (the device does not re-check the
# approval there), and it is not true of OpenWrt, whose device-side
# guard re-checks it.  A platform that cannot write at all never gets
# the note.


def _vendor_record(state: Path, record: dict, platform: str) -> None:
    """A plan record of a vendor platform, with a claim the platform has."""
    record["platform"] = platform
    record["explanation"] = make_explanation(
        record["uci_batch"], expect=[{"kind": "ping", "host": "192.0.2.1"}]
    )
    write_record(state, record)


def test_approve_shows_the_host_only_note_for_a_platform_that_writes(
    tmp_path, monkeypatch, capsys
):
    """The owner of a vendor change is told who checks it."""
    state, record = write_plan(tmp_path, monkeypatch)
    _vendor_record(state, record, "vyos")
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    out = capsys.readouterr().out
    assert "approval is checked by the Newton host only" in out
    assert "the device does not re-check it" in out


def test_approve_does_not_show_the_host_only_note_for_a_read_only_platform(
    tmp_path, monkeypatch, capsys
):
    """A platform that cannot write never gets the note.

    The Junos writes, so the read-only platform of this case
    is one of the vendors that has no write path yet.
    """
    state, record = write_plan(tmp_path, monkeypatch)
    _vendor_record(state, record, "eos")
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    output = capsys.readouterr()
    assert "the device does not re-check it" not in output.out
    assert "the device does not re-check it" not in output.err


def test_approve_does_not_show_the_host_only_note_for_openwrt(
    tmp_path, monkeypatch, capsys
):
    """The OpenWrt guard re-checks the approval on the device."""
    write_plan(tmp_path, monkeypatch)
    monkeypatch.setattr(approve, "_getpass", refuse_getpass)
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    assert approve.main([SID]) == 1
    out = capsys.readouterr().out
    assert "the device does not re-check it" not in out


def test_approve_the_host_only_note_belongs_to_the_platforms_that_write():
    """The note follows the platforms that may write.

    The Junos writes, so it gets the note like the other two
    vendor platforms.
    """
    assert approve.platform_can_write("vyos") is True
    assert approve.platform_can_write("routeros") is True
    assert approve.platform_can_write("junos") is True
    for read_only in ("openwrt", "eos", "iosxe", "fortios"):
        assert approve.platform_can_write(read_only) is False
