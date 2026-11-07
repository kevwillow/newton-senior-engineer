"""``staged_at`` must be part of the canonical plan identity.

Editing ``staged_at`` on a stored plan record (without touching any
other field) must change the plan hash, so approve and apply both
refuse the record with the existing "plan record was modified or is
invalid" message.  An old record that predates the field (no
``staged_at`` at all) is refused the same way -- ``canonical_plan_json``
raises ``ValueError`` on a missing hash field, and both callers turn
that into the standard message; no compatibility path is added.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exhelp import record_fields, record_fields_display

import newton_mcp.server as server
from newton_mcp import plan


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
BASE_HASH = "b" * 64
STAGED_AT = "2026-10-07T12:00:00+00:00"


def _record(*, staged_at=STAGED_AT, approval=False, **overrides):
    """Build a plan record carrying every hash field, including staged_at."""
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.skilltest=host",
        "diff": "dhcp.skilltest='host'",
        "probes": [["fail"]],
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": approval,
        "router_digest": DIGEST,
        **record_fields("set dhcp.skilltest=host"),
        **record_fields_display(),
        "staged_at": staged_at,
    }
    record.update(overrides)
    record["plan_hash"] = plan.compute_plan_hash(record)
    return record


def _write_plan(root, record):
    plans = root / "state" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    (plans / f"{SID}.json").write_text(json.dumps(record))


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


# ---- staged_at is part of the canonical identity --------------------------


def test_staged_at_is_in_plan_hash_fields():
    """PLAN_HASH_FIELDS must list ``staged_at`` so editing it invalidates the
    hash (and so the host-side stage-expiry check in approve.py cannot be
    bypassed by simply rewriting the timestamp on disk)."""
    assert "staged_at" in plan.PLAN_HASH_FIELDS


def test_editing_staged_at_changes_the_hash():
    """Two records identical except for ``staged_at`` produce different
    hashes -- the timestamp is now part of the canonical identity."""
    base = _record()
    edited = _record(staged_at="2099-01-01T00:00:00+00:00")
    assert base["plan_hash"] != edited["plan_hash"]


def test_canonical_plan_json_requires_staged_at():
    """canonical_plan_json refuses records that lack ``staged_at`` (the
    existing missing-field ValueError that every caller already handles).
    A record missing ``staged_at`` cannot produce a hash and must be
    refused by both approve and apply -- there is no compatibility path."""
    record = _record()
    del record["staged_at"]
    with pytest.raises(ValueError):
        plan.canonical_plan_json(record)


# ---- apply refuses a record whose staged_at was edited ---------------------


def test_apply_refuses_record_with_edited_staged_at(configured, monkeypatch):
    """The recorded plan_hash was computed with the ORIGINAL staged_at;
    replacing staged_at with a future timestamp leaves the stored hash
    unchanged, so apply's hash compare fails and the standard
    "plan record was modified or is invalid" refusal is returned.  The
    stage_expiry check inside approve would have accepted the new
    timestamp, which is the bug the field closes."""
    record = _record()
    original_hash = record["plan_hash"]
    # rewrite only the timestamp; keep plan_hash stale
    record["staged_at"] = "2099-01-01T00:00:00+00:00"
    assert record["plan_hash"] == original_hash  # the stored hash did not move
    _write_plan(configured, record)

    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("apply must not run on a tampered record"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert "plan record was modified or is invalid" in result["error"]


# ---- apply refuses a record that predates the field -----------------------


def test_apply_refuses_old_record_missing_staged_at(configured, monkeypatch):
    """A record from before the field was written without ``staged_at``.  canonical_plan_json
    raises ValueError (a missing hash field); apply turns that into the
    standard refusal.  No compatibility path is added."""
    record = _record()
    del record["staged_at"]
    record["plan_hash"] = plan.compute_plan_hash(
        {**record, "staged_at": STAGED_AT}
    )
    _write_plan(configured, record)

    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("apply must not run on an old record"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert "plan record was modified or is invalid" in result["error"]


# ---- approve refuses a record whose staged_at was edited ------------------


def test_approve_refuses_record_with_edited_staged_at(
    configured, monkeypatch, capsys
):
    """newton-approve: ``_load_plan`` recomputes the hash with the NEW
    PLAN_HASH_FIELDS and sees the stored plan_hash does not match; it
    raises ValueError, the CLI prints "plan record was modified or is
    invalid", and the approval file is NOT created."""
    import io
    import newton_mcp.approve as approve

    record = _record(staged_at="2026-10-07T12:00:00+00:00", approval=True)
    _write_plan(configured, record)
    # rewrite only staged_at on disk; the stored plan_hash does not move
    on_disk = json.loads((configured / "state" / "plans" / f"{SID}.json").read_text())
    on_disk["staged_at"] = "2099-01-01T00:00:00+00:00"
    (configured / "state" / "plans" / f"{SID}.json").write_text(json.dumps(on_disk))

    class TTYStringIO(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(approve.sys, "stdin", TTYStringIO(f"approve {SID[:8]}\n"))
    monkeypatch.setattr(approve, "_getpass", lambda prompt: pytest.fail("getpass must not run"))

    assert approve.main([SID]) == 1
    err = capsys.readouterr().err
    assert "plan record was modified or is invalid" in err
    assert not (configured / "state" / "approvals" / f"{SID}.json").exists()


def test_approve_refuses_old_record_missing_staged_at(
    configured, monkeypatch, capsys
):
    """newton-approve: a record from before the field (no staged_at) also fails to
    recompute the hash; same ValueError, same refusal message, no
    approval file written."""
    import io
    import newton_mcp.approve as approve

    record = _record(approval=True)
    del record["staged_at"]
    # the stored hash was computed assuming the legacy field set
    record["plan_hash"] = plan.compute_plan_hash(
        {**record, "staged_at": STAGED_AT}
    )
    _write_plan(configured, record)

    class TTYStringIO(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(approve.sys, "stdin", TTYStringIO(f"approve {SID[:8]}\n"))
    monkeypatch.setattr(approve, "_getpass", lambda prompt: pytest.fail("getpass must not run"))

    assert approve.main([SID]) == 1
    err = capsys.readouterr().err
    assert "plan record was modified or is invalid" in err
    assert not (configured / "state" / "approvals" / f"{SID}.json").exists()
