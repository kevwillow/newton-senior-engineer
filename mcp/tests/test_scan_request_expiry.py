"""SC-2: planned scan requests expire 30 minutes after planning.

A scan request carries ``created_at`` and is usable forever when no consent
exists yet; without a bound, an old plan can be approved and run minutes
or hours later, far past the window the operator had in mind.  The max
age is the same 30 minutes as the consent window and is checked inside
``scans.load_request`` so both callers (``newton-approve`` and the run
tool) reach it.  A ``created_at`` in the future by more than 5 minutes
is refused with the existing "scan request was modified or is invalid"
message: the request hash already covers ``created_at`` so the future
stamp would otherwise fail the hash check, but the failed-hash path
should still be the one an operator with a clock-skewed machine hits.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import newton_mcp.approve as approve
import newton_mcp.scans as scans
import newton_mcp.server as server
from test_scans import (
    REQUEST_ID,
    TerminalInput,
    _request,
    _write_consent,
    _write_inventory,
    _write_request,
)


SCAN_REQUEST_MAX_AGE = timedelta(minutes=30)
SCAN_REQUEST_FUTURE_TOLERANCE = timedelta(minutes=5)
# Pinned "now" used by the controllable clock below.  Picked so all the
# offsets in the cases below line up with the 30-minute max-age window
# without depending on the wall clock the runner sees.
FROZEN_NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def frozen_clock(monkeypatch):
    """Freeze ``scans._now()`` to a known UTC instant so each test can
    set ``created_at`` to a precise offset without sleeping."""
    monkeypatch.setattr(scans, "_now", lambda: FROZEN_NOW)
    return FROZEN_NOW


def _record_with_created_at(created_at: str) -> dict[str, object]:
    record = _request()
    record["created_at"] = created_at
    record["request_hash"] = scans.compute_request_hash(record)
    return record


def test_load_request_accepts_fresh_request(tmp_path, monkeypatch, frozen_clock):
    record = _record_with_created_at(FROZEN_NOW.isoformat())
    _write_request(tmp_path, record)
    loaded = scans.load_request(tmp_path / "state", REQUEST_ID)
    assert loaded["id"] == REQUEST_ID


def test_load_request_accepts_request_29_minutes_old(
    tmp_path, monkeypatch, frozen_clock
):
    older = (FROZEN_NOW - SCAN_REQUEST_MAX_AGE + timedelta(minutes=1)).isoformat()
    record = _record_with_created_at(older)
    _write_request(tmp_path, record)
    loaded = scans.load_request(tmp_path / "state", REQUEST_ID)
    assert loaded["created_at"] == older


def test_load_request_refuses_request_31_minutes_old(
    tmp_path, monkeypatch, frozen_clock
):
    older = (FROZEN_NOW - SCAN_REQUEST_MAX_AGE - timedelta(minutes=1)).isoformat()
    record = _record_with_created_at(older)
    _write_request(tmp_path, record)
    with pytest.raises(scans.ScanError, match="scan request expired; plan a new scan request"):
        scans.load_request(tmp_path / "state", REQUEST_ID)


def test_load_request_refuses_future_created_at_with_hash_mismatch(
    tmp_path, monkeypatch, frozen_clock
):
    # ``created_at`` more than the future-tolerance in the future ->
    # the existing "modified or invalid" path; the hash already
    # covers created_at so this is largely belt-and-braces, but the
    # message stays the same as the other integrity checks so an
    # operator whose clock is ahead sees one error for both shapes
    # (hash mismatch and future stamp).
    future = (FROZEN_NOW + SCAN_REQUEST_FUTURE_TOLERANCE + timedelta(minutes=5)).isoformat()
    record = _request()
    record["created_at"] = future
    record["request_hash"] = scans.compute_request_hash(record)
    _write_request(tmp_path, record)
    with pytest.raises(
        scans.ScanError,
        match="scan request was modified or is invalid; plan it again",
    ):
        scans.load_request(tmp_path / "state", REQUEST_ID)


def test_newton_approve_refuses_31_minute_old_request_without_writing_consent(
    tmp_path, monkeypatch, frozen_clock, capsys
):
    _write_inventory(
        tmp_path,
        monkeypatch,
        vantages=(("outside-a", "outside"),),
    )
    older = (FROZEN_NOW - SCAN_REQUEST_MAX_AGE - timedelta(minutes=1)).isoformat()
    record = _record_with_created_at(older)
    _write_request(tmp_path, record)
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: "synthetic scan approval phrase"
    )
    monkeypatch.setattr(
        approve.sys, "stdin", TerminalInput(f"approve {REQUEST_ID[:8]}\n")
    )

    rc = approve.main([REQUEST_ID])
    captured = capsys.readouterr()
    consent = tmp_path / "state" / "scan-consents" / f"{REQUEST_ID}.json"

    assert rc == 1
    assert "expired" in captured.err
    assert not consent.exists()


def test_newton_run_scan_refuses_31_minute_old_request_without_runner(
    tmp_path, monkeypatch, frozen_clock
):
    _write_inventory(
        tmp_path,
        monkeypatch,
        vantages=(("outside-a", "outside"),),
    )
    older = (FROZEN_NOW - SCAN_REQUEST_MAX_AGE - timedelta(minutes=1)).isoformat()
    record = _record_with_created_at(older)
    _write_request(tmp_path, record)
    consent_path = _write_consent(tmp_path, record)
    monkeypatch.setattr(
        scans,
        "run_vantage",
        lambda *a, **k: pytest.fail("runner must not be called on an expired request"),
    )

    result = server.newton_run_scan("router", REQUEST_ID)

    assert "error" in result
    assert "expired" in result["error"]
    assert consent_path.exists(), "expired request must NOT consume consent"
    assert not consent_path.with_suffix(".used").exists()


def test_request_hash_covers_created_at_so_edit_after_writing_fails_hash(
    tmp_path, monkeypatch, frozen_clock
):
    # An attacker (or a buggy client) writes the record at plan time
    # with a fresh created_at, then edits only the on-disk JSON's
    # created_at field to a moment inside the 30-min window WITHOUT
    # recomputing the hash.  Because the request hash already covers
    # created_at, the load path refuses with the same
    # "modified or is invalid" message that other integrity checks
    # emit.  This is the property SC-2 relies on -- if the hash did
    # NOT cover created_at, the same edit would defeat the 5-min
    # future check and shorten the apparent age of any old plan.
    record = _record_with_created_at(FROZEN_NOW.isoformat())
    path = _write_request(tmp_path, record)
    fresh = (FROZEN_NOW - timedelta(minutes=2)).isoformat()
    on_disk = json.loads(path.read_text())
    on_disk["created_at"] = fresh
    path.write_text(json.dumps(on_disk))
    with pytest.raises(
        scans.ScanError,
        match="scan request was modified or is invalid; plan it again",
    ):
        scans.load_request(tmp_path / "state", REQUEST_ID)
