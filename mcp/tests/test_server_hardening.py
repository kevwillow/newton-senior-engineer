"""R2 review hardening for the MCP server:

* consume_approval refuses every malformed record with the same client-safe
  message ("approval record is invalid; ask the user to approve the plan
  again") and leaves the bad file in place; today a UnicodeDecodeError
  escapes the surface.
* write_audit creates mcp-audit.log with mode 0o600 (via os.open) and the
  state directory with mode 0o700 when this code created it.
* The plans and approvals directories are created with mode 0o700.

The mode tests run under os.umask(0) so the requested bits actually stick.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from exhelp import explained, record_fields, record_fields_display

import newton_mcp.server as server
from newton_mcp.plan import compute_plan_hash
from newton_mcp.server import NewtonError, NewtonService


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
DIGEST = "d" * 64


# ---- shared fixtures --------------------------------------------------------


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def _record():
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.skilltest=host",
        "diff": "dhcp.skilltest='host'",
        "probes": [["fail"], ["iface-absent", "guestx"]],
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": True,
        "router_digest": DIGEST,
        **record_fields("set dhcp.skilltest=host"),
        **record_fields_display(),
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": "2026-10-07T12:00:00+00:00",
    }
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _write_plan(root, record):
    plans = root / "state" / "plans"
    plans.mkdir(parents=True, exist_ok=True)
    (plans / f"{SID}.json").write_text(json.dumps(record))


def _approval_file(root, body):
    approvals = root / "state" / "approvals"
    approvals.mkdir(parents=True, exist_ok=True)
    path = approvals / f"{SID}.json"
    path.write_bytes(body)
    return path


# ---- consume_approval: invalid records share one client-safe message --------


INVALID_MSG = "approval record is invalid; ask the user to approve the plan again"


def _bad_bodies(plan_hash):
    """Every shape that must be refused with INVALID_MSG; the bad file is
    left in place, so the user can inspect it.  The plan_hash matches the
    record so the refusal comes from the bad field, not a hash mismatch."""
    return [
        pytest.param(b"\xff\xfe\xfd not utf-8 at all", id="invalid-utf8"),
        pytest.param(b"{not json at all, definitely", id="invalid-json"),
        pytest.param(b'"a plain string, not an object"', id="non-dict-body"),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "not-an-iso-datetime",
                "token": "f" * 64,
            }).encode(),
            id="expires_at-unparseable",
        ),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:30:00+00:00",
                "not_before": 4070908800,
                "not_after": 4070910600,
            }).encode(),
            id="missing-token",
        ),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:30:00+00:00",
                "not_before": 4070908800,
                "not_after": 4070910600,
                "token": "nothex",
            }).encode(),
            id="non-hex-token",
        ),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:30:00+00:00",
                "not_before": 4070908800,
                "not_after": 4070910600,
                "token": "F" * 64,
            }).encode(),
            id="uppercase-token",
        ),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:30:00+00:00",
                "not_before": 4070908800,
                "not_after": 4070910600,
                "token": "f" * 63,
            }).encode(),
            id="63-char-token",
        ),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:30:00+00:00",
                "not_before": 4070908800,
                "not_after": 4070910600,
                "token": "f" * 65,
            }).encode(),
            id="65-char-token",
        ),
        pytest.param(
            json.dumps({
                "plan_id": SID,
                "plan_hash": plan_hash,
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2099-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:30:00+00:00",
                "not_before": 4070908800,
                "not_after": 4070910600,
                "token": 5,
            }).encode(),
            id="non-string-token",
        ),
    ]


_FIXED_RECORD = None  # computed lazily, see _shared_record_plan_hash


def _shared_record_plan_hash():
    """The plan_hash of the shared test record.  Computed lazily so this
    module can be imported even if the hash depends on plan.py details."""
    global _FIXED_RECORD
    if _FIXED_RECORD is None:
        _FIXED_RECORD = _record()
    return _FIXED_RECORD["plan_hash"]


@pytest.mark.parametrize("body", _bad_bodies(_record()["plan_hash"]))
def test_consume_approval_refuses_each_malformed_record_with_one_message(
    configured, monkeypatch, body
):
    record = _record()
    _write_plan(configured, record)
    approval_path = _approval_file(configured, body)
    used_path = approval_path.with_suffix(".used")
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("a bad approval must never reach the script"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert result["error"] == INVALID_MSG, result
    assert "internal server error" not in result["error"]
    # the bad file is left in place so the user can inspect it
    assert approval_path.exists(), "bad approval file must be left in place"
    assert not used_path.exists()


# ---- SW2 Item 2: records without the bound window share one message ---------

OLD_APPROVAL_MSG = (
    "approval was made by an older newton-approve or edited; approve the plan again"
)
CREATED_AT = "2099-01-01T00:00:00+00:00"
EXPIRES_AT = "2099-01-01T00:30:00+00:00"
WINDOW = {"not_before": 4070908800, "not_after": 4070910600}


def _old_format_bodies():
    """Records the new-approve flow could never write, or one whose window
    was edited after the fact.  All share the old-approve message."""
    def body(**updates):
        approval = {
            "plan_id": SID,
            "plan_hash": _shared_record_plan_hash(),
            "device": "quasar",
            "base_hash": BASE_HASH,
            "created_at": CREATED_AT,
            "expires_at": EXPIRES_AT,
            "token": "f" * 64,
        }
        approval.update(updates)
        return json.dumps(approval).encode()

    return [
        pytest.param(body(), id="no-window-fields"),
        pytest.param(body(not_before=None, not_after=None), id="null-window"),
        pytest.param(
            body(not_before=CREATED_AT, not_after=EXPIRES_AT), id="string-window"
        ),
        pytest.param(
            body(not_before=4070908800.0, not_after=4070910600.0),
            id="float-window",
        ),
        pytest.param(
            body(not_before=True, not_after=True), id="bool-window"
        ),
        pytest.param(
            body(not_before=4070910600, not_after=4070908800),
            id="window-not-ordered",
        ),
        pytest.param(
            body(**WINDOW, expires_at="2099-01-01T02:00:00+00:00"),
            id="expires-at-edited-alone",
        ),
        pytest.param(
            body(not_before=4070908800, not_after=4070908900),
            id="not-after-not-the-floor",
        ),
        pytest.param(
            json.dumps(
                {
                    "plan_id": SID,
                    "plan_hash": _shared_record_plan_hash(),
                    "device": "quasar",
                    "base_hash": BASE_HASH,
                    "expires_at": EXPIRES_AT,
                    **WINDOW,
                    "token": "f" * 64,
                }
            ).encode(),
            id="no-created-at",
        ),
    ]


@pytest.mark.parametrize("body", _old_format_bodies())
def test_consume_approval_refuses_old_or_edited_window_records_with_one_message(
    configured, monkeypatch, body
):
    record = _record()
    _write_plan(configured, record)
    approval_path = _approval_file(configured, body)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("an unbindable approval must never reach the script"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert result["error"] == OLD_APPROVAL_MSG, result
    assert "internal server error" not in result["error"]
    # the file is left in place so the user can inspect it, and the
    # approval is neither claimed nor spent
    assert approval_path.exists()
    assert not approval_path.with_suffix(".claimed").exists()
    assert not approval_path.with_suffix(".used").exists()


def test_consume_approval_old_format_message_comes_before_the_expiry_one(
    configured, monkeypatch
):
    """An old-format record that is ALSO expired reports the old-approve
    refusal: the operator is told to approve again, not that it expired."""
    record = _record()
    _write_plan(configured, record)
    _approval_file(
        configured,
        json.dumps(
            {
                "plan_id": SID,
                "plan_hash": record["plan_hash"],
                "device": "quasar",
                "base_hash": BASE_HASH,
                "created_at": "2000-01-01T00:00:00+00:00",
                "expires_at": "2000-01-01T00:30:00+00:00",
                "token": "f" * 64,
            }
        ).encode(),
    )
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert result["error"] == OLD_APPROVAL_MSG
    assert "expired" not in result["error"]


def test_consume_approval_invalid_utf8_does_not_escape_a_traceback(configured, monkeypatch):
    """Today a UnicodeDecodeError on the approval file escapes as 'internal
    server error'; the new decode-catch turns it into the invalid message."""
    record = _record()
    _write_plan(configured, record)
    _approval_file(configured, b"\xff\xfe garbage bytes")
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert result["error"] == INVALID_MSG


def test_consume_approval_isdirectoryerror_does_not_escape_a_traceback(configured, monkeypatch):
    """When the approval path is a directory, ``read_bytes`` raises
    ``IsADirectoryError``; that OSError must surface as INVALID_MSG, not
    as an 'internal server error' stack trace."""
    record = _record()
    _write_plan(configured, record)
    approvals = configured / "state" / "approvals"
    approvals.mkdir(parents=True, exist_ok=True)
    approval_path = approvals / f"{SID}.json"
    approval_path.mkdir()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert result["error"] == INVALID_MSG, result
    assert "internal server error" not in result["error"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses mode 000 file permissions")
def test_consume_approval_unreadable_file_does_not_escape_a_traceback(configured, monkeypatch):
    """When the approval file exists but is unreadable (mode 000),
    ``read_bytes`` raises ``PermissionError``; that OSError must surface
    as INVALID_MSG, not as an 'internal server error' stack trace.
    Skipped under root, which bypasses mode bits."""
    record = _record()
    _write_plan(configured, record)
    approval_path = _approval_file(configured, b"{}")
    os.chmod(approval_path, 0o000)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run"),
    )
    try:
        result = server.newton_apply_change("quasar", SID)
    finally:
        os.chmod(approval_path, 0o600)
    assert result["error"] == INVALID_MSG, result
    assert "internal server error" not in result["error"]


# ---- write_audit creates the audit log and state dir with the right modes ----


def test_write_audit_creates_log_with_mode_0600_under_permissive_umask(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "fresh"))
    old_umask = os.umask(0)
    try:
        server.write_audit("newton_read", "quasar", "ok")
    finally:
        os.umask(old_umask)
    log = tmp_path / "fresh" / "mcp-audit.log"
    assert log.exists()
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert "tool=newton_read device=quasar result=ok" in log.read_text()


def test_write_audit_chmods_state_dir_to_0700_when_it_created_it(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "fresh"))
    old_umask = os.umask(0)
    try:
        server.write_audit("newton_read", "quasar", "ok")
    finally:
        os.umask(old_umask)
    state = tmp_path / "fresh"
    assert state.is_dir()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_write_audit_does_not_relax_an_existing_dir_mode(tmp_path, monkeypatch):
    """If the state dir already existed with a more permissive mode (a setup
    mistake), write_audit does not widen it."""
    state = tmp_path / "state"
    state.mkdir(0o755)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    old_umask = os.umask(0)
    try:
        server.write_audit("newton_read", "quasar", "ok")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(state.stat().st_mode) == 0o755


# ---- plans and approvals directories are mode 0o700 -------------------------


def test_plan_creates_plans_dir_with_mode_0700(configured, monkeypatch):
    """A fresh plan() creates the plans directory with mode 0o700."""
    state = configured / "state"
    assert not (state / "plans").exists()
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess(
            list(a), 0,
            (
                "BACKUP /tmp/x.tar.gz (1 config files)\n"
                f"STAGED session={SID}\n"
                f"BASEHASH {BASE_HASH}\n"
                f"PROBES 0 {'a' * 64}\n"
                "PROFILE lab\n"
                f"APPROVAL not-required\n"
                f"PLANDIGEST {DIGEST}\n"
                "----- diff -----\n"
                "dhcp.skilltest='host'\n"
                "----------------\n"
            ),
            "",
        ),
    )
    old_umask = os.umask(0)
    try:
        # the new parent-sticky check refuses a state dir at 0777; the test
        # must seed the state dir at the only mode that passes the check.
        # Without this, the redact-key load + umask=0 path drops the parent
        # to 0777, and the plans mkdir below is then skipped.
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state, 0o700)
        server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    finally:
        os.umask(old_umask)
    plans = state / "plans"
    assert plans.is_dir()
    assert stat.S_IMODE(plans.stat().st_mode) == 0o700


def test_consume_approval_creates_approvals_dir_with_mode_0700(configured, monkeypatch):
    """If consume_approval has to create the approvals directory itself,
    it does so with mode 0o700."""
    state = configured / "state"
    approvals = state / "approvals"
    # No approval file is written: this exercises the mkdir branch in
    # consume_approval and the resulting "approval required" refusal is a
    # side effect of the missing file, not the dir creation.
    assert not approvals.exists()
    record = _record()
    _write_plan(configured, record)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess(
            list(a), 0, f"CONFIRMED session={SID}", ""
        ),
    )
    old_umask = os.umask(0)
    try:
        # the new parent-sticky check refuses a state dir at 0777; seed
        # the parent at 0700 first so the approvals mkdir can succeed.
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state, 0o700)
        result = server.newton_apply_change("quasar", SID)
    finally:
        os.umask(old_umask)
    # the refusal is "approval required" because the file is absent; the
    # server created the dir to look for it
    assert "approval required" in result["error"], result
    assert approvals.is_dir()
    assert stat.S_IMODE(approvals.stat().st_mode) == 0o700