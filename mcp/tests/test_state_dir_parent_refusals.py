"""SW2 item 4: every state-dir write site refuses a group- or world-writable
parent without the sticky bit, before it creates or uses the directory.

``receipts.check_state_write_path(path, state_root)`` is the one rule: the
state dir itself is checked with ``check_state_dir`` (lstat: not a symlink,
ours, no group/other write) and ``path``'s parent with
``check_state_dir_parent`` (stat: group/other write without the sticky bit
is refused).  This file walks the call sites so a site that stops calling the
check is caught by a test that fails when the check is removed.

Two shapes of hostile parent appear below:

* root-level sites (audit, error log, receipts, the redact key, the guided
  confirmation store) write straight into the state dir, so the hostile
  directory is the state dir's PARENT (mode 0777, no sticky bit);
* subdirectory sites (plans, approvals, scan requests/consents, the
  ssh-disabled marker, the approval record) write into ``state/<sub>/``, so
  their parent is the state dir itself, which is what is dropped to 0777.

Every test also asserts that nothing was created: a refusal that still lays
the directory down would leave the very path an attacker wanted.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

import newton_mcp.adapters.ssh_cli as ssh_cli
import newton_mcp.approve as approve
import newton_mcp.guided as guided
import newton_mcp.redact as redact
import newton_mcp.receipts as receipts
import newton_mcp.scans as scans
import newton_mcp.server as server
from exhelp import explained

SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
DIGEST = "d" * 64

# a complete owrt-change.sh plan transcript: the plan has to parse before it
# reaches the state/plans write the test is about
PLAN_STDOUT = (
    "BACKUP /tmp/x.tar.gz (1 config files)\n"
    f"STAGED session={SID}\n"
    f"BASEHASH {BASE_HASH}\n"
    f"PROBES 0 {'a' * 64}\n"
    "PROFILE lab\n"
    "APPROVAL not-required\n"
    f"PLANDIGEST {DIGEST}\n"
    "----- diff -----\n"
    "dhcp.skilltest='host'\n"
    "----------------\n"
)

REFUSAL = "is group- or world-writable without the sticky bit"
# both refusals say "group- or world-writable": the parent rule adds the
# sticky-bit clause, the state-dir rule (a dir that is group-writable at all)
# says so without it
UNSAFE = "group- or world-writable"


def hostile_parent(tmp_path: Path) -> Path:
    """A 0777 (no sticky bit) directory to hang a state dir under."""
    parent = tmp_path / "hostile"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o777)
    assert stat.S_IMODE(parent.stat().st_mode) == 0o777
    return parent


def hostile_state(tmp_path: Path) -> Path:
    """A state dir itself at 0777 (no sticky bit), as the parent of state/<sub>/."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o777)
    return state


def hostile_state_with_key(tmp_path: Path, monkeypatch) -> Path:
    """As hostile_state, but the redact key already exists.

    ``redact.get_key()`` reads the same state dir earlier in every plan/apply
    call, so its cache is warmed while the state dir is still 0700; the site
    under test is then reached with the state dir dropped to 0777.
    """
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    redact.get_key()  # mints redact.key under the still-tight state dir
    os.chmod(state, 0o777)
    return state


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """An inventory plus NEWTON_STATE_DIR, like the server tests use."""
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return tmp_path


# ---- the helper itself (one test per rule branch) ---------------------------


def test_check_state_write_path_refuses_0777_parent(tmp_path):
    parent = hostile_parent(tmp_path)
    msg = receipts.check_state_write_path(parent / "state", parent / "state")
    assert msg is not None and REFUSAL in msg


def test_check_state_write_path_accepts_1777_parent(tmp_path):
    parent = tmp_path / "sticky"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o1777)
    assert receipts.check_state_write_path(parent / "state", parent / "state") is None


# ---- root-level sites -------------------------------------------------------


def test_receipts_record_refuses_0777_parent(tmp_path):
    """receipts.record: the state root is the path's own parent."""
    state = hostile_parent(tmp_path) / "state"
    assert receipts.record(state, "junos", "interfaces", "ok", "matched", "1.0") is False
    assert not state.exists()


def test_write_audit_refuses_0777_parent(tmp_path, monkeypatch):
    """server.write_audit stays silent (best effort) and writes nothing."""
    state = hostile_parent(tmp_path) / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    server.write_audit("newton_read", "quasar", "ok")
    assert not state.exists()


def test_log_unexpected_error_refuses_0777_parent(tmp_path, monkeypatch):
    """server._log_unexpected_error stays silent and writes nothing."""
    state = hostile_parent(tmp_path) / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    server._log_unexpected_error("newton_read", "quasar")
    assert not state.exists()


def test_redact_key_refuses_0777_parent(tmp_path, monkeypatch):
    """redact.get_key raises rather than mint a key into an unsafe state dir."""
    state = hostile_parent(tmp_path) / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    with pytest.raises(RuntimeError, match=REFUSAL):
        redact.get_key()
    assert not state.exists()


def test_guided_store_confirmation_refuses_0777_parent(tmp_path):
    """guided.store_confirmation refuses before creating the state root."""
    state = hostile_parent(tmp_path) / "state"
    record = guided.confirmation_record(
        {"strictness": "normal"}, "s", device="-", platform="openwrt"
    )
    with pytest.raises(guided.GuidedError, match=REFUSAL):
        guided.store_confirmation(record, state)
    assert not state.exists()


# ---- subdirectory sites -----------------------------------------------------


def test_plan_refuses_group_writable_state_dir(configured, monkeypatch):
    """newton_plan_change refuses before creating state/plans."""
    state = hostile_state_with_key(configured, monkeypatch)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess(list(a), 0, PLAN_STDOUT, ""),
    )
    result = server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host")
    )
    assert UNSAFE in str(result.get("error")), result
    assert not (state / "plans").exists()


def test_consume_approval_refuses_group_writable_state_dir(configured, monkeypatch):
    """consume_approval refuses before creating state/approvals."""
    state = hostile_state_with_key(configured, monkeypatch)
    service = server.NewtonService()
    with pytest.raises(server.NewtonError, match=UNSAFE):
        service.consume_approval("quasar", SID, {"plan_id": SID, "device": "quasar"})
    assert not (state / "approvals").exists()


def test_scans_save_request_refuses_group_writable_state_dir(tmp_path):
    """scans.save_request raises ScanError instead of creating state/scan-requests."""
    state = hostile_state(tmp_path)
    with pytest.raises(scans.ScanError, match=UNSAFE):
        scans.save_request(state, {"id": "a" * 32, "device": "quasar"})
    assert not (state / "scan-requests").exists()


def test_scans_save_consent_refuses_group_writable_state_dir(tmp_path):
    """scans.save_consent raises ScanError instead of creating state/scan-consents."""
    state = hostile_state(tmp_path)
    with pytest.raises(scans.ScanError, match=UNSAFE):
        scans.save_consent(state, {"request_id": "a" * 32, "decision": "yes"})
    assert not (state / "scan-consents").exists()


def test_approve_atomic_write_refuses_group_writable_state_dir(tmp_path, monkeypatch):
    """approve's atomic write of state/approvals/<plan>.json refuses."""
    state = hostile_state(tmp_path)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    with pytest.raises(OSError, match=UNSAFE):
        approve._atomic_write(state / "approvals" / f"{'a' * 32}.json", {"a": 1})
    assert not (state / "approvals").exists()


def test_ssh_cli_disable_marker_refuses_group_writable_state_dir(tmp_path):
    """The ssh-disabled marker write refuses instead of creating the dir."""
    state = hostile_state(tmp_path)
    with pytest.raises(OSError, match=UNSAFE):
        ssh_cli._write_disable_marker(state, "quasar")
    assert not (state / "ssh-disabled").exists()


# ---- the same rule, a sticky parent is fine ---------------------------------


def test_sticky_state_dir_parent_is_accepted(tmp_path, monkeypatch):
    """A 1777 parent (the /tmp shape) is not a refusal: writes proceed."""
    parent = tmp_path / "sticky"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o1777)
    state = parent / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    server.write_audit("newton_read", "quasar", "ok")
    assert (state / "mcp-audit.log").exists()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700