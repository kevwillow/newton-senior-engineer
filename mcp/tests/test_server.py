import asyncio
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from exhelp import explained, record_fields, record_fields_display

import newton_mcp.redact as redact_mod
import newton_mcp.server as server
from newton_mcp.plan import canonical_plan_json, compute_plan_hash


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
PROBES_SHA = "1" * 64


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text("""[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n""")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


@pytest.fixture
def configured_lab(tmp_path, monkeypatch):
    inventory = tmp_path / "devices-lab.toml"
    inventory.write_text("""[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\nprofile = "lab"\nlab = true\n""")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


@pytest.mark.parametrize("command", [
    "uci show", "uci get system.@system[0].hostname", "uci changes", "uci export network",
    "ubus list", "ubus list network.interface", "ubus call system board",
    "ubus call network.interface dump", "ubus call network.interface.lan status",
    "ip addr show", "ip -4 route list table main", "ip link show dev br-lan",
    "ifstatus lan", "fw4 check", "fw4 print", "nft list ruleset",
    "cat /etc/openwrt_release", "cat /etc/config/firewall", "wifi status",
    "logread -e dnsmasq -l 10", "apk info dnsmasq", "ping -c 3 192.0.2.1",
    "traceroute openwrt.org", "nslookup openwrt.org 1.1.1.1", "iwinfo", "df -h", "uname -a",
])
def test_allowlist_accepts_read_only_cases(command):
    assert server.validate_read(command) == __import__("shlex").split(command)


@pytest.mark.parametrize("command", [
    "uci show; reboot", "ip link set lan1 down", "cat /etc/shadow", "nft flush ruleset",
    "ubus call system reboot", "logread -f", "ping -c 100 x", "$(reboot)",
    "uci show\nreboot", "uci commit", "uci show | reboot", "ip route add 1.2.3.0/24",
    "wifi", "fw4 reload", "rm -rf /", "nslookup x;id",
])
def test_allowlist_rejects_mutation_and_injection(command):
    with pytest.raises(server.NewtonError):
        server.validate_read(command)


def test_plan_output_fixture_parses_host_reservation():
    text = (Path(__file__).parent / "fixtures" / "plan_output.txt").read_text()
    parsed = server.parse_plan(text)
    assert parsed == {
        "session_id": SID,
        "base_hash": BASE_HASH,
        "diff": "dhcp.skilltest='host'\ndhcp.skilltest.name='skilltest'\ndhcp.skilltest.mac='02:00:00:00:00:99'\ndhcp.skilltest.ip='192.0.2.99'",
        "backup_path": "/home/user/.local/state/network-agent/backups/Quasar-20261003-205204.tar.gz",
        "touched_configs": ["dhcp"],
        "probes_count": 2,
        "probes_sha": PROBES_SHA,
        "profile": "lab",
        "sections": ["dhcp skilltest host-reservation skilltest"],
        "leash": ["wan-rule firewall.wan_rule.src"],
        "approval_required": False,
        "digest": ROUTER_DIGEST,
        "staged_check": {"fw4": "not-checked", "reason": "no-report", "not_checked": ["dhcp"]},
    }


def test_inventory_missing_file_returns_clear_error(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_INVENTORY", str(tmp_path / "gone.toml"))
    with pytest.raises(server.NewtonError, match="inventory file not found"):
        server.load_inventory()


def test_inventory_bad_platform(tmp_path, monkeypatch):
    p = tmp_path / "devices.toml"
    p.write_text("[devices.x]\nplatform='linux'\nhost='x'\nuser='root'\n")
    monkeypatch.setenv("NEWTON_INVENTORY", str(p))
    with pytest.raises(server.NewtonError, match="unsupported platform"):
        server.load_inventory()


def test_password_file_mode_rejected(tmp_path, monkeypatch):
    password = tmp_path / "password"
    password.write_text("secret")
    os.chmod(password, 0o644)
    p = tmp_path / "devices.toml"
    p.write_text(f"[devices.x]\nplatform='openwrt'\nhost='x'\nuser='root'\nauth='password'\npassword_file='{password}'\n")
    monkeypatch.setenv("NEWTON_INVENTORY", str(p))
    with pytest.raises(server.NewtonError, match="mode 0600"):
        server.load_inventory()


def test_read_is_ssh_quoted_and_truncated(configured, monkeypatch):
    seen = {}
    def fake_run(args, **kwargs):
        seen.update(args=args, kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0, "x" * (64 * 1024 + 1), "err")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    result = server.newton_read("quasar", "ip link show dev br-lan")
    assert result["exit_code"] == 0
    assert result["truncated"] is True
    stdout_envelope = result["stdout"]
    stderr_envelope = result["stderr"]
    assert stdout_envelope["kind"] == "untrusted-device-data"
    assert stdout_envelope["source"] == "quasar:ip link show dev br-lan"
    assert stdout_envelope["text"] == "x" * (64 * 1024)
    assert stderr_envelope["kind"] == "untrusted-device-data"
    assert stderr_envelope["source"] == "quasar:ip link show dev br-lan"
    assert stderr_envelope["text"] == "err"
    assert seen["args"][-3:] == [
        "--",
        "root@192.0.2.1",
        f"{server.PROG} read ip link show dev br-lan",
    ]
    assert seen["kwargs"]["timeout"] == 30


def test_backup_parses_script_output(configured, monkeypatch):
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], 0, "BACKUP /tmp/a.tar.gz (2 config files)\n", ""))
    result = server.newton_backup("quasar")
    assert result["config_files"] == 2
    path_envelope = result["backup_path"]
    assert path_envelope["kind"] == "untrusted-device-data"
    assert path_envelope["source"] == "quasar:backup"
    assert path_envelope["text"] == "/tmp/a.tar.gz"


def _plan_cp(text=None):
    return subprocess.CompletedProcess([], 0, text or (Path(__file__).parent / "fixtures" / "plan_output.txt").read_text(), "")


def _record(*, approval=False, device="quasar", staged_at="2026-10-07T12:00:00+00:00", **updates):
    record = {
        "device": device,
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.skilltest=host",
        "diff": "dhcp.skilltest='host'",
        "probes": [["fail"], ["iface-absent", "guestx"]],
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": approval,
        "router_digest": ROUTER_DIGEST,
        **record_fields("set dhcp.skilltest=host"),
        **record_fields_display(),
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": staged_at,
    }
    record.update(updates)
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _write_plan(configured, record):
    state = configured / "state" / "plans"
    state.mkdir(parents=True, exist_ok=True)
    (state / f"{SID}.json").write_text(json.dumps(record))


def _write_approval(configured, record, **updates):
    approval = {
        "plan_id": SID,
        "plan_hash": record["plan_hash"],
        "device": record["device"],
        "base_hash": record["base_hash"],
        "approved_by": "operator",
        "created_at": "2099-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:30:00+00:00",
        "token": "e" * 64,
    }
    approval.update(updates)
    # SW2 Item 2: the window the v2 token binds travels in the record too.
    # Derive it from created_at/expires_at unless the caller set it, so a
    # test that moves one of those two keeps a self-consistent record.
    for field, other in (("not_before", "created_at"), ("not_after", "expires_at")):
        if field not in updates:
            approval[field] = int(
                datetime.fromisoformat(approval[other]).timestamp()
            )
    state = configured / "state" / "approvals"
    state.mkdir(parents=True, exist_ok=True)
    (state / f"{SID}.json").write_text(json.dumps(approval))


def test_canonical_plan_hash_vector():
    vector = json.loads((Path(__file__).parent / "fixtures" / "plan_hash_vector.json").read_text())
    assert canonical_plan_json(vector["record"]) == vector["canonical_json"]
    assert compute_plan_hash(vector["record"]) == vector["plan_hash"]


def test_plan_persists_complete_hashed_state_and_new_instance_enforces_it(configured_lab, monkeypatch):
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: _plan_cp())
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    planned = server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", timeout_s=120, probes=[["fail"]], **explained("set dhcp.skilltest=host"),
    )
    record = configured_lab / "state" / "plans" / f"{SID}.json"
    saved = json.loads(record.read_text())
    assert saved == {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set dhcp.skilltest=host",
        "diff": "dhcp.skilltest='host'\ndhcp.skilltest.name='skilltest'\ndhcp.skilltest.mac='02:00:00:00:00:99'\ndhcp.skilltest.ip='192.0.2.99'",
        "probes": [["fail"], ["iface-absent", "guestx"]],
        "timeout_s": 120,
        "base_hash": BASE_HASH,
        "requires_approval": False,
        "router_digest": ROUTER_DIGEST,
        **record_fields("set dhcp.skilltest=host"),
        "reasons": [],
        "risk": "low",
        "created_at": saved["created_at"],
        "staged_at": saved["staged_at"],
        "plan_hash": saved["plan_hash"],
        "manifest_checks": [],
        "router_leash": ["wan-rule firewall.wan_rule.src"],
        "router_profile": "lab",
        "router_requires_approval": False,
        "staged_check": {"fw4": "not-checked", "reason": "no-report", "not_checked": ["dhcp"]},
        "router_sections": ["dhcp skilltest host-reservation skilltest"],
        "backup_path": "/home/user/.local/state/network-agent/backups/Quasar-20261003-205204.tar.gz",
    }
    assert saved["plan_hash"] == compute_plan_hash(saved)
    assert planned["approval_required"] is False
    assert planned["risk"] == "low"
    calls = []
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: calls.append((a, k)) or subprocess.CompletedProcess([], 0, "CONFIRMED session=" + SID, ""))
    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    assert calls[0][0][2:] == ("apply", "root@192.0.2.1", SID, "120")
    assert calls[0][1]["timeout"] == 120 + 300
    assert calls[0][1]["extra_env"] == {
        "OWRT_EXPECT_BASE": BASE_HASH,
        "OWRT_APPROVAL_TOKEN": "none",
    }


def test_approval_gate_blocks_before_subprocess(configured, monkeypatch):
    _write_plan(configured, _record(approval=True))
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    result = server.newton_apply_change("quasar", SID)
    assert "approval required" in result["error"]
    assert f"sudo -u newton /usr/local/bin/newton-approve {SID}" in result["error"]


def test_approval_gate_marks_used_only_after_script_reaches_router(configured, monkeypatch):
    """APR-05: the approval is .used AFTER run_script
    reached the router (here the script reported CONFIRMED and the
    caller-stamped ``APPLYING session=<sid>`` line was also in
    stdout), not before.  A failure before the APPLYING line leaves
    the original .json in place so the human can retry."""
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record)
    seen = {}
    def fake_run(*args, **kwargs):
        seen["used_before_script"] = (configured / "state" / "approvals" / f"{SID}.used").is_file()
        seen["claimed_before_script"] = (configured / "state" / "approvals" / f"{SID}.claimed").is_file()
        return subprocess.CompletedProcess(
            [],
            0,
            f"APPLYING session={SID}\nCONFIRMED session={SID}",
            "",
        )
    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    assert server.newton_apply_change("quasar", SID)["result"] == "confirmed"
    # while the script was running, the approval was only CLAIMED
    assert seen["claimed_before_script"] is True
    assert seen["used_before_script"] is False
    # and it is .used only after a successful reach
    assert (configured / "state" / "approvals" / f"{SID}.used").is_file()
    assert not (configured / "state" / "approvals" / f"{SID}.claimed").exists()


def test_replayed_approval_is_refused(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    used = configured / "state" / "approvals" / f"{SID}.used"
    used.parent.mkdir(parents=True)
    used.write_text("{}")
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    assert "already used" in server.newton_apply_change("quasar", SID)["error"]


# --- APR-05: the approval is .used only after the script
# reached the router.  Five tests pin the contract:

# (1) run_script that fails BEFORE the router (no APPLYING line, non-zero
#     rc) leaves <sid>.json in place and no .used/.claimed; a second apply
#     call reuses the same approval.
def test_apply_failure_before_router_keeps_approval_for_retry(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record)
    calls = []
    def fake_run(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(
            [], 1, "lost connection before reaching the router", "ssh: connection reset"
        )
    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change("quasar", SID)
    # The run reported a generic error, not an unknown outcome.
    assert result["result"] == "error", result
    # The original approval is still in place, .claimed was released.
    approvals = configured / "state" / "approvals"
    assert (approvals / f"{SID}.json").exists()
    assert not (approvals / f"{SID}.claimed").exists()
    assert not (approvals / f"{SID}.used").exists()
    # The first apply call DID run the script (the run failed in a
    # way that did not reach the router; the approval is intact).
    assert len(calls) == 1
    # A second apply call uses the same approval (no .used burned it).
    server.newton_apply_change("quasar", SID)
    assert len(calls) == 2


# (2) stdout contains the exact ``APPLYING session=<sid>`` line and then
#     the script fails (e.g. the apply step itself fails): .used, no .json.
def test_apply_failure_after_applying_line_burns_approval(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record)
    def fake_run(*args, **kwargs):
        # the script printed APPLYING and then the apply itself failed;
        # stdout carries the APPLYING line, returncode is non-zero.
        return subprocess.CompletedProcess(
            [],
            1,
            f"APPLYING session={SID}\napply refused: bad-approval",
            "",
        )
    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change("quasar", SID)
    # The exact mid-flight state is preserved (the run reached the router,
    # so the approval is burned even if the apply itself failed).
    assert result["result"] == "error", result
    approvals = configured / "state" / "approvals"
    assert not (approvals / f"{SID}.json").exists()
    assert not (approvals / f"{SID}.claimed").exists()
    assert (approvals / f"{SID}.used").exists()


# (3) TimeoutExpired is treated as ``reached_router`` (outcome unknown,
#     so the approval is burned so the next apply cannot replay it).
def test_apply_timeout_burns_approval(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record)
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="owrt-change.sh", timeout=600)
    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change("quasar", SID)
    assert result["result"] == "unknown", result
    approvals = configured / "state" / "approvals"
    assert not (approvals / f"{SID}.json").exists()
    assert not (approvals / f"{SID}.claimed").exists()
    assert (approvals / f"{SID}.used").exists()


# (4) A second apply call while a .claimed is present (the previous apply
#     crashed between claim and settle, or two applies race) is refused
#     with a clear in-use message; no script is run.
def test_apply_refuses_when_approval_is_already_claimed(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    approvals = configured / "state" / "approvals"
    approvals.mkdir(parents=True, exist_ok=True)
    # A previous apply crashed between claim and settle; only the
    # .claimed file is left behind, the original .json is gone.
    (approvals / f"{SID}.claimed").write_text("{}")
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run with a .claimed file"),
    )
    result = server.newton_apply_change("quasar", SID)
    assert "in use by an apply in progress" in result["error"], result
    # The .claimed file is still there; consume_approval never overwrote it.
    assert (approvals / f"{SID}.claimed").exists()
    assert not (approvals / f"{SID}.used").exists()


# (5) The device text contains ``APPLYING session=<sid>`` mid-line (not
#     at the start of a line) -- it does NOT count as reached.  Only an
#     exact-line match burns the approval.
def test_apply_mid_line_applying_text_does_not_burn_approval(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record)
    def fake_run(*args, **kwargs):
        # the APPLYING token is on a line with other text, NOT alone.
        return subprocess.CompletedProcess(
            [],
            1,
            f"helper said: APPLYING session={SID} but aborted\n"
            f"second line: APPLYING session={SID} trailing",
            "",
        )
    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    result = server.newton_apply_change("quasar", SID)
    # No exact-line match: the run is treated as a pre-router failure.
    assert result["result"] == "error", result
    approvals = configured / "state" / "approvals"
    assert (approvals / f"{SID}.json").exists()
    assert not (approvals / f"{SID}.claimed").exists()
    assert not (approvals / f"{SID}.used").exists()


# Bonus: classify_apply must NOT match ``APPLYING session=<sid>`` (the
# the apply-reached signal) as ``unknown``.  APPLYING is a host-side
# line; only APPLIED counts as a router outcome line.
def test_classify_apply_does_not_match_applying_line():
    """U-2 widened the APPLIED mask; the APPLYING line is the host
    signal that the script reached the router, not a router outcome
    line.  ``APPLYING`` is a prefix of ``APPLIED`` -- without the
    word boundary, ``APPLYING session=<sid>`` alone would mis-fire
    as ``unknown``."""
    assert (
        server.classify_apply(0, f"APPLYING session={SID}", SID)
        == "error"
    )
    assert (
        server.classify_apply(0, f"APPLYING session={SID}\nCONFIRMED session={SID}", SID)
        == "confirmed"
    )


def test_expired_approval_is_refused(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    # a self-consistent 30-minute window that ended in the past: the
    # expiry refusal stands (the window fields agree with the two times)
    _write_approval(
        configured,
        record,
        created_at="1999-12-31T23:30:00+00:00",
        expires_at="2000-01-01T00:00:00+00:00",
    )
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    assert "expired" in server.newton_apply_change("quasar", SID)["error"]


@pytest.mark.parametrize("field", ["uci_batch", "diff"])
def test_plan_edited_after_approval_is_refused(configured, monkeypatch, field):
    record = _record(approval=True)
    _write_approval(configured, record)
    record[field] += "\nset system.@system[0].hostname=edited"
    _write_plan(configured, record)
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    assert "plan record was modified" in server.newton_apply_change("quasar", SID)["error"]


def test_approval_for_wrong_device_is_refused(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record, device="other-router")
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    assert "device mismatch" in server.newton_apply_change("quasar", SID)["error"]


def test_approval_for_wrong_plan_hash_is_refused(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record, plan_hash="0" * 64)
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    assert "plan hash mismatch" in server.newton_apply_change("quasar", SID)["error"]


def test_approval_for_wrong_base_hash_is_refused(configured, monkeypatch):
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record, base_hash="0" * 64)
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], 0, "CONFIRMED session=" + SID, ""))
    assert "base hash mismatch" in server.newton_apply_change("quasar", SID)["error"]


@pytest.mark.parametrize(("output", "returncode", "result"), [
    (f"CONFIRMED session={SID}", 0, "confirmed"),
    (f"CONFIRMED session={SID} (3 consecutive passes)", 0, "confirmed"),
    (f"ROLLBACK WINDOW PASSED session={SID}", 1, "rolled_back"),
    (f"ALERT session={SID}", 1, "unknown"),
    ("OUTCOME UNKNOWN", 1, "unknown"),
    ("ERROR: nope", 1, "error"),
])
def test_apply_outcome_mapping(configured_lab, monkeypatch, output, returncode, result):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], returncode, output, "stderr"))
    assert server.newton_apply_change("quasar", SID)["result"] == result


@pytest.mark.parametrize(("output", "returncode", "result"), [
    (f"CONFIRMED session={SID}", 0, "confirmed"),
    (f"ROLLBACK WINDOW PASSED session={SID}", 1, "rolled_back"),
    (f"ALERT session={SID}", 1, "unknown"),
    ("OUTCOME UNKNOWN", 1, "unknown"),
    ("ERROR: nope", 1, "error"),
])
def test_apply_outcome_mapping_on_a_non_lab_device_goes_through_consume_approval(
    configured, monkeypatch, output, returncode, result
):
    """The same mapping, but the device needs approval, so the
    run only starts after consume_approval accepted a real approval record."""
    record = _record(approval=True)
    _write_plan(configured, record)
    _write_approval(configured, record)
    consumed = []
    real = server.NewtonService.consume_approval

    def spy(self, device_name, session_id, rec):
        token = real(self, device_name, session_id, rec)
        consumed.append(token)
        return token

    monkeypatch.setattr(server.NewtonService, "consume_approval", spy)
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], returncode, output, "stderr"),
    )
    assert server.newton_apply_change("quasar", SID)["result"] == result
    assert len(consumed) == 1 and consumed[0] != "none"


@pytest.mark.parametrize(("timeout_s", "valid"), [(59, False), (60, True), (600, True), (601, False)])
def test_plan_timeout_bounds(configured, monkeypatch, timeout_s, valid):
    calls = []
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: calls.append((a, k)) or _plan_cp(),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1})

    result = server.newton_plan_change("quasar", "set dhcp.skilltest=host", timeout_s=timeout_s, **explained("set dhcp.skilltest=host"))

    if valid:
        assert result["session_id"] == SID
        assert calls
    else:
        assert result == {"error": "timeout_s must be an integer 60..600"}
        assert calls == []


@pytest.mark.parametrize(("stdout", "stderr", "returncode", "result"), [
    (f"x CONFIRMED session={SID}", "", 0, "error"),
    ("CONFIRMED session=ffffffffffffffffffffffffffffffff", "", 0, "error"),
    ("ROLLBACK WINDOW PASSED session=ffffffffffffffffffffffffffffffff", "", 1, "error"),
    ("", f"CONFIRMED session={SID}", 0, "error"),
    (f"ROLLBACK WINDOW PASSED session={SID}\ntrailing text", "", 1, "error"),
    (f"APPLIED session={SID} rollback=60s\nERROR: lost outcome", "", 1, "unknown"),
])
def test_apply_outcome_requires_final_anchored_stdout_for_session(
    configured_lab, monkeypatch, stdout, stderr, returncode, result
):
    _write_plan(configured_lab, _record())
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], returncode, stdout, stderr),
    )
    assert server.newton_apply_change("quasar", SID)["result"] == result


def test_apply_old_spoof_shape_is_unknown(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    stdout = (
        f"APPLIED session={SID} rollback=60s\n"
        f"ROLLBACK WINDOW PASSED session={SID}\n"
        f"VERIFY FAILED session={SID} — not confirming\n"
        f"ALERT session={SID} rolled back, but DNS/DHCP check failed\n"
    )
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 1, stdout, ""),
    )
    assert server.newton_apply_change("quasar", SID)["result"] == "unknown"


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected"),
    [
        (0, f"CONFIRMED session={SID}x", "error"),
        (1, f"ROLLBACK WINDOW PASSED session={SID}x", "error"),
        (1, f"CONFIRMED session={SID}", "error"),
        (0, f"ROLLBACK WINDOW PASSED session={SID}", "error"),
        (0, f"CONFIRMED session={SID}\nALERT session={SID}", "unknown"),
        (0, f"ALERT session={SID}\nCONFIRMED session={SID}\n", "confirmed"),
        (1, f"ALERT session={SID}\nROLLBACK WINDOW PASSED session={SID}\n", "rolled_back"),
    ],
)
def test_classify_apply_strict_terminal_contract(returncode, stdout, expected):
    """Kills M14-M20/M22: exact SID, required rc, and last non-empty line decide."""
    assert server.classify_apply(returncode, stdout, SID) == expected


@pytest.mark.parametrize(
    "separator",
    ["\u2028", "\u2029", "\u0085", "\x0c", "\x1e"],
)
def test_classify_apply_splits_stdout_on_newline_only(separator):
    """U-4: Unicode/C0 separators in device text must not forge an outcome line."""
    assert server.classify_apply(
        1,
        f"ERROR: x{separator}APPLIED session={SID} rollback=60s",
        SID,
    ) == "error"

    assert server.classify_apply(
        0,
        f"x{separator}CONFIRMED session={SID}",
        SID,
    ) == "error"


def test_run_script_closes_stdin_in_child_process(tmp_path, configured):
    home = tmp_path / "newton-home"
    scripts = home / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / "owrt-change.sh"
    script.write_text("#!/bin/sh\nIFS= read -r line || true\nprintf '%s\\n' \"$line\"\n")
    script.chmod(0o755)
    code = (
        "from newton_mcp.server import Device, NewtonService; "
        "s=object.__new__(NewtonService); "
        "cp=s.run_script(Device('x','openwrt','host','root'),'apply',timeout=2); "
        "print(cp.stdout, end='')"
    )
    env = os.environ.copy()
    env["NEWTON_HOME"] = str(home)
    child = subprocess.run(
        [sys.executable, "-c", code], input="JSONRPC-FRAME\n", text=True,
        capture_output=True, env=env, timeout=10,
    )
    assert child.returncode == 0, child.stderr
    assert "JSONRPC-FRAME" not in child.stdout


def test_apply_timeout_maps_to_unknown(configured_lab, monkeypatch):
    _write_plan(configured_lab, _record())
    def timeout(*a, **k): raise subprocess.TimeoutExpired([], 1)
    monkeypatch.setattr(server.NewtonService, "run_script", timeout)
    assert server.newton_apply_change("quasar", SID)["result"] == "unknown"


def test_status_abort_and_audit(configured, monkeypatch):
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], 0, "ok", ""))
    status_result = server.newton_change_status("quasar", SID)
    assert status_result["exit_code"] == 0
    assert status_result["log"] == {"kind": "untrusted-device-data", "source": "quasar:status", "text": "ok"}
    abort_result = server.newton_abort_change("quasar", SID)
    assert abort_result["exit_code"] == 0
    assert abort_result["log"] == {"kind": "untrusted-device-data", "source": "quasar:abort", "text": "ok"}
    audit = (configured / "state" / "mcp-audit.log").read_text()
    assert "newton_change_status" in audit and "newton_abort_change" in audit


def test_mcp_in_memory_client_lists_exactly_thirteen_tools():
    """Exercise the SDK's in-memory transport rather than an OS socket."""
    from mcp.shared.memory import create_connected_server_and_client_session
    async def listed():
        async with create_connected_server_and_client_session(server.mcp._mcp_server) as session:
            await session.initialize()
            return await session.list_tools()
    response = asyncio.run(listed())
    assert {tool.name for tool in response.tools} == server.TOOL_NAMES
    assert "newton_approve" not in {tool.name for tool in response.tools}
    apply_tool = next(tool for tool in response.tools if tool.name == "newton_apply_change")
    assert set(apply_tool.inputSchema["properties"]) == {"device", "session_id"}
    plan_tool = next(tool for tool in response.tools if tool.name == "newton_plan_change")
    assert set(plan_tool.inputSchema["properties"]) == {
        "device", "uci_batch", "timeout_s", "probes", "manifest_checks",
        "explanation", "owner_confirmed_in_chat"
    }
    # no tool is named probe and no tool takes a shell check any more
    assert "probe" not in {tool.name for tool in response.tools}
    assert "check" not in plan_tool.inputSchema["properties"]


def test_mcp_tool_descriptions_tell_the_agent_how_to_approve():
    """Both plan and apply descriptions point the agent at newton-approve and the session_id."""
    from mcp.shared.memory import create_connected_server_and_client_session
    async def listed():
        async with create_connected_server_and_client_session(server.mcp._mcp_server) as session:
            await session.initialize()
            return await session.list_tools()
    response = asyncio.run(listed())
    descriptions = {tool.name: tool.description for tool in response.tools}
    for name in ("newton_plan_change", "newton_apply_change"):
        assert "newton-approve" in descriptions[name]
        assert "session_id" in descriptions[name]
    # the plan description documents the probe list, the 19 probe names,
    # manifest_checks, and that no shell check exists
    plan_description = descriptions["newton_plan_change"]
    assert "no shell check" in plan_description
    assert "manifest_checks" in plan_description
    for probe_name in (
        "fail", "ping", "resolve", "service-running", "uci-equals", "uci-unset",
        "listen", "nft-rule", "nft-rule-order", "nft-rule-near", "nft-set-has",
        "conf-has", "proc-args", "iface-field", "iface-absent", "sysctl-equals",
        "ra-absent", "log-has", "root-password-class",
    ):
        assert probe_name in plan_description, probe_name
    # newton_read documents its read table compactly
    read_description = descriptions["newton_read"]
    for verb in ("uci", "ubus", "ifstatus", "nft", "logread", "ping", "traceroute", "nslookup"):
        assert verb in read_description, verb


# ---- security regressions found in review; the approval
# decisions themselves moved to tests/test_policy.py with policy.classify ----


def test_plan_existing_section_requires_approval_only_on_prod(configured_lab, monkeypatch):
    reads = []
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: _plan_cp())
    monkeypatch.setattr(
        server.NewtonService, "read",
        lambda self, d, c: reads.append(c) or {"exit_code": 0, "stdout": "host", "stderr": "", "truncated": False},
    )
    planned = server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    assert planned["approval_required"] is False
    assert planned["approval_reasons"] == []
    assert reads == []
    prod = configured_lab / "devices-prod.toml"
    prod.write_text('[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n')
    monkeypatch.setenv("NEWTON_INVENTORY", str(prod))
    planned_prod = server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    assert planned_prod["approval_required"] is True
    assert planned_prod["approval_reasons"] == ["profile 'prod': every write requires approval"]
    assert reads == []


def test_touched_configs_strip_operators():
    out = ("BACKUP /tmp/a.tar.gz (2 config files)\nSTAGED session=" + "a" * 32 + " from f\nBASEHASH " + "b" * 64
           + "\nPROBES 0 " + "c" * 64 + "\nPROFILE lab\nAPPROVAL not-required\nPLANDIGEST " + "d" * 64
           + "\n----- diff -----\n-firewall.x\ndhcp.y.dns+='1'\n----------------\n")
    assert server.parse_plan(out)["touched_configs"] == ["dhcp", "firewall"]


@pytest.mark.parametrize("command", ["ip -batch x", "ip -b -", "ip -force link", "iwinfo phy0-ap0 scan", "uci -q get dhcp.x"])
def test_more_reads_rejected(command):
    with pytest.raises(server.NewtonError):
        server.validate_read(command)


def test_ip_route_get_allowed():
    assert server.validate_read("ip route get 1.1.1.1")


@pytest.mark.parametrize("text,secret", [
    ("wireless.default_radio0.key='hunter2pass'", "hunter2pass"),
    ("\toption key 'hunter2pass'", "hunter2pass"),
    ("\toption sae_password \"s3cret!\"", "s3cret!"),
    ("network.wg0.private_key='AAAAbase64='", "AAAAbase64="),
    ("rpcd.@login[0].password='$p$root'", "$p$root"),
])
def test_secrets_redacted(text, secret):
    out = redact_mod.redact_text(text)
    assert secret not in out and "<redacted:" in out


def test_ssh_port_passed_to_script(configured):
    svc = server.NewtonService()
    assert svc.script_env(svc.device("quasar"))["OWRT_SSH_PORT"] == "22"


def test_mcp_identifies_operator_to_change_script(configured):
    """Guards: MCP-triggered protocol runs audit operator=mcp."""
    svc = server.NewtonService()
    assert svc.script_env(svc.device("quasar"))["OWRT_OPERATOR"] == "mcp"


def test_proxy_command_reaches_script_env_and_read(tmp_path, monkeypatch):
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.lab]\nplatform="openwrt"\nhost="10.109.0.11"\nuser="root"\nproxy_command="ssh -W %h:%p root@jump"\n')
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv)); monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    svc = server.NewtonService()
    assert svc.script_env(svc.device("lab"))["OWRT_SSH_PROXY"] == "ssh -W %h:%p root@jump"
    seen = {}
    def fake_run(args, **kw):
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, "ok", "")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    svc.read("lab", "uci show system")
    assert "ProxyCommand=ssh -W %h:%p root@jump" in seen["args"]


@pytest.mark.parametrize("bad", ['proxy_command="ssh jump"', 'proxy_command=5'])
def test_bad_proxy_command_rejected(tmp_path, monkeypatch, bad):
    inv = tmp_path / "devices.toml"
    inv.write_text(f'[devices.lab]\nplatform="openwrt"\nhost="h"\nuser="root"\n{bad}\n')
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    with pytest.raises(server.NewtonError):
        server.load_inventory()


def test_inventory_missing_profile_defaults_to_prod(configured):
    device = server.NewtonService().device("quasar")
    assert (device.profile, device.mgmt_interface, device.mgmt_zone) == ("prod", "lan", "lan")


def test_inventory_parses_profile_and_mgmt_names(tmp_path, monkeypatch):
    inv = tmp_path / "devices.toml"
    inv.write_text('[devices.r1]\nplatform="openwrt"\nhost="h"\nuser="root"\nprofile="lab"\nlab=true\nmgmt_interface="mgmt0"\nmgmt_zone="core"\n')
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    device = server.NewtonService().device("r1")
    assert (device.profile, device.mgmt_interface, device.mgmt_zone) == ("lab", "mgmt0", "core")
    assert server.NewtonService().list_devices()["devices"][0]["profile"] == "lab"


@pytest.mark.parametrize("bad", ['profile="staging"', "profile=3", 'mgmt_zone="not a zone"', "mgmt_interface=5", 'profile="prod"\nmgmt_interface="lan lan"'])
def test_inventory_rejects_invalid_profile_and_mgmt_names(tmp_path, monkeypatch, bad):
    inv = tmp_path / "devices.toml"
    inv.write_text(f'[devices.r1]\nplatform="openwrt"\nhost="h"\nuser="root"\n{bad}\n')
    monkeypatch.setenv("NEWTON_INVENTORY", str(inv))
    with pytest.raises(server.NewtonError):
        server.load_inventory()


def test_plan_without_profile_requires_approval_for_cosmetic_change(configured, monkeypatch):
    """Spec item 8: a device with no profile is prod, so even a cosmetic write needs approval."""
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: _plan_cp())
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    planned = server.newton_plan_change("quasar", "set dhcp.skilltest=host", **explained("set dhcp.skilltest=host"))
    assert planned["approval_required"] is True
    assert planned["approval_reasons"] == ["profile 'prod': every write requires approval"]
    saved = json.loads((configured / "state" / "plans" / f"{SID}.json").read_text())
    assert saved["requires_approval"] is True
    assert saved["reasons"] == planned["approval_reasons"]


def test_plan_refuses_non_staging_verbs(configured_lab, monkeypatch):
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: _plan_cp())
    result = server.newton_plan_change("quasar", "commit system\nset system.@system[0].hostname='x'", **explained("commit system\nset system.@system[0].hostname='x'"))
    assert "only set/add/add_list/del_list/delete/rename/reorder are allowed" in result["error"]


def test_plan_refuses_disguised_mutation_probe_before_staging(configured_lab, monkeypatch):
    """A probe outside the fixed grammar is refused before staging and cannot be applied."""
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: pytest.fail("must not stage or run the script"),
    )
    batch = "set system.@system[0].hostname=x"
    planned = server.newton_plan_change(
        "quasar", batch, probes=[["ping", "8.8.8.8; reboot"]], **explained(batch),
    )
    assert planned["error"] == "probe 1: bad-arg-1"
    # the host-only oracle rule: uci-equals on a secret option never stages
    planned = server.newton_plan_change(
        "quasar", batch, probes=[["uci-equals", "dropbear.@dropbear[0].Password", "on"]], **explained(batch),
    )
    assert planned["error"] == "probe 1: secret-option"
    plans = configured_lab / "state" / "plans"
    assert not plans.exists() or not list(plans.glob("*.json"))


def test_plan_with_router_required_approval_requires_approval_and_blocks_apply(
    configured_lab, monkeypatch
):
    """The router's APPROVAL required verdict alone forces approval and blocks apply."""
    text = (Path(__file__).parent / "fixtures" / "plan_output.txt").read_text().replace(
        "APPROVAL not-required", "APPROVAL required"
    )
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, text, ""),
    )
    batch = "set system.@system[0].hostname=x"
    planned = server.newton_plan_change("quasar", batch, **explained(batch))
    assert planned["approval_required"] is True
    assert planned["router_requires_approval"] is True
    saved = json.loads((configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert saved["requires_approval"] is True
    assert saved["router_requires_approval"] is True
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: pytest.fail("must not run"))
    result = server.newton_apply_change("quasar", SID)
    assert "approval required" in result["error"]
    assert f"sudo -u newton /usr/local/bin/newton-approve {SID}" in result["error"]


def test_plan_without_probes_stays_approval_free_on_lab(configured_lab, monkeypatch):
    """The same plan with no probes is still free on a lab device."""
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: _plan_cp())
    planned = server.newton_plan_change("quasar", "set system.@system[0].hostname=x", **explained("set system.@system[0].hostname=x"))
    assert planned["approval_required"] is False
    assert planned["approval_reasons"] == []
    assert planned["risk"] == "low"


def test_plan_record_carries_staged_at_after_successful_stage(
    configured_lab, monkeypatch
):
    """R2: every successful ``_stage_plan`` must leave an ISO UTC
    ``staged_at`` in the persisted record so approve.py can compute the
    device-side window without re-running plan().

    The field is captured AFTER the last successful stage so it can
    never lie about how fresh the stage on the device is.
    """
    monkeypatch.setattr(server.NewtonService, "run_script", lambda *a, **k: _plan_cp())
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    before = datetime.now(timezone.utc)
    server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", timeout_s=120, probes=[["fail"]], **explained("set dhcp.skilltest=host"),
    )
    after = datetime.now(timezone.utc)
    saved = json.loads((configured_lab / "state" / "plans" / f"{SID}.json").read_text())
    assert "staged_at" in saved, saved
    staged_at = datetime.fromisoformat(saved["staged_at"])
    # ISO UTC with the same shape as created_at (Z+00:00, tz-aware)
    assert staged_at.tzinfo is not None
    assert staged_at >= before
    assert staged_at <= after
    # staged_at IS part of the canonical hash: a stored record with a
    # future staged_at must not match the recomputed hash and therefore
    # must be refused by approve/apply.
    from newton_mcp.plan import PLAN_HASH_FIELDS
    assert "staged_at" in PLAN_HASH_FIELDS
    # removing it from the record breaks the hash (the field is required)
    with pytest.raises(ValueError):
        compute_plan_hash({k: v for k, v in saved.items() if k != "staged_at"})
    # and rewriting the value shifts the hash
    tampered = dict(saved)
    tampered["staged_at"] = "2099-01-01T00:00:00+00:00"
    assert compute_plan_hash(tampered) != saved["plan_hash"]


# --- APR-08: staged_at is stamped BEFORE the plan script
# starts, so the host's stage expiry is never later than the router's.


class _RecordingDatetime(datetime):
    """A datetime subclass that returns successive fixed values from
    ``_sequence`` on each ``.now(...)`` call, like test_approve's
    _SequenceDatetime.  Used by the APR-08 test to prove that
    ``staged_at`` is captured BEFORE the plan script runs -- the
    sequence is [before_script, ...] so a run_script stub can take the
    second ``now()`` to advance the clock and the recorded staged_at
    must still be the BEFORE instant.
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


def test_staged_at_is_stamped_before_plan_script_runs(configured_lab, monkeypatch):
    """APR-08: ``staged_at`` must be captured BEFORE the plan script
    starts.  The router counts stage age from stage-up at stage time,
    so a host that stamps staged_at AFTER the plan script returns
    (the previous behaviour) showed and capped an approval a few
    seconds to tens of seconds too late.  An approval at the edge
    would then fail with stale-stage and burn the human approval
    (APR-05).  This test patches ``datetime.now()`` to return one
    instant when ``_stage_plan`` stamps staged_at, and a LATER
    instant from the run_script stub.  The persisted staged_at must
    be the BEFORE instant -- the time the host handed the stage
    off to the router, not the time the script returned.
    """
    before_script = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
    after_script = datetime(2026, 10, 7, 12, 5, 0, tzinfo=timezone.utc)  # +5 min

    # The sequence: (1) the staged_at stamp inside _stage_plan,
    # (2) the first datetime.now() call inside the run_script stub
    # (the stub can use it to verify the script saw a LATER clock).
    _RecordingDatetime._sequence = [before_script, after_script]
    monkeypatch.setattr(server, "datetime", _RecordingDatetime)

    def fake_run(*args, **kwargs):
        # The second datetime.now() returns after_script; if
        # _stage_plan had stamped staged_at AFTER run_script, the
        # persisted value would be after_script and this test would
        # fail.  Use ``server.datetime`` (the patched subclass), not
        # the test module's bare ``datetime`` import, so the stub
        # actually advances the same clock _stage_plan advanced.
        observed = server.datetime.now(timezone.utc)
        assert observed == after_script, (
            f"the stub saw {observed!r}, expected the AFTER instant"
        )
        return _plan_cp()

    monkeypatch.setattr(server.NewtonService, "run_script", fake_run)
    monkeypatch.setattr(
        server.NewtonService, "read",
        lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False},
    )
    server.newton_plan_change(
        "quasar", "set dhcp.skilltest=host", timeout_s=120, probes=[["fail"]], **explained("set dhcp.skilltest=host"),
    )
    saved = json.loads(
        (configured_lab / "state" / "plans" / f"{SID}.json").read_text()
    )
    staged_at = datetime.fromisoformat(saved["staged_at"])
    assert staged_at == before_script, (
        f"staged_at={staged_at!r} should equal the BEFORE instant "
        f"captured before run_script started, not {after_script!r}"
    )
