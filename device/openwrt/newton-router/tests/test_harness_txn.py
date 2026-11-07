"""Smoke tests for the transaction harness.

The fake ubus is stateful (control/rpcd-backup, control/rpcd-pending.json,
control/rpcd-lost, control/{apply,confirm,rollback}.rc) and the new Router
helpers wrap it. These tests are the proof that the harness is trustworthy:
the helpers' output matches what the program would see, and the fake
preserves the behaviour the rest of the suite relies on.
"""

import json
import re
import subprocess
from pathlib import Path

import pytest

from conftest import PROGRAM, SID


def _ubus(root, *args, timeout=10):
    e = {"NEWTON_ROUTER_ROOT": str(root), "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    proc = subprocess.run(
        [str(root / "bin/ubus")] + [str(a) for a in args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_fresh_plan_returns_sealed_plan(router):
    plan = router.fresh_plan()
    assert (plan.txn / "sealed").exists()
    assert plan.digest and plan.base and plan.diff and plan.psha
    assert all(len(x) == 64 for x in (plan.digest, plan.base, plan.diff, plan.psha))


def test_uci_apply_overwrites_dhcp_with_staged_and_records_pending(router):
    plan = router.fresh_plan()
    staged = router.root / "control/staged/dhcp"
    rc, _, _ = _ubus(
        router.root, "call", "uci", "apply",
        json.dumps({"rollback": True, "timeout": plan.t, "ubus_rpc_session": plan.sid}),
    )
    assert rc == 0
    assert (router.root / "etc/config/dhcp").read_bytes() == staged.read_bytes()
    pending = json.loads((router.root / "control/rpcd-pending.json").read_text())
    assert pending["sid"] == plan.sid
    assert isinstance(pending["deadline"], int)
    calls = router.calls_matching("ubus uci-apply")
    assert any("guard-pending=0" in c for c in calls)


def test_rpcd_tick_before_deadline_keeps_change_after_restores(router):
    plan = router.fresh_plan()
    apply_args = [
        "call", "uci", "apply",
        json.dumps({"rollback": True, "timeout": plan.t, "ubus_rpc_session": plan.sid}),
    ]
    assert _ubus(router.root, *apply_args)[0] == 0
    staged = (router.root / "control/staged/dhcp").read_bytes()
    assert (router.root / "etc/config/dhcp").read_bytes() == staged
    router.set_uptime(50)
    assert router.rpcd_tick() == 0
    assert (router.root / "etc/config/dhcp").read_bytes() == staged
    pending = json.loads((router.root / "control/rpcd-pending.json").read_text())
    router.set_uptime(pending["deadline"] + 5)
    assert router.rpcd_tick() == 0
    live = (router.root / "etc/config/dhcp").read_bytes()
    assert live != staged
    assert not (router.root / "control/rpcd-pending.json").exists()


def test_uci_confirm_exits_5_with_rpcd_lost_and_0_otherwise(router):
    plan = router.fresh_plan()
    apply_args = [
        "call", "uci", "apply",
        json.dumps({"rollback": True, "timeout": plan.t, "ubus_rpc_session": plan.sid}),
    ]
    assert _ubus(router.root, *apply_args)[0] == 0
    (router.root / "control/rpcd-lost").write_text("")
    confirm_args = ["call", "uci", "confirm", json.dumps({"ubus_rpc_session": plan.sid})]
    assert _ubus(router.root, *confirm_args)[0] == 5
    assert (router.root / "control/rpcd-pending.json").exists()
    (router.root / "control/rpcd-lost").unlink()
    assert _ubus(router.root, *confirm_args)[0] == 0
    assert not (router.root / "control/rpcd-pending.json").exists()


def test_uci_rollback_restores_backup_and_clears_pending(router):
    plan = router.fresh_plan()
    apply_args = [
        "call", "uci", "apply",
        json.dumps({"rollback": True, "timeout": plan.t, "ubus_rpc_session": plan.sid}),
    ]
    assert _ubus(router.root, *apply_args)[0] == 0
    staged = (router.root / "control/staged/dhcp").read_bytes()
    assert (router.root / "etc/config/dhcp").read_bytes() == staged
    backup = (router.root / "control/rpcd-backup/dhcp").read_bytes()
    rollback_args = ["call", "uci", "rollback", json.dumps({"ubus_rpc_session": plan.sid})]
    assert _ubus(router.root, *rollback_args)[0] == 0
    assert (router.root / "etc/config/dhcp").read_bytes() == backup
    assert not (router.root / "control/rpcd-pending.json").exists()
    assert _ubus(router.root, *rollback_args)[0] == 5


def test_session_destroy_removes_sid_from_sessions(router):
    sessions = router.root / "control/sessions"
    assert SID in sessions.read_text()
    args = ["call", "session", "destroy", json.dumps({"ubus_rpc_session": SID})]
    assert _ubus(router.root, *args)[0] == 0
    assert SID not in sessions.read_text()


@pytest.mark.parametrize(
    "setup,expected",
    [
        ("listed", 0),
        ("unlisted", 4),
        ("ubus-rc-3", 3),
    ],
    ids=["listed", "unlisted", "ubus-rc-3"],
)
def test_session_list_old_behaviour_preserved(router, setup, expected):
    list_args = ["call", "session", "list", json.dumps({"ubus_rpc_session": SID})]
    if setup == "unlisted":
        router.write("control/sessions", b"")
    if setup == "ubus-rc-3":
        router.write("control/ubus.rc", "3\n")
    code, _, _ = _ubus(router.root, *list_args)
    assert code == expected


def test_token_is_64_hex_and_differs_per_digest(router):
    nbf, exp = router.window()
    a = router.token("a" * 64, nbf, exp)
    b = router.token("b" * 64, nbf, exp)
    assert re.fullmatch(r"[0-9a-f]{64}", a)
    assert a != b


def test_guard_status_idle_then_pending_after_arm(router):
    plan = router.fresh_plan()
    assert router.guard_status() == "idle"
    router.set_fake(
        "df",
        out=(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/sda1 1000000 1000 999000 1% /etc\n"
        ),
    )
    res = router.guard("arm", plan.sid, "120")
    assert res.rc == 0 and res.out.startswith("armed")
    assert router.guard_status().startswith(f"pending {plan.sid}")


def test_scratch_program_replaces_one_line_and_overrides_program(router, tmp_path):
    text = PROGRAM.read_text()
    target = "RPCD_LOST=''"
    if text.count(target) != 1:
        target = "PROG_PID=$$"
    path = router.scratch_program(tmp_path, target, target + ": scratch")
    assert path.exists()
    assert router.program == path
    assert (target + ": scratch") in path.read_text()
    assert path.read_text().count(target + ": scratch") == 1
