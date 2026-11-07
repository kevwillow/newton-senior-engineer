"""Design 6.3 `confirm` and 9.2 groups 5 and 6.

Covers the `cmd_confirm` refusals (`too-late`, `not-applied`, role, owner),
the rpcd-confirm-failed branch, the lost-timer (RPCD_LOST) path, the
guard-refused-its-confirm path (M27), the kill between rpcd confirm and
the guard's confirm (M-crash), and the happy path (M26, M47). Each test
asserts something a plausible defect would break; the exact stdout,
stderr, and exit codes are pinned.
"""

import subprocess

import pytest

from conftest import PROGRAM


DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


def lock_is_free(router):
    proc = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return proc.returncode == 0


def ready_for_arm(router):
    router.set_fake("df", out=DF_OUT)


def snapshot_config(router):
    cfg = router.root / "etc/config"
    return {p.name: p.read_bytes() for p in sorted(cfg.iterdir())
            if p.is_file() and not p.is_symlink()}


def applied(router, t=90, **kw):
    """A sealed and applied plan, with the rpcd save dir in place.

    Returns the same SimpleNamespace as `fresh_plan`. Asserts that the
    apply returned rc=0. The default T=90 and the fixture uptime of 100
    give the rpcd deadline 190, the guard deadline 221, and
    `pending <sid> 121`."""
    plan = router.fresh_plan(t=t, **kw)
    ready_for_arm(router)
    profile = kw.get("profile", "lab")
    if profile == "prod":
        nbf, exp = router.window()
        token = router.token(plan.digest, nbf, exp)
    else:
        token = "none"
        nbf = 0
        exp = 0
    res = router.apply(plan.sid, plan.t, token, nbf, exp, caller=kw.get("caller", "agent-one"))
    assert res.rc == 0, (res.rc, res.out, res.err)
    rpcd_dir = router.root / "var/run/rpcd" / f"uci-{plan.sid}"
    rpcd_dir.mkdir(parents=True, exist_ok=True)
    return plan


# ---- 1. happy path (M26) -------------------------------------------------


def test_confirm_happy_path(router):
    """Stdout exactly `confirmed <sid>\\n`, stderr empty, exit 0; calls.log
    shows `ubus uci-confirm sid=<sid> guard-pending=1` before the
    `session destroy` line; the guard is `idle`; `tmp/newton/last` =
    `confirmed <sid>\\n`; the whole lock dir is gone; `var/run/rpcd/uci-<sid>`
    is gone; the session is destroyed; `etc/config` keeps the new content;
    the program lock is free; the stdout is exactly one line (M47)."""
    plan = applied(router)
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    calls = router.calls()
    confirm_line = f"ubus uci-confirm sid={plan.sid} guard-pending=1"
    assert confirm_line in calls, calls
    destroy_idx = next(i for i, c in enumerate(calls)
                       if c.startswith("ubus call session destroy"))
    confirm_idx = calls.index(confirm_line)
    assert confirm_idx < destroy_idx, (confirm_idx, destroy_idx, calls)
    assert router.guard_status() == "idle"
    assert (router.root / "tmp/newton/last").read_text() == f"confirmed {plan.sid}\n"
    assert not (router.root / "tmp/owrt-safe-apply.lock").exists()
    assert not (router.root / "var/run/rpcd" / f"uci-{plan.sid}").exists()
    sessions = (router.root / "control/sessions").read_text()
    assert plan.sid not in sessions.split()
    assert any("session destroy" in c for c in calls)
    staged_dhcp = (router.root / "control/staged/dhcp").read_bytes()
    assert (router.root / "etc/config/dhcp").read_bytes() == staged_dhcp
    assert lock_is_free(router)
    assert res.out.count("\n") == 1
    assert "confirmed" in res.out and plan.sid in res.out


# ---- 2. too-late (6.3 step 3) --------------------------------------------


def _nothing_changed_after_too_late(router, plan):
    """The post-too-late invariants: no `uci-confirm` log line, the guard
    is still `pending`, the txn dir still exists with its `applied` file."""
    assert not router.calls_matching("ubus uci-confirm")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert (plan.txn / "applied").exists()
    assert (plan.txn / "owner").exists()
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "uptime,expect_ok",
    [
        (186, False),  # rpcd_dl - UP_NOW = 4, too-late
        (185, True),   # rpcd_dl - UP_NOW = 5, confirms (5 boundary)
        (191, False),  # rpcd_dl passed
    ],
    ids=["rpcd-4", "rpcd-5", "rpcd-passed"],
)
def test_confirm_too_late_rpcd_deadline(router, uptime, expect_ok):
    """rpcd_dl is 190; the cutoff is 5 s away. At UP_NOW=186 the
    difference is 4 -> too-late; at UP_NOW=185 it is 5 -> confirms; at
    UP_NOW=191 the deadline is past -> too-late. Nothing changed on the
    refused runs."""
    plan = applied(router)
    router.set_uptime(uptime)
    res = router.forced(f"confirm {plan.sid}")
    if expect_ok:
        assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    else:
        assert (res.rc, res.err, res.out) == (3, "error too-late\n", "")
        _nothing_changed_after_too_late(router, plan)


@pytest.mark.parametrize(
    "uptime,expect_ok",
    [
        (217, False),  # guard_left = 4, too-late (pushes rpcd_dl away)
        (216, True),   # guard_left = 5, confirms (5 boundary)
        (222, False),  # guard deadline passed; guard shows pending 0
    ],
    ids=["guard-4", "guard-5", "guard-passed"],
)
def test_confirm_too_late_guard_window(router, uptime, expect_ok):
    """Hand-write `txn/applied` to `100000 221 boot-one` to push the
    rpcd deadline far away; the guard deadline is still 221. At
    UP_NOW=217 the guard left is 4 -> too-late; at UP_NOW=216 it is 5
    -> confirms; at UP_NOW=222 the deadline is past and the guard
    reports `pending <sid> 0`."""
    plan = applied(router)
    (plan.txn / "applied").write_text("100000 221 boot-one\n")
    router.set_uptime(uptime)
    res = router.forced(f"confirm {plan.sid}")
    if expect_ok:
        assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    else:
        assert (res.rc, res.err, res.out) == (3, "error too-late\n", "")
        _nothing_changed_after_too_late(router, plan)


# ---- 3. not-applied (6.3 step 2) -----------------------------------------


@pytest.mark.parametrize(
    "setup",
    [
        "sealed-not-applied",
        "boot-id-mismatch",
        "applying-without-applied",
    ],
    ids=["sealed-not-applied", "boot-id-mismatch", "applying-without-applied"],
)
def test_confirm_not_applied(router, setup):
    """A sealed plan with no `applied` file; an `applied` file whose
    boot id differs from the live boot id; an `applying` file but no
    `applied`. All three are refused with `error not-applied`, exit 1."""
    if setup == "sealed-not-applied":
        plan = router.fresh_plan()
    elif setup == "boot-id-mismatch":
        plan = applied(router)
        router.set_boot_id("boot-two")
    else:
        plan = applied(router)
        (plan.txn / "applied").unlink()
    live = snapshot_config(router)
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.err, res.out) == (1, "error not-applied\n", "")
    assert not router.calls_matching("ubus uci-confirm")
    assert snapshot_config(router) == live
    assert lock_is_free(router)


# ---- 4. rpcd confirm fails (6.3 step 4) ----------------------------------


def test_confirm_rpcd_confirm_failed(router):
    """`control/confirm.rc` = 1: stderr exactly `error rpcd-confirm-failed
    1`, exit 1; the guard stays armed (`pending`), `etc/config` unchanged
    (still the applied content), the txn kept, no `rpcd-confirmed` file;
    after `set_uptime(300)` and `status` the answer starts with
    `rolled-back` (the guard restored by itself)."""
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "1\n")
    post_dhcp = (router.root / "etc/config/dhcp").read_bytes()
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.err, res.out) == (1, "error rpcd-confirm-failed 1\n", "")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert (router.root / "etc/config/dhcp").read_bytes() == post_dhcp
    assert (plan.txn / "applied").exists()
    assert (plan.txn / "owner").exists()
    assert not (plan.txn / "rpcd-confirmed").exists()
    assert lock_is_free(router)
    router.set_uptime(300)
    status = router.forced(f"status {plan.sid}", role="read")
    assert status.rc == 0, (status.rc, status.out, status.err)
    assert status.err == ""
    assert status.out.split(" ", 1)[0] == "rolled-back", status.out


# ---- 5. lost-timer path (6.3 step 4) -------------------------------------


def test_confirm_lost_timer_shipped_program_rpcd_5(router):
    """The shipped program has `RPCD_LOST=''` (fail-safe). With
    `control/confirm.rc` = 5: `error rpcd-confirm-failed 5`, exit 1,
    the guard stays armed."""
    text = PROGRAM.read_text()
    assert text.count("RPCD_LOST=''") == 1
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "5\n")
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.err, res.out) == (1, "error rpcd-confirm-failed 5\n", "")
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_confirm_lost_timer_5_with_post(router, tmp_path):
    """Scratch program with `RPCD_LOST='5 6'`; `control/confirm.rc` = 5
    and the confighash equals `post`: stdout `confirmed <sid>
    rpcd-timer-lost`, exit 0, guard idle, `etc/config` kept."""
    router.scratch_program(tmp_path, "RPCD_LOST=''", "RPCD_LOST='5 6'")
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "5\n")
    post_dhcp = (router.root / "etc/config/dhcp").read_bytes()
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.out, res.err) == (
        0, f"confirmed {plan.sid} rpcd-timer-lost\n", "",
    )
    assert router.guard_status() == "idle"
    assert (router.root / "etc/config/dhcp").read_bytes() == post_dhcp
    assert (router.root / "tmp/newton/last").read_text() == \
        f"confirmed {plan.sid}\n"


def test_confirm_lost_timer_6_with_post(router, tmp_path):
    """Same scratch program, rc=6: still the lost path, stdout
    `confirmed <sid> rpcd-timer-lost`, exit 0."""
    router.scratch_program(tmp_path, "RPCD_LOST=''", "RPCD_LOST='5 6'")
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "6\n")
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.out, res.err) == (
        0, f"confirmed {plan.sid} rpcd-timer-lost\n", "",
    )
    assert router.guard_status() == "idle"


def test_confirm_lost_timer_7_not_listed(router, tmp_path):
    """Same scratch program, rc=7 (not in RPCD_LOST): the lost branch
    is off, so `rpcd-confirm-failed 7` exit 1."""
    router.scratch_program(tmp_path, "RPCD_LOST=''", "RPCD_LOST='5 6'")
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "7\n")
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.err, res.out) == (1, "error rpcd-confirm-failed 7\n", "")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert not (plan.txn / "rpcd-confirmed").exists()


def test_confirm_lost_timer_5_config_changed(router, tmp_path):
    """Same scratch program, rc=5 but `etc/config` was edited after the
    apply: confighash no longer equals `post` -> the lost path is off
    (defence against a half-rolled-back change), `rpcd-confirm-failed
    5`, exit 1, guard stays armed (M28)."""
    router.scratch_program(tmp_path, "RPCD_LOST=''", "RPCD_LOST='5 6'")
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "5\n")
    router.write(
        "etc/config/network",
        b"config interface 'lan'\n\toption proto 'dhcp'\n",
    )
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.err, res.out) == (1, "error rpcd-confirm-failed 5\n", "")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert not (plan.txn / "rpcd-confirmed").exists()


def test_confirm_lost_timer_whole_word_match(router, tmp_path):
    """`RPCD_LOST='15 6'` and rc=5: whole-word matching means `5` is not
    in the list (the word is `15`), so the lost branch is off ->
    `rpcd-confirm-failed 5`, exit 1, guard stays armed."""
    router.scratch_program(tmp_path, "RPCD_LOST=''", "RPCD_LOST='15 6'")
    plan = applied(router)
    router.set_fake("ubus")
    router.write("control/confirm.rc", "5\n")
    res = router.forced(f"confirm {plan.sid}")
    assert (res.rc, res.err, res.out) == (1, "error rpcd-confirm-failed 5\n", "")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert not (plan.txn / "rpcd-confirmed").exists()


# ---- 6. guard refuses its confirm after rpcd confirmed (M27) -------------


def test_confirm_guard_refuses_its_confirm(router):
    """`control/confirm-hook` overwrites `proc/uptime` to `300.00 90.00`
    so the guard's window is past. The rpcd confirm still succeeds (the
    hook is run during that call), but the guard's `confirm` returns
    `refused expired` and the program fails with `confirm-incomplete`,
    exit 1, stdout empty, `etc/config` back at the original bytes, the
    guard is `restored <sid> confirm-incomplete`."""
    live = snapshot_config(router)
    plan = applied(router)
    assert snapshot_config(router) != live
    router.write(
        "control/confirm-hook",
        f'printf "300.00 90.00\\n" > "{router.root}/proc/uptime"\n',
    )
    res = router.forced(f"confirm {plan.sid}")
    assert res.rc == 1, (res.rc, res.out, res.err)
    assert res.out == ""
    assert res.err.startswith("error confirm-incomplete "), res.err
    assert snapshot_config(router) == live
    assert router.guard_status() == f"restored {plan.sid} confirm-incomplete"
    assert lock_is_free(router)


# ---- 7. roles: not-owner / read role / root (direct mode) ----------------


def test_confirm_other_caller_is_not_owner(router):
    """A non-owner confirming the plan is refused with `error not-owner`."""
    plan = applied(router)
    res = router.forced(f"confirm {plan.sid}", caller="agent-two")
    assert (res.rc, res.err, res.out) == (3, "error not-owner\n", "")
    assert not router.calls_matching("ubus uci-confirm")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert lock_is_free(router)


def test_confirm_read_role_is_refused(router):
    """A read role confirming the plan is refused with `error role`."""
    plan = applied(router)
    res = router.forced(f"confirm {plan.sid}", role="read")
    assert (res.rc, res.err, res.out) == (3, "error role\n", "")
    assert not router.calls_matching("ubus uci-confirm")
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert lock_is_free(router)


def test_confirm_root_can_confirm_direct(router):
    """Root (direct mode) can confirm the plan without any owner check."""
    plan = applied(router)
    res = router.direct("confirm", plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- 8. kill between rpcd confirm and the guard's confirm (M-crash) ------


def test_confirm_kill_after_rpcd_confirm(router):
    """`NEWTON_ROUTER_CRASH_AT` = 1 (the first crash point of confirm,
    right after `rpcd-confirmed` is written). The run is killed (rc
    -9); the guard is still `pending`; after `set_uptime(300)` and
    `router.guard("tick")` the guard restored (`restored <sid>
    deadline`) and `etc/config` has the original bytes."""
    live = snapshot_config(router)
    plan = applied(router)
    assert snapshot_config(router) != live
    res = router.forced(
        f"confirm {plan.sid}", caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": "1"}, timeout=30,
    )
    assert res.rc == -9, (res.rc, res.out, res.err)
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert (plan.txn / "rpcd-confirmed").read_text() == "ok\n"
    router.set_uptime(300)
    tick = router.guard("tick")
    assert tick.rc == 0, (tick.rc, tick.out, tick.err)
    assert router.guard_status() == f"restored {plan.sid} deadline"
    assert snapshot_config(router) == live
    assert lock_is_free(router)


# ---- 9. SIGHUP during confirm (skipped: fake cannot limit ubus.sleep) -----


def test_confirm_sighup_is_ignored(router):
    """A SIGHUP while `uci confirm` runs is ignored (design 3.4: confirm traps HUP and PIPE;
    6.7: "connection dropped during confirm": the program finishes and the guard is confirmed).

    The fake ubus runs `control/confirm-hook` inside its `uci confirm` call: the hook writes a
    marker and sleeps, so the test sends SIGHUP to the process group once the marker exists
    (never before the program's trap is in place)."""
    import os
    import signal
    import time

    from conftest import BUSYBOX

    plan = applied(router)
    marker = router.root / "control/confirm-started"
    router.write(
        "control/confirm-hook",
        f'touch "{marker}"\n/usr/bin/sleep 2\n',
    )
    env = router._merged_env({
        "SSH_ORIGINAL_COMMAND": f"confirm {plan.sid}", "PATH": "/usr/bin:/bin", "LC_ALL": "C",
    })
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(router.program), "--caller=agent-one", "--role=change"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "uci confirm never started"
        os.killpg(proc.pid, signal.SIGHUP)
        out, err = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert (proc.returncode, out.decode(), err.decode()) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"
    assert not (router.root / "tmp/owrt-safe-apply.lock").exists()
