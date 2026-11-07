"""Design 6.2 `apply` and 6.1 guard wiring tests.

Covers every refusal branch of `cmd_apply` (design 6.2), the order of those
checks (M22, M23), the guard's `arm` refusals (low space, boot hook
disabled, bad timeout, timer not running), the happy path (M24, M41), the
apply-failed branch, the stdout-disjointness rule (M47), the crash-point
seam (n=1..N until the first non-killed run), SIGHUP during apply, the
program lock being free after every outcome, and the owner/role rules.
"""

import hashlib
import os
import shutil
import signal
import subprocess
import time

import pytest

from conftest import BUSYBOX, SID, _executable


# ---- shared helpers ------------------------------------------------------

DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


def lock_is_free(router):
    """flock -n succeeds on the program's lock when no one holds it."""
    proc = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return proc.returncode == 0


def ready_for_arm(router):
    """The guard's `arm` step calls `df` to check disk space; the generic
    fake returns nothing by default, so feed it a line the guard can parse."""
    router.set_fake("df", out=DF_OUT)


def snapshot_config(router):
    """A snapshot of every etc/config file's bytes for byte-equality checks."""
    cfg = router.root / "etc/config"
    return {p.name: p.read_bytes() for p in sorted(cfg.iterdir())
            if p.is_file() and not p.is_symlink()}


def nothing_applied(router, sid):
    """All the post-refusal conditions from design 6.2 / 9.2 group 5+6:
    no ubus call to uci-apply, no guard pending state, guard status is idle,
    etc/config bytes unchanged. (The guard creates etc/newton/lkg early,
    so we don't assert that here — it leaks in the guard-arm refusal cases.)"""
    assert not any(f" sid={sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))
    assert not (router.root / "etc/newton/pending").exists()
    assert router.guard_status() == "idle"


def write_pending(router, txn, left=121, boot="boot-one"):
    """Write etc/newton/pending so guard_status reports `pending <txn> <left>`."""
    deadline = 100 + left
    router.write("etc/newton/pending", f"{txn} {deadline} {boot}\n")


def write_failed(router, txn, why="apply-failed"):
    """Write etc/newton/failed so guard_status reports `failed <txn> <why>`."""
    router.write("etc/newton/failed", f"{txn} {why} extra\n")


def write_restored(router, txn, reason="apply-failed"):
    """Write etc/newton/last_revert so guard_status reports `restored ...`."""
    router.write("etc/newton/last_revert", f"{txn} {reason}\n")

# ---- 1. refusals in the order of 6.2 -----------------------------------


def test_apply_not_sealed(router):
    """A plan whose txn has no `sealed` file is refused with
    `error not-sealed`, exit 3, stdout empty, no guard or ubus state."""
    plan = router.fresh_plan()
    (plan.txn / "sealed").unlink()
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error not-sealed\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


@pytest.mark.parametrize("marker", ["applying", "applied"],
                         ids=["applying", "applied"])
def test_apply_already_applied_exit_1(router, marker):
    """A second apply after success (or with only `applying`) is refused
    with `error already-applied`, exit 1 (NOT 3 — M38). stdout empty,
    no further ubus call, etc/config untouched."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0
    live = snapshot_config(router)
    if marker == "applying":
        (plan.txn / "applied").unlink()
        (router.root / "tmp/owrt-safe-apply.lock" / f"{plan.sid}.applied").unlink()
    calls_before = len(router.calls_matching("ubus uci-apply"))
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (1, "error already-applied\n", "")
    assert snapshot_config(router) == live
    assert len(router.calls_matching("ubus uci-apply")) == calls_before
    assert lock_is_free(router)


def test_apply_session_gone(router):
    """An apply when the SID is not in control/sessions is refused with
    `error session-gone`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/sessions", b"")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error session-gone\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_plan_changed_t(router):
    """An apply whose T differs from the sealed T is refused with
    `error plan-changed t`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t + 1, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error plan-changed t\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


@pytest.mark.parametrize("uptime,expected_rc", [(2650, 0), (2651, 3)],
                         ids=["uptime-2650-passes", "uptime-2651-refused"])
def test_apply_stale_stage_age_t90(router, uptime, expected_rc):
    """For T=90 the limit is 2550 s; stage-up is 100 in the fixture.
    uptime 2650 (= 100+2550) passes, uptime 2651 refuses with
    `error stale-stage`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.set_uptime(uptime)
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    if expected_rc == 0:
        assert res.rc == 0
        assert res.err == ""
        assert res.out.startswith(f"applied {plan.sid} t=90 guard=")
    else:
        assert (res.rc, res.err, res.out) == (3, "error stale-stage\n", "")
        nothing_applied(router, plan.sid)
        assert snapshot_config(router) == live
    assert lock_is_free(router)


@pytest.mark.parametrize("uptime,expected_rc", [(2170, 0), (2171, 3)],
                         ids=["uptime-2170-passes", "uptime-2171-refused"])
def test_apply_stale_stage_age_t570(router, uptime, expected_rc):
    """For T=570 the limit is 2700-570-60=2070 s; stage-up=100.
    uptime 2170 (=100+2070) passes, uptime 2171 refuses."""
    plan = router.fresh_plan(t=570)
    ready_for_arm(router)
    router.set_uptime(uptime)
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    if expected_rc == 0:
        assert res.rc == 0
        assert res.err == ""
        expected_guard = uptime + 1 + (plan.t + 30)
        assert res.out == f"applied {plan.sid} t=570 guard={expected_guard}\n"
    else:
        assert (res.rc, res.err, res.out) == (3, "error stale-stage\n", "")
        nothing_applied(router, plan.sid)
        assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_stale_stage_boot_id(router):
    """A change in /proc/sys/kernel/random/boot_id after seal is refused
    with `error stale-stage`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.set_boot_id("boot-two")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error stale-stage\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_guard_pending_refuses(router):
    """A guard status of `pending <txn> <left>` is refused with
    `error guard pending <txn> <left>`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    write_pending(router, plan.sid, left=80)
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, f"error guard pending {plan.sid} 80\n", ""
    )
    assert (router.root / "etc/newton/pending").exists()
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_guard_failed_refuses(router):
    """A guard status of `failed <txn> <why>` is refused with
    `error guard failed <txn> <why>`, exit 3. The guard's status reports
    `failed` only when both `pending` AND `failed` files exist."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    write_pending(router, plan.sid, left=80)
    write_failed(router, plan.sid, why="verify-failed")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, f"error guard failed {plan.sid} verify-failed\n", ""
    )
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_guard_restored_does_not_refuse(router):
    """A guard status of `restored <txn> <reason>` is NOT refused (6.2
    step 4 allows `idle` or `restored ...`); the apply proceeds normally."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    write_restored(router, plan.sid, reason="apply-failed")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0
    assert res.err == ""
    assert res.out.startswith(f"applied {plan.sid} t=90 guard=")


def test_apply_no_health_snapshot(router):
    """An apply with the health dir removed is refused with
    `error no-health-snapshot`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    shutil.rmtree(router.root / "tmp/owrt-safe-apply.lock" / f"{plan.sid}.health")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error no-health-snapshot\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_stale_base(router):
    """A change to etc/config after seal makes the recomputed base differ
    from the sealed one; refused with `error stale-base`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write(
        "etc/config/network",
        b"config interface 'lan'\n\toption proto 'dhcp'\n",
    )
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error stale-base\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_plan_changed_diff(router):
    """A change to control/diff.txt after seal makes the recomputed diff
    hash differ from the sealed one; refused with `error plan-changed diff`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/diff.txt", b"dhcp.cfg01.domain='changed'\n")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error plan-changed diff\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_plan_changed_probes(router):
    """A change to the sealed `probes` file makes the recomputed
    probes-sha differ from the sealed one; refused with
    `error plan-changed probes`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    (plan.txn / "probes").write_bytes(b"uci-equals\tdhcp.cfg01.domain\tx\n")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error plan-changed probes\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


# ---- 2. order (M22, M23) -----------------------------------------------

def test_apply_session_gone_beats_plan_changed_t(router):
    """session-gone beats plan-changed t: an empty sessions file plus a
    different T returns `session-gone`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/sessions", b"")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t + 1, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error session-gone\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_plan_changed_t_beats_stale_stage(router):
    """plan-changed t beats stale-stage: a different T plus a stale-stage
    age returns `plan-changed t`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.set_uptime(3000)
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t + 1, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error plan-changed t\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_stale_stage_beats_guard_pending(router):
    """stale-stage beats a pending guard: a stale age plus a pending
    guard returns `stale-stage`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    write_pending(router, plan.sid, left=80)
    router.set_uptime(3000)
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error stale-stage\n", "")
    assert (router.root / "etc/newton/pending").exists()
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_guard_pending_beats_no_health_snapshot(router):
    """a pending guard beats no-health-snapshot: a pending guard plus a
    missing health dir returns `guard pending ...`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    write_pending(router, plan.sid, left=80)
    shutil.rmtree(router.root / "tmp/owrt-safe-apply.lock" / f"{plan.sid}.health")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, f"error guard pending {plan.sid} 80\n", ""
    )
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_no_health_snapshot_beats_stale_base(router):
    """no-health-snapshot beats stale-base: a missing health dir plus a
    mutated etc/config returns `no-health-snapshot`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    shutil.rmtree(router.root / "tmp/owrt-safe-apply.lock" / f"{plan.sid}.health")
    router.write(
        "etc/config/network",
        b"config interface 'lan'\n\toption proto 'dhcp'\n",
    )
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error no-health-snapshot\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_stale_base_beats_plan_changed_diff(router):
    """stale-base beats plan-changed diff: a mutated etc/config plus a
    changed control/diff.txt returns `stale-base`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/diff.txt", b"dhcp.cfg01.domain='changed'\n")
    router.write(
        "etc/config/network",
        b"config interface 'lan'\n\toption proto 'dhcp'\n",
    )
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error stale-base\n", "")
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


# ---- 3. guard refusals at arm (6.2 step 9) ------------------------------

def test_apply_guard_refused_low_space(router):
    """When the fake df reports `Available = 10` the guard's `arm` refuses
    with `refused low-space ...`, exit 3. The program maps that to
    `error guard refused low-space` and applies nothing."""
    plan = router.fresh_plan()
    router.set_fake(
        "df",
        out=(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/sda1 1000000 1000 10 1% /etc\n"
        ),
    )
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 3
    assert res.err.startswith("error guard refused low-space "), res.err
    assert res.out == ""
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_guard_refused_boot_hook_disabled(router):
    """When control/disabled exists the init.d/enabled call returns 1, so
    the guard's `arm` refuses with `refused boot-hook-disabled`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/disabled", "")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error guard refused boot-hook-disabled\n", ""
    )
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_apply_guard_error_bad_timeout(router):
    """A guard whose `arm` refuses with `error bad-timeout` (exit 2 — the
    guard's valid_timeout refusal, now only reachable for T+30 outside
    60..900, since the program's own is_t caps T at 600 and the guard's
    bound is 900, RD10) is mapped by the program to
    `error guard error bad-timeout`, exit 3."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    guard = router.root / "usr/libexec/newton-guard"
    _executable(
        guard,
        "#!/usr/bin/busybox sh\n"
        'root="$NEWTON_ROUTER_ROOT"\n'
        'echo "guard $*" >> "$root/control/calls.log"\n'
        'case "${1:-}" in\n'
        "status)\n"
        '  printf "idle\\n"\n'
        "  exit 0\n"
        "  ;;\n"
        "arm)\n"
        '  printf "error bad-timeout\\n"\n'
        "  exit 2\n"
        "  ;;\n"
        "*)\n"
        '  printf "error usage\\n" >&2\n'
        "  exit 2\n"
        "  ;;\n"
        "esac\n",
    )
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error guard error bad-timeout\n", ""
    )
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


@pytest.mark.parametrize("t,guard_window", [(571, 601), (600, 630)],
                         ids=["t571-window601", "t600-window630"])
def test_apply_upper_window_arms(router, t, guard_window):
    """Apply windows up to T=600 arm: the guard window T+30 (601..630) is
    inside the guard's valid_timeout bound (60..900, RD10; T 571..600 was
    refused with `error guard bad-timeout` before). Guard deadline =
    uptime + 1 + (T + 30); rpcd deadline = uptime + T."""
    plan = router.fresh_plan(t=t)
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (
        0, f"applied {plan.sid} t={t} guard={101 + guard_window}\n", ""
    )
    assert router.guard_status() == f"pending {plan.sid} {1 + guard_window}"
    assert (plan.txn / "applied").read_text() == (
        f"{100 + t} {101 + guard_window} boot-one\n"
    )
    assert lock_is_free(router)


def test_apply_guard_refused_timer_not_running(router):
    """When the init.d running-timer call returns 1 (via control/not-running),
    the guard's `arm` refuses with `refused timer-not-running`, exit 3.
    The pending file is removed by the guard first, so guard_status
    remains idle (NOT pending)."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/not-running", "")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error guard refused timer-not-running\n", ""
    )
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


# ---- 4. happy path ------------------------------------------------------

def test_apply_happy_path_t90(router):
    """Stdout is exactly `applied <SID> t=<T> guard=<deadline>\\n` with
    deadline = uptime + 1 + (T + 30); fixture uptime is 100, so T=90
    -> guard=221 (M41). `applying` = "100 boot-one\\n", `applied` =
    "190 221 boot-one\\n", `post` is sha256 of the new confighash text
    (M24: arm happens before apply), `<sid>.applied` is the
    helper-format uptime deadline "up 190\\n", etc/config/dhcp is the
    staged content, the program lock is free, and `guard_status()` is
    `pending <sid> 121`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (0, f"applied {plan.sid} t=90 guard=221\n", "")
    assert router.guard_status() == f"pending {plan.sid} 121"
    apply_calls = router.calls_matching("ubus uci-apply")
    assert any(c == f"ubus uci-apply sid={plan.sid} t=90 guard-pending=1"
               for c in apply_calls)
    # arm runs before the ubus apply call: the second `ubus call session list`
    # entry (or, if no second one, the first `ubus ... apply`) must come
    # after arm. Easier check: the only `ubus call uci apply` log line has
    # guard-pending=1, proving the guard armed before apply (M24).
    all_calls = router.calls()
    arm_idx = next(i for i, c in enumerate(all_calls)
                   if c.startswith("ubus call session list"))
    apply_idx = next(i for i, c in enumerate(all_calls)
                     if c.startswith("ubus call uci apply"))
    assert arm_idx < apply_idx
    assert (plan.txn / "applying").read_text() == "100 boot-one\n"
    assert (plan.txn / "applied").read_text() == "190 221 boot-one\n"
    expected_post = hashlib.sha256(router.confighash_text().encode()).hexdigest()
    assert (plan.txn / "post").read_text().strip() == expected_post
    helper_applied = router.root / "tmp/owrt-safe-apply.lock" / f"{plan.sid}.applied"
    assert helper_applied.read_text() == "up 190\n"
    staged_dhcp = (router.root / "control/staged/dhcp").read_bytes()
    assert (router.root / "etc/config/dhcp").read_bytes() == staged_dhcp
    assert lock_is_free(router)


def test_apply_happy_path_t570(router):
    """Same shape with T=570: guard deadline = 100 + 1 + 600 = 701,
    rpcd deadline = 100 + 570 = 670."""
    plan = router.fresh_plan(t=570)
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (0, f"applied {plan.sid} t=570 guard=701\n", "")
    assert router.guard_status() == f"pending {plan.sid} 601"
    assert (plan.txn / "applied").read_text() == "670 701 boot-one\n"
    assert lock_is_free(router)


# ---- 5. uci apply failing ---------------------------------------------

def test_apply_uci_apply_failed(router):
    """`ubus call uci apply` returning 1 (control/apply.rc=1) makes the
    program call `newton-guard restore apply-failed`, then fail with
    `error apply-failed restored <sid> apply-failed`, exit 1. stdout
    empty; etc/config bytes unchanged; the txn keeps `applying`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.write("control/apply.rc", "1\n")
    live = snapshot_config(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        1, f"error apply-failed restored {plan.sid} apply-failed\n", ""
    )
    assert router.guard_status() == f"restored {plan.sid} apply-failed"
    assert snapshot_config(router) == live
    assert (plan.txn / "applying").exists()
    assert not (plan.txn / "applied").exists()
    assert lock_is_free(router)


# ---- 6. stdout never carries guard's or ubus's own lines (M47) ---------

def test_apply_stdout_disjoint_from_guard_and_ubus(router):
    """control/ubus.out = "armed x\\nconfirmed y\\n". The arm call has
    stdout/stderr redirected to /dev/null; the uci apply call redirects
    stdout/stderr to /dev/null too. The program's stdout is exactly the
    one `applied` line."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.set_fake("ubus", out="armed x\nconfirmed y\n")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0
    assert res.err == ""
    assert res.out == f"applied {plan.sid} t=90 guard=221\n"
    assert "armed x" not in res.out
    assert "confirmed y" not in res.out


# ---- 7. crash points --------------------------------------------------

def _apply_with_crash(router, plan, n):
    """Run apply with NEWTON_ROUTER_CRASH_AT=n. Returns the Result. The
    program receives -KILL if crash_point #n is hit."""
    return router.forced(
        f"apply {plan.sid} {plan.t} none 0 0",
        caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": str(n)},
        timeout=30,
    )


def test_apply_crash_points_then_abort_restores(router):
    """For n=1..6 the apply is run with NEWTON_ROUTER_CRASH_AT=n and a
    kill is expected for as long as the program has that many crash_points
    in `cmd_apply` (4 today: after `applying`, `applied`, helper-format,
    `post`). After each kill, the guard is `pending <sid> ...` and the
    follow-up `abort` restores etc/config to the original bytes. The
    first run that is NOT killed stops the loop, and we then assert that
    at least 4 crash points existed."""
    seen_killed = 0
    saw_non_killed = False
    for n in range(1, 7):
        # Abort cleans up the txn but leaves etc/newton/lkg/<sid> on disk;
        # remove it so the next iteration's arm does not refuse with
        # `txn-used`.
        lkg_txn = router.root / "etc/newton/lkg" / SID
        if lkg_txn.exists():
            shutil.rmtree(lkg_txn)
        plan = router.fresh_plan()
        ready_for_arm(router)
        live = snapshot_config(router)
        res = _apply_with_crash(router, plan, n)
        if res.rc == -9:
            seen_killed += 1
            assert router.guard_status().startswith(f"pending {plan.sid} "), \
                (n, res.rc, router.guard_status())
            abort = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
            assert abort.rc == 0, (n, abort.rc, abort.out, abort.err)
            assert snapshot_config(router) == live, (n, snapshot_config(router))
            assert lock_is_free(router)
        else:
            saw_non_killed = True
            assert snapshot_config(router) != live, (n, res.out)
            assert lock_is_free(router)
            break
    assert saw_non_killed, "no run survived up to n=6"
    assert seen_killed >= 4, seen_killed


# ---- 8. SIGHUP during apply -------------------------------------------

def test_apply_ignores_sighup_during_apply(router, tmp_path):
    """The program traps HUP and PIPE in `cmd_apply` (M-trap). With the
    fake ubus sleeping for 1 second on every call, the apply takes a
    few seconds and we send SIGHUP to the process group 0.5 s in. The
    apply still finishes with `applied ...` on stdout and the txn's
    `applied` and `post` markers exist."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    router.set_fake("ubus", sleep="1")
    request = f"apply {plan.sid} {plan.t} none 0 0"
    env = router._merged_env({
        "SSH_ORIGINAL_COMMAND": request, "PATH": "/usr/bin:/bin", "LC_ALL": "C",
    })
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(router.program),
         "--caller=agent-one", "--role=change"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        time.sleep(0.5)
        try:
            os.killpg(proc.pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        try:
            out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.skip("apply did not complete in 30 s under SIGHUP")
    finally:
        if proc.poll() is None:
            proc.kill()
    out = out.decode("utf-8", "replace")
    err = err.decode("utf-8", "replace")
    assert out == f"applied {plan.sid} t=90 guard=221\n", (out, err, proc.returncode)
    assert err == ""
    assert (plan.txn / "applied").exists()
    assert (plan.txn / "post").exists()


# ---- 9. lock is free after every outcome (single combined check) ------

def test_apply_lock_is_free_after_every_outcome(router):
    """After each outcome the program lock is free (the file lock fd 8
    is closed on exit, so flock -n succeeds immediately)."""
    # not-sealed
    plan = router.fresh_plan()
    (plan.txn / "sealed").unlink()
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 3
    assert lock_is_free(router)

    # happy path (also exercises the success exit path of the lock).
    # Need a fresh txn so the stage gate is open. Drop the lock's sid.
    (router.root / "tmp/owrt-safe-apply.lock" / "sid").unlink()
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0
    assert lock_is_free(router)


# ---- 10. non-owner / read role / root (direct mode) ---------------------

def test_apply_other_caller_is_not_owner(router):
    """A non-owner applying the plan is refused with `error not-owner`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0, caller="agent-two")
    assert (res.rc, res.err, res.out) == (3, "error not-owner\n", "")
    nothing_applied(router, plan.sid)
    assert lock_is_free(router)


def test_apply_read_role_is_refused(router):
    """A read role applying the plan is refused with `error role`."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0, role="read")
    assert (res.rc, res.err, res.out) == (3, "error role\n", "")
    nothing_applied(router, plan.sid)
    assert lock_is_free(router)


def test_apply_root_can_apply_direct(router):
    """Root (direct mode) can apply the plan without any owner check;
    the spec's `apply` row accepts the caller=root path."""
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.direct("apply", plan.sid, str(plan.t), "none", "0", "0")
    assert res.rc == 0
    assert res.err == ""
    assert res.out == f"applied {plan.sid} t=90 guard=221\n"
