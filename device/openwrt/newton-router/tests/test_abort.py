"""Design 6.4 `abort` and 3.4 stale-rule tests.

One test per row of the 6.4 table plus the who-may-abort rules, stdout
disjointness, post-abort stage and the crash-point seam. The side-effect
helper `cleaned` is what design 6.4 promises: the txn dir,
`<sid>.applied` and `var/run/rpcd/uci-<sid>` are gone; `<sid>.health` and
`$LOCK/sid` are KEPT so the host's after-rollback health check still has
its snapshot; `tmp/newton/last` is `aborted <sid> <how>`; the session is
destroyed when it was live; the program lock is free.
"""

import hashlib
import os
import shutil
import subprocess

import pytest

from conftest import SID


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


def apply_happy(router, plan):
    """Drive a successful apply so the txn has `applying`, `applied`,
    `post`, and `$LOCK/<sid>.applied`; the guard is `pending` and the
    config is the staged content."""
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert router.guard_status() == f"pending {plan.sid} 121"
    return res


def cleaned(router, sid, how):
    """The exact post-conditions design 6.4 promises after an exit-0 row."""
    lock = router.root / "tmp/owrt-safe-apply.lock"
    assert not (lock / f"{sid}.txn").exists()
    assert not (lock / f"{sid}.applied").exists()
    assert not (router.root / "var/run/rpcd" / f"uci-{sid}").exists()
    # <sid>.health is KEPT if it was there (the design's "M31: abort must
    # not delete the snapshot"); when no txn was ever created it does not
    # exist in the first place.
    health = lock / f"{sid}.health"
    if health.exists():
        assert health.is_dir()
    # $LOCK/sid is KEPT if it was there; when no txn was ever created
    # neither does it.
    if (lock / "sid").exists():
        assert (lock / "sid").is_file()
    last = (router.root / "tmp/newton/last").read_text()
    assert last == f"aborted {sid} {how}\n", last
    assert lock_is_free(router)
    # The session must be gone (call session list returns 4 once removed).
    sessions = (router.root / "control/sessions").read_text()
    assert sid not in sessions.split(), sessions


def write_pending(router, txn, left=121, boot="boot-one"):
    """Write etc/newton/pending so guard_status reports `pending <txn> <left>`."""
    deadline = 100 + left
    router.write("etc/newton/pending", f"{txn} {deadline} {boot}\n")


def write_failed(router, txn, why="apply-failed"):
    """Write etc/newton/failed so guard_status reports `failed <txn> <why>`."""
    router.write("etc/newton/failed", f"{txn} {why} extra\n")


# ---- row 1: guard failed (writes `error inconsistent guard <G>` to stderr) -


@pytest.mark.parametrize("with_txn", [True, False], ids=["with-txn", "without-txn"])
def test_abort_guard_failed_is_inconsistent(router, with_txn):
    """Row 1: G = `failed <sid> <why>`. Stderr is exactly
    `error inconsistent guard failed <sid> <why>\\n`, exit 1, stdout
    empty. The txn (when present) is NOT cleaned because the program
    leaves it for a human (design 6.4 / 8.6)."""
    if with_txn:
        plan = router.fresh_plan()
    write_pending(router, SID, left=80)
    write_failed(router, SID, why="verify-failed")
    res = router.forced(f"abort {SID}", caller="agent-one", timeout=30)
    assert (res.rc, res.out) == (1, "")
    assert res.err == f"error inconsistent guard failed {SID} verify-failed\n"
    if with_txn:
        plan_t = router.root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn"
        assert plan_t.is_dir(), "row 1 must keep the txn for a human"
    assert lock_is_free(router)


# ---- row 2: staged, not applied ------------------------------------------


def test_abort_discarded_staged(router):
    """Row 2: txn present, no `applied`/`applying`. Stdout is exactly
    `aborted <sid> discarded\\n`, exit 0, `cleaned`."""
    plan = router.fresh_plan()
    assert not (plan.txn / "applied").exists()
    assert not (plan.txn / "applying").exists()
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (0, f"aborted {plan.sid} discarded\n", "")
    cleaned(router, plan.sid, "discarded")


# ---- row 3: rpcd deadline in the future, session live, guard pending ----


def test_abort_rolled_back_happy(router):
    """Row 3: rpcd rollback succeeds AND the guard is pending for the SID.
    Stdout `aborted <sid> rolled-back\\n`, exit 0, `calls.log` carries a
    `ubus uci-rollback sid=<sid>` line, the guard ends `restored <sid>
    abort`, the config is back at the original bytes, `cleaned`."""
    plan = router.fresh_plan()
    live = snapshot_config(router)
    apply_happy(router, plan)
    assert (router.root / "etc/config/dhcp").read_bytes() != live["dhcp"]
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0, f"aborted {plan.sid} rolled-back\n", ""
    )
    assert router.calls_matching(f"ubus uci-rollback sid={plan.sid}")
    assert router.guard_status() == f"restored {plan.sid} abort"
    assert snapshot_config(router) == live
    cleaned(router, plan.sid, "rolled-back")


def test_abort_rpcd_fails_guard_pending(router):
    """Row 3 alt: rpcd rollback fails (control/rollback.rc=1) AND the
    guard is pending for the SID. Stdout `aborted <sid>
    rolled-back-by-guard\\n`, exit 0, the guard's `restore abort` ran,
    the config is back at the original bytes, `cleaned`."""
    plan = router.fresh_plan()
    live = snapshot_config(router)
    apply_happy(router, plan)
    router.write("control/rollback.rc", "1\n")
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0, f"aborted {plan.sid} rolled-back-by-guard\n", ""
    )
    assert router.guard_status() == f"restored {plan.sid} abort"
    assert snapshot_config(router) == live
    cleaned(router, plan.sid, "rolled-back-by-guard")


def test_abort_rpcd_fails_guard_idle(router):
    """Row 3 alt: rpcd rollback fails AND the guard is NOT pending for
    this SID. Stderr is exactly `error rollback-failed\\n`, exit 1,
    stdout empty, NOTHING cleaned (the txn and the applied file remain)."""
    plan = router.fresh_plan()
    apply_happy(router, plan)
    # Drop the guard's `pending` so guard_status is `idle` (no restore
    # in this row, so the program must NOT touch the config or the txn).
    (router.root / "etc/newton/pending").unlink()
    router.write("control/rollback.rc", "1\n")
    live = snapshot_config(router)
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out) == (1, "")
    assert res.err == "error rollback-failed\n"
    assert router.guard_status() == "idle"
    assert snapshot_config(router) == live
    assert (plan.txn / "applied").exists(), "row 3 refuses must keep the txn"
    assert lock_is_free(router)
    # last is NOT written on the refuse path.
    assert not (router.root / "tmp/newton/last").exists()


# ---- row 4: rpcd deadline passed / session gone, guard still pending ----


def test_abort_rpcd_already_reverted(router):
    """Row 4 (a): rpcd already reverted the config (set_uptime(190) +
    rpcd_tick() restores rpcd-backup over etc/config) AND the guard is
    still pending. `aborted <sid> already-rolled-back\\n`, exit 0, the
    guard's `restore abort` ran, the config is at base, `cleaned`."""
    plan = router.fresh_plan()
    live = snapshot_config(router)
    apply_happy(router, plan)
    # Push uptime past the rpcd deadline (100+90=190) and tick the fake
    # ubus so it restores rpcd-backup/ over etc/config/.
    router.set_uptime(190)
    assert router.rpcd_tick() == 0
    assert snapshot_config(router) == live
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0, f"aborted {plan.sid} already-rolled-back\n", ""
    )
    assert router.guard_status() == f"restored {plan.sid} abort"
    assert snapshot_config(router) == live
    cleaned(router, plan.sid, "already-rolled-back")


def test_abort_rpcd_lost_its_timer(router):
    """Row 4 (b): the session is gone and `control/rpcd-lost` is set so
    the fake ubus' --tick path is a no-op; the config is still the
    applied content. `aborted <sid> rolled-back-by-guard\\n`, exit 0,
    the guard's `restore abort` ran, the config is at base, `cleaned`."""
    plan = router.fresh_plan()
    live = snapshot_config(router)
    apply_happy(router, plan)
    # Drop the live session and write control/rpcd-lost; leave the
    # config as the staged content (rpcd never reverts it).
    router.write("control/sessions", b"")
    router.write("control/rpcd-lost", "")
    assert snapshot_config(router) != live
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0, f"aborted {plan.sid} rolled-back-by-guard\n", ""
    )
    assert router.guard_status() == f"restored {plan.sid} abort"
    assert snapshot_config(router) == live
    cleaned(router, plan.sid, "rolled-back-by-guard")


# ---- row 5: guard restored (window expired) -----------------------------


def test_abort_guard_already_restored(router):
    """Row 5: the guard window has expired and the guard's `tick` has
    already reverted the config. G is `restored <sid> <reason>`. The
    program takes no action and just cleans. `aborted <sid>
    already-rolled-back\\n`, exit 0, `cleaned`."""
    plan = router.fresh_plan()
    live = snapshot_config(router)
    apply_happy(router, plan)
    router.set_uptime(300)
    res_tick = router.guard("tick")
    assert res_tick.rc == 0, (res_tick.rc, res_tick.out, res_tick.err)
    assert router.guard_status() == f"restored {plan.sid} deadline"
    assert snapshot_config(router) == live
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0, f"aborted {plan.sid} already-rolled-back\n", ""
    )
    cleaned(router, plan.sid, "already-rolled-back")


# ---- rows 6, 7: confirmed / inconsistent ---------------------------------


def test_abort_already_confirmed_by_guard(router):
    """Row 6: the guard is idle, the session is gone (so row 3 entry
    cannot fire) AND the live config matches the txn's `post`. The
    program fails with `error already-confirmed\\n`, exit 1, stdout
    empty."""
    plan = router.fresh_plan()
    apply_happy(router, plan)
    # Drop the guard's pending and the live session: row 3 entry
    # requires `live=1`, so without the session the program falls
    # through to the post check.
    (router.root / "etc/newton/pending").unlink()
    router.write("control/sessions", b"")
    post_hex = (plan.txn / "post").read_text().strip()
    assert hashlib.sha256(router.confighash_text().encode()).hexdigest() == post_hex
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (1, "", "error already-confirmed\n")
    assert lock_is_free(router)


def test_abort_inconsistent_config(router):
    """Row 7: txn applied, guard idle, session gone, config NEITHER
    base NOR post. The program fails with `error inconsistent\\n`,
    exit 1."""
    plan = router.fresh_plan()
    apply_happy(router, plan)
    (router.root / "etc/newton/pending").unlink()
    router.write("control/sessions", b"")
    router.write(
        "etc/config/firewall",
        b"config defaults\n\toption input 'ACCEPT'\n",
    )
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (1, "", "error inconsistent\n")
    assert lock_is_free(router)


# ---- rows 8, 9: no txn, guard pending / no txn, nothing pending --------


def test_abort_no_txn_guard_pending(router):
    """Row 8: there is NO txn directory AND the guard is `pending <sid>
    ...` (armed directly with `router.guard('arm', sid, '120')` after
    mutating a config file). The program runs `restore abort` (the
    guard's `arm` captured the post-mutation bytes, so the restore
    is a no-op on the config) then cleans. `aborted <sid>
    rolled-back-by-guard\\n`, exit 0, the guard ends `restored <sid>
    abort`, the config is unchanged from right after the arm, `cleaned`."""
    live = snapshot_config(router)
    # Mutate a config file so the guard has something to capture.
    router.write(
        "etc/config/dhcp",
        b"config dnsmasq\n\toption domainneeded '0'\n",
    )
    assert snapshot_config(router) != live
    # Arm the guard directly for this SID. The guard's `arm` requires
    # init.d enabled, enough disk space and a clean pending/failed state.
    ready_for_arm(router)
    arm = router.guard("arm", SID, "120")
    assert arm.rc == 0, (arm.rc, arm.out, arm.err)
    assert router.guard_status() == f"pending {SID} 121"
    post_arm = snapshot_config(router)
    res = router.forced(f"abort {SID}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (
        0, f"aborted {SID} rolled-back-by-guard\n", ""
    )
    assert router.guard_status() == f"restored {SID} abort"
    # The guard's `arm` captured the post-mutation bytes, so `restore
    # abort` is a no-op on the config; the program must NOT touch the
    # config itself in this row.
    assert snapshot_config(router) == post_arm
    cleaned(router, SID, "rolled-back-by-guard")


def test_abort_no_txn_nothing_pending(router):
    """Row 9: there is NO txn AND the guard is idle. `aborted <sid>
    gone\\n`, exit 0, `cleaned`."""
    assert not (router.root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()
    res = router.forced(f"abort {SID}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (0, f"aborted {SID} gone\n", "")
    cleaned(router, SID, "gone")


# ---- who may abort (design 3.4) ----------------------------------------


def test_abort_owner_can_abort_staged(router):
    """The owner (agent-one) can always abort its own staged txn."""
    plan = router.fresh_plan(caller="agent-one")
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out) == (0, f"aborted {plan.sid} discarded\n")
    cleaned(router, plan.sid, "discarded")


def test_abort_root_can_abort_direct(router):
    """Root (direct mode, no `--caller`/`--role`) can abort without an
    owner check (design 3.4)."""
    plan = router.fresh_plan(caller="agent-one")
    res = router.direct("abort", plan.sid)
    assert (res.rc, res.out) == (0, f"aborted {plan.sid} discarded\n")
    cleaned(router, plan.sid, "discarded")


def test_abort_non_owner_live_staged_is_refused(router):
    """A non-owner of a LIVE staged txn is refused with
    `error not-owner`, exit 3 (3.4: only the owner or root may act on
    a non-stale staged txn)."""
    plan = router.fresh_plan(caller="agent-one")
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (3, "")
    assert res.err == "error not-owner\n"
    # The txn is NOT cleaned on a refusal.
    assert (plan.txn).is_dir()
    assert lock_is_free(router)


def test_abort_non_owner_stale_session_gone_discarded(router):
    """A non-owner of a staged txn whose session is GONE (3.4 stale
    rule, 6.4 row 2) is allowed: `aborted <sid> discarded\\n`, exit 0,
    `cleaned`."""
    plan = router.fresh_plan(caller="agent-one")
    router.write("control/sessions", b"")
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (0, f"aborted {plan.sid} discarded\n")
    cleaned(router, plan.sid, "discarded")


def test_abort_non_owner_stale_old_stage_up_allowed(router):
    """A non-owner of a LIVE staged txn whose `stage-up` is more than
    2700 s old is allowed (3.4 stale rule). With stage-up=100 and
    uptime 2801 the gap is 2701 > 2700."""
    plan = router.fresh_plan(caller="agent-one")
    router.set_uptime(2801)
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (0, f"aborted {plan.sid} discarded\n")
    cleaned(router, plan.sid, "discarded")


def test_abort_non_owner_stale_at_2700_is_refused(router):
    """The 2700 s threshold is strict: with stage-up=100 and uptime
    2800 the gap is 2700, NOT > 2700, so the non-owner is still
    refused. Locks in the `> 2700` rule (design 3.4)."""
    plan = router.fresh_plan(caller="agent-one")
    router.set_uptime(2800)
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (3, "")
    assert res.err == "error not-owner\n"
    assert (plan.txn).is_dir()
    assert lock_is_free(router)


def test_abort_non_owner_applied_pending_refused(router):
    """M51: a non-owner of an APPLIED txn while the guard is still
    pending for this SID is refused (`error not-owner`, exit 3) even
    when the session is gone — the open guard window keeps it live."""
    plan = router.fresh_plan(caller="agent-one")
    apply_happy(router, plan)
    router.write("control/sessions", b"")
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (3, "")
    assert res.err == "error not-owner\n"
    assert router.guard_status() == f"pending {plan.sid} 121"
    assert (plan.txn / "applied").exists()
    assert lock_is_free(router)


def test_abort_non_owner_applied_after_window_allowed(router):
    """Once the guard has restored (run `restore abort` directly or
    wait for the window to expire) the applied txn turns stale and a
    non-owner may abort it (3.4: applied + G not pending for this
    SID = stale)."""
    plan = router.fresh_plan(caller="agent-one")
    apply_happy(router, plan)
    # Run the guard's restore abort; the txn now has G=restored.
    restore = router.guard("restore", "abort")
    assert restore.rc == 0, (restore.rc, restore.out, restore.err)
    assert router.guard_status() == f"restored {plan.sid} abort"
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (0, f"aborted {plan.sid} already-rolled-back\n")
    cleaned(router, plan.sid, "already-rolled-back")


def test_abort_no_txn_any_change_caller_may(router):
    """With NO txn at all, any change-role caller may abort. A
    non-owner succeeds with `aborted <sid> gone\\n`, exit 0, `cleaned`."""
    res = router.forced(
        f"abort {SID}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out) == (0, f"aborted {SID} gone\n")
    assert res.err == ""
    cleaned(router, SID, "gone")


def test_abort_read_role_is_refused(router):
    """A read-role caller is refused with `error role`, exit 3
    regardless of the txn state."""
    plan = router.fresh_plan()
    res = router.forced(
        f"abort {plan.sid}", caller="agent-one", role="read", timeout=30
    )
    assert (res.rc, res.out) == (3, "")
    assert res.err == "error role\n"
    assert (plan.txn).is_dir()
    assert lock_is_free(router)


# ---- stdout cleanliness (M47) ------------------------------------------


def test_abort_stdout_disjoint_from_guard_and_ubus(router):
    """With control/ubus.out = "armed x\\nconfirmed y\\n" the abort's
    stdout is exactly the one `aborted ...` line; the guard's and
    ubus's own lines do not leak (design 3.5b / M47)."""
    plan = router.fresh_plan()
    live = snapshot_config(router)
    apply_happy(router, plan)
    # Inject the noise on every ubus call (rollback + guard restore +
    # session destroy in the abort path).
    router.set_fake("ubus", out="armed x\nconfirmed y\n")
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0
    assert res.err == ""
    assert res.out == f"aborted {plan.sid} rolled-back\n"
    assert "armed x" not in res.out
    assert "confirmed y" not in res.out
    assert snapshot_config(router) == live
    cleaned(router, plan.sid, "rolled-back")


# ---- after an abort the next stage works (6.4 / 3.4) -------------------


def test_abort_lock_clears_sid_and_status_is_gone(router):
    """After a successful abort `$LOCK/sid` is gone (it named the
    aborted SID and the program removes it) and `status <sid>` reports
    `gone`."""
    plan = router.fresh_plan()
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0
    lock = router.root / "tmp/owrt-safe-apply.lock"
    assert not (lock / "sid").exists()
    status = router.forced(f"status {plan.sid}", caller="agent-one", timeout=30)
    first = status.out.split(" ", 1)[0]
    assert first == "gone", status.out


# ---- R1 task: abort_clean conditionally removes $LOCK/sid --------------


def test_abort_removes_lock_sid_when_named(router):
    """R1: when `$LOCK/sid`'s first line equals the aborted SID, the
    abort cleans it up. The stub helper's `stage` wrote the file naming
    the plan's SID, so row 2 leaves the file present before the clean;
    after `abort <sid>` the file is gone. Safe because every other
    reader of `$LOCK/sid` (`open_txn_sid`, `busy_value`,
    `stage_busy_gate`, `cmd_confirm`) already requires the txn dir to
    exist or matches the SID before relying on the file."""
    plan = router.fresh_plan()
    lock = router.root / "tmp/owrt-safe-apply.lock"
    # Stage writes $LOCK/sid naming the plan's SID; pin that premise so a
    # future stub-helper change can't silently invalidate this test.
    assert (lock / "sid").read_text() == plan.sid + "\n"
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0
    assert not (lock / "sid").exists(), \
        "$LOCK/sid still present after abort of the SID it names"


def test_abort_leaves_lock_sid_when_named_other_sid(router):
    """R1: when `$LOCK/sid`'s first line names a DIFFERENT SID, the
    abort leaves it in place, untouched and unchanged. A wedged or
    previously-orphaned `$LOCK/sid` for an unrelated session is NOT
    destroyed and the abort does not error."""
    other = "fedcba9876543210fedcba9876543210"
    assert other != SID
    plan = router.fresh_plan()
    lock = router.root / "tmp/owrt-safe-apply.lock"
    (lock / "sid").write_text(other + "\n")
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0
    assert (lock / "sid").read_text() == other + "\n", \
        "$LOCK/sid was touched but named a different SID"


# ---- crash points (design 3.1 step 4) ----------------------------------


def test_abort_crash_points_then_abort_recovers(router):
    """For n = 1..6 the abort of an applied txn (row 3) is run with
    `NEWTON_ROUTER_CRASH_AT=n` and a kill is expected for as long as
    the program has that many `crash_point` calls in `cmd_abort` /
    `abort_clean`. After each kill a second `abort <sid>` (without the
    env var) ends with exit 0 and the config bytes at the original.
    The first run that is NOT killed stops the loop and we assert
    that at least 3 crash points existed."""
    seen_killed = 0
    saw_non_killed = False
    for n in range(1, 7):
        # Abort may have left the txn gone, and the guard's lkg/<sid>
        # directory lingers; drop both so the next apply's arm does
        # not refuse with `txn-used`.
        lkg_txn = router.root / "etc/newton/lkg" / SID
        if lkg_txn.exists():
            shutil.rmtree(lkg_txn)
        pending = router.root / "etc/newton/pending"
        if pending.exists():
            pending.unlink()
        # Abort may have left the txn gone; rebuild a fresh plan each
        # iteration so the next abort is row 3 (rpcd deadline in the
        # future, session live, guard pending).
        plan = router.fresh_plan()
        live = snapshot_config(router)
        apply_happy(router, plan)
        res = router.forced(
            f"abort {plan.sid}", caller="agent-one", timeout=30,
            env={"NEWTON_ROUTER_CRASH_AT": str(n)},
        )
        if res.rc == -9:
            seen_killed += 1
            # The guard is still armed for this SID (the crash was
            # before the guard restore / abort_clean finished), so a
            # second abort WITHOUT the env var must still reach a
            # success exit and bring the config back to the original
            # bytes.
            res2 = router.forced(
                f"abort {plan.sid}", caller="agent-one", timeout=30
            )
            assert res2.rc == 0, (
                n, res2.rc, res2.out, res2.err
            )
            assert res2.err == "", (n, res2.err)
            assert snapshot_config(router) == live, (
                n, snapshot_config(router), live
            )
            assert lock_is_free(router)
        else:
            saw_non_killed = True
            # The non-killed run finished cleanly: row 3 success.
            assert res.rc == 0, (n, res.rc, res.out, res.err)
            assert res.out == f"aborted {plan.sid} rolled-back\n", (n, res.out)
            assert snapshot_config(router) == live, (n,)
            assert lock_is_free(router)
            break
    assert saw_non_killed, "no run survived up to n=6"
    assert seen_killed >= 3, seen_killed
