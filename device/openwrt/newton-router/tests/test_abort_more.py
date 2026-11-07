"""Tests for four planted defects that survived.

1. M31: abort must NOT delete the health snapshot.
2. Cleanup of the rpcd save dir.
3. abort_restore accepts only the exact first line `restored <SID> abort`.
4. Non-owner abort ticks the guard first; owner and root do not.
5. Non-owner abort with `failed` guard status still fails `inconsistent`.
6. A second abort for a SID whose first abort already cleaned it (the
   still-running apply's wrapper aborting its own SID again) keeps the
   `aborted <sid> <how>` line that names the restorer.
"""

import pytest

from conftest import SID, _executable
from test_abort import apply_happy, cleaned, lock_is_free
from test_guard_compat import use_stub_guard
from test_status import status


# ---- shared helpers ----------------------------------------------------


def applied(router):
    """Build a fresh plan (which makes the health dir) and apply it.
    Returns the plan. The harness helper for the applied rows."""
    plan = router.fresh_plan()
    apply_happy(router, plan)
    return plan


def health_kept(router, sid):
    """M31: the health snapshot is KEPT (design 6.4). $LOCK/<sid>.health/
    is a directory and its newton-fw4-loaded file is still there."""
    health = router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.health"
    assert health.is_dir(), f"health dir gone: {health}"
    fw4 = health / "newton-fw4-loaded"
    assert fw4.is_file(), f"newton-fw4-loaded file gone: {fw4}"
    # $LOCK/sid still names the SID (if it was there before the abort).
    sid_file = router.root / "tmp/owrt-safe-apply.lock" / "sid"
    if sid_file.exists():
        assert sid_file.read_text() == sid + "\n", sid_file.read_text()


def make_rpcd_save(router, sid):
    """Create var/run/rpcd/uci-<sid>/ with a marker file inside."""
    save = router.root / "var/run/rpcd" / f"uci-{sid}"
    save.mkdir(parents=True, exist_ok=True)
    (save / "marker").write_text("saved\n")


def use_logging_stub_guard(router, status_text, restore_text="", restore_rc=0):
    """A logging stub guard (use_stub_guard-style, with restore support
    and a silent tick).

    `status` cats <root>/control/guard-status.txt exactly and exits 0.
    `restore` cats <root>/control/guard-restore.txt exactly and exits
    <restore_rc> (default 0).
    `tick` exits 0 silently.
    All other commands print `error usage` to stderr and exit 2.
    Every call is logged to control/calls.log as `guard <args>`.
    """
    root = router.root
    guard = root / "usr/libexec/newton-guard"
    body = (
        "#!/usr/bin/busybox sh\n"
        'root="$NEWTON_ROUTER_ROOT"\n'
        'echo "guard $*" >> "$root/control/calls.log"\n'
        'case "${1:-}" in\n'
        "status)\n"
        '  cat "$root/control/guard-status.txt"\n'
        "  ;;\n"
        "restore)\n"
        '  cat "$root/control/guard-restore.txt"\n'
        '  if [ -f "$root/control/guard-restore.rc" ]; then\n'
        '    read -r rc < "$root/control/guard-restore.rc"\n'
        '    exit "$rc"\n'
        "  fi\n"
        "  exit 0\n"
        "  ;;\n"
        "tick)\n"
        "  exit 0\n"
        "  ;;\n"
        "*)\n"
        '  printf "error usage\\n" >&2\n'
        "  exit 2\n"
        "  ;;\n"
        "esac\n"
    )
    _executable(guard, body)
    router.write("control/guard-status.txt", status_text)
    if restore_text:
        router.write("control/guard-restore.txt", restore_text)
    if restore_rc:
        router.write("control/guard-restore.rc", f"{restore_rc}\n")


# ---- 1. M31: abort keeps the health snapshot and sid file ---------------

_ROWS = [
    ("discarded", "staged"),
    ("rolled-back", "applied"),
    ("rolled-back-by-guard", "applied_rpcd_fail"),
    ("already-rolled-back", "applied_rpcd_revert"),
    ("gone", "no_txn"),
]
_ROW_IDS = ["discarded", "rolled-back", "rolled-back-by-guard",
            "already-rolled-back", "gone"]


def _setup_row(router, setup):
    """Build the txn/guard state for an exit-0 row. Returns (sid, plan
    or None)."""
    if setup == "staged":
        plan = router.fresh_plan()
    elif setup == "applied":
        plan = applied(router)
    elif setup == "applied_rpcd_fail":
        plan = applied(router)
        router.write("control/rollback.rc", "1\n")
    elif setup == "applied_rpcd_revert":
        plan = applied(router)
        router.set_uptime(190)
        assert router.rpcd_tick() == 0
    else:  # no_txn
        plan = None
    return (plan.sid if plan else SID, plan)


@pytest.mark.parametrize("row,setup", _ROWS, ids=_ROW_IDS)
def test_abort_keeps_health_snapshot_and_sid(router, row, setup):
    """M31: abort must NOT delete the health snapshot. For each exit-0
    row that had a health snapshot, $LOCK/<sid>.health/ (with its
    newton-fw4-loaded file) still exists, and $LOCK/sid still names the
    SID. (For the `gone` row the snapshot was never created; only the
    rest of `cleaned` is checked.)"""
    sid, plan = _setup_row(router, setup)
    res = router.forced(f"abort {sid}", caller="agent-one", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    if plan is not None:
        health_kept(router, sid)
    cleaned(router, sid, row)


# ---- 2. cleanup of the rpcd save dir -----------------------------------

@pytest.mark.parametrize("row,setup", _ROWS, ids=_ROW_IDS)
def test_abort_cleans_rpcd_save_dir(router, row, setup):
    """The rpcd save dir var/run/rpcd/uci-<sid>/ (with a marker file)
    is created BEFORE the abort and is gone AFTER; $LOCK/<sid>.txn and
    $LOCK/<sid>.applied are also gone (for the rows that had a txn)."""
    sid, plan = _setup_row(router, setup)
    make_rpcd_save(router, sid)
    res = router.forced(f"abort {sid}", caller="agent-one", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    lock = router.root / "tmp/owrt-safe-apply.lock"
    assert not (lock / f"{sid}.txn").exists(), f"{sid}.txn still there"
    assert not (lock / f"{sid}.applied").exists(), f"{sid}.applied still there"
    assert not (router.root / "var/run/rpcd" / f"uci-{sid}").exists(), \
        f"rpcd save dir still there"


# ---- 3. abort_restore accepts only the exact first line ----------------

@pytest.mark.parametrize(
    "restore_text,restore_rc",
    [
        ("restored othertxn abort\n", 0),
        ("restored " + SID + " deadline\n", 0),
        ("", 0),
        ("refused nothing-pending\n", 0),
        ("restored " + SID + " abort\n", 1),
    ],
    ids=["wrong-sid", "wrong-reason", "empty", "refused", "right-line-exit-1"],
)
def test_abort_restore_refuses_wrong_line(router, restore_text, restore_rc):
    """abort_restore accepts only the exact first line `restored <SID>
    abort` (design 6.4 row 3 / row 4 / row 8). Any other line OR exit 1
    fails the abort: stderr exactly `error rollback-failed`, exit 1,
    stdout empty, NOTHING cleaned (the txn dir, <sid>.applied and the
    rpcd save dir are all still there)."""
    plan = applied(router)
    make_rpcd_save(router, sid=plan.sid)
    use_logging_stub_guard(
        router,
        status_text=f"pending {SID} 100\n",
        restore_text=restore_text,
        restore_rc=restore_rc,
    )
    router.set_uptime(200)
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (1, "", "error rollback-failed\n")
    lock = router.root / "tmp/owrt-safe-apply.lock"
    assert (lock / f"{SID}.txn").is_dir(), "txn dir must remain on rollback-failed"
    assert (lock / f"{SID}.applied").is_file(), \
        "<sid>.applied must remain on rollback-failed"
    assert (router.root / "var/run/rpcd" / f"uci-{SID}").is_dir(), \
        "rpcd save dir must remain on rollback-failed"
    # The guard's `restore abort` was attempted.
    assert router.calls_matching("guard restore abort")
    # The program did NOT write `last`.
    assert not (router.root / "tmp/newton/last").exists()
    # The lock is released.
    assert lock_is_free(router)


def test_abort_restore_accepts_exact_line(router):
    """Success case: restore prints exactly `restored <SID> abort` with
    exit 0 -> `aborted <sid> already-rolled-back` or
    `rolled-back-by-guard`, exit 0, cleaned (including the rpcd save
    dir)."""
    plan = applied(router)
    make_rpcd_save(router, sid=plan.sid)
    use_logging_stub_guard(
        router,
        status_text=f"pending {SID} 100\n",
        restore_text=f"restored {SID} abort\n",
    )
    router.set_uptime(200)
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert res.err == ""
    assert res.out in (
        f"aborted {SID} already-rolled-back\n",
        f"aborted {SID} rolled-back-by-guard\n",
    ), res.out
    how = res.out.split()[2]
    cleaned(router, SID, how)


# ---- 4. non-owner abort ticks the guard first; owner and root do not ----


def _stale_staged_setup(router):
    """Fresh staged plan owned by agent-one, stub guard with status
    `idle`, session destroyed so the stale rule allows a non-owner."""
    plan = router.fresh_plan(caller="agent-one")
    use_stub_guard(router, status_text="idle\n")
    router.write("control/sessions", b"")
    return plan


def test_abort_non_owner_ticks_guard_first(router):
    """A non-owner of a staged txn whose session is gone (stale) ticks
    the guard BEFORE reading its status (the line `guard tick` appears
    in calls.log before `guard status`)."""
    plan = _stale_staged_setup(router)
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert res.rc == 0, (res.rc, res.out, res.err)
    calls = router.calls_matching("guard")
    tick_idx = next((i for i, c in enumerate(calls) if c == "guard tick"), -1)
    status_idx = next((i for i, c in enumerate(calls) if c == "guard status"), -1)
    assert tick_idx >= 0, f"guard tick not logged: {calls}"
    assert status_idx >= 0, f"guard status not logged: {calls}"
    assert tick_idx < status_idx, f"tick not before status: {calls}"


def test_abort_owner_does_not_tick_guard(router):
    """The owner (agent-one) does not tick the guard."""
    plan = _stale_staged_setup(router)
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    calls = router.calls_matching("guard")
    assert not any(c == "guard tick" for c in calls), calls


def test_abort_root_does_not_tick_guard(router):
    """Root (direct mode, no --caller/--role) does not tick the guard."""
    plan = _stale_staged_setup(router)
    res = router.direct("abort", plan.sid)
    assert res.rc == 0, (res.rc, res.out, res.err)
    calls = router.calls_matching("guard")
    assert not any(c == "guard tick" for c in calls), calls


# ---- 5. non-owner abort with failed guard status -----------------------

def test_abort_non_owner_failed_guard_is_inconsistent(router):
    """A non-owner of a staged txn whose session is gone (stale), with
    the guard answering `status` with `failed <sid> lkg-corrupt`:
    stderr exactly `error inconsistent guard failed <sid> lkg-corrupt\\n`,
    exit 1, stdout empty. The stale rule allows the non-owner because
    the guard is not pending."""
    plan = router.fresh_plan(caller="agent-one")
    use_stub_guard(router, status_text=f"failed {SID} lkg-corrupt\n")
    router.write("control/sessions", b"")
    res = router.forced(
        f"abort {plan.sid}", caller="agent-two", role="change", timeout=30
    )
    assert (res.rc, res.out, res.err) == (
        1, "",
        f"error inconsistent guard failed {SID} lkg-corrupt\n",
    )
    # The txn is NOT cleaned on a refusal.
    assert (plan.txn).is_dir()
    assert lock_is_free(router)


# ---- 6. the wrapper's second abort for the same SID ---------------------
# Live sequence: the USER aborts during the rollback window, then the
# still-running apply's wrapper reads `status` and sends ITS OWN abort for
# the same SID. The txn dir is gone, so that second abort takes row 9's
# `gone` path; `$R/tmp/newton/last` must keep the first abort's
# `aborted <sid> <how>` line, because `cmd_status` reads it to name who
# really restored the config (`guard=restored:rpcd` / `:guard` /
# `:already-base`). Overwriting it with `aborted <sid> gone` loses the
# restorer label.


SID_OTHER = "fedcba9876543210fedcba9876543210"


def first_abort_in_window(router, rpcd_rc=None):
    """Apply a plan, then let the USER abort during the window (row 3).

    With `rpcd_rc=None` the rpcd rollback succeeds (`rolled-back`); with
    `rpcd_rc=1` it fails and the guard restores instead
    (`rolled-back-by-guard`). Returns (sid, how).
    """
    plan = applied(router)
    if rpcd_rc is not None:
        router.write("control/rollback.rc", f"{rpcd_rc}\n")
    res = router.forced(f"abort {plan.sid}", caller="agent-one", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    how = res.out.split()[2]
    assert res.out == f"aborted {plan.sid} {how}\n", res.out
    assert router.guard_status() == f"restored {plan.sid} abort"
    assert not plan.txn.exists()
    return plan.sid, how


def read_last(router):
    return (router.root / "tmp/newton/last").read_text()


@pytest.mark.parametrize(
    "rpcd_rc,how,label",
    [
        (None, "rolled-back", "restored:rpcd"),
        (1, "rolled-back-by-guard", "restored:guard"),
    ],
    ids=["rpcd", "by-guard"],
)
def test_abort_twice_keeps_the_restorer_label(router, rpcd_rc, how, label):
    """The live sequence end to end: apply, USER abort during the window
    (row 3), then the wrapper's own abort for the same SID. The second
    abort prints `aborted <sid> gone` and still cleans everything, but
    `tmp/newton/last` keeps the first abort's `aborted <sid> <how>` line
    and `status` keeps naming the real restorer."""
    sid, how = first_abort_in_window(router, rpcd_rc=rpcd_rc)
    kept = read_last(router)
    assert kept == f"aborted {sid} {how}\n", kept
    res, word, fields = status(router, sid)
    assert fields["guard"] == label, res.out

    # The second abort cleans as usual: a stale rpcd save dir and the
    # <sid>.applied marker are still removed even though `last` is kept.
    make_rpcd_save(router, sid)
    lock = router.root / "tmp/owrt-safe-apply.lock"
    (lock / f"{sid}.applied").write_text(f"221 {sid} boot-one\n")

    res2 = router.forced(f"abort {sid}", caller="agent-one", timeout=30)
    assert (res2.rc, res2.out, res2.err) == (0, f"aborted {sid} gone\n", "")
    assert read_last(router) == kept, read_last(router)
    assert not (lock / f"{sid}.applied").exists()
    assert not (router.root / "var/run/rpcd" / f"uci-{sid}").exists()
    assert sid not in (router.root / "control/sessions").read_text().split()
    assert lock_is_free(router)
    res3, word, fields = status(router, sid)
    assert fields["guard"] == label, res3.out
    assert word == "rolled-back", (word, res3.out)
    assert res3.err == ""


@pytest.mark.parametrize(
    "last_line",
    [
        pytest.param(f"aborted {SID_OTHER} rolled-back", id="other-sid"),
        pytest.param(f"confirmed {SID}", id="confirmed"),
    ],
)
def test_abort_gone_overwrites_a_last_that_names_another_session(
    router, last_line
):
    """Row 9 with no txn: `tmp/newton/last` holding `aborted <other sid>
    ...` or `confirmed <sid>` does NOT name this SID's restorer, so the
    `gone` path writes `aborted <sid> gone` as before."""
    router.write("tmp/newton/last", last_line + "\n")
    res = router.forced(f"abort {SID}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (0, f"aborted {SID} gone\n", "")
    assert read_last(router) == f"aborted {SID} gone\n"


def test_abort_gone_writes_last_when_there_is_none(router):
    """Row 9 with no txn and no `tmp/newton/last` at all: the `gone` path
    writes `aborted <sid> gone` and cleans as before."""
    assert not (router.root / "tmp/newton/last").exists()
    make_rpcd_save(router, SID)
    res = router.forced(f"abort {SID}", caller="agent-one", timeout=30)
    assert (res.rc, res.out, res.err) == (0, f"aborted {SID} gone\n", "")
    cleaned(router, SID, "gone")
