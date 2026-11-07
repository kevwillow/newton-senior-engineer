"""Design 6.5 `status SID`, 6.6 boot, 3.5 health-check,
non-owner rule for in-txn helpers (3.4), program lock after every
lock-taking subcommand (M46), and the guard-tick-first rule of 6.5 (M29).

The 14 rules of the status table are tested one per case in 6.5's order;
each test pins the word and the values of `guard=`, `rpcd=`, `config=` and
`boot=`. Other tests pin exit codes, output shape, and the rules outside
the table (3.5, 6.6, 3.4 owner, M46 lock, M29 tick). Helpers `snapshot_config`,
`applied`, `write_pending`, `write_failed` and `write_restored` are
re-defined locally so this file is self-contained.
"""

import shutil
import subprocess

import pytest

from conftest import SID


DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


# ---- shared helpers ------------------------------------------------------


def lock_is_free(router):
    """The program lock is free when `flock -n` returns 0 at once."""
    proc = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return proc.returncode == 0


def ready_for_arm(router):
    """Feed the fake `df` a usable line so the guard's `arm` does not
    refuse on `low-space`."""
    router.set_fake("df", out=DF_OUT)


def snapshot_config(router):
    return {p.name: p.read_bytes() for p in sorted((router.root / "etc/config").iterdir())
            if p.is_file() and not p.is_symlink()}


def write_pending(router, txn, left=121, boot="boot-one"):
    """`router.guard_status()` reports `pending <txn> <left>`."""
    router.write("etc/newton/pending", f"{txn} {100 + left} {boot}\n")


def write_failed(router, txn, why="apply-failed"):
    """`router.guard_status()` reports `failed <txn> <why>` when both
    `pending` and `failed` files exist."""
    router.write("etc/newton/failed", f"{txn} {why} extra\n")


def write_restored(router, txn, reason="apply-failed"):
    """`router.guard_status()` reports `restored <txn> <reason>`."""
    router.write("etc/newton/last_revert", f"{txn} {reason}\n")


def applied(router, sid=SID, t=90):
    """Drive `fresh_plan` + `apply` for sid/t. Returns the plan so the
    caller can see the post-apply state (config=post, guard pending,
    txn `applied` marker present, `etc/newton/lkg/<sid>` populated)."""
    plan = router.fresh_plan(sid=sid, t=t)
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out) == (0, f"applied {plan.sid} t={t} guard="
                                 f"{100 + 1 + t + 30}\n"), (res.rc, res.out, res.err)
    return plan


def status(router, sid=SID):
    """Run `status <sid>` as a forced read-role caller. Returns
    (rc, word, fields_dict) where fields_dict carries sid, guard, rpcd,
    config, boot in that order."""
    res = router.forced(f"status {sid}", role="read", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    lines = res.out.splitlines()
    assert len(lines) == 1, res.out
    line = lines[0]
    parts = line.split()
    assert len(parts) == 6, line
    word, sid_kv, guard_kv, rpcd_kv, config_kv, boot_kv = parts
    assert sid_kv == f"sid={sid}", line
    fields = {}
    for kv in (guard_kv, rpcd_kv, config_kv, boot_kv):
        key, _, value = kv.partition("=")
        fields[key] = value
    return res, word, fields


# ---- 1. the 14-rule table of design 6.5 ---------------------------------


def write_rpcd_confirmed(router, sid, value):
    (router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn" / "rpcd-confirmed").write_text(
        value + "\n"
    )


def reset_config_to_dhcp_base(router):
    """Write back the original dhcp bytes (the only file the harness
    mutates). The other four config files never change, so live
    confighash returns to base the moment dhcp is back to '1'."""
    router.write(
        "etc/config/dhcp",
        b"config dnsmasq\n\toption domainneeded '1'\n",
    )


def drop_guard_pending(router):
    """Remove the guard's `pending` file so its `status` falls through
    to `restored` (next-priority line in `status_line`). Used to build
    the state where the guard says `restored <sid> <reason>`."""
    pending = router.root / "etc/newton/pending"
    if pending.exists():
        pending.unlink()


# ---- rule 1: guard failed (G starts `failed`) ---------------------------


def test_status_rule_1_guard_failed_is_inconsistent(router):
    """When guard status starts `failed`, the word is `inconsistent`,
    guard=failed:<why>. We drive `applied` so both `txn/base` and
    `txn/post` exist (so `config` is `post`, not `-`); the guard is
    then forced into `failed` by also writing `etc/newton/failed`."""
    plan = applied(router)
    write_pending(router, plan.sid, left=80)
    write_failed(router, plan.sid, why="apply-failed")
    res, word, fields = status(router, plan.sid)
    assert word == "inconsistent"
    assert fields == {
        "guard": "failed:apply-failed",
        "rpcd": "-", "config": "post", "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 2: txn, no applying or applied -> staged -----------------------


def test_status_rule_2_staged_with_no_applying_or_applied(router):
    """After stage but before any apply, the word is `staged`."""
    plan = router.fresh_plan()
    # Seal creates txn/{sealed} but no applying or applied yet
    assert (plan.txn / "sealed").exists()
    assert not (plan.txn / "applying").exists()
    assert not (plan.txn / "applied").exists()
    res, word, fields = status(router, plan.sid)
    assert word == "staged"
    assert fields == {
        "guard": "idle", "rpcd": "-", "config": "-", "boot": "same",
    }
    assert res.err == ""


# ---- rule 3: applied, G pending, rpcd-confirmed present -----------------


@pytest.mark.parametrize("value", ["ok", "lost"],
                         ids=["ok-confirmed", "lost"])
def test_status_rule_3_applied_pending_with_rpcd_file(router, value):
    """With the txn applied, the guard pending for this SID, and a
    `rpcd-confirmed` file present, the word is `applied-pending-confirm`
    and `rpcd=` is `confirmed` (file says `ok`) or `lost` (`lost`)."""
    plan = applied(router)
    write_rpcd_confirmed(router, plan.sid, value)
    res, word, fields = status(router, plan.sid)
    expected_rpcd = "confirmed" if value == "ok" else "lost"
    assert word == "applied-pending-confirm"
    assert fields == {
        "guard": "pending",
        "rpcd": expected_rpcd,
        "config": "post",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 4: applied, G pending, uptime < rpcd dl, session live --------


def test_status_rule_4_applied_pending_rpcd_pending(router):
    """With the txn applied, the guard pending, no `rpcd-confirmed` file,
    uptime (100) under the rpcd deadline (190) and the session live, the
    word is `applied-pending-confirm` and `rpcd=pending`."""
    plan = applied(router)
    res, word, fields = status(router, plan.sid)
    assert word == "applied-pending-confirm"
    assert fields == {
        "guard": "pending",
        "rpcd": "pending",
        "config": "post",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 5: applied, G pending, cfg = base -> rolled-back ---------------


def test_status_rule_5_applied_pending_config_base_rolled_back(router):
    """With the txn applied, the guard pending for this SID, no rpcd
    file, and the live config back at the base bytes, the word is
    `rolled-back` and `rpcd=rolled-back`. Rule 4 (rpcd=pending) needs
    the session live AND uptime under the rpcd deadline; we kill the
    session so rule 4 cannot short-circuit. Uptime is left at 100 so
    the guard's tick (M29) does not restore the still-alive window."""
    plan = applied(router)
    reset_config_to_dhcp_base(router)
    router.write("control/sessions", b"")
    res, word, fields = status(router, plan.sid)
    assert word == "rolled-back"
    assert fields == {
        "guard": "pending",
        "rpcd": "rolled-back",
        "config": "base",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 6: applied, G pending, cfg = post -> lost ----------------------


def test_status_rule_6_applied_pending_config_post_lost(router):
    """With the txn applied, the guard pending for this SID, no rpcd
    file, and the live config matching the `post` sha256, the word is
    `applied-pending-confirm` and `rpcd=lost`. We kill the session so
    rule 4's `session_live && uptime<rpcd_dl` short-circuit fails, but
    keep uptime at 100 so the guard's tick (M29) does not restore the
    still-alive window — at uptime 100 the guard deadline (221) is
    still in the future."""
    plan = applied(router)
    router.write("control/sessions", b"")
    res, word, fields = status(router, plan.sid)
    assert word == "applied-pending-confirm"
    assert fields == {
        "guard": "pending",
        "rpcd": "lost",
        "config": "post",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 7: applied, G restored for this SID ---------------------------


def test_status_rule_7_applied_guard_restored_rolled_back(router):
    """With the txn applied and the guard reporting `restored <sid>
    <reason>`, the word is `rolled-back`. Removing `etc/newton/pending`
    is what makes the guard's `status_line` fall through to the
    `restored` line; we then write `etc/newton/last_revert` directly."""
    plan = applied(router)
    drop_guard_pending(router)
    write_restored(router, plan.sid, reason="deadline")
    res, word, fields = status(router, plan.sid)
    assert word == "rolled-back"
    assert fields == {
        "guard": "restored:deadline",
        "rpcd": "-",
        "config": "post",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 8: applied, guard idle or another txn, cfg = post -> confirmed -


def test_status_rule_8_applied_other_guard_confirmed(router):
    """With the txn applied (config=post), an `idle` guard, and the live
    config at `post`, the word is `confirmed` (the "crash after the
    guard confirmed but before cleanup" scenario from 6.5). We drop the
    guard's pending file so it falls through to `idle`."""
    plan = applied(router)
    drop_guard_pending(router)
    res, word, fields = status(router, plan.sid)
    assert word == "confirmed"
    assert fields == {
        "guard": "idle",
        "rpcd": "-",
        "config": "post",
        "boot": "same",
    }, fields
    assert res.err == ""


def test_status_rule_8_applied_another_pending_txn_confirmed(router):
    """Same rule 8 row, reached through the `another txn` branch: guard
    says `pending <other>` so the rule's `idle-or-other-txn` predicate
    matches, and the live config is `post` so rule 8 fires."""
    plan = applied(router)
    drop_guard_pending(router)
    other_sid = "fedcba9876543210fedcba9876543210"
    write_pending(router, other_sid, left=80)
    res, word, fields = status(router, plan.sid)
    assert word == "confirmed"
    assert fields == {
        "guard": "other",
        "rpcd": "-",
        "config": "post",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rule 9: applied, anything else -> inconsistent ----------------------


def test_status_rule_9_applied_idle_base_inconsistent(router):
    """With the txn applied, the guard idle (no pending, no restore),
    and the live config back at base, none of rules 3..8 match; the
    word is `inconsistent`."""
    plan = applied(router)
    drop_guard_pending(router)
    reset_config_to_dhcp_base(router)
    res, word, fields = status(router, plan.sid)
    assert word == "inconsistent"
    assert fields == {
        "guard": "idle",
        "rpcd": "-",
        "config": "base",
        "boot": "same",
    }, fields
    assert res.err == ""


# ---- rules 10-14 run after the txn directory is gone --------------------


SID_OTHER = "fedcba9876543210fedcba9876543210"


def forget_txn(router, sid=SID):
    """Remove the txn directory and the `LOCK/sid` pointer (the helper
    ran setup kept it after apply) so cmd_status falls into the
    `no txn` branch."""
    shutil.rmtree(router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn")
    sid_path = router.root / "tmp/owrt-safe-apply.lock" / "sid"
    if sid_path.exists():
        sid_path.unlink()


def write_last(router, text):
    router.write("tmp/newton/last", text + "\n")


# ---- rules 10-14 run after the txn directory is gone --------------------


SID_OTHER = "fedcba9876543210fedcba9876543210"


def write_last(router, text):
    router.write("tmp/newton/last", text + "\n")


# ---- rule 10: no txn, last = confirmed <SID> ---------------------------


def test_status_rule_10_no_txn_last_confirmed(router):
    """With no txn, `tmp/newton/last` holding `confirmed <sid>` and the
    guard idle, the word is `confirmed`."""
    write_last(router, f"confirmed {SID}")
    res, word, fields = status(router, SID)
    assert word == "confirmed"
    assert fields == {
        "guard": "idle",
        "rpcd": "-",
        "config": "-",
        "boot": "-",
    }, fields
    assert res.err == ""


# ---- rule 11: no txn, G = restored <SID> <reason> -> rolled-back --------


def test_status_rule_11_no_txn_guard_restored_rolled_back(router):
    """With no txn and the guard saying `restored <sid> <reason>` (a
    fresh abort left only the guard's `last_revert`), the word is
    `rolled-back` and `rpcd=-`."""
    write_restored(router, SID, reason="abort")
    res, word, fields = status(router, SID)
    assert word == "rolled-back"
    assert fields == {
        "guard": "restored:abort",
        "rpcd": "-",
        "config": "-",
        "boot": "-",
    }, fields
    assert res.err == ""


# ---- 1a. guard reason=abort + $R/tmp/newton/last names the restorer ----
# After abort the guard reports `restored <sid> abort` regardless of
# who actually restored the config. `cmd_status` reads the first line of
# `$R/tmp/newton/last` (the `aborted <sid> <how>` line `cmd_abort` wrote)
# and labels `guard=` with the real restorer: `rpcd` (rolled-back),
# `guard` (rolled-back-by-guard), or `already-base` (already-rolled-back).
# Anything else (no file, another sid, a different how word, trailing
# text, or guard reason != abort) keeps the generic `restored:abort`.


def _guard_says_restored_abort(router, sid=SID):
    """Drop the guard's pending file and write its `last_revert` so the
    next `status` sees `restored <sid> abort`."""
    drop_guard_pending(router)
    write_restored(router, sid, reason="abort")


@pytest.mark.parametrize("how,expected", [
    ("rolled-back", "restored:rpcd"),
    ("already-rolled-back", "restored:already-base"),
    ("rolled-back-by-guard", "restored:guard"),
], ids=["rpcd", "already-base", "by-guard"])
def test_status_guard_abort_last_names_restorer(router, how, expected):
    """Guard `restored <sid> abort` + `tmp/newton/last` `aborted <sid>
    <how>` -> `guard=restored:<label>` where the label names who
    really restored the config."""
    _guard_says_restored_abort(router)
    write_last(router, f"aborted {SID} {how}")
    res, word, fields = status(router, SID)
    assert fields["guard"] == expected, (how, fields, res.out)
    assert word == "rolled-back", (how, word, fields)
    assert res.err == ""


def test_status_guard_abort_last_other_sid_keeps_abort(router):
    """Guard `restored <sid> abort` but `tmp/newton/last` is for a
    different SID -> `guard=restored:abort` (the SID guard wins)."""
    _guard_says_restored_abort(router)
    write_last(router, f"aborted {SID_OTHER} rolled-back")
    res, word, fields = status(router, SID)
    assert fields["guard"] == "restored:abort", fields
    assert word == "rolled-back"
    assert res.err == ""


def test_status_guard_abort_last_discarded_keeps_abort(router):
    """Guard `restored <sid> abort` + `last` `aborted <sid> discarded`
    -> `restored:abort` (`discarded` is not a restorer word)."""
    _guard_says_restored_abort(router)
    write_last(router, f"aborted {SID} discarded")
    res, word, fields = status(router, SID)
    assert fields["guard"] == "restored:abort", fields
    assert word == "rolled-back"
    assert res.err == ""


def test_status_guard_abort_last_trailing_text_keeps_abort(router):
    """Guard `restored <sid> abort` + `last` `aborted <sid> rolled-back
    x` (trailing text after the word) -> `restored:abort` (whole-string
    match only)."""
    _guard_says_restored_abort(router)
    write_last(router, f"aborted {SID} rolled-back x")
    res, word, fields = status(router, SID)
    assert fields["guard"] == "restored:abort", fields
    assert word == "rolled-back"
    assert res.err == ""


def test_status_guard_abort_no_last_file_keeps_abort(router):
    """Guard `restored <sid> abort` + no `tmp/newton/last` file ->
    `restored:abort` (rule 11 keeps working unchanged)."""
    _guard_says_restored_abort(router)
    res, word, fields = status(router, SID)
    assert fields["guard"] == "restored:abort", fields
    assert word == "rolled-back"
    assert res.err == ""


def test_status_guard_deadline_with_rpcd_last_keeps_deadline(router):
    """Guard reason `deadline` keeps the generic `restored:deadline`
    even when `last` says rpcd rolled back: the label rule only
    rewrites `restored:abort`."""
    drop_guard_pending(router)
    write_restored(router, SID, reason="deadline")
    write_last(router, f"aborted {SID} rolled-back")
    res, word, fields = status(router, SID)
    assert fields["guard"] == "restored:deadline", fields
    assert word == "rolled-back"
    assert res.err == ""


def test_status_guard_abort_label_with_txn_present(router):
    """The label rule is the same on the txn-dir-present path (rule 7):
    guard `restored <sid> abort` + `last` `aborted <sid> rolled-back`
    -> `restored:rpcd`, and the word is still `rolled-back`."""
    plan = applied(router)
    drop_guard_pending(router)
    write_restored(router, plan.sid, reason="abort")
    write_last(router, f"aborted {plan.sid} rolled-back")
    res, word, fields = status(router, plan.sid)
    assert fields["guard"] == "restored:rpcd", fields
    assert word == "rolled-back", word
    assert res.err == ""


# ---- rule 12: no txn, last = aborted <SID> ... -> gone ------------------


def test_status_rule_12_no_txn_last_aborted_gone(router):
    """With no txn and `tmp/newton/last` holding `aborted <sid> ...`,
    the word is `gone` (the guard idle in this state)."""
    write_last(router, f"aborted {SID} discarded")
    res, word, fields = status(router, SID)
    assert word == "gone"
    assert fields == {
        "guard": "idle",
        "rpcd": "-",
        "config": "-",
        "boot": "-",
    }, fields
    assert res.err == ""


# ---- rule 13: no txn, G = pending <SID> ... -> inconsistent --------------


def test_status_rule_13_no_txn_pending_inconsistent(router):
    """With no txn and the guard still saying `pending <sid> ...`
    (the post-abort window leaked), the word is `inconsistent`."""
    write_pending(router, SID, left=80)
    res, word, fields = status(router, SID)
    assert word == "inconsistent"
    assert fields == {
        "guard": "pending",
        "rpcd": "-",
        "config": "-",
        "boot": "-",
    }, fields
    assert res.err == ""


# ---- rule 14: no txn, otherwise -> gone ----------------------------------


def test_status_rule_14_no_txn_default_gone(router):
    """With no txn, no `last`, no guard state at all, the word is
    `gone`."""
    res, word, fields = status(router, SID)
    assert word == "gone"
    assert fields == {
        "guard": "idle",
        "rpcd": "-",
        "config": "-",
        "boot": "-",
    }, fields
    assert res.err == ""


# ---- 2. invariants: rc, role, output shape, ubus stub --------------------


@pytest.mark.parametrize("state_name", [
    "fresh_plan_failed",         # rule 1: guard=failed → inconsistent (rc must be 0)
    "staged",                    # rule 2: staged
    "applied_post",              # rule 3..6, 8: pending window
    "applied_idle_base",         # rule 9: txn applied + idle guard + cfg base
])
def test_status_rc_is_0_for_every_state(router, state_name):
    """Every state, including `inconsistent`, has rc=0 on `status`; the
    read role may run it; stdout is exactly the one line."""
    if state_name == "fresh_plan_failed":
        plan = router.fresh_plan()
        write_pending(router, plan.sid, left=80)
        write_failed(router, plan.sid, why="apply-failed")
        sid = plan.sid
    elif state_name == "staged":
        plan = router.fresh_plan()
        sid = plan.sid
    elif state_name == "applied_post":
        plan = applied(router)
        sid = plan.sid
    elif state_name == "applied_idle_base":
        plan = applied(router)
        drop_guard_pending(router)
        reset_config_to_dhcp_base(router)
        sid = plan.sid
    res = router.forced(f"status {sid}", role="read", timeout=30)
    assert res.rc == 0, (state_name, res.rc, res.out, res.err)
    assert res.err == "", (state_name, res.out, res.err)
    out_lines = res.out.splitlines()
    assert len(out_lines) == 1, (state_name, res.out)
    parts = out_lines[0].split()
    assert parts[0] in {
        "applied-pending-confirm", "staged", "rolled-back",
        "confirmed", "inconsistent", "gone",
    }, (state_name, res.out)
    assert parts[1] == f"sid={sid}", (state_name, res.out)
    keys = [p.split("=", 1)[0] for p in parts[2:]]
    assert keys == ["guard", "rpcd", "config", "boot"], (state_name, parts)


def test_status_read_role_runs_it(router):
    """The read role (any caller name) is enough to run `status`; the
    answer is the same line as a change-role caller would get."""
    plan = applied(router)
    res_read = router.forced(f"status {plan.sid}", role="read", caller="agent-read",
                             timeout=30)
    res_change = router.forced(f"status {plan.sid}", role="change",
                               caller="agent-one", timeout=30)
    assert (res_read.rc, res_read.out, res_read.err) == \
        (res_change.rc, res_change.out, res_change.err)
    assert res_read.rc == 0


def test_status_does_not_echo_ubus_out(router):
    """A `control/ubus.out` stub line ("extra-from-ubus") never
    appears on stdout; the program's own output is exactly the one
    status line."""
    plan = router.fresh_plan()
    router.set_fake("ubus", out="extra-from-ubus\n")
    res, _, _ = status(router, plan.sid)
    assert "extra-from-ubus" not in res.out
    assert "extra-from-ubus" not in res.err
    assert res.out.count("\n") == 1


# ---- 3. M29: `status` ticks the guard first -----------------------------


def test_status_ticks_guard_first_when_window_expired(router):
    """After `applied` we run `set_uptime(300)` so the guard's pending
    window has expired (210 s past the 221 deadline), and write
    `control/not-running` so the timer never runs. `router.guard_status()`
    still says `pending <sid> 0` (it does not tick); the next call to
    `status`, however, ticks first, the guard restores the lkg, and the
    answer is `rolled-back`. The config is back at the base bytes
    (dhcp's `option domainneeded '1'`) and the guard is
    `restored <sid> deadline`."""
    plan = applied(router)
    router.set_uptime(300)
    router.write("control/not-running", "")
    before = router.guard_status()
    assert before.startswith(f"pending {plan.sid} "), before
    res, word, fields = status(router, plan.sid)
    assert word == "rolled-back", (res.out, res.err)
    assert fields == {
        "guard": "restored:deadline",
        "rpcd": "-",
        "config": "base",
        "boot": "same",
    }, fields
    assert (router.root / "etc/config/dhcp").read_bytes() == (
        b"config dnsmasq\n\toption domainneeded '1'\n"
    )


# ---- 4. Reboot (6.6) ----------------------------------------------------


def test_status_after_reboot_guard_boot_restores(router):
    """Design 6.6: after `applied`, simulate a reboot
    (`set_boot_id("boot-two")`, `set_uptime(8)`), invoke the guard's
    `boot` (which restores the pending window, reason `boot`); the
    next `status` says `rolled-back`, the guard is `restored:boot`,
    `boot=new`, and the config is back at the base bytes."""
    plan = applied(router)
    router.set_uptime(8)
    router.set_boot_id("boot-two")
    g = router.guard("boot")
    assert g.rc == 0, (g.rc, g.out, g.err)
    res, word, fields = status(router, plan.sid)
    assert word == "rolled-back", (res.out, res.err)
    assert fields == {
        "guard": "restored:boot",
        "rpcd": "-",
        "config": "base",
        "boot": "new",
    }, fields
    assert (router.root / "etc/config/dhcp").read_bytes() == (
        b"config dnsmasq\n\toption domainneeded '1'\n"
    )


# ---- 5. health-check (design 3.5) ---------------------------------------


def remove_lock_dir(router):
    """Simulate a reboot that wiped /tmp — drop every file under
    `tmp/owrt-safe-apply.lock` (idempotent: a fresh router never has it)."""
    p = router.root / "tmp/owrt-safe-apply.lock"
    if p.exists():
        shutil.rmtree(p)



def test_health_check_no_snapshot_other_guard(router):
    """With no `<sid>.health` directory and the guard idle, the answer
    is exactly `health: not compared: no health snapshot for session
    <sid>` on stderr, rc=1, stdout empty."""
    remove_lock_dir(router)
    res = router.direct("health-check", SID, timeout=15)
    assert res.rc == 1
    assert res.out == ""
    assert res.err == (
        f"health: not compared: no health snapshot for session {SID}\n"
    ), res.err


def test_health_check_no_snapshot_restored_boot(router):
    """After a fake reboot (the lock directory is gone) and a guard
    `boot` (guard line reads `restored <sid> boot`), the answer is the
    `the router rebooted during the window; the guard restored the
    config at boot` text. We synthesise the guard state by writing
    `etc/newton/last_revert` to `<sid> boot` and dropping pending."""
    remove_lock_dir(router)
    drop_guard_pending(router)
    write_restored(router, SID, reason="boot")
    res = router.direct("health-check", SID, "after-rollback", timeout=15)
    assert res.rc == 1
    assert res.out == ""
    assert res.err == (
        "health: not compared: the router rebooted during the window;"
        " the guard restored the config at boot\n"
    ), res.err


def test_health_check_no_snapshot_pending_guard(router):
    """With the guard still saying `pending <sid> ...`, no snapshot,
    and a regular `health-check` (no `after-rollback` token) the answer
    is the `no health snapshot` text (not the reboot one)."""
    remove_lock_dir(router)
    write_pending(router, SID, left=80)
    res = router.direct("health-check", SID, timeout=15)
    assert res.rc == 1
    assert res.out == ""
    assert res.err == (
        f"health: not compared: no health snapshot for session {SID}\n"
    ), res.err


# ---- 6. 3.4 open-txn rule (M50): non-owner helpers ----------------------


def setup_init_fakes(router):
    """Make the helper-driven `fwrestart` and `dnsmasq-*` paths succeed:
    `nft` exits 0 (the fw4 table is loaded), `init.d/firewall` and
    `init.d/dnsmasq` both `running` then `restart` cleanly."""
    from conftest import _executable  # local import to keep the helpers self-contained
    initd = router.root / "etc/init.d"
    _executable(
        initd / "firewall",
        '#!/usr/bin/sh\nexit 0\n',
    )
    _executable(
        initd / "dnsmasq",
        '#!/usr/bin/sh\n'
        'case "$1" in running) exit 0 ;; restart) exit 0 ;; *) exit 0 ;; esac\n',
    )


def open_txn_helper(router):
    """Build a sealed plan with `agent-one` as the caller; the txn is
    open afterwards (no apply is run). Returns the plan so the caller
    can pass `plan.sid` etc."""
    setup_init_fakes(router)
    return router.fresh_plan()


@pytest.mark.parametrize("sub,argv,expected_rc", [
    ("fwrestart", ("fwrestart", "1"), 2),
    ("dnsmasq-repair", ("dnsmasq-repair",), 3),
    ("dnsmasq-ensure", ("dnsmasq-ensure",), 3),
])
def test_non_owner_blocked_while_txn_open(router, sub, argv, expected_rc):
    """While `agent-one`'s txn is open, `agent-two` (change role) is
    refused with `error not-owner` on the helper subcommands:
    `fwrestart` exits 2, the dnsmasq ones exit 3."""
    plan = open_txn_helper(router)
    res = router.forced(" ".join(argv), role="change", caller="agent-two",
                        timeout=15)
    assert res.rc == expected_rc, (sub, res.rc, res.out, res.err)
    assert res.err == "error not-owner\n", (sub, res.err, res.out)
    assert res.out == ""
    # sanity: the txn is still owned by agent-one
    owner = (plan.txn / "owner").read_text().strip()
    assert owner == "agent-one"


@pytest.mark.parametrize("call_kind", ["owner", "root"])
def test_owner_and_root_may_run_helpers_while_txn_open(router, call_kind):
    """The owner (`agent-one`) and root (direct) can run `fwrestart 1`,
    `dnsmasq-repair`, and `dnsmasq-ensure` while the txn is open."""
    plan = open_txn_helper(router)
    if call_kind == "owner":
        runs = [
            router.forced("fwrestart 1", role="change", caller="agent-one", timeout=15),
            router.forced("dnsmasq-repair", role="change", caller="agent-one", timeout=15),
            router.forced("dnsmasq-ensure", role="change", caller="agent-one", timeout=15),
        ]
    else:
        runs = [
            router.direct("fwrestart", "1", timeout=15),
            router.direct("dnsmasq-repair", timeout=15),
            router.direct("dnsmasq-ensure", timeout=15),
        ]
    for r in runs:
        assert r.rc == 0, (call_kind, r.rc, r.out, r.err)
        assert r.err == "", (call_kind, r.out, r.err)


def test_any_change_caller_after_txn_aborted(router):
    """After the txn is aborted (no txn dir), any change-role caller
    can run `fwrestart 1`, `dnsmasq-repair`, and `dnsmasq-ensure`.
    The `agent-two` (non-owner, change role) call succeeds here."""
    plan = open_txn_helper(router)
    # Simulate the post-abort state: no txn dir, no `LOCK/sid`.
    shutil.rmtree(plan.txn)
    sid_path = router.root / "tmp/owrt-safe-apply.lock" / "sid"
    if sid_path.exists():
        sid_path.unlink()
    res1 = router.forced("fwrestart 1", role="change", caller="agent-two", timeout=15)
    res2 = router.forced("dnsmasq-repair", role="change", caller="agent-two", timeout=15)
    res3 = router.forced("dnsmasq-ensure", role="change", caller="agent-two", timeout=15)
    for r in (res1, res2, res3):
        assert r.rc == 0, (r.rc, r.out, r.err)
        assert r.err == "", (r.out, r.err)


# ---- 7. M46: program lock after every lock-taking subcommand ------------


def _lock_take_setup_ok(router, sub):
    """Build the minimum state each subcommand needs before the lock
    is taken: stage needs nothing, seal needs the txn, apply needs the
    sealed plan and arm-ready, confirm needs an applied plan, abort
    needs an applied plan, health-snapshot needs the txn dir, the
    dnsmasq helpers and `fwrestart` only need the init.d fakes."""
    setup_init_fakes(router)
    if sub in ("seal", "apply", "confirm", "abort", "health-snapshot"):
        # Confirm needs the txn in `applying` or `applied` state.
        plan = router.fresh_plan()
        if sub in ("apply", "confirm", "abort"):
            ready_for_arm(router)
            apply_res = router.apply(plan.sid, plan.t, "none", 0, 0)
            assert apply_res.rc == 0, (sub, apply_res.rc, apply_res.err)
        return plan
    return None


@pytest.mark.parametrize("sub", [
    "stage", "seal", "apply", "confirm", "abort",
    "health-snapshot", "dnsmasq-repair", "dnsmasq-ensure",
], ids=["stage", "seal", "apply", "confirm", "abort",
       "health-snapshot", "dnsmasq-repair", "dnsmasq-ensure"])
def test_program_lock_is_free_after_subcommand(router, sub):
    """After every lock-taking subcommand the program lock is free
    (M46): `flock -n` on `tmp/newton/flock` succeeds at once. The
    full set of subcommands that take the lock is `stage`, `seal`,
    `apply`, `verify`, `confirm`, `abort`, `health-snapshot`,
    `dnsmasq-repair`, `dnsmasq-ensure`, `fwrestart`; `verify` and
    `fwrestart` have their own tests, so this parameterised test
    covers the rest."""
    plan = _lock_take_setup_ok(router, sub)
    # Build the request line: "sub sid" or "sub sid t token" etc.
    if sub == "stage":
        request = "stage"
        stdin = b"set dhcp.cfg01.domain=lan\n"
        call_caller = "agent-one"
        call_role = "change"
    elif sub == "seal":
        request = f"seal {plan.sid} 90"
        stdin = b""
        call_caller = "agent-one"
        call_role = "change"
    elif sub == "apply":
        request = f"apply {plan.sid} 90 none 0 0"
        stdin = b""
        call_caller = "agent-one"
        call_role = "change"
    elif sub == "confirm":
        request = f"confirm {plan.sid}"
        stdin = b""
        call_caller = "agent-one"
        call_role = "change"
    elif sub == "abort":
        request = f"abort {plan.sid}"
        stdin = b""
        call_caller = "agent-one"
        call_role = "change"
    elif sub == "health-snapshot":
        request = f"health-snapshot {plan.sid}"
        stdin = b""
        call_caller = "agent-one"
        call_role = "change"
    elif sub in ("dnsmasq-repair", "dnsmasq-ensure"):
        request = sub
        stdin = b""
        call_caller = "agent-two"
        call_role = "change"
    # Run via the program. `confirm` and `abort` may fail post-lock
    # (the design test of the lock is "lock is free afterwards"); we
    # only assert the lock state.
    res = router.forced(request, role=call_role, caller=call_caller,
                        stdin=stdin, timeout=30)
    # We do not assert res.rc here: confirm/abort may return non-zero
    # on this state, and the focus is the lock release (M46).
    assert lock_is_free(router), (sub, res.rc, res.out, res.err)
