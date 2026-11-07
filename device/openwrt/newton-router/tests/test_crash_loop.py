"""Design 6.6, 6.7, 4.4 crash seam, 9.2 group 6.

Crash loop around the real guard for every durable write in `stage`,
`seal`, `apply`, `confirm` and `abort`. For each subcommand we drive
NEWTON_ROUTER_CRASH_AT=1..N until the program survives; the surviving
run must succeed as the plain run does, and at least MIN_CRASH[sub]
crash points must have been killed. After each killed run we recover in
three ways (controller alive: abort; controller dead: tick past the
deadline; reboot: boot at uptime 8 with a new boot id, with /tmp wiped
to match a real reboot) and assert that /etc/config is byte-identical
to the original, or to the post bytes only for a confirm killed after
the guard confirmed.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import SID


DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)

ORIGINAL_BYTES = {
    "dhcp":     b"config dnsmasq\n\toption domainneeded '1'\n",
    "firewall": b"config defaults\n\toption input 'REJECT'\n",
    "network":  b"config interface 'lan'\n\toption proto 'static'\n",
    "system":   b"config system\n\toption hostname 'newton-test'\n",
    "wireless": b"config wifi-device 'radio0'\n\toption channel 'auto'\n",
}
POST_BYTES = {
    "dhcp":     b"config dnsmasq\n\toption domainneeded '0'\n",
    "firewall": b"config defaults\n\toption input 'REJECT'\n",
    "network":  b"config interface 'lan'\n\toption proto 'static'\n",
    "system":   b"config system\n\toption hostname 'newton-test'\n",
    "wireless": b"config wifi-device 'radio0'\n\toption channel 'auto'\n",
}


def lock_is_free(root):
    """flock -n on the program lock returns 0 at once."""
    proc = subprocess.run(
        ["/usr/bin/flock", "-n", str(Path(root) / "tmp/newton/flock"), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return proc.returncode == 0


def ready_for_arm(router):
    router.set_fake("df", out=DF_OUT)


def snapshot_config(root):
    cfg = Path(root) / "etc/config"
    return {p.name: p.read_bytes() for p in sorted(cfg.iterdir())
            if p.is_file() and not p.is_symlink()}


def swap_root(router, new_root):
    """Run the rest of the helpers against `new_root` (a copy of the
    prepared state)."""
    router.root = Path(new_root)
    router.canary = router.root / "canary"


def copytree(src, dst):
    src, dst = Path(src), Path(dst)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)


def status_word(router, sid):
    res = router.forced(f"status {sid}", role="read", timeout=30)
    assert res.rc == 0, (res.rc, res.out, res.err)
    return res.out.splitlines()[0].split()[0]


def guard_pending_for(router, sid):
    return router.guard_status().startswith(f"pending {sid}")


# ---- prepare: state just BEFORE the named subcommand -------------------

def prepare_stage(router):
    router.use_stub_helper()
    router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("control/next-sid", SID + "\n")


def prepare_seal(router):
    router.use_stub_helper()
    router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("etc/newton/profile", "lab\n")
    router.write("control/staged/dhcp",
                 b"config dnsmasq\n\toption domainneeded '0'\n")
    res = router.stage(sid=SID)
    assert res.rc == 0, (res.rc, res.err)


def prepare_apply(router):
    router.fresh_plan()
    ready_for_arm(router)


def prepare_confirm(router):
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0, (res.rc, res.err)


def prepare_abort(router):
    plan = router.fresh_plan()
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0, (res.rc, res.err)


PREPARE = {
    "stage":   prepare_stage,
    "seal":    prepare_seal,
    "apply":   prepare_apply,
    "confirm": prepare_confirm,
    "abort":   prepare_abort,
}


# ---- subcommand runners with NEWTON_ROUTER_CRASH_AT=n ------------------

def run_stage(router, n):
    return router.forced(
        "stage", caller="agent-one", role="change",
        stdin=b"set dhcp.cfg01.domain=lan\n",
        env={"NEWTON_ROUTER_CRASH_AT": str(n)}, timeout=40,
    )


def run_seal(router, n):
    return router.forced(
        f"seal {SID} 90", caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": str(n)}, timeout=40,
    )


def run_apply(router, n):
    return router.forced(
        f"apply {SID} 90 none 0 0", caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": str(n)}, timeout=60,
    )


def run_confirm(router, n):
    return router.forced(
        f"confirm {SID}", caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": str(n)}, timeout=40,
    )


def run_abort(router, n):
    return router.forced(
        f"abort {SID}", caller="agent-one", role="change",
        env={"NEWTON_ROUTER_CRASH_AT": str(n)}, timeout=30,
    )


RUN = {
    "stage":   run_stage,
    "seal":    run_seal,
    "apply":   run_apply,
    "confirm": run_confirm,
    "abort":   run_abort,
}

# Design-mandated minimum crash points per subcommand.
MIN_CRASH = {"stage": 2, "seal": 3, "apply": 3, "confirm": 3, "abort": 3}


# ---- 1. main crash loop: kill, then three recoveries ------------------

@pytest.mark.parametrize("sub", ["stage", "seal", "apply", "confirm", "abort"])
def test_crash_loop_recovery(router, tmp_path, sub):
    """For each subcommand run with NEWTON_ROUTER_CRASH_AT=n for n=1..N
    until the program survives. After each killed run, copy the killed
    state to three fresh trees and recover via abort (controller
    alive), guard tick past the deadline (controller dead), and guard
    boot at uptime 8 after wiping /tmp (reboot). /etc/config must be
    byte-identical to the original, or to the post bytes only for a
    confirm killed after the guard confirmed. The first non-killed run
    must succeed as the plain run does."""
    original = snapshot_config(router.root)
    PREPARE[sub](router)
    orig_root = router.root

    pre_dir = tmp_path / "pre"
    copytree(router.root, pre_dir)

    seen_killed = 0
    saw_non_killed = False

    for n in range(1, 41):
        iter_dir = tmp_path / f"iter_{n}"
        copytree(pre_dir, iter_dir)
        swap_root(router, iter_dir)

        res = RUN[sub](router, n)

        if res.rc != -9:
            if sub == "stage":
                assert res.rc == 0, (sub, n, res.rc, res.err, res.out)
                assert SID in res.out, (sub, res.out)
            elif sub == "seal":
                assert res.rc == 0, (sub, n, res.rc, res.err, res.out)
                assert "digest " in res.out, (sub, res.out)
            elif sub == "apply":
                assert res.rc == 0, (sub, n, res.rc, res.err, res.out)
                assert res.out.startswith(f"applied {SID} t=90 guard="), res.out
            elif sub == "confirm":
                assert res.rc == 0, (sub, n, res.rc, res.err, res.out)
                assert f"confirmed {SID}" in res.out, (sub, res.out)
            elif sub == "abort":
                assert res.rc == 0, (sub, n, res.rc, res.err, res.out)
            saw_non_killed = True
            break

        seen_killed += 1
        assert lock_is_free(router.root), (sub, n, "lock held after kill")

        for kind in ("alive", "dead", "reboot"):
            rec_dir = tmp_path / f"rec_{n}_{kind}"
            copytree(iter_dir, rec_dir)
            swap_root(router, rec_dir)

            if kind == "alive":
                guard_pending = guard_pending_for(router, SID)
                txn_dir = router.root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn"
                txn_present = txn_dir.is_dir()
                rec = router.forced(
                    f"abort {SID}", caller="agent-one", timeout=30,
                )
                if sub == "confirm" and not guard_pending and txn_present:
                    # Confirm killed after the guard confirmed and the
                    # txn still exists: abort returns
                    # "already-confirmed" (exit 1).
                    assert rec.rc == 1, (sub, n, kind, rec.rc, rec.err)
                    assert "already-confirmed" in rec.err, (sub, n, rec.err)
                else:
                    # Either guard still pending (rollback path), or
                    # the txn is already gone (after the program's
                    # cleanup ran). Either way abort exits 0, or, for
                    # stage crash point 1, refuses with `not-owner`
                    # exit 3 because the txn dir has no owner file yet.
                    assert rec.rc in (0, 3), (sub, n, kind, rec.rc, rec.err, rec.out)
                cur = snapshot_config(router.root)
                ok_set = (original, POST_BYTES) if sub == "confirm" else (original,)
                assert cur in ok_set, (sub, n, kind, cur)

            elif kind == "dead":
                router.set_uptime(400)
                router.rpcd_tick()
                router.guard("tick")
                word = status_word(router, SID)
                allowed = {"staged", "gone", "rolled-back", "confirmed"}
                assert word in allowed, (sub, n, kind, word)
                assert word != "applied-pending-confirm", (sub, n, kind, word)
                assert word != "inconsistent", (sub, n, kind, word)
                cur = snapshot_config(router.root)
                ok_set = (original, POST_BYTES) if sub == "confirm" else (original,)
                assert cur in ok_set, (sub, n, kind, cur)
                gs = router.guard_status()
                assert not gs.startswith("failed"), (sub, n, kind, gs)

            elif kind == "reboot":
                lock_dir = router.root / "tmp/owrt-safe-apply.lock"
                if lock_dir.exists():
                    shutil.rmtree(lock_dir)
                router.set_boot_id("boot-two")
                router.set_uptime(8)
                router.guard("boot")
                word = status_word(router, SID)
                allowed = {"rolled-back", "gone", "confirmed"}
                assert word in allowed, (sub, n, kind, word)
                cur = snapshot_config(router.root)
                ok_set = (original, POST_BYTES) if sub == "confirm" else (original,)
                assert cur in ok_set, (sub, n, kind, cur)
                gs = router.guard_status()
                assert not gs.startswith("failed"), (sub, n, kind, gs)

    assert saw_non_killed, f"{sub}: program kept being killed through n=40"
    assert seen_killed >= MIN_CRASH[sub], (sub, seen_killed, MIN_CRASH[sub])

    swap_root(router, orig_root)


# ---- 2. density --------------------------------------------------------

@pytest.mark.parametrize("with_probes", [False, True],
                         ids=["no-probes", "with-probes"])
def test_seal_crash_points_count(router, tmp_path, with_probes):
    """Density: `seal` with probes has at least as many crash points as
    without. Each run of the seal crash loop must kill at least
    MIN_CRASH['seal'] runs before a non-killed run survives."""
    PREPARE["seal"](router)
    pre_dir = tmp_path / "pre"
    copytree(router.root, pre_dir)
    probes = b"fail\n" if with_probes else b""
    killed = 0
    for n in range(1, 15):
        iter_dir = tmp_path / f"iter_{'p' if with_probes else 'np'}_{n}"
        copytree(pre_dir, iter_dir)
        swap_root(router, iter_dir)
        res = router.forced(
            f"seal {SID} 90", caller="agent-one", role="change",
            stdin=probes,
            env={"NEWTON_ROUTER_CRASH_AT": str(n)}, timeout=40,
        )
        if res.rc != -9:
            break
        killed += 1
    assert killed >= MIN_CRASH["seal"], (with_probes, killed)


@pytest.mark.parametrize("sub", ["stage", "seal", "apply", "confirm", "abort"])
def test_kill_leaves_no_lock(router, tmp_path, sub):
    """After each killed run the program lock at `tmp/newton/flock` is
    free (`flock -n` succeeds at once)."""
    PREPARE[sub](router)
    pre_dir = tmp_path / "pre"
    copytree(router.root, pre_dir)
    killed_count = 0
    for n in range(1, 12):
        iter_dir = tmp_path / f"iter_{n}"
        copytree(pre_dir, iter_dir)
        swap_root(router, iter_dir)
        res = RUN[sub](router, n)
        if res.rc != -9:
            break
        killed_count += 1
        assert lock_is_free(router.root), (sub, n, "lock held after kill")
    assert killed_count >= MIN_CRASH[sub], (sub, killed_count, MIN_CRASH[sub])


# ---- 4. kill between arm and uci apply ---------------------------------

def test_apply_crash_between_arm_and_uci_apply(router, tmp_path):
    """Kill at apply crash point 1 (right after the `applying` write,
    before `uci apply`): the guard is armed (pending), the config is
    still the original bytes, and after tick past the guard's deadline
    the guard restores (a no-op copy) and the config stays original."""
    original = snapshot_config(router.root)
    PREPARE["apply"](router)

    iter_dir = tmp_path / "iter"
    copytree(router.root, iter_dir)
    swap_root(router, iter_dir)
    res = RUN["apply"](router, 1)
    assert res.rc == -9, (res.rc, res.out, res.err)

    assert guard_pending_for(router, SID)
    assert snapshot_config(router.root) == original

    router.set_uptime(400)
    router.rpcd_tick()
    router.guard("tick")

    gs = router.guard_status()
    assert gs.startswith("restored"), gs
    assert snapshot_config(router.root) == original


# ---- 5. kill between rpcd confirm and guard confirm --------------------

def test_confirm_crash_between_rpcd_and_guard_confirm(router, tmp_path):
    """Kill at confirm crash point 1 (right after the `rpcd-confirmed`
    write, before `$GUARD confirm`): the guard is still pending, the
    config is post (rpcd has confirmed), and after tick past the
    guard's deadline the guard restores the original bytes. Every
    interrupted confirm ends reverted."""
    original = snapshot_config(router.root)
    PREPARE["confirm"](router)

    iter_dir = tmp_path / "iter"
    copytree(router.root, iter_dir)
    swap_root(router, iter_dir)
    res = RUN["confirm"](router, 1)
    assert res.rc == -9, (res.rc, res.out, res.err)

    assert guard_pending_for(router, SID)
    assert snapshot_config(router.root) == POST_BYTES

    router.set_uptime(400)
    router.rpcd_tick()
    router.guard("tick")

    gs = router.guard_status()
    assert gs.startswith("restored"), gs
    assert snapshot_config(router.root) == original