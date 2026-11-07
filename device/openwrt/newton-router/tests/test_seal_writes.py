"""`seal` must check every durable write and
`apply` must fail closed when the sealed leash copy is missing or unreadable.

The eight `seal` durable writes (t, base, diff, probes, probes-sha, profile,
leash, digest) plus the `sealed` marker are caught. A directory of the same
name inside the txn dir makes the write fail with EISDIR; the program must
refuse with `error internal write`, leave no `sealed` file, free the program
lock, and leave `apply` to refuse with `error not-sealed`. A missing or
unreadable `$txn/leash` at apply time makes `apply` refuse with
`error needs-approval leash-unreadable` even on a lab plan with token `none`,
and a correct token still applies.
"""

import os
import shutil
import subprocess

import pytest

from conftest import SID


# ---- shared helpers (modelled on test_apply.py; copy what we need) ----------

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
    """The guard's `arm` step calls `df`; feed it a parseable line."""
    router.set_fake("df", out=DF_OUT)


def snapshot_config(router):
    """A snapshot of every etc/config file's bytes for byte-equality checks."""
    cfg = router.root / "etc/config"
    return {p.name: p.read_bytes() for p in sorted(cfg.iterdir())
            if p.is_file() and not p.is_symlink()}


def nothing_applied(router, sid):
    """Post-refusal: no ubus call to uci-apply, no guard pending state, idle guard."""
    assert not any(f" sid={sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))
    assert not (router.root / "etc/newton/pending").exists()
    assert router.guard_status() == "idle"


# ---- fixtures ---------------------------------------------------------------

STAGE_FILES_BEFORE_SEAL = ("owner", "stage-up", "boot")


def _staged(router, sid=SID):
    """Run the same steps `fresh_plan` runs before seal, with a configurable
    txn directory we can mess with. Returns the txn path."""
    router.use_stub_helper()
    if not (router.root / "control/diff.txt").exists():
        router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("etc/newton/profile", "lab\n")
    live_dhcp = (router.root / "etc/config/dhcp").read_bytes()
    staged_dhcp = b"config dnsmasq\n\toption domainneeded '0'\n"
    router.write("control/staged/dhcp", staged_dhcp)
    assert staged_dhcp != live_dhcp
    res = router.stage(sid=sid)
    assert (res.rc, res.out, res.err) == (0, sid + "\n", "")
    health = router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.health"
    health.mkdir(parents=True, exist_ok=True)
    (health / "newton-fw4-loaded").write_text("0\n")
    return router.txn(sid)


# ---- 1. every seal write failure is refused and leaves no sealed marker ----


WRITE_NAMES = [
    "t", "base", "diff", "probes", "probes-sha", "profile", "leash", "digest",
]


@pytest.mark.parametrize("name", WRITE_NAMES,
                         ids=WRITE_NAMES)
def test_seal_write_failure_is_refused(router, name):
    """For each of the eight numbered durable seal writes, a directory of
    that exact name inside the txn dir blocks the write (EISDIR even for
    root). The program must refuse with `error internal write`, exit 1,
    stdout empty, the txn dir must NOT have a `sealed` file, and the program
    lock must be free. A follow-up `apply` of the same SID refuses with
    `error not-sealed`."""
    txn = _staged(router)
    blocker = txn / name
    blocker.mkdir()
    res = router.seal(SID, 90)
    assert (res.rc, res.out, res.err) == (1, "", "error internal write\n")
    assert not (txn / "sealed").exists()
    # the blocker directory is left in place (the program never removed it
    # on purpose; only the `sealed` marker is taken away by seal_write_fail)
    assert blocker.is_dir()
    # the txn's pre-seal stage files still exist (seal never reached them)
    for pre in STAGE_FILES_BEFORE_SEAL:
        assert (txn / pre).exists(), pre
    assert lock_is_free(router)
    # a follow-up apply of this SID refuses with not-sealed; the program
    # lock is free afterwards
    if not (router.root / "tmp/owrt-safe-apply.lock" / "sid").exists():
        (router.root / "tmp/owrt-safe-apply.lock" / "sid").write_text(SID + "\n")
    ready_for_arm(router)
    live = snapshot_config(router)
    res = router.apply(SID, 90, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (3, "", "error not-sealed\n")
    nothing_applied(router, SID)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


def test_seal_sealed_marker_write_failure_is_refused(router):
    """The `sealed` marker is the ninth and last write. A dangling symlink named
    `sealed` (the existence test follows the link and sees nothing, the write cannot
    create the target) makes that write fail while the eight before it succeed:
    refused with `error internal write`, exit 1, and no `sealed` left (the link is
    taken away too, so the txn cannot look sealed)."""
    txn = _staged(router)
    (txn / "sealed").symlink_to("/nonexistent-dir-for-newton-test/sealed")
    res = router.seal(SID, 90)
    assert (res.rc, res.out, res.err) == (1, "", "error internal write\n")
    assert not (txn / "sealed").exists()
    assert not (txn / "sealed").is_symlink()
    assert lock_is_free(router)


# ---- 2. retry after the failure succeeds -----------------------------------


def test_seal_retry_after_write_failure_succeeds(router):
    """After a failed seal that left a directory where `leash` should be,
    removing that directory and trying again must produce a real seal:
    exit 0, the `sealed` marker exists, and `leash` is a regular file with
    the program-output bytes."""
    txn = _staged(router)
    (txn / "leash").mkdir()
    res = router.seal(SID, 90)
    assert (res.rc, res.err) == (1, "error internal write\n")
    assert not (txn / "sealed").exists()
    assert lock_is_free(router)
    # drop the program lock's active SID so the retry can take the lock too
    if (router.root / "tmp/owrt-safe-apply.lock" / "sid").exists():
        (router.root / "tmp/owrt-safe-apply.lock" / "sid").unlink()
    shutil.rmtree(txn / "leash")
    res = router.seal(SID, 90)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert (txn / "sealed").exists()
    leash = txn / "leash"
    assert leash.is_file() and not leash.is_dir()
    # no `leash` lines on a lab profile with no offending change
    assert leash.read_bytes() == b""
    assert lock_is_free(router)


# ---- 3. missing leash copy at apply fails closed --------------------------


def test_apply_missing_leash_copy_needs_approval(router):
    """A sealed plan whose txn holds a sealed marker but whose `<txn>/leash`
    copy is missing: a lab-profile plan with no offence has the seal write
    an empty leash copy by default. Delete that copy before apply; lab
    profile, token `none` must refuse with `error needs-approval
    leash-unreadable` (exit 3), nothing applied, no guard arm, no `applying`
    file, no `ubus uci-apply` call, no `etc/newton/pending`."""
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    live = snapshot_config(router)
    # delete the sealed leash copy
    (plan.txn / "leash").unlink()
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.out, res.err) == (
        3, "", "error needs-approval leash-unreadable\n"
    )
    assert not (plan.txn / "applying").exists()
    nothing_applied(router, plan.sid)
    assert snapshot_config(router) == live
    assert lock_is_free(router)


# ---- 4. valid token applies even with a missing leash copy -----------------


def test_apply_missing_leash_copy_with_token_applies(router):
    """Same setup as case 3, but `apply` with the seal-digest token: exit 0
    and stdout starts with `applied <sid>`. This proves the leash-unreadable
    code is added to the requested codes, not a blanket refusal."""
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    (plan.txn / "leash").unlink()
    nbf, exp = router.window()
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert res.err == ""
    assert res.out.startswith(f"applied {plan.sid} t={plan.t} guard=")
    assert lock_is_free(router)


# ---- 5. empty (legitimate) leash copy at apply does NOT require a token ---


def test_apply_empty_leash_copy_lab_is_not_required(router):
    """Lab profile, the seal stored an empty leash file (no leash lines):
    `apply` with token `none` applies (exit 0). Guards against over-refusing
    a legitimate empty leash file vs. a missing one (grep exits 1 vs. 2)."""
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    # confirm the seal wrote an empty leash file
    assert (plan.txn / "leash").is_file()
    assert (plan.txn / "leash").read_bytes() == b""
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert res.err == ""
    assert res.out.startswith(f"applied {plan.sid} t={plan.t} guard=")
    assert lock_is_free(router)
