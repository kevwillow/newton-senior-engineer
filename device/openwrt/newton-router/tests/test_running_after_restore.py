"""The `running=` field of the status line: what the router runs now,
after the guard put a session's settings back on its own (design 6.5).

When the guard restores a session at its deadline, it puts the old files
back and reloads the config (the guard's restore calls `reload_config`),
so the services run the settings that are back again.  After a reboot the
change was pending from an earlier boot, so the services had already
started with the changed files and the restore reloaded them.  The health
check then compares the running network with the snapshot the apply took,
the state before the change: it passes when the running network is the
restored one and fails when it is not.  The status line then carries one
more field, at its very end:

- `running=match`     the health check passes: the running network matches
                       the settings that are back;
- `running=differs`   the health check fails: it does not;
- `running=unproven`  Newton cannot say: no health snapshot, or another
                       command holds the program lock;
- `running=boot`      the guard put the settings back at boot: the services
                       started from the restored files, so there is nothing
                       to compare.

Every other guard label (abort, idle, pending, another session) keeps the
line byte-for-byte as it was.
"""

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from conftest import BUSYBOX, SID, _use_verify_stub


LOCK_DIR = "tmp/owrt-safe-apply.lock"


# ---- shared helpers ------------------------------------------------------


def health_snapshot(router, sid=SID):
    """The health snapshot the apply took: $LOCK/<sid>.health."""
    router.write(f"{LOCK_DIR}/{sid}.health/newton-fw4-loaded", "0\n")


def guard_restored(router, sid=SID, reason="deadline"):
    """The guard's status line says `restored <sid> <reason>`."""
    router.write("etc/newton/last_revert", f"{sid} {reason}\n")


def status_line(router, sid=SID, timeout=30):
    """The one line `status <sid>` prints."""
    res = router.forced(f"status {sid}", role="read", timeout=timeout)
    assert res.rc == 0, (res.rc, res.out, res.err)
    lines = res.out.splitlines()
    assert len(lines) == 1, res.out
    return lines[0]


def lock_is_free(router):
    """The program lock is free when `flock -n` returns 0 at once."""
    proc = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return proc.returncode == 0


def start_status(router, sid=SID):
    """Start `status <sid>` without waiting for it; returns the Popen."""
    return subprocess.Popen(
        [BUSYBOX, "sh", str(router.program), "--caller=agent-one", "--role=read"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=router._merged_env({"SSH_ORIGINAL_COMMAND": f"status {sid}"}),
        start_new_session=True,
    )


def waits_for_the_lock(path, timeout=20):
    """True when a process has the program lock file open as fd 8.

    The program takes the lock with `exec 8>>` (its lock_take), so a
    process with that fd 8 open is inside lock_take: it has passed the
    check the status makes before the lock."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                link = os.readlink(entry / "fd" / "8")
            except OSError:
                continue
            if link == str(path):
                return True
        time.sleep(0.05)
    return False


def wait_for(proc, timeout):
    """Wait for a started run; returns (out, err, rc) or None on timeout."""
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    return out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), proc.returncode


# ---- 1. the health check passes -----------------------------------------


def test_a_restored_session_whose_health_check_passes_says_match(router):
    """The guard restored the session at its deadline, the health snapshot
    is there and the health check passes: the running network matches the
    settings that are back."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router)
    line = status_line(router)
    assert line == (
        f"rolled-back sid={SID} guard=restored:deadline rpcd=- config=- boot=-"
        " running=match"
    ), line
    # the health check ran, in the after-rollback mode (a restore restarts
    # the services on purpose, so the restart check does not apply)
    assert router.calls_matching("helper health-check") == [
        f"helper health-check {SID} after-rollback"
    ], router.calls()


# ---- 2. the health check fails -------------------------------------------


def test_a_failed_health_check_says_differs(router):
    """The same state, but the health check fails (the helper answers
    rc 1): the running network does not match the settings that are back."""
    _use_verify_stub(router)
    health_snapshot(router)
    router.write("control/health-check.rc", "1\n")
    guard_restored(router)
    line = status_line(router)
    assert line.endswith(" running=differs"), line
    assert router.calls_matching("helper health-check") == [
        f"helper health-check {SID} after-rollback"
    ], router.calls()


# ---- 3. no health snapshot ----------------------------------------------


def test_a_restored_session_without_a_health_snapshot_says_unproven(router):
    """No health snapshot: there is nothing to compare the running network
    with, so the answer is `unproven` and no health check runs."""
    _use_verify_stub(router)
    guard_restored(router)
    line = status_line(router)
    assert line.endswith(" running=unproven"), line
    assert router.calls_matching("helper health-check") == [], router.calls()


# ---- 4. a restore after a reboot ----------------------------------------


def test_a_restore_after_a_reboot_without_a_snapshot_says_unproven(router):
    """The guard restored the session after a reboot: the change was
    pending from an earlier boot, so the services had already started
    with the changed files and the restore only reloaded them.  The
    running network is compared with the health snapshot the apply took;
    after a reboot that snapshot is normally gone (it lives in /tmp), so
    the answer is `unproven` and no health check runs."""
    _use_verify_stub(router)
    guard_restored(router, reason="reboot")
    line = status_line(router)
    assert line == (
        f"rolled-back sid={SID} guard=restored:reboot rpcd=- config=- boot=-"
        " running=unproven"
    ), line
    assert router.calls_matching("helper health-check") == [], router.calls()


def test_a_restore_after_a_reboot_whose_health_check_passes_says_match(router):
    """The same restore, with the health snapshot of the apply still there
    and its health check passing: the running network matches the settings
    that are back."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router, reason="reboot")
    line = status_line(router)
    assert line == (
        f"rolled-back sid={SID} guard=restored:reboot rpcd=- config=- boot=-"
        " running=match"
    ), line
    assert router.calls_matching("helper health-check") == [
        f"helper health-check {SID} after-rollback"
    ], router.calls()


# ---- 5. a restore at boot -----------------------------------------------


def test_a_restore_at_boot_says_boot_and_checks_nothing(router):
    """The guard restored the session at boot: the router rebooted while
    the session was open, and the guard put the old files back before the
    services started from them.  The answer is `boot` and no health check
    runs."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router, reason="boot")
    line = status_line(router)
    assert line == (
        f"rolled-back sid={SID} guard=restored:boot rpcd=- config=- boot=-"
        " running=boot"
    ), line
    assert router.calls_matching("helper health-check") == [], router.calls()


# ---- 6. every other guard label keeps the line --------------------------


def test_a_restore_by_an_abort_keeps_the_line_as_it_was(router):
    """The guard says `restored <sid> abort`: the restore was not the
    guard's own doing at its deadline, so the line is the one of today,
    without a `running=` field."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router, reason="abort")
    line = status_line(router)
    assert line == (
        f"rolled-back sid={SID} guard=restored:abort rpcd=- config=- boot=-"
    ), line
    assert " running=" not in line, line


# ---- 7. another command holds the program lock --------------------------


def test_a_lock_another_command_holds_says_unproven(router):
    """Another command holds the program lock: the status does not hang and
    does not fail, it answers `unproven` (the health check would race the
    change that is running now)."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router)
    lock = router.root / "tmp/newton/flock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = subprocess.Popen(
        ["/usr/bin/flock", str(lock), "/bin/sleep", "60"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline and lock_is_free(router):
            time.sleep(0.05)
        assert not lock_is_free(router), "the holder did not take the lock"
        started = time.time()
        line = status_line(router, timeout=40)
        elapsed = time.time() - started
    finally:
        holder.terminate()
        holder.wait(timeout=10)
    assert line.endswith(" running=unproven"), line
    # the lock bound is 10 s: the status waits for it, then answers
    assert elapsed < 30, elapsed
    assert router.calls_matching("helper health-check") == [], router.calls()


# ---- 8. the quarantined count comes first -------------------------------


def test_the_quarantined_count_comes_before_the_running_field(router):
    """A config file that appeared during the window is moved to the
    guard's quarantine when the guard restores.  The status line names the
    count and the running field, in that order."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router)
    qdir = router.root / "etc/newton/quarantine" / SID
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "myvpn").write_text("config vpn 'x'\n")
    (qdir / "other").write_text("config other 'y'\n")
    line = status_line(router)
    assert line.endswith(" quarantined=2 running=match"), line


# ---- 9. the snapshot goes while the status waits for the lock ------------


def test_a_snapshot_that_goes_while_the_status_waits_for_the_lock_says_unproven(router):
    """The health snapshot is there when the status starts, but it goes
    while the status waits for the program lock: the command that holds
    the lock removes it and only then lets go.  There is nothing left to
    compare, so the answer is `unproven` and not `differs`."""
    _use_verify_stub(router)
    health_snapshot(router)
    guard_restored(router)
    lock = router.root / "tmp/newton/flock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = subprocess.Popen(
        ["/usr/bin/flock", str(lock), "/bin/sleep", "60"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    proc = None
    try:
        deadline = time.time() + 10
        while time.time() < deadline and lock_is_free(router):
            time.sleep(0.05)
        assert not lock_is_free(router), "the holder did not take the lock"
        proc = start_status(router)
        # the status is inside lock_take: it has passed the check it makes
        # before the lock, so the snapshot it saw is the one that is there
        assert waits_for_the_lock(lock, timeout=20), (
            "the status did not reach the lock"
        )
        # the snapshot goes while the status waits for the lock
        shutil.rmtree(router.root / LOCK_DIR / f"{SID}.health")
        # and the lock is released (the holder's own process group, so the
        # sleep it runs goes with it and lets the lock go)
        os.killpg(os.getpgid(holder.pid), signal.SIGTERM)
        holder.wait(timeout=10)
        done = wait_for(proc, 40)
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
        if holder.poll() is None:
            os.killpg(os.getpgid(holder.pid), signal.SIGTERM)
            holder.wait(timeout=10)
    assert done is not None, "the status did not finish within 40 s of the release"
    out, err, rc = done
    assert rc == 0, (rc, out, err)
    assert out.strip().endswith(" running=unproven"), out
