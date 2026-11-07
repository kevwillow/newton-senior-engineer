import hashlib
import inspect
import os
import re
import signal
import stat
import subprocess
import time

import pytest

from conftest import BUSYBOX, GUARD, GUARD_TIMEOUT, HERE, arm, run_guard, snapshot
from test_guard import (
    calls,
    change_config,
    fresh_copy,
    manifest_ok,
    set_boot,
    set_uptime,
    tree_state,
)


DEFAULT_NAMES = ["dhcp", "firewall", "network", "system", "wireless"]

SKIPPED_NAMES = [
    b"network.apk-new",
    b"bad name",
    b"tab\tname",
    b"esc\x1b[31mred",
    b"line\nbreak",
    b"back\\slash",
    b"high\xffbyte",
    b".hidden",
]


def escape(name_bytes):
    out = []
    for byte in name_bytes:
        char = chr(byte)
        if (
            "a" <= char <= "z"
            or "A" <= char <= "Z"
            or "0" <= char <= "9"
            or char in "._-"
        ):
            out.append(char)
        else:
            out.append("\\x%02x" % byte)
    return "".join(out)


def skipped_line(names):
    listed = [n for n in names if not n.startswith(b".")]
    return "skipped " + " ".join(escape(n) for n in sorted(listed)) + "\n"


def write_config_bytes(cfg, name, data=b"skipped\n"):
    if isinstance(name, str):
        name = name.encode()
    path = os.path.join(os.fsencode(str(cfg)), name)
    with open(path, "wb") as handle:
        handle.write(data)


def guard_log_text(router):
    path = router / "etc/newton/guard.log"
    return path.read_text() if path.exists() else ""


def assert_arm_failed_clean(router, result, message):
    ng = router / "etc/newton"
    assert result.returncode == 1
    assert result.stdout == message
    assert not (ng / "pending").exists()
    assert not (ng / ".pending.tmp").exists()
    assert not (ng / "lkg/txn-0001").exists()
    assert run_guard(router, "status").stdout == "idle\n"
    assert "start" not in calls(router, "init")


# atomic_write must fail loudly.


def test_g1_mv_fail_pending_blocks_arm_then_recovers(router):
    original = snapshot(router)
    (router / "control/mv-fail").write_text("/pending\n")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-write-failed\n")
    (router / "control/mv-fail").unlink()
    result = arm(router)
    assert result.stdout == "armed txn-0001 161 60\n"
    assert manifest_ok(router, "txn-0001") == sorted(original)


def test_g1_mv_fail_once_pending_first_arm_fails_second_succeeds(router):
    (router / "control/mv-fail-once").write_text("/pending\n")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-write-failed\n")
    assert not (router / "control/mv-fail-once").exists()
    result = arm(router)
    assert result.stdout == "armed txn-0001 161 60\n"


def test_g1_printf_failure_to_dev_full(router):
    ng = router / "etc/newton"
    ng.mkdir(parents=True, exist_ok=True)
    (ng / ".pending.tmp").symlink_to("/dev/full")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-write-failed\n")
    assert not (ng / ".pending.tmp").exists()


def test_g1_sync_failure_blocks_arm(router):
    (router / "control/sync-fail").write_text("")
    # An unconditional sync failure now hits the checked LKG-write sync first.
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error lkg-write-failed\n")


def test_g1_truncated_pending_is_detected(router):
    (router / "control/mv-truncate").write_text("/pending\n")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-mismatch\n")


def test_g1_revert_record_write_failure_keeps_pending(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/mv-fail").write_text("last_revert\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (router / "etc/newton/pending").exists()
    assert not (router / "etc/newton/failed").exists()
    assert (router / "etc/newton/restore_attempts").read_text() == "txn-0001 1\n"
    assert snapshot(router) == original
    assert not list((router / "etc/newton").glob(".*.tmp"))
    (router / "control/mv-fail").unlink()
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 deadline\n")
    assert not (router / "etc/newton/restore_attempts").exists()
    assert run_guard(router, "status").stdout == "restored txn-0001 deadline\n"


def test_g1_failed_marker_write_failure_is_logged(router):
    arm(router)
    (router / "etc/newton/lkg/txn-0001/network").write_text("corrupt\n")
    (router / "control/mv-fail").write_text("/failed\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (1, "failed txn-0001 lkg-corrupt\n")
    assert not (router / "etc/newton/failed").exists()
    assert not list((router / "etc/newton").glob(".*.tmp"))
    assert "failed marker write failed" in guard_log_text(router)


def test_g1_boot_counter_write_failure_still_restores(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/mv-fail").write_text("boot_attempts\n")
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 boot\n")
    assert snapshot(router) == original
    assert not list((router / "etc/newton").glob(".*.tmp"))
    assert "boot attempts write failed" in guard_log_text(router)


def test_g1_boot_loop_marker_write_failure_does_not_restore(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    (router / "etc/newton/boot_attempts").write_text("txn-0001 3\n")
    (router / "control/mv-fail").write_text("/failed\n")
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "failed txn-0001 boot-loop\n")
    assert not (router / "etc/newton/failed").exists()
    assert "failed marker write failed" in guard_log_text(router)
    assert not list((router / "etc/newton").glob(".*.tmp"))
    assert snapshot(router) == changed


# a pending file that vanishes is not corruption.


def hold_lock(router):
    (router / "etc/newton").mkdir(parents=True, exist_ok=True)
    lock = router / "etc/newton/guard.lock"
    holder = subprocess.Popen(
        ["/usr/bin/flock", str(lock), "sleep", "30"],
        start_new_session=True,
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        probe = subprocess.run(["/usr/bin/flock", "-n", str(lock), "true"])
        if probe.returncode != 0:
            return holder
        assert holder.poll() is None
        time.sleep(0.02)
    os.killpg(holder.pid, signal.SIGTERM)
    holder.wait(timeout=3)
    pytest.fail("lock holder did not acquire the state lock")


def run_locked_tick(router, action):
    holder = hold_lock(router)
    guard = None
    try:
        env = os.environ.copy()
        env["NEWTON_GUARD_ROOT"] = str(router)
        guard = subprocess.Popen(
            [BUSYBOX, "sh", str(GUARD), "tick"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(0.5)
        assert guard.poll() is None
        action()
        os.killpg(holder.pid, signal.SIGTERM)
        holder.wait(timeout=3)
        stdout, stderr = guard.communicate(timeout=GUARD_TIMEOUT)
        return guard.returncode, stdout, stderr
    finally:
        if holder.poll() is None:
            os.killpg(holder.pid, signal.SIGTERM)
            holder.wait(timeout=3)
        if guard is not None and guard.poll() is None:
            os.killpg(guard.pid, signal.SIGTERM)
            guard.communicate(timeout=3)


def test_g7_pending_vanishing_under_lock_is_not_corruption(router):
    arm(router)
    (router / "etc/newton/pending").write_text("not a pending record\n")
    rc, stdout, stderr = run_locked_tick(router, lambda: (router / "etc/newton/pending").unlink())
    assert (rc, stdout, stderr) == (0, "idle\n", "")
    assert not (router / "etc/newton/failed").exists()
    assert "restore failed" not in guard_log_text(router)


def test_g7_pending_replaced_under_lock_is_not_restored(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    pending = router / "etc/newton/pending"
    pending.write_text("not a pending record\n")
    rc, stdout, stderr = run_locked_tick(
        router, lambda: pending.write_text("txn-0001 9999 boot-one\n")
    )
    assert (rc, stdout, stderr) == (0, "pending txn-0001 9899\n", "")
    assert snapshot(router) == changed
    assert not (router / "etc/newton/failed").exists()


# file names in /etc/config.


def test_g8_skipped_names_escaped_in_status(router):
    cfg = router / "etc/config"
    for name in SKIPPED_NAMES:
        write_config_bytes(cfg, name)
    (cfg / "-dash").write_bytes(b"dash\n")
    result = arm(router)
    assert result.stdout == "armed txn-0001 161 60\n"
    assert manifest_ok(router, "txn-0001") == sorted(DEFAULT_NAMES + ["-dash"])
    lkg = router / "etc/newton/lkg/txn-0001"
    for name in SKIPPED_NAMES:
        assert not os.path.exists(os.path.join(os.fsencode(str(lkg)), name))
    status = run_guard(router, "status")
    expected = "pending txn-0001 61\n" + skipped_line(SKIPPED_NAMES)
    assert status.stdout == expected
    assert all(char == "\n" or 0x20 <= ord(char) <= 0x7E for char in status.stdout)


def test_g8_restore_never_touches_skipped_files(router):
    cfg = router / "etc/config"
    for name in SKIPPED_NAMES:
        write_config_bytes(cfg, name)
    arm(router)
    changed_path = os.path.join(os.fsencode(str(cfg)), b"bad name")
    changed_ino = os.stat(changed_path).st_ino
    with open(changed_path, "wb") as handle:
        handle.write(b"changed skipped\n")
    os.unlink(os.path.join(os.fsencode(str(cfg)), b"tab\tname"))
    write_config_bytes(cfg, b"new.skip", b"new skipped\n")
    (cfg / "network").write_bytes(b"changed network\n")
    (cfg / "extra2").write_bytes(b"preserve me\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    assert os.stat(changed_path).st_ino == changed_ino
    with open(changed_path, "rb") as handle:
        assert handle.read() == b"changed skipped\n"
    assert not os.path.exists(os.path.join(os.fsencode(str(cfg)), b"tab\tname"))
    assert os.path.exists(os.path.join(os.fsencode(str(cfg)), b"new.skip"))
    qdir = router / "etc/newton/quarantine/txn-0001"
    quarantined = os.listdir(os.fsencode(str(qdir))) if qdir.exists() else []
    for name in SKIPPED_NAMES + [b"new.skip"]:
        assert name not in quarantined
    assert (cfg / "network").read_bytes() == b"config interface 'lan'\n\toption proto 'static'\n"
    assert (qdir / "extra2").read_bytes() == b"preserve me\n"


def test_g8_only_skipped_names_refuses(router):
    cfg = router / "etc/config"
    for name in DEFAULT_NAMES:
        (cfg / name).unlink()
    write_config_bytes(cfg, b"only.skip")
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (3, "refused no-config\n")


def test_g8_skipped_files_do_not_count_for_space(router):
    cfg = router / "etc/config"
    write_config_bytes(cfg, "big.skip", b"x" * (3 * 1024 * 1024))
    total = sum(len((cfg / name).read_bytes()) for name in DEFAULT_NAMES)
    need = 2 * ((total + 1023) // 1024) + 256
    (router / "control/avail").write_text(f"{need - 1}\n")
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (3, f"refused low-space {need - 1} {need}\n")
    (router / "control/avail").write_text(f"{need}\n")
    assert run_guard(router, "arm", "txn-0001", "60").returncode == 0


def test_g8_status_and_single_line_outputs(router):
    write_config_bytes(router / "etc/config", b"skip.me")
    status = run_guard(router, "status")
    assert status.stdout == "idle\nskipped skip.me\n"
    arm(router)
    tick = run_guard(router, "tick")
    assert tick.stdout == "pending txn-0001 61\n"
    assert len(tick.stdout.splitlines()) == 1
    assert run_guard(router, "confirm", "txn-0001").returncode == 0
    boot = run_guard(router, "boot")
    assert boot.stdout == "idle\n"
    assert len(boot.stdout.splitlines()) == 1


# test timeouts.


def test_g9_run_guard_timeout_default_is_60():
    parameter = inspect.signature(run_guard).parameters["timeout"]
    assert parameter.default == GUARD_TIMEOUT == 60
    assert parameter.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


# pin atomic_write and arm exactly.


def test_round1_first_sync_failure_blocks_arm(router):
    # Fails only the sync before the pending rename (the temp file still exists).
    (router / "control/sync-fail-if-exists").write_text("etc/newton/.pending.tmp\n")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-write-failed\n")
    assert len(calls(router, "sync")) >= 1


def test_round1_last_sync_failure_blocks_arm(router):
    # The rename happened, so only the sync after it fails.
    (router / "control/sync-fail-if-exists").write_text("etc/newton/pending\n")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-write-failed\n")


def test_round1_read_back_with_extra_line_blocks_arm(router):
    (router / "control/mv-append").write_text("/pending\n")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error pending-mismatch\n")


# seal the LKG manifest.


def seal_of(router, txn="txn-0001"):
    return router / f"etc/newton/lkg/{txn}/.seal"


def assert_lkg_refusal_untouched(router, result, why):
    assert (result.returncode, result.stdout) == (1, f"failed txn-0001 {why}\n")
    assert not (router / "etc/newton/quarantine").exists()
    assert not list((router / "etc/config").glob(".newton-tmp.*"))
    assert (router / "etc/newton/pending").exists()


def test_g3_arm_writes_seal(router):
    arm(router)
    lkg = router / "etc/newton/lkg/txn-0001"
    digest = hashlib.sha256((lkg / ".manifest").read_bytes()).hexdigest()
    assert (lkg / ".seal").read_text() == f"{digest} 5 {' '.join(sorted(DEFAULT_NAMES))}\n"
    assert (lkg / ".manifest").exists()
    assert (lkg / ".seal").exists()


def test_g3_truncated_manifest_refused(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    manifest = router / "etc/newton/lkg/txn-0001/.manifest"
    lines = manifest.read_text().splitlines(keepends=True)
    manifest.write_text("".join(lines[:-1]))
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-corrupt")
    assert snapshot(router) == changed


@pytest.mark.parametrize("keep", ["drop-last-row", "empty"])
def test_g3_truncated_manifest_with_matching_sha_refused(router, keep):
    # A manifest cut short at arm time is sealed with its own sha256. The sealed count and
    # names come from the copy loop, so they must still stop the restore.
    arm(router)
    change_config(router)
    changed = snapshot(router)
    manifest = router / "etc/newton/lkg/txn-0001/.manifest"
    lines = manifest.read_text().splitlines(keepends=True)
    manifest.write_text("" if keep == "empty" else "".join(lines[:-1]))
    _, count, names = seal_of(router).read_text().split(" ", 2)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    seal_of(router).write_text(f"{digest} {count} {names}")
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-corrupt")
    assert snapshot(router) == changed


def test_g3_empty_manifest_refused(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    (router / "etc/newton/lkg/txn-0001/.manifest").write_text("")
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-corrupt")
    assert snapshot(router) == changed


def test_g3_missing_seal_refused(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    seal_of(router).unlink()
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-unsealed")
    assert snapshot(router) == changed


@pytest.mark.parametrize("mutate", ["sha", "count", "rename", "extra-name"])
def test_g3_wrong_seal_refused(router, mutate):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    sha, count, names = seal_of(router).read_text().split(" ", 2)
    if mutate == "sha":
        seal = f"{'0' * 64} {count} {names}"
    elif mutate == "count":
        seal = f"{sha} 4 {names}"
    elif mutate == "rename":
        seal = f"{sha} {count} {names.replace('dhcp', 'dhcx', 1)}"
    else:
        seal = f"{sha} {count} {names.rstrip('\n')} extra\n"
    seal_of(router).write_text(seal)
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-corrupt")
    assert snapshot(router) == changed


def test_g3_empty_seal_refused(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    seal_of(router).write_text("")
    # An empty seal cannot be parsed, so the guard treats it as unsealed.
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-unsealed")
    assert snapshot(router) == changed


def test_g3_unsealed_extra_lkg_entry_refused(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    (router / "etc/newton/lkg/txn-0001/rogue").write_text("x\n")
    assert_lkg_refusal_untouched(router, run_guard(router, "restore", "manual"), "lkg-corrupt")
    assert snapshot(router) == changed


def assert_lkg_write_failed_clean(router, result):
    assert (result.returncode, result.stdout) == (1, "error lkg-write-failed\n")
    assert not (router / "etc/newton/lkg/txn-0001").exists()
    assert not (router / "etc/newton/pending").exists()
    assert run_guard(router, "status").stdout == "idle\n"


def test_g3_arm_manifest_truncation_fails_closed(router):
    (router / "control/mv-truncate").write_text(".manifest\n")
    assert_lkg_write_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"))


def test_g3_arm_seal_write_failure_fails_closed(router):
    (router / "control/mv-fail").write_text(".seal\n")
    assert_lkg_write_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"))


@pytest.mark.parametrize("command", ["tick", "boot"])
def test_g3_tick_and_boot_refuse_bad_seal(router, command):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    seal_of(router).write_text("bad\n")
    if command == "tick":
        set_uptime(router, 161)
    result = run_guard(router, command)
    expected_rc = 1 if command == "tick" else 0
    assert (result.returncode, result.stdout) == (expected_rc, "failed txn-0001 lkg-corrupt\n")
    assert snapshot(router) == changed
    assert not (router / "etc/newton/quarantine").exists()
    assert not list((router / "etc/config").glob(".newton-tmp.*"))
    assert (router / "etc/newton/pending").exists()


# transient restore failures are retried, not made permanent.


def assert_g4_retry_state(router, result):
    assert (result.returncode, result.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    ng = router / "etc/newton"
    assert (ng / "pending").exists()
    assert not (ng / "failed").exists()
    assert (ng / "restore_attempts").read_text() == "txn-0001 1\n"
    assert not list((router / "etc/config").glob(".newton-tmp.*"))


def g4_timer_run(router):
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(router)
    env.pop("NEWTON_GUARD_CRASH_AT", None)
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(GUARD), "timer"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stdout, stderr = proc.communicate(timeout=20)
    return proc.returncode, stdout, stderr


def test_g4_cp_fail_once_retried_by_tick(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    assert_g4_retry_state(router, run_guard(router, "restore", "manual"))
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 deadline\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/restore_attempts").exists()
    assert run_guard(router, "status").stdout == "restored txn-0001 deadline\n"


def test_g4_cp_partial_once_retried_by_tick(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-partial-once").write_text(".newton-tmp.\n")
    assert_g4_retry_state(router, run_guard(router, "restore", "manual"))
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 deadline\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_mv_fail_once_retried_by_tick(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/mv-fail-once").write_text(".newton-tmp.\n")
    assert_g4_retry_state(router, run_guard(router, "restore", "manual"))
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 deadline\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_quarantine_failure_retried(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/mv-fail-once").write_text("quarantine/\n")
    assert_g4_retry_state(router, run_guard(router, "restore", "manual"))
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 deadline\n")
    assert snapshot(router) == original
    assert (router / "etc/newton/quarantine/txn-0001/extra").read_bytes() == b"preserve me\n"
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_cp_fail_always_fails_after_three_attempts(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    set_uptime(router, 161)
    first = run_guard(router, "tick")
    second = run_guard(router, "tick")
    third = run_guard(router, "tick")
    assert (first.returncode, first.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (second.returncode, second.stdout) == (1, "retry txn-0001 verify-failed 2\n")
    assert (third.returncode, third.stdout) == (1, "failed txn-0001 verify-failed\n")
    assert (router / "etc/newton/failed").read_text() == "txn-0001 verify-failed\n"
    assert (router / "etc/newton/pending").exists()
    calls_before = len(calls(router, "cp"))
    fourth = run_guard(router, "tick")
    assert (fourth.returncode, fourth.stdout) == (0, "failed txn-0001 verify-failed\n")
    assert len(calls(router, "cp")) == calls_before
    (router / "control/cp-fail").unlink()
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/failed").exists()
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_boot_retries_restore_io_failure(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "retry txn-0001 verify-failed 1\n")
    assert (router / "etc/newton/boot_attempts").read_text() == "txn-0001 1\n"
    assert (router / "etc/newton/restore_attempts").read_text() == "txn-0001 1\n"
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 boot\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/boot_attempts").exists()
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_restore_attempts_other_txn_ignored(router):
    arm(router)
    change_config(router)
    (router / "etc/newton/restore_attempts").write_text("other-txn-9 2\n")
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    # tick, not restore: a manual restore clears restore_attempts first and would hide the txn check.
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (router / "etc/newton/restore_attempts").read_text() == "txn-0001 1\n"


def test_g4_restore_attempts_write_failure_is_permanent(router):
    arm(router)
    change_config(router)
    (router / "control/mv-fail").write_text("restore_attempts\n")
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (1, "failed txn-0001 verify-failed\n")
    assert (router / "etc/newton/failed").read_text() == "txn-0001 verify-failed\n"
    assert (router / "etc/newton/pending").exists()
    assert not list((router / "etc/newton").glob(".*.tmp"))


def test_g4_restore_attempts_cleared_then_new_arm(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    assert run_guard(router, "restore", "manual").stdout == "retry txn-0001 verify-failed 1\n"
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert result.stdout == "restored txn-0001 deadline\n"
    assert not (router / "etc/newton/restore_attempts").exists()
    arm(router, "txn-0002")
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_preflight_failure_stays_permanent(router):
    arm(router)
    change_config(router)
    (router / "etc/newton/lkg/txn-0001/network").write_text("corrupt\n")
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (1, "failed txn-0001 lkg-corrupt\n")
    assert (router / "etc/newton/failed").read_text() == "txn-0001 lkg-corrupt\n"
    assert not (router / "etc/newton/restore_attempts").exists()


def test_g4_seal_preflight_failure_stays_permanent(router):
    # A manifest cut short and re-sealed with its own sha256 is still caught by the sealed count and
    # names. That is a preflight failure: permanent at once, no retry, even with cp ready to fail.
    arm(router)
    change_config(router)
    changed = snapshot(router)
    manifest = router / "etc/newton/lkg/txn-0001/.manifest"
    lines = manifest.read_text().splitlines(keepends=True)
    manifest.write_text("".join(lines[:-1]))
    _, count, names = seal_of(router).read_text().split(" ", 2)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    seal_of(router).write_text(f"{digest} {count} {names}")
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (1, "failed txn-0001 lkg-corrupt\n")
    assert (router / "etc/newton/failed").read_text() == "txn-0001 lkg-corrupt\n"
    assert not (router / "etc/newton/restore_attempts").exists()
    assert snapshot(router) == changed


def test_g4_arm_and_confirm_clear_stale_restore_attempts(router):
    ng = router / "etc/newton"
    ng.mkdir(parents=True, exist_ok=True)
    (ng / "restore_attempts").write_text("old-txn-0001 2\n")
    arm(router)
    assert not (ng / "restore_attempts").exists()
    (ng / "restore_attempts").write_text("txn-0001 1\n")
    result = run_guard(router, "confirm", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "confirmed txn-0001\n")
    assert not (ng / "restore_attempts").exists()


def test_g4_timer_stops_after_three_failed_attempts(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    set_uptime(router, 161)
    rc, stdout, stderr = g4_timer_run(router)
    assert rc == 0
    assert stdout == (
        "retry txn-0001 verify-failed 1\n"
        "retry txn-0001 verify-failed 2\n"
        "failed txn-0001 verify-failed\n"
    )
    assert (router / "etc/newton/failed").read_text() == "txn-0001 verify-failed\n"
    assert "stop" in calls(router, "init")


def test_g4_manual_restore_starts_a_fresh_budget(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    set_uptime(router, 161)
    assert run_guard(router, "tick").stdout == "retry txn-0001 verify-failed 1\n"
    assert run_guard(router, "tick").stdout == "retry txn-0001 verify-failed 2\n"
    manual = run_guard(router, "restore", "manual")
    assert (manual.returncode, manual.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (router / "etc/newton/restore_attempts").read_text() == "txn-0001 1\n"
    assert not (router / "etc/newton/failed").exists()


def test_g4_boot_clears_stale_restore_attempts_without_pending(router):
    ng = router / "etc/newton"
    ng.mkdir(parents=True, exist_ok=True)
    (ng / "restore_attempts").write_text("txn-0001 2\n")
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "idle\n")
    assert not (ng / "restore_attempts").exists()


def test_g4_post_copy_verification_failure_is_retried(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    # The move succeeds but empties its target, so only the final verification pass notices.
    (router / "control/mv-truncate-once").write_text(".newton-tmp.\n")
    assert_g4_retry_state(router, run_guard(router, "restore", "manual"))
    set_uptime(router, 161)
    result = run_guard(router, "tick")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 deadline\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/restore_attempts").exists()



# bound the quarantine.


QROOT = "etc/newton/quarantine"


def make_qdir(router, name, seq, mtime=None):
    d = router / QROOT / name
    d.mkdir(parents=True)
    (d / ".seq").write_text(f"{seq}\n")
    (d / "junk").write_bytes(b"x\n")
    if mtime is not None:
        os.utime(d, (mtime, mtime))
    return d


def qnames(router):
    return {p.name for p in (router / QROOT).iterdir()}


def flatten_mtimes(router):
    old = time.mktime((2000, 1, 1, 0, 0, 0, 0, 0, 0))
    qroot = router / QROOT
    if qroot.exists():
        for d in qroot.iterdir():
            os.utime(d, (old, old))


def quarantined_restore(router, txn, extra=b"extra\n"):
    arm(router, txn)
    (router / "etc/config/extra").write_bytes(extra)
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, f"restored {txn} manual\n")


def test_g6_five_quarantine_dirs_kept(router):
    for i in range(1, 8):
        flatten_mtimes(router)
        quarantined_restore(router, f"txn-{i:04d}")
        assert len(qnames(router)) <= 5
    assert qnames(router) == {f"txn-{i:04d}" for i in range(3, 8)}


def test_g6_prune_orders_by_seq_not_mtime(router):
    old = time.mktime((2001, 1, 1, 0, 0, 0, 0, 0, 0))
    for seq in range(1, 6):
        # The oldest (.seq 1) directory gets the NEWEST mtime.
        make_qdir(router, f"pre-{seq}", seq, mtime=old if seq > 1 else time.time())
    quarantined_restore(router, "txn-0001")
    assert qnames(router) == {"txn-0001", "pre-2", "pre-3", "pre-4", "pre-5"}


def test_g6_size_cap_256kib(router):
    for i in range(1, 4):
        quarantined_restore(router, f"txn-{i:04d}", extra=b"x" * (100 * 1024))
    assert qnames(router) == {"txn-0002", "txn-0003"}
    total = 0
    for d in (router / QROOT).iterdir():
        out = subprocess.run(
            ["du", "-sk", str(d)], capture_output=True, text=True, check=True
        ).stdout
        total += int(out.split()[0])
    assert total <= 256


def test_g6_active_dir_protected_from_size_rule(router):
    make_qdir(router, "old-txn-0000", 1)
    arm(router)
    (router / "etc/config/extra").write_bytes(b"x" * (300 * 1024))
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    assert qnames(router) == {"txn-0001"}
    assert (router / QROOT / "txn-0001/extra").stat().st_size == 300 * 1024


def test_g6_active_protected_with_lowest_seq(router):
    for seq in range(10, 16):
        make_qdir(router, f"pre-{seq}", seq)
    make_qdir(router, "txn-0001", 1)
    quarantined_restore(router, "txn-0001")
    assert qnames(router) == {"txn-0001"} | {f"pre-{s}" for s in range(11, 16)}


def test_g6_confirm_prunes_quarantine(router):
    for seq in range(1, 9):
        make_qdir(router, f"q-{seq}", seq)
    make_qdir(router, "txn-0001", 2)
    arm(router)
    result = run_guard(router, "confirm", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "confirmed txn-0001\n")
    assert qnames(router) == {"txn-0001"} | {f"q-{s}" for s in range(4, 9)}


def test_g6_dir_without_seq_is_oldest(router):
    noseq = router / QROOT / "noseq"
    noseq.mkdir(parents=True)
    (noseq / "junk").write_bytes(b"x\n")
    for seq in range(1, 5):
        make_qdir(router, f"q-{seq}", seq)
    quarantined_restore(router, "txn-0001")
    assert qnames(router) == {"txn-0001", "q-1", "q-2", "q-3", "q-4"}


def test_g6_fifo_in_quarantine_does_not_hang_pruning(router):
    for seq in range(1, 7):
        make_qdir(router, f"q-{seq}", seq)
    # q-6 survives the count rule, so its size is measured: reading a FIFO would block forever.
    os.mkfifo(router / QROOT / "q-6/fifo")
    quarantined_restore(router, "txn-0001")
    assert "q-1" not in qnames(router)
    assert "q-6" in qnames(router)


# the operator recover command.


def recover_dirs(router):
    qroot = router / QROOT
    return [p for p in qroot.iterdir() if p.name.startswith("recover-")]


def test_g2_recover_clears_wedge(router):
    arm(router)
    (router / "etc/newton/pending").write_text("garbage\n")
    tick = run_guard(router, "tick")
    assert (tick.returncode, tick.stdout) == (1, "failed - pending-corrupt\n")
    assert (router / "etc/newton/failed").read_text() == "- pending-corrupt\n"
    assert run_guard(router, "arm", "txn-0002", "60").stdout == "refused failed -\n"
    assert run_guard(router, "confirm", "txn-0001").stdout == "refused pending-corrupt\n"
    result = run_guard(router, "recover")
    assert result.returncode == 0
    assert re.fullmatch(r"recovered recover-\d{8}T\d{6}(\.\d+)?\n", result.stdout)
    assert calls(router, "init")[-1] == "stop"
    ng = router / "etc/newton"
    for state in ("pending", "failed", "boot_attempts", "restore_attempts"):
        assert not (ng / state).exists()
    assert len(recover_dirs(router)) == 1
    qdir = recover_dirs(router)[0]
    assert (qdir / "pending").read_text() == "garbage\n"
    assert (qdir / "failed").read_text() == "- pending-corrupt\n"
    assert (qdir / ".seq").exists()
    assert run_guard(router, "status").stdout == "idle\n"
    assert arm(router, "txn-0002").returncode == 0
    assert "recover" in guard_log_text(router)


def test_g2_recover_refuses_valid_pending(router):
    arm(router)
    before = tree_state(router / "etc/newton")
    for args in (("recover",), ("recover", "restore", "txn-0001")):
        result = run_guard(router, *args)
        assert (result.returncode, result.stdout) == (3, "refused pending txn-0001\n")
        assert tree_state(router / "etc/newton") == before


def test_g2_recover_nothing_to_recover(router):
    # Any guard run creates the state directory and its lock file, so the
    # snapshot is taken after one that writes nothing: the comparison is about
    # state, not about the empty directory appearing.
    assert run_guard(router, "restore", "manual").stdout == "nothing-pending\n"
    before = tree_state(router / "etc/newton")
    result = run_guard(router, "recover")
    assert (result.returncode, result.stdout) == (0, "nothing-to-recover\n")
    assert tree_state(router / "etc/newton") == before


def test_g2_recover_restore_restores_lkg(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "etc/newton/pending").write_text("garbage\n")
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/pending").exists()
    assert calls(router, "reload") == ["reload"]
    assert len(recover_dirs(router)) == 1
    assert (recover_dirs(router)[0] / "pending").read_text() == "garbage\n"
    assert run_guard(router, "status").stdout == "restored txn-0001 recover\n"


def test_g2_recover_restore_preflight_refusals(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    changed = snapshot(router)
    pending = router / "etc/newton/pending"
    pending.write_text("garbage\n")
    result = run_guard(router, "recover", "restore", "txn-9999")
    assert (result.returncode, result.stdout) == (3, "refused lkg-missing txn-9999\n")
    (router / "etc/newton/lkg/txn-0001/network").write_text("corrupt\n")
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (3, "refused lkg-corrupt txn-0001\n")
    (router / "etc/newton/lkg/txn-0001/network").write_bytes(original["network"][0])
    (router / "etc/newton/lkg/txn-0001/.seal").unlink()
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (3, "refused lkg-unsealed txn-0001\n")
    assert pending.read_text() == "garbage\n"
    assert not (router / "etc/newton/quarantine").exists()
    assert snapshot(router) == changed


def test_g2_recover_usage_and_validation(router):
    for args in (
        ("recover", "bogus"),
        ("recover", "restore"),
        ("recover", "foo", "txn-0001"),
        ("recover", "restore", "a", "b", "c"),
    ):
        result = run_guard(router, *args)
        assert (result.returncode, result.stdout) == (2, "error usage\n")
    result = run_guard(router, "recover", "restore", "BAD_TXN")
    assert (result.returncode, result.stdout) == (2, "error bad-txn\n")
    bogus = run_guard(router, "bogus")
    assert bogus.returncode == 2
    assert "recover [restore TXN]" in bogus.stderr


VALID_TXN_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def pending_is_corrupt(path):
    if not path.exists():
        return False
    fields = path.read_text().rstrip("\n").split(" ")
    if len(fields) != 3:
        return True
    txn, deadline, boot_id = fields
    return not (
        8 <= len(txn) <= 64
        and set(txn) <= VALID_TXN_CHARS
        and deadline.isdigit()
        and boot_id != ""
    )


def settle_plain(root):
    set_boot(root, "boot-two")
    assert run_guard(root, "boot").returncode == 0
    status = run_guard(root, "status").stdout
    if status == "failed - pending-corrupt\n" or pending_is_corrupt(root / "etc/newton/pending"):
        assert run_guard(root, "recover", "restore", "txn-0001").returncode == 0
    assert not (root / "etc/newton/pending").exists()


def settle_restored(root, original):
    set_boot(root, "boot-two")
    assert run_guard(root, "boot").returncode == 0
    status = run_guard(root, "status").stdout
    wedged = status == "failed - pending-corrupt\n" or pending_is_corrupt(root / "etc/newton/pending")
    if wedged or snapshot(root) != original:
        result = run_guard(root, "recover", "restore", "txn-0001")
        assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    assert not (root / "etc/newton/pending").exists()
    assert snapshot(root) == original


def test_g2_recover_crash_safety(router, tmp_path):
    original = snapshot(router)
    template = fresh_copy(router, tmp_path, "g2-crash-template")
    arm(template)
    change_config(template)
    (template / "etc/newton/pending").write_text("garbage\n")
    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"g2-plain-{point}")
        result = run_guard(root, "recover", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            assert result.stdout.startswith("recovered recover-")
            break
        settle_plain(root)
    else:
        pytest.fail("recover crash cap exceeded")
    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"g2-restore-{point}")
        result = run_guard(root, "recover", "restore", "txn-0001", crash=point)
        if result.returncode != -9:
            assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
            break
        settle_restored(root, original)
    else:
        pytest.fail("recover restore crash cap exceeded")


def test_g2_recover_dir_protected_from_prune(router):
    for seq in range(100, 106):
        make_qdir(router, f"pre-{seq}", seq)
    arm(router)
    change_config(router)
    (router / "etc/newton/pending").write_text("garbage\n")
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    names = qnames(router)
    rec = [n for n in names if n.startswith("recover-")]
    assert len(rec) == 1
    # The 5-rule ran (oldest of the six pre-made dirs were removed) yet the
    # fresh recover directory and the restored transaction's directory remain.
    assert names == {rec[0], "txn-0001", "pre-103", "pre-104", "pre-105"}


def test_g2_recover_dir_survives_size_pressure(router):
    arm(router)
    (router / "etc/config/extra").write_bytes(b"x" * (300 * 1024))
    (router / "etc/newton/pending").write_text("garbage\n")
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    rec = [n for n in qnames(router) if n.startswith("recover-")]
    # Over the 256 KiB cap with only protected directories left: neither may be removed.
    assert len(rec) == 1
    assert (router / QROOT / rec[0] / "pending").read_text() == "garbage\n"
    assert (router / QROOT / "txn-0001/extra").stat().st_size == 300 * 1024


def test_g2_readme_documents_recover():
    text = (HERE / "README.md").read_text()
    assert "`recover`" in text
    assert "recover restore" in text
    assert "`.seq`" in text


# the arm snapshot must be consistent across files.


def cp_hook(router, pattern, command, once=True):
    name = "cp-hook-once" if once else "cp-hook"
    (router / f"control/{name}").write_text(pattern + "\n" + command + "\n")


APPEND_DHCP = 'echo changed >> "$NEWTON_GUARD_ROOT/etc/config/dhcp"'


def test_g5_changed_once_takes_fresh_snapshot(router):
    cp_hook(router, "/system", APPEND_DHCP)
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (0, "armed txn-0001 161 60\n")
    new_dhcp = (router / "etc/config/dhcp").read_bytes()
    assert new_dhcp.endswith(b"changed\n")
    assert (router / "etc/newton/lkg/txn-0001/dhcp").read_bytes() == new_dhcp
    assert len(calls(router, "cp")) == 10


def test_g5_changed_every_time_refuses(router):
    cp_hook(router, "/system", APPEND_DHCP, once=False)
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (3, "refused config-changed dhcp\n")
    ng = router / "etc/newton"
    assert not (ng / "pending").exists()
    assert not (ng / "lkg/txn-0001").exists()
    assert run_guard(router, "status").stdout == "idle\n"
    assert "start" not in calls(router, "init")
    # One candidate plus exactly one fresh snapshot, never a third.
    assert len(calls(router, "cp")) == 10


def test_g5_file_added_during_snapshot_in_fresh_snapshot(router):
    cp_hook(router, "/wireless", 'echo zzz >> "$NEWTON_GUARD_ROOT/etc/config/zzz"')
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (0, "armed txn-0001 161 60\n")
    assert manifest_ok(router, "txn-0001") == sorted(DEFAULT_NAMES + ["zzz"])
    assert (router / "etc/newton/lkg/txn-0001/zzz").read_bytes() == b"zzz\n"


def test_g5_file_deleted_during_snapshot_left_out(router):
    cp_hook(router, "/system", 'rm -f "$NEWTON_GUARD_ROOT/etc/config/dhcp"')
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (0, "armed txn-0001 161 60\n")
    remaining = sorted(n for n in DEFAULT_NAMES if n != "dhcp")
    assert manifest_ok(router, "txn-0001") == remaining


def test_g5_directory_swap_during_snapshot_refuses(router):
    cp_hook(
        router,
        "/system",
        'rm -rf "$NEWTON_GUARD_ROOT/etc/config/dhcp" && '
        'mkdir "$NEWTON_GUARD_ROOT/etc/config/dhcp"',
    )
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (3, "refused config-changed dhcp\n")
    ng = router / "etc/newton"
    assert not (ng / "lkg/txn-0001").exists()
    assert not (ng / "pending").exists()
    assert run_guard(router, "status").stdout == "idle\n"


def test_g5_fifo_swap_during_snapshot_is_never_read(router):
    # A FIFO that replaces a copied file must be rejected by its type: hashing it would block forever.
    cp_hook(
        router,
        "/system",
        'rm -f "$NEWTON_GUARD_ROOT/etc/config/dhcp" && mkfifo "$NEWTON_GUARD_ROOT/etc/config/dhcp"',
    )
    result = run_guard(router, "arm", "txn-0001", "60", timeout=20)
    assert (result.returncode, result.stdout) == (3, "refused config-changed dhcp\n")
    ng = router / "etc/newton"
    assert not (ng / "lkg/txn-0001").exists()
    assert not (ng / "pending").exists()
    assert run_guard(router, "status").stdout == "idle\n"


def test_g5_stable_config_single_snapshot(router):
    result = arm(router)
    assert result.stdout == "armed txn-0001 161 60\n"
    assert len(calls(router, "cp")) == 5


def test_g5_mode_only_change_not_compared_names_and_hashes_only(router):
    cp_hook(router, "/system", 'chmod 0600 "$NEWTON_GUARD_ROOT/etc/config/dhcp"')
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (0, "armed txn-0001 161 60\n")
    assert len(calls(router, "cp")) == 5


def test_g5_skipped_file_change_does_not_retry(router):
    (router / "etc/config/skip.me").write_bytes(b"skip\n")
    cp_hook(router, "/system", 'echo changed >> "$NEWTON_GUARD_ROOT/etc/config/skip.me"')
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (0, "armed txn-0001 161 60\n")
    assert len(calls(router, "cp")) == 5


def test_g5_crash_sweep_mid_snapshot_change(router, tmp_path):
    template = fresh_copy(router, tmp_path, "g5-crash-template")
    cp_hook(template, "/system", APPEND_DHCP)
    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"g5-crash-{point}")
        result = run_guard(root, "arm", "txn-0001", "60", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            assert result.stdout == "armed txn-0001 161 60\n"
            # The hook fired once: two full snapshots of 5 files.
            assert len(calls(root, "cp")) == 10
            break
        pending = root / "etc/newton/pending"
        if pending.exists():
            # The guard never touches /etc/config during arm, so the live
            # config at the crash point is what boot must restore.
            before = snapshot(root)
            set_boot(root, "boot-two")
            recovered = run_guard(root, "boot")
            assert recovered.returncode == 0
            assert snapshot(root) == before
            assert not pending.exists()
        else:
            assert run_guard(root, "status").stdout == "idle\n"
            assert run_guard(root, "arm", "txn-0002", "60").returncode == 0
    else:
        pytest.fail("arm crash cap exceeded")


# R1, R4, R5, R6 and R8.


def damage_lkg(router, txn, reason):
    lkg = router / f"etc/newton/lkg/{txn}"
    if reason == "lkg-corrupt":
        (lkg / "network").write_text("corrupt\n")
    elif reason == "lkg-unsealed":
        (lkg / ".seal").unlink()
    else:
        assert reason == "lkg-missing"
        (lkg / ".manifest").unlink()


@pytest.mark.parametrize("reason", ["lkg-corrupt", "lkg-unsealed", "lkg-missing"])
def test_r1_recover_releases_valid_pending_with_failed_marker(router, reason):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    damage_lkg(router, "txn-0001", reason)
    set_uptime(router, 161)
    failed = run_guard(router, "tick")
    assert (failed.returncode, failed.stdout) == (1, f"failed txn-0001 {reason}\n")
    ng = router / "etc/newton"
    assert (ng / "pending").exists()
    assert (ng / "failed").read_text() == f"txn-0001 {reason}\n"

    result = run_guard(router, "recover")
    assert result.returncode == 0
    assert re.fullmatch(r"recovered recover-\d{8}T\d{6}(\.\d+)?\n", result.stdout)
    qdir = recover_dirs(router)[0]
    assert (qdir / "pending").exists()
    assert (qdir / "failed").read_text() == f"txn-0001 {reason}\n"
    assert run_guard(router, "status").stdout == "idle\n"
    assert snapshot(router) == changed
    assert arm(router, "txn-0002").returncode == 0


@pytest.mark.parametrize("reason", ["lkg-corrupt", "lkg-unsealed", "lkg-missing"])
def test_r1_recover_restore_can_select_another_sealed_lkg(router, reason):
    original = snapshot(router)
    arm(router, "txn-0001")
    assert run_guard(router, "confirm", "txn-0001").stdout == "confirmed txn-0001\n"
    change_config(router)
    arm(router, "txn-0002")
    (router / "etc/config/network").write_text("changed twice\n")
    (router / "etc/config/extra").write_text("changed extra twice\n")
    damage_lkg(router, "txn-0002", reason)
    set_uptime(router, 161)
    failed = run_guard(router, "tick")
    assert (failed.returncode, failed.stdout) == (1, f"failed txn-0002 {reason}\n")

    before = tree_state(router)
    refused = run_guard(router, "recover", "restore", "txn-0002")
    assert (refused.returncode, refused.stdout) == (3, f"refused {reason} txn-0002\n")
    assert tree_state(router) == before

    restored = run_guard(router, "recover", "restore", "txn-0001")
    assert (restored.returncode, restored.stdout) == (0, "restored txn-0001 recover\n")
    assert snapshot(router) == original
    qdir = recover_dirs(router)[0]
    assert (qdir / "pending").exists()
    assert (qdir / "failed").read_text() == f"txn-0002 {reason}\n"


def test_r1_recover_clears_verify_failed_with_valid_pending(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    set_uptime(router, 161)
    assert run_guard(router, "tick").stdout == "retry txn-0001 verify-failed 1\n"
    assert run_guard(router, "tick").stdout == "retry txn-0001 verify-failed 2\n"
    assert run_guard(router, "tick").stdout == "failed txn-0001 verify-failed\n"
    result = run_guard(router, "recover")
    assert result.returncode == 0
    assert result.stdout.startswith("recovered recover-")
    assert run_guard(router, "status").stdout == "idle\n"


def test_r1_any_failed_marker_releases_recover(router):
    arm(router)
    ng = router / "etc/newton"
    (ng / "failed").write_text("other-txn verify-failed\n")
    result = run_guard(router, "recover")
    assert result.returncode == 0
    qdir = recover_dirs(router)[0]
    assert (qdir / "pending").read_text().startswith("txn-0001 ")
    assert (qdir / "failed").read_text() == "other-txn verify-failed\n"
    assert run_guard(router, "status").stdout == "idle\n"


def test_r4_confirm_reports_pending_removal_failure(router):
    arm(router)
    ng = router / "etc/newton"
    (ng / "boot_attempts").write_text("txn-0001 1\n")
    (router / "control/rm-fail").write_text("/pending\n")
    result = run_guard(router, "confirm", "txn-0001")
    assert (result.returncode, result.stdout, result.stderr) == (1, "error confirm-failed\n", "")
    assert (ng / "pending").exists()
    assert (ng / "boot_attempts").read_text() == "txn-0001 1\n"
    assert "stop" not in calls(router, "init")
    assert "confirm failed txn=txn-0001 pending-not-removed" in guard_log_text(router)

    (router / "control/rm-fail").unlink()
    confirmed = run_guard(router, "confirm", "txn-0001")
    assert (confirmed.returncode, confirmed.stdout) == (0, "confirmed txn-0001\n")


def test_r4_restore_pending_removal_failure_uses_retry_budget(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/rm-fail").write_text("/pending\n")
    set_uptime(router, 161)
    first = run_guard(router, "tick")
    second = run_guard(router, "tick")
    third = run_guard(router, "tick")
    assert (first.returncode, first.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (second.returncode, second.stdout) == (1, "retry txn-0001 verify-failed 2\n")
    assert (third.returncode, third.stdout) == (1, "failed txn-0001 verify-failed\n")
    ng = router / "etc/newton"
    assert (ng / "pending").exists()
    assert (ng / "failed").read_text() == "txn-0001 verify-failed\n"
    assert snapshot(router) == original

    (router / "control/rm-fail").unlink()
    restored = run_guard(router, "restore", "manual")
    assert (restored.returncode, restored.stdout) == (0, "restored txn-0001 manual\n")
    assert not (ng / "restore_attempts").exists()
    assert not (ng / "failed").exists()


def test_r4_restore_pending_removal_failure_once_then_succeeds(router):
    arm(router)
    change_config(router)
    (router / "control/rm-fail-once").write_text("/pending\n")
    set_uptime(router, 161)
    first = run_guard(router, "tick")
    second = run_guard(router, "tick")
    assert (first.returncode, first.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (second.returncode, second.stdout) == (0, "restored txn-0001 deadline\n")
    ng = router / "etc/newton"
    assert not (ng / "pending").exists()
    assert not (ng / "restore_attempts").exists()


@pytest.mark.parametrize("mode", ["fail", "partial"])
def test_r5_lkg_copy_failure_is_lkg_write_failure(router, mode):
    (router / f"control/cp-{mode}").write_text("/etc/newton/lkg/\n")
    result = run_guard(router, "arm", "txn-0001", "60")
    assert result.stderr == ""
    assert_arm_failed_clean(router, result, "error lkg-write-failed\n")


def test_r5_lkg_copy_failure_once_allows_second_arm(router):
    (router / "control/cp-fail-once").write_text("/etc/newton/lkg/\n")
    first = run_guard(router, "arm", "txn-0001", "60")
    assert first.stderr == ""
    assert_arm_failed_clean(router, first, "error lkg-write-failed\n")
    second = run_guard(router, "arm", "txn-0001", "60")
    assert (second.returncode, second.stdout) == (0, "armed txn-0001 161 60\n")


def test_r6_valid_expired_pending_removed_under_lock_is_idle(router):
    arm(router)
    change_config(router)
    changed = snapshot(router)
    set_uptime(router, 161)
    pending = router / "etc/newton/pending"
    rc, stdout, stderr = run_locked_tick(router, pending.unlink)
    assert (rc, stdout, stderr) == (0, "idle\n", "")
    assert snapshot(router) == changed
    assert not (router / "etc/newton/failed").exists()
    assert "restore failed" not in guard_log_text(router)
    assert not (router / "etc/newton/quarantine").exists()


def assert_r8_recover_restore_complete(root, original):
    result = run_guard(root, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    assert snapshot(root) == original
    assert not (root / "etc/newton/pending").exists()
    assert not list((root / "etc/config").glob(".newton-tmp.*"))
    assert not list((root / "etc/newton").glob(".*.tmp"))
    assert calls(root, "init")[-1] == "stop"


def test_r8_recover_restore_crash_sweep_resumes_without_boot(router, tmp_path):
    original = snapshot(router)
    template = fresh_copy(router, tmp_path, "r8-crash-template")
    arm(template)
    change_config(template)
    (template / "etc/newton/pending").write_text("garbage\n")
    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"r8-crash-{point}")
        result = run_guard(root, "recover", "restore", "txn-0001", crash=point)
        if result.returncode != -9:
            assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
            assert snapshot(root) == original
            assert calls(root, "init")[-1] == "stop"
            break
        assert_r8_recover_restore_complete(root, original)
    else:
        pytest.fail("recover restore crash cap exceeded")


def test_r8_only_same_transaction_deadline_zero_can_resume(router):
    arm(router, "txn-0001")
    change_config(router)
    pending = router / "etc/newton/pending"
    pending.write_text("txn-0001 0 boot-one\n")

    before = tree_state(router)
    other = run_guard(router, "recover", "restore", "txn-0002")
    assert (other.returncode, other.stdout) == (3, "refused pending txn-0001\n")
    assert tree_state(router) == before
    plain = run_guard(router, "recover")
    assert (plain.returncode, plain.stdout) == (3, "refused pending txn-0001\n")
    assert tree_state(router) == before

    pending.write_text("txn-0001 500 boot-one\n")
    before = tree_state(router)
    future = run_guard(router, "recover", "restore", "txn-0001")
    assert (future.returncode, future.stdout) == (3, "refused pending txn-0001\n")
    assert tree_state(router) == before


def test_r8_resumed_recover_directory_survives_size_pressure(router, tmp_path):
    template = fresh_copy(router, tmp_path, "r8-size-template")
    arm(template)
    (template / "etc/config/extra").write_bytes(b"x" * (300 * 1024))
    (template / "etc/newton/pending").write_text("garbage\n")

    crashed = None
    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"r8-size-{point}")
        result = run_guard(root, "recover", "restore", "txn-0001", crash=point)
        pending = root / "etc/newton/pending"
        if result.returncode == -9 and pending.exists() and pending.read_text().startswith("txn-0001 0 "):
            crashed = root
            break
    else:
        pytest.fail("no crash point left a recover restore resume pending")

    assert_r8_recover_restore_complete(crashed, snapshot(router))
    names = qnames(crashed)
    recover = [name for name in names if name.startswith("recover-")]
    assert len(recover) == 1
    assert recover[0] in names
    assert "txn-0001" in names
    assert (crashed / QROOT / recover[0] / "pending").read_text() == "garbage\n"


def test_r8_resume_still_runs_the_lkg_preflight(router):
    arm(router)
    change_config(router)
    (router / "etc/newton/pending").write_text("txn-0001 0 boot-one\n")
    (router / "etc/newton/lkg/txn-0001/network").write_text("corrupt\n")
    before = tree_state(router)
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (3, "refused lkg-corrupt txn-0001\n")
    assert tree_state(router) == before


def test_r8_resume_starts_a_fresh_retry_budget(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    ng = router / "etc/newton"
    (ng / "pending").write_text("txn-0001 0 boot-one\n")
    (ng / "restore_attempts").write_text("txn-0001 2\n")
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    first = run_guard(router, "recover", "restore", "txn-0001")
    assert (first.returncode, first.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (ng / "restore_attempts").read_text() == "txn-0001 1\n"
    assert not (ng / "failed").exists()
    second = run_guard(router, "recover", "restore", "txn-0001")
    assert (second.returncode, second.stdout) == (0, "restored txn-0001 recover\n")
    assert snapshot(router) == original


def test_r8_resume_protects_the_newest_recover_directory(router):
    arm(router)
    (router / "etc/config/extra").write_bytes(b"x" * (300 * 1024))
    make_qdir(router, "recover-20200101T000000", 1)
    make_qdir(router, "recover-20200102T000000", 2)
    (router / "etc/newton/pending").write_text("txn-0001 0 boot-one\n")
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    names = qnames(router)
    # Over the 256 KiB cap: the oldest unprotected directory goes, the newest recover directory stays.
    assert "recover-20200101T000000" not in names
    assert "recover-20200102T000000" in names
    assert "txn-0001" in names


def test_r6_count_rule_skips_the_protected_recover_directory(router):
    # Review R6: a resumed `recover restore` protects its recover directory from the count rule too,
    # even when that directory is the oldest of more than five.
    arm(router)
    change_config(router)
    make_qdir(router, "recover-20200101T000000", 1)
    for seq in range(2, 7):
        make_qdir(router, f"q-{seq}", seq)
    (router / "etc/newton/pending").write_text("txn-0001 0 boot-one\n")
    result = run_guard(router, "recover", "restore", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 recover\n")
    # Newest five by sequence: txn-0001, q-6, q-5, q-4, q-3. q-2 is sixth and goes; the seventh is protected.
    assert qnames(router) == {"txn-0001", "q-6", "q-5", "q-4", "q-3", "recover-20200101T000000"}


# Review fix R3.


R3_OLD_NAMES = [
    "newton-guard.df.out",
    "newton-guard.df.last",
    "newton-guard.prune.unsorted",
    "newton-guard.prune.sorted",
    "newton-guard.qprune.unsorted",
    "newton-guard.qprune.sorted",
    "newton-guard.qprune.sizes",
    "newton-guard.live.rows",
]


def test_r3_planted_symlinks_are_never_followed(router):
    victim = router / "victim"
    victim.write_bytes(b"PRECIOUS\n")
    for name in R3_OLD_NAMES:
        (router / "tmp" / name).symlink_to("../victim")
    arm(router, "txn-0001")
    change_config(router)
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    arm(router, "txn-0002")
    confirmed = run_guard(router, "confirm", "txn-0002")
    assert (confirmed.returncode, confirmed.stdout) == (0, "confirmed txn-0002\n")
    assert victim.read_bytes() == b"PRECIOUS\n"
    for name in R3_OLD_NAMES:
        link = router / "tmp" / name
        assert link.is_symlink(), f"{name} no longer a symlink"
        assert os.readlink(str(link)) == "../victim"
    tmp_entries = sorted(p.name for p in (router / "tmp").iterdir())
    assert set(tmp_entries) == set(R3_OLD_NAMES)


def test_r3_scratch_directory_is_private_and_removed(router):
    block = router / "control/df-block"
    block.touch()
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(router)
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(GUARD), "arm", "txn-0001", "60"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        ready = router / "control/df-ready"
        for _ in range(100):
            if ready.exists():
                break
            time.sleep(0.02)
        assert ready.exists()
        names = [p for p in (router / "tmp").iterdir()]
        assert len(names) == 1
        scratch = names[0]
        assert scratch.is_dir()
        assert not scratch.is_symlink()
        assert re.fullmatch(r"newton-guard\.[A-Za-z0-9]{6}", scratch.name)
        assert stat.S_IMODE(scratch.stat().st_mode) == 0o700
    finally:
        block.unlink(missing_ok=True)
        stdout, stderr = proc.communicate(timeout=GUARD_TIMEOUT)
    assert proc.returncode == 0
    assert sorted(p.name for p in (router / "tmp").iterdir()) == []
    change_config(router)
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    assert sorted(p.name for p in (router / "tmp").iterdir()) == []
    arm(router, "txn-0002")
    confirmed = run_guard(router, "confirm", "txn-0002")
    assert (confirmed.returncode, confirmed.stdout) == (0, "confirmed txn-0002\n")
    assert sorted(p.name for p in (router / "tmp").iterdir()) == []


def test_r3_mktemp_failure_refuses_arm_and_skips_pruning(router):
    (router / "control/mktemp-fail").write_text("")
    assert_arm_failed_clean(router, run_guard(router, "arm", "txn-0001", "60"), "error scratch-failed\n")
    (router / "control/mktemp-fail").unlink()
    arm(router, "txn-0001")
    change_config(router)
    (router / "control/mktemp-fail").write_text("")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout, result.stderr) == (0, "restored txn-0001 manual\n", "")
    (router / "control/mktemp-fail").unlink()
    arm(router, "txn-0002")
    (router / "control/mktemp-fail").write_text("")
    result = run_guard(router, "confirm", "txn-0002")
    assert (result.returncode, result.stdout, result.stderr) == (0, "confirmed txn-0002\n", "")
    (router / "control/mktemp-fail").unlink()


def test_r3_no_fixed_scratch_names_left():
    source = GUARD.read_text()
    for name in R3_OLD_NAMES:
        assert name not in source, f"fixed scratch name {name} still in guard"
    matches = re.findall(r"newton-guard\.[A-Za-z0-9]+", source)
    assert set(matches) == {"newton-guard.XXXXXX"}


# DEV-02: the state lock moved from $R/tmp/newton-guard.lock to the root-only
# state directory, so a local user cannot pre-plant or hold it (design 3).


def hold_tmp_lock(router):
    """A local process holding the OLD tmp lock file with flock, as a local
    non-root user could before DEV-02."""
    lock = router / "tmp/newton-guard.lock"
    lock.touch()
    holder = subprocess.Popen(
        ["/usr/bin/flock", str(lock), "sleep", "30"],
        start_new_session=True,
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        assert holder.poll() is None
        probe = subprocess.run(["/usr/bin/flock", "-n", str(lock), "true"])
        if probe.returncode != 0:
            return holder
        time.sleep(0.02)
    os.killpg(holder.pid, signal.SIGTERM)
    holder.wait(timeout=3)
    pytest.fail("the tmp lock holder did not take its lock")


def test_d2_planted_tmp_lock_does_not_block_arm(router):
    holder = hold_tmp_lock(router)
    try:
        try:
            result = run_guard(router, "arm", "txn-0001", "60", timeout=20)
        except subprocess.TimeoutExpired:
            pytest.fail("arm waited for the planted tmp lock")
        assert (result.returncode, result.stdout) == (0, "armed txn-0001 161 60\n")
        assert (router / "etc/newton/guard.lock").exists()
    finally:
        os.killpg(holder.pid, signal.SIGTERM)
        holder.wait(timeout=3)


def read_manifest_names(router, txn):
    manifest = router / f"etc/newton/lkg/{txn}/.manifest"
    return [line.split("  ", 1)[1] for line in manifest.read_text().splitlines()]


def test_d2_the_state_lock_lives_in_the_state_directory(router):
    arm(router)
    assert (router / "etc/newton/guard.lock").exists()
    assert sorted(p.name for p in (router / "tmp").iterdir()) == []
    assert (router / "etc/newton/guard.lock").stat().st_size == 0, "the lock is written"
    source = GUARD.read_text()
    assert '"$R/tmp/newton-guard.lock"' not in source
    assert '"$NG/guard.lock"' in source
    # Nothing that lists or seals the state directory counts entries, so a
    # new file there cannot change a manifest or a seal.
    assert "guard.lock" not in read_manifest_names(router, "txn-0001")


def test_r3_timer_removes_its_scratch_before_stopping(router):
    arm(router)
    change_config(router)
    set_uptime(router, 161)
    rc, stdout, stderr = g4_timer_run(router)
    assert (rc, stdout, stderr) == (0, "restored txn-0001 deadline\n", "")
    assert sorted(p.name for p in (router / "tmp").iterdir()) == []
    source = GUARD.read_text()
    start = source.index("timer_cmd() {")
    after = source[start + len("timer_cmd() {"):]
    end = after.index("\n}")
    body = after[:end]
    init_stop_lines = [line for line in body.splitlines() if '"$INIT" stop' in line]
    assert len(init_stop_lines) == 1
    lines = body.splitlines()
    for stop_line in init_stop_lines:
        idx = lines.index(stop_line)
        assert lines[idx - 1].strip() == "scratch_cleanup"


# Review fix R2.


def test_r2_timer_waits_between_restore_attempts(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    set_uptime(router, 161)
    rc, stdout, _stderr = g4_timer_run(router)
    assert rc == 0
    assert stdout == (
        "retry txn-0001 verify-failed 1\n"
        "retry txn-0001 verify-failed 2\n"
        "failed txn-0001 verify-failed\n"
    )
    assert calls(router, "sleep") == ["1", "15", "1", "15"]


def test_r2_timer_after_boot_retry_waits_before_its_first_tick(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    boot = run_guard(router, "boot")
    assert (boot.returncode, boot.stdout) == (0, "retry txn-0001 verify-failed 1\n")
    set_uptime(router, 161)
    rc, stdout, _stderr = g4_timer_run(router)
    assert (rc, stdout) == (0, "restored txn-0001 deadline\n")
    assert calls(router, "sleep") == ["15"]
    assert snapshot(router) == original


def test_r2_first_attempt_is_not_delayed(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    set_uptime(router, 161)
    rc, stdout, _stderr = g4_timer_run(router)
    assert (rc, stdout) == (0, "restored txn-0001 deadline\n")
    assert calls(router, "sleep") == []
    assert snapshot(router) == original


def test_r2_manual_commands_are_not_delayed(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    set_uptime(router, 161)
    first = run_guard(router, "tick")
    second = run_guard(router, "tick")
    third = run_guard(router, "tick")
    assert (first.returncode, first.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    assert (second.returncode, second.stdout) == (1, "retry txn-0001 verify-failed 2\n")
    assert (third.returncode, third.stdout) == (1, "failed txn-0001 verify-failed\n")
    assert calls(router, "sleep") == []
    (router / "control/cp-fail").unlink()
    manual = run_guard(router, "restore", "manual")
    assert (manual.returncode, manual.stdout) == (0, "restored txn-0001 manual\n")
    assert snapshot(router) == original


def test_r2_no_gap_before_the_deadline(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail-once").write_text(".newton-tmp.\n")
    manual = run_guard(router, "restore", "manual")
    assert (manual.returncode, manual.stdout) == (1, "retry txn-0001 verify-failed 1\n")
    ng = router / "etc/newton"
    assert (ng / "pending").exists()
    assert (ng / "restore_attempts").read_text() == "txn-0001 1\n"
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(router)
    env.pop("NEWTON_GUARD_CRASH_AT", None)
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(GUARD), "timer"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        time.sleep(1.5)
        assert proc.poll() is None
        before = calls(router, "sleep")
        assert before
        assert "15" not in before
        set_uptime(router, 222)
        stdout, _stderr = proc.communicate(timeout=GUARD_TIMEOUT)
        assert proc.returncode == 0
        assert stdout == "restored txn-0001 deadline\n"
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=3)


def test_r2_other_transaction_attempts_do_not_delay_the_timer(router):
    arm(router)
    change_config(router)
    (router / "etc/newton/restore_attempts").write_text("other-txn-9 2\n")
    set_uptime(router, 161)
    rc, stdout, _stderr = g4_timer_run(router)
    assert (rc, stdout) == (0, "restored txn-0001 deadline\n")
    assert calls(router, "sleep") == []


def test_r2_no_gap_when_the_restore_has_already_failed(router):
    arm(router)
    change_config(router)
    ng = router / "etc/newton"
    (ng / "failed").write_text("txn-0001 verify-failed\n")
    (ng / "restore_attempts").write_text("txn-0001 2\n")
    set_uptime(router, 161)
    rc, stdout, _stderr = g4_timer_run(router)
    assert (rc, stdout) == (0, "")
    assert calls(router, "sleep") == []


def test_r2_garbage_attempt_counter_does_not_delay_the_timer(router):
    arm(router)
    change_config(router)
    (router / "etc/newton/restore_attempts").write_text("txn-0001 many\n")
    set_uptime(router, 161)
    rc, stdout, _stderr = g4_timer_run(router)
    assert (rc, stdout) == (0, "restored txn-0001 deadline\n")
    assert calls(router, "sleep") == []


# Follow-up fix N1.


def default_signals():
    # A runner started with nohup or in the background can have SIGHUP/SIGINT ignored, and children inherit that;
    # the guard under test must see the default dispositions.
    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(number, signal.SIG_DFL)


def start_blocked_arm(router):
    (router / "control/df-block").touch()
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(router)
    env.pop("NEWTON_GUARD_CRASH_AT", None)
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(GUARD), "arm", "txn-0001", "60"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=default_signals,
    )
    ready = router / "control/df-ready"
    for _ in range(300):
        if ready.exists():
            break
        time.sleep(0.02)
    assert ready.exists()
    return proc


@pytest.mark.parametrize("sig", [signal.SIGHUP, signal.SIGINT, signal.SIGTERM], ids=["hup", "int", "term"])
def test_n1_signal_removes_the_scratch_directory(router, sig):
    proc = start_blocked_arm(router)
    try:
        names = [p for p in (router / "tmp").iterdir()]
        assert len(names) == 1
        scratch = names[0]
        assert scratch.is_dir()
        assert not scratch.is_symlink()
        assert re.fullmatch(r"newton-guard\.[A-Za-z0-9]{6}", scratch.name)
        os.kill(proc.pid, sig)
        time.sleep(0.3)
        (router / "control/df-block").unlink()
        stdout, _stderr = proc.communicate(timeout=GUARD_TIMEOUT)
    finally:
        (router / "control/df-block").unlink(missing_ok=True)
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
    assert proc.returncode == 1
    assert stdout == ""
    assert sorted(p.name for p in (router / "tmp").iterdir()) == []
    assert not (router / "etc/newton/pending").exists()
    assert not (router / "etc/newton/lkg/txn-0001").exists()
    assert run_guard(router, "status").stdout == "idle\n"
    assert "start" not in calls(router, "init")
    assert arm(router).stdout == "armed txn-0001 161 60\n"


def test_n1_readme_says_which_signals_remove_the_scratch_directory():
    text = (HERE / "README.md").read_text()
    for name in ("SIGHUP", "SIGINT", "SIGTERM", "SIGKILL"):
        assert name in text, f"{name} missing from README"


# Follow-up fix N2.


def start_timer(router):
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(router)
    env.pop("NEWTON_GUARD_CRASH_AT", None)
    return subprocess.Popen(
        [BUSYBOX, "sh", str(GUARD), "timer"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def wait_for_sleep_calls(router, count, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if len(calls(router, "sleep")) >= count:
            return True
        time.sleep(0.05)
    return False


def stop_timer(proc):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
    return proc.communicate()[0]


def test_n2_unwritable_state_timer_waits_between_attempts(router):
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    (router / "control/mv-fail").write_text("/etc/newton/.\n")
    set_uptime(router, 161)
    proc = start_timer(router)
    try:
        reached = wait_for_sleep_calls(router, 6)
    finally:
        stdout = stop_timer(proc)
    assert reached
    assert calls(router, "sleep")[:6] == ["1", "15", "1", "15", "1", "15"]
    assert stdout.startswith("failed txn-0001 verify-failed\n" * 3)
    assert (router / "etc/newton/pending").exists()
    assert not (router / "etc/newton/failed").exists()
    assert not (router / "etc/newton/restore_attempts").exists()


def test_n2_unwritable_state_timer_keeps_trying_until_a_restore_works(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    (router / "control/cp-fail").write_text(".newton-tmp.\n")
    (router / "control/mv-fail").write_text("/etc/newton/.\n")
    set_uptime(router, 161)
    proc = start_timer(router)
    try:
        assert wait_for_sleep_calls(router, 4)
        (router / "control/cp-fail").unlink()
        (router / "control/mv-fail").unlink()
        stdout, _stderr = proc.communicate(timeout=GUARD_TIMEOUT)
    finally:
        if proc.poll() is None:
            stop_timer(proc)
    assert proc.returncode == 0
    assert stdout.endswith("restored txn-0001 deadline\n")
    assert snapshot(router) == original
    assert not (router / "etc/newton/pending").exists()
    assert not (router / "etc/newton/failed").exists()
    assert "stop" in calls(router, "init")


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_n2_read_only_state_directory_timer_waits_between_attempts(router):
    arm(router)
    change_config(router)
    (router / "control/mv-fail").write_text("newton-tmp\n")
    set_uptime(router, 161)
    os.chmod(router / "etc/newton", 0o555)
    proc = start_timer(router)
    try:
        reached = wait_for_sleep_calls(router, 6)
    finally:
        stdout = stop_timer(proc)
        os.chmod(router / "etc/newton", 0o755)
    assert reached
    assert calls(router, "sleep")[:6] == ["1", "15", "1", "15", "1", "15"]
    assert stdout.startswith("failed txn-0001 verify-failed\n" * 3)
    assert (router / "etc/newton/pending").exists()
    assert not (router / "etc/newton/failed").exists()
