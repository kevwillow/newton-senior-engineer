import os
import signal
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from conftest import BUSYBOX, GUARD, GUARD_TIMEOUT, INIT, arm, run_guard, snapshot


def set_uptime(root, value):
    (root / "proc/uptime").write_text(f"{value:.2f} 90.00\n")


def set_boot(root, value):
    (root / "proc/sys/kernel/random/boot_id").write_text(value + "\n")


def calls(root, name):
    path = root / f"control/{name}.calls"
    return path.read_text().splitlines() if path.exists() else []


def manifest_ok(root, txn):
    lkg = root / f"etc/newton/lkg/{txn}"
    lines = (lkg / ".manifest").read_text().splitlines()
    names = []
    import hashlib

    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.md5((lkg / name).read_bytes()).hexdigest() == digest
        names.append(name)
    assert names == sorted(names)
    return names


def tree_state(root, ignore=("guard.lock",)):
    """The state directory tree. The lock file is not state: it is opened for
    flock only and never written, so it is skipped (DEV-02)."""
    if not root.exists():
        return None
    state = {}
    for path in [root, *sorted(root.rglob("*"))]:
        relative = str(path.relative_to(root))
        if relative in ignore:
            continue
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            state[relative] = ("symlink", os.readlink(path), mode)
        elif path.is_file():
            state[relative] = ("file", path.read_bytes(), mode)
        else:
            state[relative] = ("directory", mode)
    return state


@pytest.mark.parametrize("txn", ["1234567", "x" * 65, "UPPERCASE", "bad_name", "../xxxxx", "$(id)xxxx", ""])
def test_bad_txn(router, txn):
    result = run_guard(router, "arm", txn, "60")
    assert result.returncode == 2
    assert result.stdout == "error bad-txn\n"
    assert not (router / "etc/newton/pending").exists()


@pytest.mark.parametrize("timeout", ["59", "901", "060", "6e1", "90s", ""])
def test_bad_timeout(router, timeout):
    result = run_guard(router, "arm", "txn-0001", timeout)
    assert result.returncode == 2
    assert result.stdout == "error bad-timeout\n"
    assert not (router / "etc/newton/pending").exists()


@pytest.mark.parametrize(
    ("txn", "timeout"),
    [("abcdefgh", "60"), ("x" * 64, "600"), ("abcdefgh", "601"),
     ("x" * 64, "630"), ("x" * 64, "900")],
)
def test_validation_boundaries_accepted(router, txn, timeout):
    result = run_guard(router, "arm", txn, timeout)
    assert result.returncode == 0
    assert result.stdout.startswith(f"armed {txn} ")


def test_arm_happy_path_and_status(router):
    before = snapshot(router)
    result = arm(router, "txn-0001", 90)
    assert result.stdout == "armed txn-0001 191 90\n"
    assert (router / "etc/newton/pending").read_text() == "txn-0001 191 boot-one\n"
    assert manifest_ok(router, "txn-0001") == sorted(before)
    for name, expected in before.items():
        path = router / f"etc/newton/lkg/txn-0001/{name}"
        assert (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) == expected
    assert "start" in calls(router, "init")
    status = run_guard(router, "status")
    assert status.stdout == "pending txn-0001 91\n"
    assert status.returncode == 0


def test_second_arm_refused_without_new_lkg(router):
    arm(router)
    for txn in ("txn-0001", "txn-0002"):
        result = run_guard(router, "arm", txn, "60")
        assert result.returncode == 3
        assert result.stdout == "refused pending txn-0001\n"
    assert {p.name for p in (router / "etc/newton/lkg").iterdir()} == {"txn-0001"}


def test_space_boundary(router):
    total = sum(len(data) for data, _ in snapshot(router).values())
    need = 2 * ((total + 1023) // 1024) + 256
    (router / "control/avail").write_text(f"{need - 1}\n")
    result = run_guard(router, "arm", "txn-0001", "60")
    assert result.returncode == 3
    assert result.stdout == f"refused low-space {need - 1} {need}\n"
    (router / "control/avail").write_text(f"{need}\n")
    assert run_guard(router, "arm", "txn-0001", "60").returncode == 0


def test_scratch_files_stay_out_of_state_directory(router):
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
        ng = router / "etc/newton"
        assert not list(ng.glob(".df.*"))
        source = GUARD.read_text()
        assert '"$NG/.df' not in source
        assert '"$NG/.prune' not in source
    finally:
        block.unlink(missing_ok=True)
        proc.communicate(timeout=GUARD_TIMEOUT)
    assert proc.returncode == 0


def test_hook_disabled_and_timer_failure(router):
    (router / "control/disabled").touch()
    result = run_guard(router, "arm", "txn-0001", "60")
    assert (result.returncode, result.stdout) == (3, "refused boot-hook-disabled\n")
    (router / "control/disabled").unlink()
    (router / "control/not-running").touch()
    result = run_guard(router, "arm", "txn-0001", "60", timeout=GUARD_TIMEOUT)
    assert (result.returncode, result.stdout) == (3, "refused timer-not-running\n")
    assert not (router / "etc/newton/pending").exists()


@pytest.mark.parametrize("kind", ["symlink", "directory", "space"])
def test_bad_config_entry(router, kind):
    cfg = router / "etc/config"
    if kind == "symlink":
        (cfg / "badlink").symlink_to("network")
        bad = "badlink"
    elif kind == "directory":
        (cfg / "baddir").mkdir()
        bad = "baddir"
    else:
        (cfg / "bad name").write_text("bad")
        bad = "bad name"
    result = run_guard(router, "arm", "txn-0001", "60")
    if kind == "space":
        assert result.returncode == 0
        assert result.stdout.startswith("armed txn-0001 ")
        assert bad not in manifest_ok(router, "txn-0001")
        assert run_guard(router, "status").stdout.endswith("skipped bad\\x20name\n")
        return
    assert result.returncode == 3
    assert result.stdout == f"refused bad-config-entry {bad}\n"


def change_config(root):
    cfg = root / "etc/config"
    (cfg / "network").write_bytes(b"changed network\n")
    (cfg / "wireless").write_bytes(b"changed wireless\n")
    (cfg / "wireless").chmod(0o644)
    (cfg / "firewall").unlink()
    (cfg / "extra").write_bytes(b"preserve me\n")


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("arm", "armed txn-0001 161 60\n"),
        ("confirm", "confirmed txn-0001\n"),
        ("restore", "restored txn-0001 manual\n"),
        ("boot", "restored txn-0001 boot\n"),
        ("tick", "restored txn-0001 deadline\n"),
    ],
)
def test_state_changing_commands_wait_for_lock(router, command, expected):
    if command != "arm":
        arm(router)
        change_config(router)
    if command == "tick":
        set_uptime(router, 161)

    args = {
        "arm": ("arm", "txn-0001", "60"),
        "confirm": ("confirm", "txn-0001"),
        "restore": ("restore", "manual"),
        "boot": ("boot",),
        "tick": ("tick",),
    }[command]
    before_config = tree_state(router / "etc/config")
    (router / "etc/newton").mkdir(parents=True, exist_ok=True)
    lock = router / "etc/newton/guard.lock"
    holder = subprocess.Popen(
        ["/usr/bin/flock", str(lock), "sleep", "30"],
        start_new_session=True,
    )
    guard = None
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            assert holder.poll() is None
            probe = subprocess.run(["/usr/bin/flock", "-n", str(lock), "true"])
            if probe.returncode != 0:
                break
            time.sleep(0.02)
        else:
            pytest.fail("lock holder did not acquire the state lock")

        # The state directory and its lock exist once the holder has them, so
        # the snapshot is taken here: it must not change while the guard waits.
        before_state = tree_state(router / "etc/newton")
        env = os.environ.copy()
        env["NEWTON_GUARD_ROOT"] = str(router)
        guard = subprocess.Popen(
            [BUSYBOX, "sh", str(GUARD), *args],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(1)
        assert guard.poll() is None
        assert tree_state(router / "etc/newton") == before_state
        assert tree_state(router / "etc/config") == before_config

        os.killpg(holder.pid, signal.SIGTERM)
        holder.wait(timeout=3)
        stdout, stderr = guard.communicate(timeout=GUARD_TIMEOUT)
        assert (guard.returncode, stdout, stderr) == (0, expected, "")
    finally:
        if holder.poll() is None:
            os.killpg(holder.pid, signal.SIGTERM)
            holder.wait(timeout=3)
        if guard is not None and guard.poll() is None:
            os.killpg(guard.pid, signal.SIGTERM)
            guard.communicate(timeout=3)


def test_restore_byte_identical_and_quarantine(router):
    before = snapshot(router)
    arm(router)
    change_config(router)
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    assert snapshot(router) == before
    assert (router / "etc/newton/quarantine/txn-0001/extra").read_bytes() == b"preserve me\n"
    assert calls(router, "reload") == ["reload"]
    assert calls(router, "init")[-1] == "stop"
    assert run_guard(router, "status").stdout == "restored txn-0001 manual\n"


def test_restore_twice_and_unchanged_files_not_rewritten(router):
    arm(router)
    cfg = router / "etc/config"
    identities = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in cfg.iterdir()}
    assert run_guard(router, "restore", "manual").returncode == 0
    assert {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in cfg.iterdir()} == identities
    after = snapshot(router)
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "nothing-pending\n")
    assert snapshot(router) == after


def test_restore_repairs_mode_only_change(router):
    arm(router)
    path = router / "etc/config/network"
    original = path.read_bytes()
    path.chmod(0o644)
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 manual\n")
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_restore_validation_and_corruption_fail_closed(router):
    for reason in ("", "UPPER", "bad_reason", "x" * 33):
        result = run_guard(router, "restore", reason)
        assert (result.returncode, result.stdout) == (2, "error bad-reason\n")
    arm(router)
    (router / "etc/newton/lkg/txn-0001/network").write_text("corrupt\n")
    result = run_guard(router, "restore", "manual")
    assert (result.returncode, result.stdout) == (1, "failed txn-0001 lkg-corrupt\n")
    assert (router / "etc/newton/pending").exists()


def test_corrupt_pending_status_confirm_and_tick(router):
    arm(router)
    pending = router / "etc/newton/pending"
    pending.write_text("not a pending record\n")
    status = run_guard(router, "status")
    assert (status.returncode, status.stdout) == (0, "failed - pending-corrupt\n")
    confirm = run_guard(router, "confirm", "txn-0001")
    assert (confirm.returncode, confirm.stdout) == (3, "refused pending-corrupt\n")
    tick = run_guard(router, "tick")
    assert (tick.returncode, tick.stdout) == (1, "failed - pending-corrupt\n")
    assert (router / "etc/newton/failed").read_text() == "- pending-corrupt\n"


def test_quarantine_collision_is_suffixed(router):
    arm(router)
    qdir = router / "etc/newton/quarantine/txn-0001"
    qdir.mkdir(parents=True)
    (qdir / "extra").write_bytes(b"older\n")
    (router / "etc/config/extra").write_bytes(b"newer\n")
    run_guard(router, "restore", "manual")
    assert (qdir / "extra").read_bytes() == b"older\n"
    assert (qdir / "extra.1").read_bytes() == b"newer\n"


def test_tick_deadline_and_reboot(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    assert run_guard(router, "tick").stdout == "pending txn-0001 61\n"
    assert snapshot(router) != original
    set_uptime(router, 161)
    assert run_guard(router, "tick").stdout == "restored txn-0001 deadline\n"
    assert snapshot(router) == original
    arm(router, "txn-0002")
    change_config(router)
    set_boot(router, "boot-two")
    set_uptime(router, 2)
    assert run_guard(router, "tick").stdout == "restored txn-0002 reboot\n"
    assert snapshot(router) == original
    assert calls(router, "reload") == ["reload", "reload"]


def test_timer_immediate_and_waiting(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    set_uptime(router, 161)
    result = run_guard(router, "timer")
    assert result.returncode == 0
    assert snapshot(router) == original
    assert calls(router, "init")[-1] == "stop"

    arm(router, "txn-0002")
    change_config(router)
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(router)
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(GUARD), "timer"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    time.sleep(1.5)
    assert proc.poll() is None
    assert snapshot(router) != original
    set_uptime(router, 222)
    proc.communicate(timeout=GUARD_TIMEOUT)
    assert proc.returncode == 0
    assert snapshot(router) == original


def test_timer_releases_lock_after_locked_recheck(router):
    original = snapshot(router)
    arm(router)
    pending = router / "etc/newton/pending"
    pending.write_text("txn-0001 99 boot-one\n")
    lock = router / "etc/newton/guard.lock"
    ready = router / "control/lock-ready"
    holder = subprocess.Popen(
        [
            "/usr/bin/flock",
            str(lock),
            "sh",
            "-c",
            f"touch '{ready}'; sleep 30",
        ],
        start_new_session=True,
    )
    timer = None
    try:
        for _ in range(100):
            if ready.exists():
                break
            time.sleep(0.02)
        assert ready.exists()
        env = os.environ.copy()
        env["NEWTON_GUARD_ROOT"] = str(router)
        timer = subprocess.Popen(
            [BUSYBOX, "sh", str(GUARD), "timer"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(0.3)
        assert timer.poll() is None
        assert subprocess.run(["/usr/bin/flock", "-n", str(lock), "true"]).returncode != 0
        pending.write_text("txn-0002 9999 boot-one\n")
        os.killpg(holder.pid, signal.SIGTERM)
        holder.wait(timeout=3)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if subprocess.run(["/usr/bin/flock", "-n", str(lock), "true"]).returncode == 0:
                break
            time.sleep(0.05)
        else:
            pytest.fail("timer kept the state lock after its locked recheck")
        assert timer.poll() is None
        assert snapshot(router) == original
    finally:
        if holder.poll() is None:
            os.killpg(holder.pid, signal.SIGTERM)
            holder.wait(timeout=3)
        if timer is not None and timer.poll() is None:
            os.killpg(timer.pid, signal.SIGTERM)
            timer.communicate(timeout=3)


def test_boot_restores_without_reload(router):
    original = snapshot(router)
    arm(router)
    change_config(router)
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "restored txn-0001 boot\n")
    assert snapshot(router) == original
    assert calls(router, "reload") == []
    assert not (router / "etc/newton/boot_attempts").exists()


def boot_crash_after_attempt(root):
    for point in range(1, 5):
        result = run_guard(root, "boot", crash=point)
        if result.returncode == -9:
            return
    raise AssertionError("boot did not hit an attempts-write crash point")


def prepare_boot_loop_failed(root):
    original = snapshot(root)
    arm(root)
    (root / "etc/config/network").write_text("unsafe\n")
    for _ in range(3):
        assert run_guard(root, "boot", crash=4).returncode == -9
    failed = run_guard(root, "boot")
    assert (failed.returncode, failed.stdout) == (0, "failed txn-0001 boot-loop\n")
    return original


def test_boot_loop_cap_confirm_and_restore(router, tmp_path):
    arm(router)
    changed = snapshot(router)
    (router / "etc/config/network").write_text("unsafe\n")
    unsafe = snapshot(router)
    for _ in range(3):
        # Four atomic-write crash points; point 4 leaves the increment durable.
        assert run_guard(router, "boot", crash=4).returncode == -9
    result = run_guard(router, "boot")
    assert (result.returncode, result.stdout) == (0, "failed txn-0001 boot-loop\n")
    assert snapshot(router) == unsafe
    assert (router / "etc/newton/pending").exists()
    assert (router / "etc/newton/lkg/txn-0001/.manifest").exists()
    assert run_guard(router, "status").stdout == "failed txn-0001 boot-loop\n"
    refused = run_guard(router, "arm", "txn-0002", "60")
    assert (refused.returncode, refused.stdout) == (3, "refused failed txn-0001\n")
    assert run_guard(router, "confirm", "txn-0001").stdout == "confirmed txn-0001\n"
    assert snapshot(router) == unsafe
    assert run_guard(router, "status").stdout == "idle\n"
    assert not (router / "etc/newton/failed").exists()
    assert not (router / "etc/newton/boot_attempts").exists()

    other = tmp_path / "other"
    shutil.copytree(router, other)
    # Re-arm a clean copy to exercise accepting a failed transaction via restore.
    shutil.rmtree(other / "etc/newton")
    (other / "etc/config/network").write_bytes(changed["network"][0])
    arm(other)
    (other / "etc/config/network").write_text("unsafe\n")
    for _ in range(3):
        assert run_guard(other, "boot", crash=4).returncode == -9
    run_guard(other, "boot")
    assert run_guard(other, "restore", "manual").stdout == "restored txn-0001 manual\n"
    assert snapshot(other) == changed
    assert run_guard(other, "status").stdout == "restored txn-0001 manual\n"
    assert not (other / "etc/newton/failed").exists()


def test_failed_confirm_crashes_do_not_stick_state(router, tmp_path):
    prepare_boot_loop_failed(router)
    for point in range(1, 301):
        root = fresh_copy(router, tmp_path, f"failed-confirm-{point}")
        result = run_guard(root, "confirm", "txn-0001", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            break
        pending = root / "etc/newton/pending"
        if pending.exists():
            assert run_guard(root, "confirm", "txn-0001").returncode == 0
        else:
            assert not run_guard(root, "status").stdout.startswith("failed ")
            boot_root = fresh_copy(root, tmp_path, f"failed-confirm-boot-{point}")
            assert run_guard(boot_root, "boot").stdout == "idle\n"
            assert not (boot_root / "etc/newton/failed").exists()
            assert not (boot_root / "etc/newton/boot_attempts").exists()
        assert run_guard(root, "arm", "txn-0002", "60").returncode == 0
    else:
        pytest.fail("failed confirm crash cap exceeded")


def test_failed_restore_crashes_recover_on_boot(router, tmp_path):
    original = prepare_boot_loop_failed(router)
    for point in range(1, 301):
        root = fresh_copy(router, tmp_path, f"failed-restore-{point}")
        result = run_guard(root, "restore", "manual", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            break
        recovered = run_guard(root, "boot")
        assert recovered.returncode == 0
        assert not (root / "etc/newton/failed").exists()
        assert run_guard(root, "status").stdout.startswith("restored txn-0001 ")
        assert snapshot(root) == original
    else:
        pytest.fail("failed restore crash cap exceeded")


def test_confirm_paths(router):
    original = snapshot(router)
    arm(router)
    (router / "etc/config/network").write_text("accepted\n")
    accepted = snapshot(router)
    result = run_guard(router, "confirm", "txn-0001")
    assert (result.returncode, result.stdout) == (0, "confirmed txn-0001\n")
    assert calls(router, "init")[-1] == "stop"
    set_uptime(router, 999)
    set_boot(router, "new-boot")
    assert run_guard(router, "tick").stdout == "idle\n"
    assert run_guard(router, "boot").stdout == "idle\n"
    assert snapshot(router) == accepted != original
    second = run_guard(router, "confirm", "txn-0001")
    assert (second.returncode, second.stdout) == (3, "refused nothing-pending\n")


def test_arm_recovers_incomplete_same_txn_and_refuses_completed_reuse(router):
    result = run_guard(router, "arm", "txn-0001", "60", crash=1)
    assert result.returncode == -9
    lkg = router / "etc/newton/lkg/txn-0001"
    assert lkg.is_dir()
    assert not (lkg / ".manifest").exists()
    before = snapshot(router)
    assert arm(router).returncode == 0
    assert manifest_ok(router, "txn-0001") == sorted(before)
    for name, expected in before.items():
        path = lkg / name
        assert (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) == expected
    assert run_guard(router, "confirm", "txn-0001").returncode == 0
    reused = run_guard(router, "arm", "txn-0001", "60")
    assert (reused.returncode, reused.stdout) == (3, "refused txn-used\n")


def test_confirm_wrong_and_expired_then_tick(router):
    original = snapshot(router)
    arm(router)
    (router / "etc/config/network").write_text("unsafe\n")
    wrong = run_guard(router, "confirm", "txn-0002")
    assert (wrong.returncode, wrong.stdout) == (3, "refused txn-mismatch txn-0001\n")
    set_uptime(router, 161)
    expired = run_guard(router, "confirm", "txn-0001")
    assert (expired.returncode, expired.stdout) == (3, "refused expired\n")
    assert run_guard(router, "tick").stdout == "restored txn-0001 deadline\n"
    assert snapshot(router) == original


def test_prune_keeps_newest_five_and_removes_incomplete(router):
    incomplete = router / "etc/newton/lkg/incomplete"
    incomplete.mkdir(parents=True)
    (incomplete / "junk").write_text("x")
    for i in range(7):
        txn = f"txn-{i:04d}"
        arm(router, txn)
        assert run_guard(router, "confirm", txn).returncode == 0
    names = {p.name for p in (router / "etc/newton/lkg").iterdir()}
    assert names == {f"txn-{i:04d}" for i in range(2, 7)}


def fresh_copy(source, parent, name):
    target = parent / name
    shutil.copytree(source, target)
    return target


def test_crash_safety_arm_and_density(router, tmp_path):
    original = snapshot(router)
    finished = None
    killed = 0
    for point in range(1, 301):
        root = fresh_copy(router, tmp_path, f"arm-{point}")
        result = run_guard(root, "arm", "txn-0001", "60", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            finished = point
            break
        killed += 1
        pending = root / "etc/newton/pending"
        if pending.exists():
            assert manifest_ok(root, "txn-0001") == sorted(original)
            set_boot(root, "boot-two")
            assert run_guard(root, "boot").returncode == 0
            assert snapshot(root) == original
        else:
            assert run_guard(root, "status").stdout == "idle\n"
            assert run_guard(root, "arm", "txn-0002", "60").returncode == 0
    assert finished is not None and killed == finished - 1

    small = fresh_copy(router, tmp_path, "density-small")
    large = fresh_copy(router, tmp_path, "density-large")
    (large / "etc/config/sixth").write_text("config sixth\n")
    assert crash_count(small, ["arm", "txn-0001", "60"]) + 1 <= crash_count(
        large, ["arm", "txn-0001", "60"]
    )


def crash_count(root, args):
    for point in range(1, 301):
        trial = root.parent / f"{root.name}-trial-{point}"
        shutil.copytree(root, trial)
        result = run_guard(trial, *args, crash=point)
        if result.returncode != -9:
            return point - 1
    raise AssertionError("crash point cap exceeded")


def prepared_changed(router, parent, name):
    root = fresh_copy(router, parent, name)
    arm(root)
    change_config(root)
    return root


@pytest.mark.parametrize("recovery", ["boot", "tick"])
def test_crash_safety_restore(router, tmp_path, recovery):
    template = prepared_changed(router, tmp_path, f"restore-template-{recovery}")
    original = {
        name: (
            (template / f"etc/newton/lkg/txn-0001/{name}").read_bytes(),
            stat.S_IMODE((template / f"etc/newton/lkg/txn-0001/{name}").stat().st_mode),
        )
        for name in manifest_ok(template, "txn-0001")
    }
    finished = None
    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"restore-{recovery}-{point}")
        result = run_guard(root, "restore", "manual", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            finished = point
            break
        if recovery == "boot":
            set_boot(root, "boot-two")
            recovered = run_guard(root, "boot")
        else:
            needs_recovery = (root / "etc/newton/pending").exists()
            reload_calls = root / "control/reload.calls"
            reload_calls.unlink(missing_ok=True)
            set_uptime(root, 161)
            recovered = run_guard(root, "tick")
            if needs_recovery:
                assert calls(root, "reload") == ["reload"]
        assert recovered.returncode == 0
        assert snapshot(root) == original
        assert not list((root / "etc/config").glob(".newton-tmp.*"))
        locations = int((root / "etc/config/extra").exists())
        qdir = root / "etc/newton/quarantine/txn-0001"
        locations += sum(p.name == "extra" or p.name.startswith("extra.") for p in qdir.glob("extra*")) if qdir.exists() else 0
        assert locations == 1
        assert not (root / "etc/newton/pending").exists()
    assert finished is not None


def test_crash_safety_confirm_and_boot(router, tmp_path):
    confirm_template = fresh_copy(router, tmp_path, "confirm-template")
    arm(confirm_template)
    (confirm_template / "etc/config/network").write_text("accepted\n")
    accepted = snapshot(confirm_template)
    original = snapshot(router)
    for point in range(1, 301):
        root = fresh_copy(confirm_template, tmp_path, f"confirm-{point}")
        result = run_guard(root, "confirm", "txn-0001", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            break
        if (root / "etc/newton/pending").exists():
            set_uptime(root, 161)
            run_guard(root, "tick")
            assert snapshot(root) == original
        else:
            set_boot(root, "boot-two")
            run_guard(root, "boot")
            assert snapshot(root) == accepted
    else:
        pytest.fail("confirm crash cap exceeded")

    boot_template = prepared_changed(router, tmp_path, "boot-template")
    original = snapshot(router)
    for point in range(1, 301):
        root = fresh_copy(boot_template, tmp_path, f"boot-{point}")
        result = run_guard(root, "boot", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            break
        recovered = run_guard(root, "boot")
        assert recovered.returncode == 0
        assert snapshot(root) == original
    else:
        pytest.fail("boot crash cap exceeded")


def test_boot_restore_crashes_keep_failure_state_recoverable(router, tmp_path):
    """Boot crashes during restore keep the failure state recoverable.

    The status, recovery-boot and byte-identical asserts below are recovery
    checks only — they do NOT discriminate the M14 removal-order swap in
    restore_core: status_line prints "failed" only while pending exists, and
    the next boot/arm clears orphaned failed/boot_attempts, so no ordering of
    the two removals can make those asserts fail. M14 is caught by the
    structural file-combination assert (failed/boot_attempts must never outlive
    pending at a crash point) and by the guard-log assert (the correct order
    never leaves orphans, so the recovery boot never has to clear any).
    """
    template = prepared_changed(router, tmp_path, "boot-state-template")
    original = snapshot(router)
    saw_removal_window = False

    for point in range(1, 301):
        root = fresh_copy(template, tmp_path, f"boot-state-{point}")
        result = run_guard(root, "boot", crash=point)
        if result.returncode != -9:
            assert result.returncode == 0
            break

        state = root / "etc/newton"
        pending = state / "pending"
        boot_attempts = state / "boot_attempts"
        failed = state / "failed"
        last_revert = state / "last_revert"
        # Structural guard for M14: restore_core must remove failed/boot_attempts
        # before pending, so their surviving a crash without pending is the swap
        # signature. Orphaned state would be cleaned by the next boot/arm, so M14
        # is an ordering regression, not a stuck state.
        assert pending.exists() or not (failed.exists() or boot_attempts.exists()), (
            f"failed/boot_attempts outlived pending at crash point {point}"
        )
        if (
            pending.exists()
            and not boot_attempts.exists()
            and last_revert.exists()
            and last_revert.read_text() == "txn-0001 boot\n"
        ):
            saw_removal_window = True

        status = run_guard(root, "status")
        assert not status.stdout.startswith("failed ")
        recovered = run_guard(root, "boot")
        assert recovered.stdout.endswith("restored txn-0001 boot\n")
        assert snapshot(root) == original
        # Behavioural M14 guard: with the correct removal order there is never
        # orphaned failure state, so the recovery boot must not clear any.
        guard_log = state / "guard.log"
        assert "cleared stale failure state" not in (
            guard_log.read_text() if guard_log.exists() else ""
        ), f"recovery boot cleared orphaned failure state at crash point {point}"
    else:
        pytest.fail("boot crash cap exceeded")

    assert saw_removal_window


def test_restore_crash_density(router, tmp_path):
    one = fresh_copy(router, tmp_path, "one-change")
    arm(one)
    (one / "etc/config/network").write_text("one\n")
    two = fresh_copy(router, tmp_path, "two-changes")
    arm(two)
    (two / "etc/config/network").write_text("one\n")
    (two / "etc/config/system").write_text("two\n")
    assert crash_count(one, ["restore", "manual"]) + 2 <= crash_count(two, ["restore", "manual"])


def test_lint_and_no_forbidden_construct():
    subprocess.run([BUSYBOX, "sh", "-n", str(GUARD)], check=True)
    subprocess.run([BUSYBOX, "sh", "-n", str(INIT)], check=True)
    subprocess.run(["shellcheck", "-s", "sh", str(GUARD), str(INIT)], check=True)
    assert "ev" + "al" not in GUARD.read_text()


def test_log_bounded_and_logger_called(router):
    arm(router)
    ng = router / "etc/newton"
    (ng / "failed").write_text("txn-0001 test-failure\n")
    for _ in range(300):
        assert run_guard(router, "boot").returncode == 0
    log = ng / "guard.log"
    assert log.stat().st_size <= 16384 + max(map(len, log.read_bytes().splitlines()), default=0) + 1
    assert len(calls(router, "logger")) >= 300


def test_relative_root_rejected():
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = "relative"
    result = subprocess.run(
        [BUSYBOX, "sh", str(GUARD), "status"], env=env, text=True, capture_output=True
    )
    assert (result.returncode, result.stdout) == (2, "error bad-root\n")
