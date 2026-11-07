"""Forced hello touches the dead-man file under a directory lock (design 2.6)."""

import fcntl
import os
import subprocess
import time
from pathlib import Path

import pytest

import conftest
from conftest import BUSYBOX


UPTIME = 100
NONCE_PREFIX = "0123456789abcdef"


def hello_dir(router):
    d = router.root / "tmp/newton"
    d.mkdir(parents=True, exist_ok=True)
    return d


def hello_file(router):
    return hello_dir(router) / "hello"


def prefill_lines(router, n, nonce_prefix="cccccccccccccccc", caller="pre", up=UPTIME):
    """Pre-fill the hello file with n existing lines."""
    f = hello_file(router)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("".join(f"{nonce_prefix}{i:08x} {caller} {up}\n" for i in range(n)))


def start_forced_hello(router, nonce):
    """Start a forced hello call without waiting for it; returns the Popen."""
    return subprocess.Popen(
        [BUSYBOX, "sh", str(router.program), "--caller=agent-one", "--role=read"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=router._merged_env({"SSH_ORIGINAL_COMMAND": f"hello {nonce}"}),
        start_new_session=True,
    )


def wait_for(proc, timeout):
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    return (out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), proc.returncode)


# ---- 1. hello waits while the directory lock is held -----------------------


def test_hello_waits_while_the_directory_lock_is_held(router):
    f = hello_file(router)
    prefill_lines(router, 10, caller="keep", up=UPTIME)
    nonce = NONCE_PREFIX
    fd = os.open(str(hello_dir(router)), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        proc = start_forced_hello(router, nonce)
        time.sleep(1.2)
        assert proc.poll() is None, proc.poll()
        lines = f.read_text().splitlines()
        assert len(lines) == 10, lines
        os.close(fd)
        done = wait_for(proc, 15)
        assert done is not None, "hello did not finish within 15 s of release"
        out, err, rc = done
        assert rc == 0, (rc, out, err)
        lines = f.read_text().splitlines()
        assert len(lines) == 11, lines
        assert lines[-1] == f"{nonce} agent-one {UPTIME}", lines[-1]
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


# ---- 2. hello stops waiting after ten seconds (append without trim) -----


def test_hello_stops_waiting_after_ten_seconds(router, capfd):
    f = hello_file(router)
    prefill_lines(router, 70, caller="keep", up=UPTIME)
    nonce = "fedcba9876543210"
    fd = os.open(str(hello_dir(router)), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        proc = start_forced_hello(router, nonce)
        t0 = time.monotonic()
        done = wait_for(proc, 30)
        elapsed = time.monotonic() - t0
        assert done is not None, "hello blocked longer than 30 s after the lock holder held past 10 s"
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    out, err, rc = done
    assert rc == 0, (rc, out, err)
    assert elapsed >= 9, elapsed
    assert out.splitlines(), out
    assert out.splitlines()[0].startswith(f"hello {nonce} "), out
    lines = f.read_text().splitlines()
    assert len(lines) == 71, lines
    assert lines[-1] == f"{nonce} agent-one {UPTIME}", lines[-1]


# ---- 3. concurrent hello calls keep every new line -------------------------


def test_concurrent_hello_calls_keep_every_new_line(router):
    f = hello_file(router)
    prefill_lines(router, 64, caller="keep", up=UPTIME)
    nonces = [f"{NONCE_PREFIX}", "1111111111111111", "2222222222222222",
              "3333333333333333", "4444444444444444", "5555555555555555",
              "6666666666666666", "7777777777777777"]
    procs = [start_forced_hello(router, n) for n in nonces]
    for p in procs:
        done = wait_for(p, 40)
        assert done is not None, "concurrent hello did not finish within 40 s"
        out, err, rc = done
        assert rc == 0, (rc, out, err)
    lines = f.read_text().splitlines()
    assert len(lines) == 64, lines
    last_eight = [l.split(" ", 1)[0] for l in lines[-8:]]
    assert set(last_eight) == set(nonces), (last_eight, nonces)
    for n in nonces:
        assert f.read_text().count(f"{n} agent-one {UPTIME}\n") == 1, n


# ---- 4. hello leaves no extra file in tmp/newton ---------------------------


def test_hello_leaves_no_extra_file_in_tmp_newton(router):
    router.forced(f"hello {NONCE_PREFIX}", role="read", caller="agent-one", timeout=15)
    names = sorted(p.name for p in hello_dir(router).iterdir() if p.is_file())
    unexpected = [n for n in names
                  if n not in ("flock", "hello", "last")]
    assert not unexpected, names


# ---- 5. direct mode hello does not take the directory lock ----------------


def test_direct_hello_does_not_take_the_lock(router):
    fd = os.open(str(hello_dir(router)), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        t0 = time.time()
        res = router.direct("hello", NONCE_PREFIX, timeout=10)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    dt = time.time() - t0
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert not hello_file(router).exists()
    assert dt < 9.0, dt
