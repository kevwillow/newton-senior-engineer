"""Design 3.5a and 3.6: staging, stdin bounds, guard and busy gates."""

import fcntl
import subprocess
import time

import pytest

from conftest import SID


SID2 = "fedcba9876543210fedcba9876543210"


def prepare(router):
    router.use_stub_helper()


def lock_is_free(router):
    result = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True,
        timeout=5,
    )
    return result.returncode == 0


def assert_prelock_refusal(router, result, message):
    assert (result.rc, result.out, result.err) == (2, "", f"error {message}\n")
    assert not (router.root / "tmp/owrt-safe-apply.lock").exists()
    assert not any(c.startswith(("helper ", "ubus ")) for c in router.calls())
    assert lock_is_free(router)


def test_stage_happy_path_records_transaction_and_exact_stdin(router):
    prepare(router)
    batch = b"set dhcp.cfg01.domain='lan value'\n\t# high byte: \xff\n"
    result = router.stage(batch=batch)
    assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
    assert (router.root / "control/stage-stdin").read_bytes() == batch
    txn = router.txn()
    assert (txn / "owner").read_text() == "agent-one\n"
    assert (txn / "stage-up").read_text() == "100\n"
    assert (txn / "boot").read_text() == "boot-one\n"
    assert all(p.read_bytes().endswith(b"\n") for p in (txn / "owner", txn / "stage-up", txn / "boot"))
    lines = router.syslog()
    assert len(lines) == 1
    assert f"cmd=stage sid={SID[:8]} rc=0" in lines[0]
    assert SID not in lines[0]
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "data,accepted,message",
    [
        ((b"x" * 1023 + b"\n") * 30, True, None),
        ((b"x" * 1023 + b"\n") * 30 + b"x", False, "stdin-too-large"),
    ],
    ids=["30720-accepted", "30721-refused"],
)
def test_stage_total_byte_limit(router, data, accepted, message):
    prepare(router)
    result = router.stage(batch=data)
    if accepted:
        assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
        assert (router.root / "control/stage-stdin").read_bytes() == data
        assert lock_is_free(router)
    else:
        assert_prelock_refusal(router, result, message)
        assert not (router.root / "control/stage-stdin").exists()


@pytest.mark.parametrize(
    "byte",
    [b"\0", b"\r", b"\x01", b"\x7f"],
    ids=["nul", "cr", "x01", "del"],
)
def test_stage_rejects_bad_bytes_before_calls(router, byte):
    prepare(router)
    assert_prelock_refusal(router, router.stage(batch=b"set x=y" + byte + b"\n"), "stdin-bad-byte")


@pytest.mark.parametrize("byte", [b"\t", b"\x80", b"\xff"], ids=["tab", "x80", "xff"])
def test_stage_accepts_allowed_non_ascii_and_tab(router, byte):
    prepare(router)
    data = b"set x=y" + byte + b"z\n"
    result = router.stage(batch=data)
    assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
    assert (router.root / "control/stage-stdin").read_bytes() == data
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "data,accepted",
    [
        (b"x\n" * 1000, True),
        (b"x\n" * 1001, False),
        (b"x\n" * 999 + b"x", True),
        (b"x\n" * 1000 + b"x", False),
    ],
    ids=["1000-terminated", "1001-terminated", "1000-unterminated", "1001-unterminated"],
)
def test_stage_line_count_limit(router, data, accepted):
    prepare(router)
    result = router.stage(batch=data)
    if accepted:
        assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
        assert (router.root / "control/stage-stdin").read_bytes() == data
        assert lock_is_free(router)
    else:
        assert_prelock_refusal(router, result, "stdin-too-many-lines")


@pytest.mark.parametrize("length,accepted", [(1024, True), (1025, False)], ids=["1024", "1025"])
def test_stage_single_line_length_limit(router, length, accepted):
    prepare(router)
    result = router.stage(batch=b"x" * length + b"\n")
    if accepted:
        assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
        assert lock_is_free(router)
    else:
        assert_prelock_refusal(router, result, "stdin-line-too-long")


def test_stage_stops_reading_at_size_limit_without_waiting_for_eof(router):
    prepare(router)
    data = (b"x" * 1023 + b"\n") * 30 + b"x"
    proc, finish = router.forced_open_stdin_start("stage", prefix=data)
    started = time.monotonic()
    result = finish(timeout=5)
    assert time.monotonic() - started < 5
    assert proc.returncode == 2
    assert_prelock_refusal(router, result, "stdin-too-large")


@pytest.mark.slow
def test_stage_open_stdin_times_out_without_holding_program_lock(router):
    # Slow by design: this waits for the real 30-second stdin watchdog.
    prepare(router)
    started = time.monotonic()
    proc, finish = router.forced_open_stdin_start("stage")
    lock_path = router.root / "tmp/newton/flock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = finish(timeout=38)
        fcntl.flock(lock_file, fcntl.LOCK_UN)
    elapsed = time.monotonic() - started
    assert proc.returncode == 2
    assert (result.out, result.err) == ("", "error stdin-timeout\n")
    assert 29 <= elapsed < 38
    assert not (router.root / "tmp/owrt-safe-apply.lock").exists()
    assert not any(c.startswith(("helper ", "ubus ")) for c in router.calls())
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "caller,shown",
    [("agent-one", SID), ("root", SID), ("agent-two", SID[:8])],
    ids=["owner-full", "root-full", "other-short"],
)
def test_stage_busy_redacts_sid_by_caller(router, caller, shown):
    prepare(router)
    assert router.stage().rc == 0
    if caller == "root":
        # The key-line label root is reserved (finding F-C): root is the direct-mode caller.
        router.write("control/next-sid", SID2 + "\n")
        result = router.direct("stage", stdin=b"set dhcp.cfg01.domain=lan\n", timeout=40)
    else:
        result = router.stage(caller=caller, sid=SID2)
    assert (result.rc, result.out, result.err) == (
        3,
        "",
        f"error busy agent-one {shown}\n",
    )
    assert [c for c in router.calls() if c.startswith("helper stage")] == ["helper stage"]
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "applied,session_live,busy",
    [("100 boot-one\n", True, False), ("101 boot-one\n", True, True), (None, False, False)],
    ids=["deadline-reached", "deadline-future", "session-gone"],
)
def test_stage_busy_state_rules(router, applied, session_live, busy):
    prepare(router)
    assert router.stage().rc == 0
    if applied is not None:
        (router.txn() / "applied").write_text(applied)
    if not session_live:
        router.write("control/sessions", b"")
    result = router.stage(sid=SID2)
    if busy:
        assert (result.rc, result.out, result.err) == (
            3, "", f"error busy agent-one {SID}\n"
        )
    else:
        assert (result.rc, result.out, result.err) == (0, SID2 + "\n", "")
        assert router.txn(SID2).is_dir()
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "failed,expected",
    [
        (False, "pending txn-pending 899"),
        (True, "failed txn-pending rollback-failed"),
    ],
    ids=["pending", "failed"],
)
def test_stage_guard_gate_never_calls_helper(router, failed, expected):
    prepare(router)
    router.write("etc/newton/pending", "txn-pending 999 boot-one\n")
    if failed:
        router.write("etc/newton/failed", "txn-pending rollback-failed\n")
    result = router.stage()
    assert (result.rc, result.out, result.err) == (3, "", f"error guard {expected}\n")
    assert not any(c.startswith("helper ") for c in router.calls())
    assert not (router.root / "control/stage-stdin").exists()
    assert lock_is_free(router)


def test_stage_helper_refusal_passes_stderr_unchanged(router):
    prepare(router)
    router.write("control/stage.rc", "1\n")
    router.write("control/stage.err", "ERROR: uci batch refused exactly\nsecond line\n")
    result = router.stage()
    assert (result.rc, result.out, result.err) == (
        1, "", "ERROR: uci batch refused exactly\nsecond line\n"
    )
    assert (router.root / "control/stage-stdin").read_bytes() == b"set dhcp.cfg01.domain=lan\n"
    assert not router.txn().exists()
    assert lock_is_free(router)


@pytest.mark.parametrize(
    "control", ["stage-extra-line", "stage-trailing-line"], ids=["line-before-sid", "line-after-sid"]
)
def test_stage_rejects_helper_output_with_extra_line(router, control):
    # The stub prints the extra line before or after the SID line; a program that
    # only looks at the first line would accept the second case.
    prepare(router)
    router.write(f"control/{control}", "unexpected\n")
    result = router.stage()
    assert (result.rc, result.out, result.err) == (1, "", "error internal stage-output\n")
    assert not router.txn().exists()
    assert lock_is_free(router)


def test_stage_read_role_is_refused_before_stdin_or_calls(router):
    prepare(router)
    result = router.stage(role="read")
    assert (result.rc, result.out, result.err) == (3, "", "error role\n")
    assert not (router.root / "tmp/owrt-safe-apply.lock").exists()
    assert not (router.root / "control/stage-stdin").exists()
    assert not any(c.startswith(("helper ", "ubus ")) for c in router.calls())
    assert lock_is_free(router)


# boot_id: BusyBox `read` returns rc=1 when the file lacks a trailing newline,
# but it has set the variable; the boot_id function must NOT clear it.
def test_boot_id_no_trailing_newline(router):
    prepare(router)
    router.write("proc/sys/kernel/random/boot_id", b"abc-no-newline")
    result = router.stage()
    assert (result.rc, result.out, result.err) == (0, SID + "\n", "")
    txn = router.txn()
    assert (txn / "boot").read_text() == "abc-no-newline\n"
    assert lock_is_free(router)
