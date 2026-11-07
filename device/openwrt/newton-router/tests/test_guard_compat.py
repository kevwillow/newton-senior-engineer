"""Program reads guard status by its FIRST line only.

The guard on the main branch prints a SECOND line for
`newton-guard status`: `skipped <names>` (the names it skips). Before this
round's program change, `hello` put it inside the handshake line. The program
now reads only the first line and pins that."""

import pytest

from conftest import SID, _executable


NONCE = "0123456789abcdef"


def use_stub_guard(router, status_text="idle\n", status_rc=0):
    """Overwrite the guard copy with a stub that logs every call to calls.log.

    `status` cats <root>/control/guard-status.txt exactly and exits
    status_rc. Every other command prints `error usage` and exits 2.
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
        '  if [ -f "$root/control/guard-status.rc" ]; then\n'
        '    read -r rc < "$root/control/guard-status.rc"\n'
        '    exit "$rc"\n'
        '  fi\n'
        '  exit 0\n'
        "  ;;\n"
        "*)\n"
        '  printf "error usage\\n" >&2\n'
        "  exit 2\n"
        "  ;;\n"
        "esac\n"
    )
    _executable(guard, body)
    router.write("control/guard-status.txt", status_text)
    if status_rc:
        router.write("control/guard-status.rc", f"{status_rc}\n")


def assert_one_hello_line(res, expect_field):
    assert res.out.count("\n") == 1
    assert res.out.endswith("\n")
    line = res.out.rstrip("\n")
    fields = line.split()
    assert all("\n" not in f for f in fields), fields
    assert expect_field in fields, fields


# ---- 1. hello reads only the first line of guard status --------------------


def test_hello_direct_idle_ignores_skipped_line(router):
    use_stub_guard(router, status_text="idle\nskipped network.bak\n")
    res = router.direct("hello", NONCE, timeout=15)
    assert res.rc == 0
    assert_one_hello_line(res, "guard-state=idle")


def test_hello_forced_idle_ignores_skipped_line(router):
    use_stub_guard(router, status_text="idle\nskipped network.bak\n")
    res = router.forced(f"hello {NONCE}", role="read", timeout=15)
    assert res.rc == 0
    assert_one_hello_line(res, "guard-state=idle")


def test_hello_idle_with_many_skipped_lines_and_two_names(router):
    use_stub_guard(
        router,
        status_text=("idle\nskipped a.b c.d\n" + "noise\n" * 50),
    )
    res = router.direct("hello", NONCE, timeout=15)
    assert res.rc == 0
    assert_one_hello_line(res, "guard-state=idle")


@pytest.mark.parametrize(
    "first_line,state",
    [
        ("idle", "idle"),
        ("pending txn-x 99", "pending"),
        ("restored txn-y deadline", "restored"),
        ("failed txn-z lkg-corrupt", "failed"),
    ],
    ids=["idle", "pending", "restored", "failed"],
)
def test_hello_first_word_of_first_line(router, first_line, state):
    use_stub_guard(router, status_text=f"{first_line}\nskipped network.bak\n")
    res = router.direct("hello", NONCE, timeout=15)
    assert res.rc == 0
    assert_one_hello_line(res, f"guard-state={state}")


# ---- 2. guard that prints nothing or exits 1 --------------------------------


@pytest.mark.parametrize(
    "status_text,status_rc",
    [
        ("", 0),
        ("", 1),
        ("some garbage\n", 1),
    ],
    ids=["empty-rc0", "empty-rc1", "garbage-rc1"],
)
def test_hello_guard_failed_when_guard_unusable(router, status_text, status_rc):
    use_stub_guard(router, status_text=status_text, status_rc=status_rc)
    res = router.direct("hello", NONCE, timeout=15)
    assert res.rc == 0
    assert_one_hello_line(res, "guard-state=failed")


@pytest.mark.parametrize(
    "status_text,status_rc",
    [
        ("", 0),
        ("", 1),
        ("some garbage\n", 1),
    ],
    ids=["empty-rc0", "empty-rc1", "garbage-rc1"],
)
def test_stage_refused_when_guard_unusable(router, status_text, status_rc):
    use_stub_guard(router, status_text=status_text, status_rc=status_rc)
    res = router.stage()
    assert (res.rc, res.out, res.err) == (3, "", "error guard failed\n")
    assert not any(c.startswith("helper ") for c in router.calls())


# ---- 3. stage guard gate with skipped line ----------------------------------


def test_stage_refused_with_failed_after_skipped(router):
    use_stub_guard(router, status_text="failed txn-z lkg-corrupt\nskipped x.y\n")
    router.use_stub_helper()
    res = router.stage()
    assert (res.rc, res.out, res.err) == (
        3, "", "error guard failed txn-z lkg-corrupt\n"
    )


def test_stage_refused_with_pending_after_skipped(router):
    use_stub_guard(router, status_text="pending txn-x 99\nskipped x.y\n")
    router.use_stub_helper()
    res = router.stage()
    assert (res.rc, res.out, res.err) == (
        3, "", "error guard pending txn-x 99\n"
    )


def test_stage_succeeds_with_idle_after_skipped(router):
    use_stub_guard(router, status_text="idle\nskipped x.y\n")
    router.use_stub_helper()
    res = router.stage()
    assert (res.rc, res.out, res.err) == (0, SID + "\n", "")


@pytest.mark.parametrize(
    "first_line",
    [" pending", "restored x pending"],
    ids=["leading-space", "word-not-first"],
)
def test_stage_first_line_only_containing_word_does_not_block(router, first_line):
    use_stub_guard(router, status_text=f"{first_line}\n")
    router.use_stub_helper()
    res = router.stage()
    assert (res.rc, res.out, res.err) == (0, SID + "\n", "")


# ---- 4. health-check with restored ------------------------------------------


def test_health_check_restored_boot_after_skipped(router):
    use_stub_guard(router, status_text=f"restored {SID} boot\nskipped x.y\n")
    res = router.direct("health-check", SID, timeout=15)
    assert (res.rc, res.out, res.err) == (
        1, "",
        "health: not compared: the router rebooted during the window;"
        " the guard restored the config at boot\n",
    )


@pytest.mark.parametrize(
    "first_line",
    [f"restored {SID} abort", "idle"],
    ids=["restored-abort", "idle"],
)
def test_health_check_no_snapshot_message(router, first_line):
    use_stub_guard(router, status_text=f"{first_line}\nskipped x.y\n")
    res = router.direct("health-check", SID, timeout=15)
    assert (res.rc, res.out, res.err) == (
        1, "", f"health: not compared: no health snapshot for session {SID}\n",
    )


# ---- 5. very long first line -----------------------------------------------


def test_hello_with_very_long_first_line(router):
    use_stub_guard(router, status_text="a" * 3000)
    res = router.direct("hello", NONCE, timeout=15)
    assert res.rc == 0
    assert res.out.count("\n") == 1
