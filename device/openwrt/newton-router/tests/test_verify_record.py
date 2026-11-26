"""The verify record: the router counts the passes, confirm needs them.

The record of a transaction is `$LOCK/<sid>.txn/verified`: one line,
`<boot id> <passes> <uptime of the last pass>`, ending in LF. Every
passing verify round adds one pass, a failing round puts the count back
to zero. A confirm refuses a transaction that was not verified three
times on this boot: `error not-verified <reason>`, exit 3, and the
guard stays armed (nothing was called).
"""

import fcntl
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

try:
    from conftest import SID, _executable, _use_verify_stub
except ImportError:
    # The lab suite has a conftest.py too. When one pytest run collects
    # both trees, the plain module name "conftest" is the one of the tree
    # collected last, so the helpers of this tree are loaded from this
    # directory by path.
    _path = Path(__file__).resolve().parent / "conftest.py"
    _spec = importlib.util.spec_from_file_location("device_router_conftest", _path)
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["device_router_conftest"] = _module
    _spec.loader.exec_module(_module)
    SID = _module.SID
    _executable = _module._executable
    _use_verify_stub = _module._use_verify_stub


DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)

NETSTAT_DHCP_LINE = "udp 0 0 0.0.0.0:67 0.0.0.0:* 123/dnsmasq\n"

NETSTAT_NO_DHCP_LINE = "udp 0 0 0.0.0.0:53 0.0.0.0:* 1/odhcpd\n"


def applied(router, sid=SID):
    """A sealed and applied plan, ready for the verify rounds.

    Returns the SimpleNamespace `fresh_plan` gives (sid, digest, base,
    diff, psha, t, txn). The rpcd save dir is in place, as after a real
    apply. The helper's health check is stubbed: the real one runs ucode
    and fw4, which the fake root does not have."""
    plan = router.fresh_plan(sid=sid)
    router.set_fake("df", out=DF_OUT)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0, (res.rc, res.out, res.err)
    rpcd_dir = router.root / "var/run/rpcd" / f"uci-{plan.sid}"
    rpcd_dir.mkdir(parents=True, exist_ok=True)
    _use_verify_stub(router)
    return plan


def record(plan):
    """The text of the transaction's verify record ('' when there is none)."""
    path = plan.txn / "verified"
    return path.read_text() if path.exists() else ""


def confirm(router, sid):
    return router.forced(f"confirm {sid}")


def install_init_fakes(router):
    """init.d/firewall and init.d/dnsmasq both succeed, so a repair
    (`fwrestart 1`, `dnsmasq-repair`, `dnsmasq-ensure`) ends the way it
    ends on a router."""
    initd = router.root / "etc/init.d"
    _executable(initd / "firewall", "#!/bin/sh\nexit 0\n")
    _executable(
        initd / "dnsmasq",
        "#!/bin/sh\n"
        'case "$1" in running) exit 0 ;; restart) exit 0 ;; *) exit 0 ;; esac\n',
    )


def need_dhcp_file(router):
    """The path of the recorded DHCP check ($LOCK/need-dhcp)."""
    return router.root / "tmp/owrt-safe-apply.lock" / "need-dhcp"


def repair_with_the_dhcp_listener(router):
    """A dnsmasq repair that finds the DHCP listener (d=1).

    The repair records the strong check (1) in $LOCK/need-dhcp, so a
    later verify cannot be asked to skip the check the repair made
    necessary."""
    install_init_fakes(router)
    router.set_fake("netstat", out=NETSTAT_DHCP_LINE)
    res = router.forced("dnsmasq-repair")
    assert (res.rc, res.out, res.err) == (0, "restarted rc=0 dhcp=1\n", "")
    assert need_dhcp_file(router).read_text() == "1\n"
    return res


def take_program_lock(router):
    """Take the router program's lock (the flock on tmp/newton/flock).

    The lock file is the one the program opens (fd 8) and flocks, so a
    call that takes the lock waits for it."""
    newton = router.root / "tmp/newton"
    newton.mkdir(parents=True, exist_ok=True)
    newton.chmod(0o700)
    handle = os.open(newton / "flock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


# ---- 1. no verify: the confirm refuses ------------------------------------


def test_confirm_without_a_verify_refuses(router):
    """No verify ran: the confirm refuses with `error not-verified
    no-record`, exit 3; the guard stays pending, nothing was confirmed
    and rpcd was never asked."""
    plan = applied(router)
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified no-record\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    assert not router.calls_matching("ubus uci-confirm")
    assert (plan.txn / "applied").exists()


# ---- 2. two passes are not enough, three are -------------------------------


def test_confirm_after_two_passes_refuses(router):
    """Two passing rounds: the record says 2, the confirm refuses with
    `error not-verified passes-2`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid, passes=2)
    assert record(plan) == "boot-one 2 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified passes-2\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_confirm_after_three_passes_succeeds(router):
    """Three passing rounds: the record says 3, the confirm keeps the
    change (`confirmed <sid>`, exit 0) and the guard goes idle."""
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- 3. a failing round resets the count -----------------------------------


def test_a_failing_round_resets_the_count(router):
    """pass, pass, fail (the ping fails), pass: the record counts the
    passes since the last failure, so the confirm refuses with
    `error not-verified passes-1`."""
    plan = applied(router)
    router.verified(plan.sid, passes=2)
    router.set_fake("ping", rc=1)
    res = router.forced(f"verify {plan.sid} 0")
    assert (res.rc, res.err) == (
        1, "verify: ping -c1 -W3 1.1.1.1 failed\n",
    )
    assert record(plan) == "boot-one 0 100\n"
    router.set_fake("ping", rc=0)
    router.verified(plan.sid, passes=1)
    assert record(plan) == "boot-one 1 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified passes-1\n", "",
    )


# ---- 4. the record must be recent ------------------------------------------


def test_confirm_after_the_record_grew_old_refuses(router):
    """Three passes at uptime 100 and the confirm at uptime 161: the
    record is 61 s old, so the confirm refuses with `error not-verified
    stale`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    router.set_uptime(161)
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified stale\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_confirm_at_the_edge_of_the_record_window_succeeds(router):
    """The same record at uptime 160 is 60 s old: the window is 60 s, so
    the confirm still succeeds."""
    plan = applied(router)
    router.verified(plan.sid)
    router.set_uptime(160)
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")


# ---- 5. a record of another boot -------------------------------------------


def test_a_record_of_another_boot_refuses(router):
    """A record that names another boot: the confirm refuses with
    `error not-verified other-boot`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-two 3 100\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified other-boot\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


# ---- 6. the record belongs to the transaction ------------------------------


def test_a_record_of_another_session_does_not_confirm(router):
    """The record of session A does not let session B confirm: B has no
    record of its own, so the confirm refuses with `error not-verified
    no-record`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    other = "b" * 32
    txn_b = router.txn(other)
    txn_b.mkdir(parents=True, exist_ok=True)
    (txn_b / "owner").write_text("agent-one\n")
    (txn_b / "applied").write_text("100000 221 boot-one\n")
    res = confirm(router, other)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified no-record\n", "",
    )


# ---- 7. a record that cannot be written ------------------------------------


def test_a_record_write_that_fails_leaves_no_record(router):
    """A directory where the record's temporary file goes: the write
    fails, the verify still ends as it would have ended (exit 0, empty
    stdout and stderr), no record is left, and the confirm refuses."""
    plan = applied(router)
    (plan.txn / "verified.new").mkdir()
    res = router.forced(f"verify {plan.sid} 0")
    assert (res.rc, res.out, res.err) == (0, "", "")
    assert not (plan.txn / "verified").exists()
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified no-record\n", "",
    )


def test_a_record_write_into_a_read_only_directory_leaves_no_record(router):
    """A read-only transaction directory: the write fails the same way,
    the verify still exits 0 and the confirm refuses."""
    plan = applied(router)
    plan.txn.chmod(0o500)
    try:
        res = router.forced(f"verify {plan.sid} 0")
        assert (res.rc, res.out, res.err) == (0, "", "")
        assert not (plan.txn / "verified").exists()
        res = confirm(router, plan.sid)
        assert (res.rc, res.err, res.out) == (
            3, "error not-verified no-record\n", "",
        )
    finally:
        plan.txn.chmod(0o700)


# ---- 8. a malformed record -------------------------------------------------


def test_a_malformed_record_refuses(router):
    """A record that is not three words: the confirm refuses with
    `error not-verified record-malformed`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("garbage\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified record-malformed\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_a_record_with_a_non_numeric_pass_count_refuses(router):
    """Three words, but the pass count is not a number: the confirm
    refuses with `error not-verified record-malformed`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one three 100\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified record-malformed\n", "",
    )


def test_a_record_with_an_oversized_pass_count_refuses(router):
    """A pass count of twenty digits: the confirm refuses with `error
    not-verified record-malformed`, exit 3.

    A number that big is out of range for the shell's own comparison: the
    comparison fails with status 2 and the check that reads it would be
    passed anyway, so the record has to be refused before it is compared.
    """
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one 99999999999999999999 100\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified record-malformed\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_a_record_with_an_oversized_uptime_refuses(router):
    """An uptime of twenty digits is out of range in the same way: the
    confirm refuses with `error not-verified record-malformed`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one 3 99999999999999999999\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified record-malformed\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_a_nine_digit_pass_count_is_still_allowed(router):
    """Nine digits are still a number the shell can compare: the record
    `boot-one 999999999 100` says more than three passes, so the
    confirm succeeds.

    A number with a leading zero is a different thing: the shell reads
    `08` as octal, and octal has no 8, so a leading zero is malformed
    (the next test)."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one 999999999 100\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- 9. a failing verify leaves zero passes -------------------------------


def test_a_failing_verify_leaves_zero_passes(router):
    """After three passes a failing round puts the count back to zero in
    the record itself, not only in the confirm's answer."""
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    router.set_fake("ping", rc=1)
    res = router.forced(f"verify {plan.sid} 0")
    assert res.rc == 1
    assert record(plan) == "boot-one 0 100\n"


# ---- 10. the held path -----------------------------------------------------


def test_the_held_path_confirms_after_one_more_pass(router):
    """A held change was verified three times; the held confirm runs one
    more round before it confirms: the record says 4, the confirm
    succeeds."""
    plan = applied(router)
    router.verified(plan.sid)
    router.verified(plan.sid, passes=1)
    assert record(plan) == "boot-one 4 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- 11. a verify that does not finish leaves no passes -------------------


def test_a_verify_that_dies_mid_way_leaves_no_passes(router):
    """Three passes, then a verify whose ping never ends: the call is
    killed before its last step, so it never writes the count of the
    passes it made. The record must not keep the old count either: it
    holds zero passes, and the confirm refuses with `error not-verified
    passes-0`."""
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    router.set_fake("ping", sleep=30)
    with pytest.raises(subprocess.TimeoutExpired):
        router.forced(f"verify {plan.sid} 0", timeout=6)
    assert record(plan) == "boot-one 0 100\n"
    (router.root / "control/ping.sleep").unlink()
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified passes-0\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_a_verify_that_leaves_through_fail_leaves_no_passes(router):
    """Three passes, then a verify that ends through `fail` (the
    transaction's `applied` file is gone, so the call refuses with
    `error not-applied`): the call ends without writing the count, so
    the passes before it must not survive it. The record holds zero
    passes and the confirm refuses with `error not-verified passes-0`."""
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    applied_file = plan.txn / "applied"
    text = applied_file.read_text()
    applied_file.unlink()
    res = router.forced(f"verify {plan.sid} 0")
    assert (res.rc, res.err, res.out) == (1, "error not-applied\n", "")
    assert record(plan) == "boot-one 0 100\n"
    applied_file.write_text(text)
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified passes-0\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_three_passes_in_a_row_still_confirm(router):
    """No regression: three verify rounds in a row, each one passing,
    leave the record at three passes and the confirm keeps the change."""
    plan = applied(router)
    router.verified(plan.sid, passes=1)
    assert record(plan) == "boot-one 1 100\n"
    router.verified(plan.sid, passes=1)
    assert record(plan) == "boot-one 2 100\n"
    router.verified(plan.sid, passes=1)
    assert record(plan) == "boot-one 3 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- 12. a number with a leading zero is malformed -------------------------


def test_a_record_with_a_leading_zero_pass_count_refuses(router):
    """A pass count of `08`: the shell reads a leading zero as octal, and
    octal has no 8, so the word is not a number at all. The confirm
    refuses with `error not-verified record-malformed`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one 08 100\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified record-malformed\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_a_verify_on_a_leading_zero_record_counts_one_pass(router):
    """A malformed record means no passes: the next verify round reads
    the old count as zero and writes one pass."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one 08 100\n")
    res = router.forced(f"verify {plan.sid} 0")
    assert (res.rc, res.out, res.err) == (0, "", "")
    assert record(plan) == "boot-one 1 100\n"


def test_a_record_with_a_leading_zero_uptime_refuses(router):
    """The uptime word `0100` is malformed for the same reason: it is
    read as the octal 64, so the age of the record is not the age it
    claims. The confirm refuses with `error not-verified
    record-malformed`, exit 3."""
    plan = applied(router)
    router.verified(plan.sid)
    (plan.txn / "verified").write_text("boot-one 3 0100\n")
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified record-malformed\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


# ---- 13. a repair drops the record ----------------------------------------


@pytest.mark.parametrize(
    "command",
    ["dnsmasq-repair", "dnsmasq-ensure", "fwrestart 1"],
    ids=["dnsmasq-repair", "dnsmasq-ensure", "fwrestart"],
)
def test_a_repair_drops_the_verify_record(router, command):
    """Three passes, then a repair of the router (`dnsmasq-repair`,
    `dnsmasq-ensure` or `fwrestart 1`): the repair changes the router,
    so the passes before it do not count any more. The record is gone,
    the confirm refuses with `error not-verified no-record`, and three
    more passes count again."""
    install_init_fakes(router)
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    res = router.forced(command)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert not (plan.txn / "verified").exists()
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified no-record\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- the record's shape ----------------------------------------------------


@pytest.mark.parametrize(
    "passes,expected",
    [
        (1, "boot-one 1 100\n"),
        (2, "boot-one 2 100\n"),
        (3, "boot-one 3 100\n"),
    ],
)
def test_the_record_holds_one_line_of_three_words(router, passes, expected):
    """The record is one line, three words, ending in LF: <boot id>
    <passes> <uptime of the last pass>."""
    plan = applied(router)
    router.verified(plan.sid, passes=passes)
    text = record(plan)
    assert text == expected
    assert text.endswith("\n")
    assert len(text.split()) == 3


# ---- 14. a standalone health check drops the record ------------------------


def test_a_health_check_drops_the_verify_record(router):
    """Three passes, then a standalone `health-check <sid>`: the check
    re-reads the health of the router, so the passes before it do not
    count any more. The record is gone, the confirm refuses with
    `error not-verified no-record`, exit 3, and the guard stays armed.

    The verify rounds themselves are untouched: `cmd_verify` runs the
    health check directly and does not go through `cmd_health_check`."""
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    res = router.forced(f"health-check {plan.sid}")
    assert (res.rc, res.out, res.err) == (0, "", "")
    assert not (plan.txn / "verified").exists()
    res = confirm(router, plan.sid)
    assert (res.rc, res.err, res.out) == (
        3, "error not-verified no-record\n", "",
    )
    assert router.guard_status().startswith(f"pending {plan.sid} ")


def test_a_health_check_while_the_lock_is_held_is_refused(router):
    """Another call holds the program lock: the health-check waits for
    it and gives up with `error lock-timeout`, exit 1, the way the other
    locked commands refuse. Nothing runs: the helper is never called."""
    plan = applied(router)
    handle = take_program_lock(router)
    try:
        res = router.forced(f"health-check {plan.sid}", timeout=40)
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)
    assert (res.rc, res.err, res.out) == (1, "error lock-timeout\n", "")
    assert not router.calls_matching("helper health-check")


# ---- 15. a health check drops only its own session's record ---------------


def test_a_health_check_of_another_session_keeps_the_verify_record(router):
    """Three passes, then another caller runs `health-check <other sid>`:
    the check of another session must not drop the record of this one.
    The record belongs to its owner, and the check drops only the record
    of the session it names. The confirm of the owner still succeeds."""
    plan = applied(router)
    router.verified(plan.sid)
    assert record(plan) == "boot-one 3 100\n"
    other = "b" * 32
    # the other session has a health snapshot, so its check runs
    health = router.root / "tmp/owrt-safe-apply.lock" / f"{other}.health"
    health.mkdir(parents=True, exist_ok=True)
    (health / "newton-fw4-loaded").write_text("0\n")
    res = router.forced(f"health-check {other}", caller="agent-two", timeout=40)
    assert (res.rc, res.out, res.err) == (0, "", "")
    assert record(plan) == "boot-one 3 100\n"
    res = confirm(router, plan.sid)
    assert (res.rc, res.out, res.err) == (0, f"confirmed {plan.sid}\n", "")
    assert router.guard_status() == "idle"


# ---- 16. an abort of another session keeps the DHCP check -----------------


def test_an_abort_of_another_session_keeps_the_dhcp_record(router):
    """The DHCP check a dnsmasq repair recorded belongs to the open
    transaction. Another caller aborts a session that has no transaction
    of its own (the "gone" path): that abort must not touch the record
    of the live transaction. `$LOCK/need-dhcp` still holds 1."""
    plan = applied(router)
    repair_with_the_dhcp_listener(router)
    other = "b" * 32
    res = router.forced(f"abort {other}", caller="agent-two")
    assert (res.rc, res.out, res.err) == (0, f"aborted {other} gone\n", "")
    assert need_dhcp_file(router).read_text() == "1\n", \
        "the abort of another session deleted the DHCP check of the open one"


def test_the_verify_after_an_abort_of_another_session_checks_the_dhcp(router):
    """The same flow, and then dnsmasq runs without its DHCP listener:
    the verify round of the live transaction still runs the strong check
    the repair recorded, so it fails with the DHCP-listener line.

    The abort of another session must not delete the record: with the
    record gone the caller could ask for no DHCP check at all and the
    router that had lost its listener would pass the round."""
    plan = applied(router)
    repair_with_the_dhcp_listener(router)
    other = "b" * 32
    res = router.forced(f"abort {other}", caller="agent-two")
    assert (res.rc, res.out, res.err) == (0, f"aborted {other} gone\n", "")
    # dnsmasq runs, but it has no DHCP listener any more
    router.set_fake("netstat", out=NETSTAT_NO_DHCP_LINE)
    res = router.forced(f"verify {plan.sid} 0")
    assert (res.rc, res.err, res.out) == (
        1,
        "verify: dnsmasq is not running with its DHCP listener "
        "(udp 67) after Newton restarted it\n",
        "",
    )


def test_the_abort_of_the_live_transaction_removes_the_dhcp_record(router):
    """The abort of the transaction the record belongs to ends it: the
    next transaction starts without the check, so that abort removes
    `$LOCK/need-dhcp`."""
    plan = applied(router)
    repair_with_the_dhcp_listener(router)
    res = router.forced(f"abort {plan.sid}")
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert not need_dhcp_file(router).exists(), \
        "the abort of the open transaction left the DHCP check behind"
