"""Design 3.5c, 4.5, 4.4, 9.2 groups 5 and 9.

Covers `cmd_verify` end-to-end against the fake router root: the happy
paths (with zero or three sealed probes), the in-order step gates
(ping, nslookup, DHCP, health-check, sealed probes; the FIRST failure
prints one stderr line and exits 1), the not-applied / role / owner
refusals, the 10 s run_bounded bound on a hung ping (M17), the M46
lock-not-held-by-watchdog invariant, the 25 s budget that turns a
late probe into a `budget` reason, the probe_reason words that
`probe_run` actually produces for `fail` and a `uci-equals` mismatch,
and the assertion that nothing the fakes print ever reaches stdout
and the helper `status|apply|confirm|abort` is never invoked.
"""

import re
import subprocess
import threading
import time

import pytest

from conftest import _executable


DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


NETSTAT_DHCP_LINE = "udp 0 0 0.0.0.0:67 0.0.0.0:* 123/dnsmasq\n"


# ---- helpers -------------------------------------------------------------

def upgrade_stub_for_verify(router):
    """Rewrite use_stub_helper's wrapper so it also stubs `health-check`.

    The real helper invokes ucode / fw4 / mktemp paths that the fixture
    does not fake (use_stub_helper only intercepts stage and diff). The
    verify path needs the health-check subcall to either pass cleanly or
    fail with the caller-provided stderr; control/health-check.rc (and
    optional control/health-check.err) drive that."""
    helper = router.root / "usr/libexec/newton/newton-safe-apply"
    _executable(
        helper,
        "#!/usr/bin/busybox sh\n"
        'root="$NEWTON_ROUTER_ROOT"\n'
        'echo "helper $*" >> "$root/control/calls.log"\n'
        'case "${1:-}" in\n'
        "stage)\n"
        '  cat > "$root/control/stage-stdin"\n'
        '  if [ -f "$root/control/stage.rc" ]; then\n'
        '    [ ! -f "$root/control/stage.err" ] || cat "$root/control/stage.err" >&2\n'
        '    read -r rc < "$root/control/stage.rc"; exit "$rc"\n'
        "  fi\n"
        '  mkdir -p "$NEWTON_LOCK"\n'
        '  read -r sid < "$root/control/next-sid"\n'
        '  printf "%s\\n" "$sid" > "$NEWTON_LOCK/sid"\n'
        '  printf "%s\\n" "$sid" >> "$root/control/sessions"\n'
        '  [ ! -f "$root/control/stage-extra-line" ] || cat "$root/control/stage-extra-line"\n'
        '  printf "%s\\n" "$sid"\n'
        '  [ ! -f "$root/control/stage-trailing-line" ] || cat "$root/control/stage-trailing-line"\n'
        "  ;;\n"
        "diff)\n"
        '  if [ -f "$root/control/diff.rc" ]; then\n'
        '    read -r rc < "$root/control/diff.rc"; exit "$rc"\n'
        "  fi\n"
        '  cat "$root/control/diff.txt"\n'
        "  ;;\n"
        "health-check)\n"
        '  if [ -f "$root/control/health-check.rc" ]; then\n'
        '    [ ! -f "$root/control/health-check.err" ] || cat "$root/control/health-check.err" >&2\n'
        '    read -r rc < "$root/control/health-check.rc"; exit "$rc"\n'
        "  fi\n"
        "  exit 0\n"
        "  ;;\n"
        "*)\n"
        '  exec /usr/bin/busybox sh "/usr/libexec/newton/newton-safe-apply.real" "$@"\n'
        "  ;;\n"
        "esac\n",
    )


def ready_for_arm(router):
    router.set_fake("df", out=DF_OUT)


def applied(router, probes=b"", caller="agent-one"):
    """Seal and apply a plan; return the SimpleNamespace `fresh_plan`
    gives (sid, digest, base, diff, psha, t, txn). The harness's
    `ready_for_arm` makes apply believe there is room; the verify-aware
    helper stub is installed afterwards so the verify call sees it."""
    plan = router.fresh_plan(probes=probes, caller=caller)
    ready_for_arm(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0, caller=caller)
    assert res.rc == 0, (res.rc, res.out, res.err)
    rpcd_dir = router.root / "var/run/rpcd" / f"uci-{plan.sid}"
    rpcd_dir.mkdir(parents=True, exist_ok=True)
    upgrade_stub_for_verify(router)
    return plan


applied_for_verify = applied


def lock_is_free(router):
    res = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return res.returncode == 0


def verify(router, sid, dhcp=0, timeout=60, **kw):
    return router.forced(f"verify {sid} {dhcp}", timeout=timeout, **kw)


# ---- 1. happy path --------------------------------------------------------

def test_verify_all_pass_no_probes(router):
    """All five steps pass with no sealed probes: exit 0, empty stdout,
    empty stderr; during the verify itself, only `health-check` is
    invoked on the helper side (stage/diff/confighash are from apply)."""
    plan = applied(router)
    before = router.calls_matching("helper ")
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.out, res.err) == (0, "", "")
    new_helpers = [line for line in router.calls_matching("helper ")
                   if line not in before]
    kinds = {line.split(" ", 2)[1] for line in new_helpers}
    assert kinds == {"health-check"}, kinds


def test_verify_all_pass_three_sealed_probes(router):
    """Three passing sealed probes (resolve via the fake nslookup, default
    rc=0): exit 0, empty stdout, empty stderr; the verify's nslookup call
    plus the three sealed probes appear in calls.log (the resolve probe
    defaults to server 127.0.0.1 like the verify nslookup does)."""
    probes = b"resolve\topenwrt.org\nresolve\topenwrt.org\nresolve\topenwrt.org\n"
    plan = applied(router, probes=probes)
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.out, res.err) == (0, "", "")
    ns = [c for c in router.calls() if c.startswith("nslookup openwrt.org")]
    assert len(ns) == 4, ns
    health = [c for c in router.calls() if c.startswith("helper health-check")]
    assert len(health) == 1, health


# ---- 2. in-order FIRST failure gates (3.5c step 2) ------------------------

def test_verify_ping_fail(router):
    """ping rc=1 -> the exact stderr line, exit 1, stdout empty; no
    helper health-check call (the earlier step wins)."""
    plan = applied(router)
    router.set_fake("ping", rc=1)
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: ping -c1 -W3 1.1.1.1 failed\n", "",
    )
    assert "nslookup openwrt.org" not in router.calls()
    assert not router.calls_matching("helper health-check")


def test_verify_nslookup_fail(router):
    """nslookup rc=1 -> the exact stderr line, exit 1, empty stdout;
    ping passed (calls.log shows the ping line)."""
    plan = applied(router)
    router.set_fake("nslookup", rc=1)
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: nslookup openwrt.org 127.0.0.1 failed\n", "",
    )
    assert any(c.startswith("ping -c1 -W3 1.1.1.1") for c in router.calls())


def test_verify_dhcp1_no_listener_fail(router):
    """DHCP=1 with pidof ok but netstat output missing the `:67 .*/dnsmasq`
    line -> exact stderr, exit 1; the helper health-check never runs."""
    plan = applied(router)
    router.set_fake("netstat", out="udp 0 0 0.0.0.0:53 0.0.0.0:* 1/odhcpd\n")
    res = verify(router, plan.sid, 1)
    assert (res.rc, res.err, res.out) == (
        1,
        "verify: dnsmasq is not running with its DHCP listener "
        "(udp 67) after Newton restarted it\n",
        "",
    )
    assert not router.calls_matching("helper health-check")


def test_verify_dhcp1_pidof_down_fail(router):
    """DHCP=1 with pidof dnsmasq rc=1 -> same wording as the listener check."""
    plan = applied(router)
    router.set_fake("pidof", rc=1)
    res = verify(router, plan.sid, 1)
    assert (res.rc, res.err, res.out) == (
        1,
        "verify: dnsmasq is not running with its DHCP listener "
        "(udp 67) after Newton restarted it\n",
        "",
    )


def test_verify_dhcp2_pidof_down_fail(router):
    """DHCP=2 with pidof dnsmasq rc=1 -> exact stderr, exit 1."""
    plan = applied(router)
    router.set_fake("pidof", rc=1)
    res = verify(router, plan.sid, 2)
    assert (res.rc, res.err, res.out) == (
        1, "verify: dnsmasq is not running after Newton restarted it\n", "",
    )


def test_verify_dhcp0_does_not_check_pidof(router):
    """DHCP=0: the DHCP step is a no-op (pidof rc=1 is irrelevant) and
    verify goes on to the health check and exits rc=0."""
    plan = applied(router)
    router.set_fake("pidof", rc=1)
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.out, res.err) == (0, "", "")
    assert router.calls_matching("helper health-check")


def test_verify_health_fail_passes_through(router):
    """A health-check that returns rc=1 with its own stderr line; the
    verify call prints that stderr verbatim and exits 1; no probe line
    is printed (the health failure wins over a sealed-probe failure)."""
    plan = applied(router)
    router.write("control/health-check.rc", "1\n")
    router.write("control/health-check.err", "health: a sample failure line\n")
    res = verify(router, plan.sid, 0)
    assert res.rc == 1, (res.rc, res.out, res.err)
    assert res.out == ""
    assert res.err == "health: a sample failure line\n"
    assert "verify: probe" not in res.err


def test_verify_sealed_probe_fail_first_one(router):
    """Sealed probes: line 1 `fail` -> `verify: probe 1 failed: fail
    planted` exactly, exit 1. n is the 1-based line number in the
    sealed `probes` file (design 3.5c step 2.5)."""
    plan = applied(router, probes=b"fail\n")
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: probe 1 failed: fail planted\n", "",
    )


def test_verify_sealed_probe_fail_second_one(router):
    """Probe 1 a passing `resolve` and probe 2 `fail` -> probe 2 is the
    one reported (the failing line's 1-based number, not the ordinal of
    failures in the file)."""
    probes = b"resolve\topenwrt.org\nfail\n"
    plan = applied(router, probes=probes)
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: probe 2 failed: fail planted\n", "",
    )


def test_verify_sealed_probe_two_failing_only_first(router):
    """Two `fail` probes: only the FIRST failing probe is reported
    (the second is never reached because verify exits 1 on the first)."""
    plan = applied(router, probes=b"fail\nfail\n")
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: probe 1 failed: fail planted\n", "",
    )


# Order pairs (3.5c step 2): the first failing step wins.

def test_verify_ping_and_nslookup_both_fail_only_ping(router):
    """Both ping and nslookup return rc=1: only the ping line is printed;
    nslookup is never invoked at all."""
    plan = applied(router)
    router.set_fake("ping", rc=1)
    router.set_fake("nslookup", rc=1)
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: ping -c1 -W3 1.1.1.1 failed\n", "",
    )
    assert "nslookup openwrt.org 127.0.0.1" not in router.calls()


def test_verify_nslookup_and_dhcp_both_fail_only_nslookup(router):
    """nslookup rc=1 and pidof rc=1: only the nslookup line; the DHCP
    step is never reached."""
    plan = applied(router)
    router.set_fake("nslookup", rc=1)
    router.set_fake("pidof", rc=1)
    res = verify(router, plan.sid, 2)
    assert (res.rc, res.err, res.out) == (
        1, "verify: nslookup openwrt.org 127.0.0.1 failed\n", "",
    )
    assert "pidof dnsmasq" not in router.calls()


def test_verify_dhcp_and_health_both_fail_only_dhcp(router):
    """DHCP=2 fails AND the health check fails: only the DHCP line; the
    helper is never invoked, so its failure-line never reaches stderr."""
    plan = applied(router)
    router.set_fake("pidof", rc=1)
    router.write("control/health-check.rc", "1\n")
    router.write("control/health-check.err", "health: would have complained\n")
    res = verify(router, plan.sid, 2)
    assert (res.rc, res.err, res.out) == (
        1, "verify: dnsmasq is not running after Newton restarted it\n", "",
    )
    assert not router.calls_matching("helper health-check")


def test_verify_health_fail_then_probe_fail_only_health(router):
    """Health-check fails AND a sealed probe fails: only the health-check
    stderr (the helper's own line) is printed; no `verify: probe ...` line."""
    plan = applied(router, probes=b"fail\n")
    router.write("control/health-check.rc", "1\n")
    router.write("control/health-check.err", "health: not compared\n")
    res = verify(router, plan.sid, 0)
    assert res.rc == 1, (res.rc, res.out, res.err)
    assert res.out == ""
    assert res.err == "health: not compared\n"
    assert "verify: probe" not in res.err


# ---- 3. not-applied and roles (3.5c step 1) -----------------------------

@pytest.mark.parametrize(
    "setup",
    [
        "sealed-not-applied",
        "boot-id-mismatch",
        "applying-without-applied",
    ],
    ids=["sealed-not-applied", "boot-id-mismatch", "applying-without-applied"],
)
def test_verify_not_applied(router, setup):
    """A sealed plan with no applied file; an applied file whose boot id
    differs from the live boot id; an applying file but no applied. All
    three are refused with `error not-applied`, exit 1, stdout empty;
    the earlier guards (applied-existence / boot-id) run before step 2
    so nothing on the network or in the helper runs."""
    if setup == "sealed-not-applied":
        plan = router.fresh_plan()
        upgrade_stub_for_verify(router)
    elif setup == "boot-id-mismatch":
        plan = applied(router)
        router.set_boot_id("boot-two")
    else:  # applying-without-applied
        plan = applied(router)
        (plan.txn / "applied").unlink()
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (1, "error not-applied\n", "")
    assert not router.calls_matching("helper health-check")
    assert not router.calls_matching("ping -c1")
    assert not router.calls_matching("nslookup openwrt.org 127.0.0.1")


def test_verify_other_caller_is_not_owner(router):
    """A non-owner (`agent-two`) verifying the plan is refused with
    `error not-owner`, exit 3, stdout empty; nothing happens (no ping,
    no helper)."""
    plan = applied(router, caller="agent-one")
    res = verify(router, plan.sid, 0, caller="agent-two")
    assert (res.rc, res.err, res.out) == (3, "error not-owner\n", "")
    assert not router.calls_matching("ping -c1")
    assert not router.calls_matching("helper health-check")


def test_verify_read_role_is_refused(router):
    """A read-role verify is refused with `error role`, exit 3;
    stdout empty; nothing happens."""
    plan = applied(router)
    res = verify(router, plan.sid, 0, role="read")
    assert (res.rc, res.err, res.out) == (3, "error role\n", "")
    assert not router.calls_matching("ping -c1")
    assert not router.calls_matching("helper health-check")


# ---- 4. bounds (M17, M46) ----------------------------------------------

@pytest.mark.slow
def test_verify_hung_ping_ends_at_bound_and_lock_is_free(router):
    """A hung ping (control/ping.sleep=60) is bounded at 10 s: the
    exact stderr line, exit 1, the call takes 9-20 s; right after, the
    program lock is free (flock -n tmp/newton/flock works at once),
    even though the watchdog's sleep subshell may still be alive
    (M46: the watchdog must close fd 8/9 with `exec 8>&- 9>&-`)."""
    plan = applied(router)
    router.set_fake("ping", sleep=60)
    start = time.monotonic()
    res = verify(router, plan.sid, 0, timeout=60)
    elapsed = time.monotonic() - start
    assert (res.rc, res.err, res.out) == (
        1, "verify: ping -c1 -W3 1.1.1.1 failed\n", "",
    )
    assert 9 <= elapsed <= 20, elapsed
    assert lock_is_free(router), \
        "the watchdog subshell must not hold the program lock"


# ---- 5. 25 s budget (3.5c step 3 / 4.5) ---------------------------------

@pytest.mark.slow
def test_verify_25s_budget_first_probe_is_budget(router):
    """ping sleep=8 + nslookup sleep=8 (each well under the 10 s bound,
    so they pass) and a dhcp=1 path that runs netstat for 10 s -> ~26 s
    of real time before the probes begin, which is past the 25 s budget
    (design 3.5c step 3). The cmd_verify's uptime_now reads /proc/uptime
    each time and the fixture does not bump it on its own, so a
    one-shot background write 12 s into the run is what makes the
    budget fire for probe 1.

    Total wall time stays under 40 s; marked slow and kept here so a
    future regression can build on this exact construction."""
    plan = applied(router, probes=b"resolve\topenwrt.org\n")
    router.set_fake("ping", sleep=8)
    router.set_fake("nslookup", sleep=8)
    router.set_fake("netstat", sleep=10, out=NETSTAT_DHCP_LINE)
    router.set_uptime(100)

    def bump_after_delay():
        time.sleep(12)
        router.write("proc/uptime", "130.00 90.00\n")
    threading.Thread(target=bump_after_delay, daemon=True).start()

    start = time.monotonic()
    res = verify(router, plan.sid, 1)
    elapsed = time.monotonic() - start
    assert (res.rc, res.err, res.out) == (
        1, "verify: probe 1 failed: resolve budget\n", "",
    )
    assert elapsed < 40, elapsed


# ---- 6. probe reason words (probe_run) -----------------------------------

def test_verify_probe_fail_planted(router):
    """A `fail` sealed probe gives the reason word `planted` (the body
    of `probe_fail` in the program, design 4.3)."""
    plan = applied(router, probes=b"fail\n")
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: probe 1 failed: fail planted\n", "",
    )


def test_verify_probe_uci_equals_mismatch(router):
    """A `uci-equals` sealed probe whose value does not match what the
    fake uci returns gives the reason word `mismatch` (probe_uci_equals)."""
    plan = applied(router,
                   probes=b"uci-equals\tfirewall.@defaults[0].input\tREJECT\n")
    router.set_fake("uci", out="ACCEPT\n")
    res = verify(router, plan.sid, 0)
    assert (res.rc, res.err, res.out) == (
        1, "verify: probe 1 failed: uci-equals mismatch\n", "",
    )


# ---- 7. stdout empty on every outcome (3.7) -----------------------------

def test_verify_stdout_empty_when_ping_fails_with_ubus_noise(router):
    """Even when the fakes print lines on stdout (ubus, ping), nothing
    reaches the program's own stdout when verify exits 1."""
    plan = applied(router)
    router.set_fake("ubus", out="login: ubus-noise-that-should-not-leak\n")
    router.set_fake("ping", rc=1, out="ping-noise\n")
    res = verify(router, plan.sid, 0)
    assert res.out == ""
    assert "ubus-noise" not in res.out
    assert "ping-noise" not in res.out


def test_verify_stdout_empty_on_happy_path(router):
    """Happy path with sealed resolve probes plus ping / nslookup noise:
    stdout is still exactly empty."""
    plan = applied(router,
                   probes=b"resolve\topenwrt.org\nresolve\topenwrt.org\n")
    router.set_fake("ping", out="PING noise-that-should-not-leak\n")
    router.set_fake("nslookup", out="Server:\t127.0.0.1\n")
    res = verify(router, plan.sid, 0)
    assert res.out == ""
    assert "noise-that-should-not-leak" not in res.out
    assert "Server:" not in res.out


# ---- 8. the helper subcommands the program never calls during verify -----

def test_verify_never_calls_helper_status_apply_confirm_abort_happy(router):
    """The verify path uses only `run_helper health-check`; calls.log
    on the happy path has no `helper status|apply|confirm|abort` line."""
    plan = applied(router)
    verify(router, plan.sid, 0)
    banned = []
    for kind in ("status", "apply", "confirm", "abort"):
        banned.extend(router.calls_matching(f"helper {kind} "))
    assert banned == [], banned


def test_verify_never_calls_helper_status_apply_confirm_abort_refused(router):
    """Even when the verify is refused (ping fails), the helper
    `status|apply|confirm|abort` subcommands are not invoked."""
    plan = applied(router)
    router.set_fake("ping", rc=1)
    verify(router, plan.sid, 0)
    banned = []
    for kind in ("status", "apply", "confirm", "abort"):
        banned.extend(router.calls_matching(f"helper {kind} "))
    assert banned == [], banned

