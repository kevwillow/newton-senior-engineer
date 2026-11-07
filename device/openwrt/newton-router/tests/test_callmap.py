"""The helper line (RD11) and the call-mapping tests
(design 3.9, 3.10)."""

import io
import re
import shutil
import tarfile

import pytest

from conftest import REPO, SID


HELPER_PATH = REPO / "scripts/owrt-safe-apply.sh"
NONCE = "0123456789abcdef"
DIFF_TXT = b"dhcp.cfg01.domain='lan'\n"

GRAMMAR_LEVEL_CODES = frozenset({
    "empty-request", "request-too-long", "bad-character", "bad-spacing",
    "too-many-tokens", "unknown-subcommand", "arg-count", "bad-arg",
    "bad-key-line", "door-not-built", "bad-root", "role",
})


def _grammar_first(res):
    first = res.err.splitlines()[0] if res.err else ""
    m = re.match(r"error ([a-z-]+)", first)
    return m.group(1) if m else None


def assert_not_grammar_level(res):
    assert _grammar_first(res) not in GRAMMAR_LEVEL_CODES, (res.rc, res.err)


# ---- setup helpers (this file only) -------------------------------------

DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


def ready_for_arm(router):
    router.set_fake("df", out=DF_OUT)


def install_fake_dnsmasq_init(router, *, running_returns=0):
    p = router.root / "etc/init.d/dnsmasq"
    p.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "#!/bin/sh\n"
        'echo "init.d/dnsmasq $*" >> "$NEWTON_ROUTER_ROOT/control/init.calls"\n'
    )
    if running_returns == 0:
        body += "exit 0\n"
    else:
        body += 'if [ "$1" = running ]; then exit 1; fi\nexit 0\n'
    p.write_text(body)
    p.chmod(0o755)


def make_health_dir(router, sid=SID, fw4_loaded=0):
    """Create $LOCK/<sid>.health/newton-fw4-loaded so health-check reaches
    the helper step (the program only writes it through health-snapshot)."""
    h = router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.health"
    h.mkdir(parents=True, exist_ok=True)
    (h / "newton-fw4-loaded").write_text(f"{fw4_loaded}\n")


def init_calls(router):
    p = router.root / "control/init.calls"
    return p.read_text().splitlines() if p.exists() else []


def assert_in_calls(calls, expected, extra=()):
    """`expected` is a list of exact lines or `substr:...` substrings.
    `extra` is an iterable of {path -> lines} dicts also searched."""
    missing = []
    stacks = [calls]
    stacks.extend(extra)
    for want in expected:
        if want.startswith("substr:"):
            needle = want[len("substr:"):]
            if not any(needle in c for s in stacks for c in s):
                missing.append(want)
        else:
            if not any(want in c for s in stacks for c in s):
                missing.append(want)
    assert not missing, (missing, calls, [e for e in extra])


def stage_setup(router):
    router.use_stub_helper()


def staged_setup(router):
    """A staged txn so diff / named / health-snapshot pass the OWNER check."""
    router.use_stub_helper()
    router.write("control/diff.txt", DIFF_TXT)
    assert router.stage().rc == 0


def sealed_setup(router):
    staged_setup(router)
    assert router.seal(SID, 90).rc == 0, router.seal(SID, 90).err


def dnsmasq_setup(router):
    install_fake_dnsmasq_init(router)


def health_setup(router):
    staged_setup(router)
    make_health_dir(router)


# =====================================================================
# (a) RD11: the helper line
# =====================================================================


def test_helper_line():
    text = HELPER_PATH.read_text()
    lines = text.splitlines()
    assert len(lines) == 431, len(lines)
    assert lines[30] == "SESSION_TIMEOUT=2700", lines[30]
    mention = [i for i, l in enumerate(lines) if "SESSION_TIMEOUT" in l]
    assert mention == [30, 98], mention


# =====================================================================
# (b) the call map (design 3.9)
#
# Each row: (row_id, request, role, setup-fn-or-None, expected-call-shape).
# `expected-call-shape` is a list of exact lines or `substr:...` substrings
# to find in either calls.log or control/init.calls.
# Roles per SPEC_ROLE (newton-router:775-805) and grammar.tsv.
# =====================================================================


CALLMAP = [
    # ---- single rows of the 3.9 table ----
    ("#2-hostname", "hostname", "read", None,
     ["uci -q get system.@system[0].hostname"]),
    ("#3-backup", "backup", "change", None, []),
    ("#4/#11-hello", f"hello {NONCE}", "read", None, []),
    ("#5-stage", "stage", "change", stage_setup, ["helper stage"]),
    ("#6/#7-seal", f"seal {SID} 90", "change", staged_setup,
     [f"helper diff {SID}", "helper confighash"]),
    ("#8-diff", f"diff {SID}", "change", staged_setup,
     [f"helper diff {SID}"]),
    ("#12/#13-diff", f"diff {SID}", "change", staged_setup,
     [f"helper diff {SID}"]),
    ("#14-named", f"named {SID}", "change", staged_setup,
     [f"helper named {SID}"]),
    ("#14b-check-staged", f"check-staged {SID}", "change", staged_setup,
     [f"helper check-staged {SID}"]),
    ("#15-fw-loaded", "fw-loaded", "read", None,
     ["nft list table inet fw4"]),
    ("#16-logd-pid", "logd-pid", "read", None, ["pidof logd"]),
    ("#17-confighash", "confighash", "read", stage_setup,
     ["helper confighash"]),
    ("#18-health-snapshot", f"health-snapshot {SID}", "change",
     staged_setup, [f"helper health-snapshot {SID}"]),
    ("#19-apply", f"apply {SID} 90 none 0 0", "change", None, []),
    ("#20-fwrestart", "fwrestart 1", "change", stage_setup,
     ["helper fwrestart 1"]),
    ("#21-dnsmasq-repair", "dnsmasq-repair", "change", dnsmasq_setup,
     ["substr:init.d/dnsmasq running", "netstat -lnup",
      "substr:init.d/dnsmasq restart"]),
    ("#22-verify", f"verify {SID} 1", "change", None, []),
    ("#24-confirm", f"confirm {SID}", "change", None, []),
    ("#25-status", f"status {SID}", "read", None, []),
    ("#26-health-check", f"health-check {SID} after-rollback", "change",
     health_setup, [f"helper health-check {SID} after-rollback"]),
    ("#27-confighash-after-abort", "confighash", "read", stage_setup,
     ["helper confighash"]),
    ("#28-abort", f"abort {SID}", "change", None, []),
    ("#31-dnsmasq-ensure", "dnsmasq-ensure", "change", dnsmasq_setup,
     ["substr:init.d/dnsmasq running"]),
    ("#32-dns-dhcp-check", "dns-dhcp-check 1", "read", None,
     ["pidof dnsmasq", "nslookup openwrt.org 127.0.0.1", "netstat -lnup"]),
    # ---- composite rows #33 to #35 as their parts ----
    ("#33a-hello", f"hello {NONCE}", "read", None, []),
    ("#33b-status", f"status {SID}", "read", None, []),
    ("#34a-hello", f"hello {NONCE}", "read", None, []),
    ("#34b-abort", f"abort {SID}", "change", None, []),
    ("#35a-hello", f"hello {NONCE}", "read", None, []),
    ("#35b-hostname", "hostname", "read", None,
     ["uci -q get system.@system[0].hostname"]),
    ("#35c-backup", "backup", "change", None, []),
]


@pytest.mark.parametrize("case", CALLMAP, ids=lambda c: c[0])
def test_callmap(case, router):
    _row, request, role, setup, expected = case
    if setup is not None:
        setup(router)
    assert_not_grammar_level(
        router.forced(request, role=role, timeout=30)
    )
    assert_not_grammar_level(
        router.direct(*request.split(), timeout=30)
    )
    extra = [init_calls(router)] if any("init.d/dnsmasq" in e for e in expected) else []
    assert_in_calls(router.calls(), expected, extra=extra)


# ---- dedicated shape tests for the rows that need them ----


def test_callmap_backup_archive_holds_only_etc_config(router):
    res = router.direct("backup", timeout=30)
    assert (res.rc, res.err) == (0, "")
    with tarfile.open(fileobj=io.BytesIO(res.outb), mode="r:gz") as tar:
        names = tar.getnames()
    assert names
    assert all(n == "etc/config" or n.startswith("etc/config/") for n in names)


def test_callmap_hello_one_line(router):
    res = router.forced(f"hello {NONCE}", role="read", timeout=15)
    assert res.rc == 0 and res.err == ""
    lines = res.out.splitlines()
    assert len(lines) == 1 and lines[0].startswith(f"hello {NONCE} api=1 ")


def test_callmap_seal_output_has_base_and_diff(router):
    staged_setup(router)
    res = router.forced(f"seal {SID} 90", role="change", timeout=30)
    assert res.rc == 0, (res.rc, res.err)
    out_lines = res.out.splitlines()
    assert any(l.startswith("base ") for l in out_lines)
    assert any(l.startswith("diff ") for l in out_lines)


def test_callmap_fw_loaded_stdout_is_0_or_1(router):
    res = router.forced("fw-loaded", role="read", timeout=15)
    assert res.rc == 0
    assert res.out in ("0\n", "1\n")


def test_callmap_dnsmasq_repair_calls_init_and_netstat(router):
    dnsmasq_setup(router)
    res = router.forced("dnsmasq-repair", role="change", timeout=30)
    assert_not_grammar_level(res)
    assert res.out.startswith("restarted rc=")
    assert "netstat -lnup" in router.calls()
    log = init_calls(router)
    assert log[0] == "init.d/dnsmasq running"
    assert "init.d/dnsmasq restart" in log


def test_callmap_dnsmasq_ensure_running_only_when_running(router):
    dnsmasq_setup(router)
    res = router.forced("dnsmasq-ensure", role="change", timeout=30)
    assert_not_grammar_level(res)
    assert res.out == "running\n"
    assert init_calls(router) == ["init.d/dnsmasq running"]


def test_callmap_dnsmasq_ensure_restart_when_not_running(router):
    install_fake_dnsmasq_init(router, running_returns=1)
    res = router.forced("dnsmasq-ensure", role="change", timeout=30)
    assert_not_grammar_level(res)
    assert res.out.startswith("started rc=")
    log = init_calls(router)
    assert "init.d/dnsmasq running" in log
    assert "init.d/dnsmasq restart" in log


def test_callmap_dns_dhcp_check_one_runs_pidof_nslookup_netstat(router):
    router.set_fake("pidof", out="411\n")
    router.set_fake(
        "netstat",
        out=("Active Internet connections (servers and established)\n"
             "Proto Recv-Q Send-Q Local Address           Foreign Address         "
             "State       PID/Program name\n"
             "udp        0      0 0.0.0.0:67              0.0.0.0:*"
             "                           411/dnsmasq\n"),
    )
    res = router.forced("dns-dhcp-check 1", role="read", timeout=30)
    assert res.rc == 0, (res.rc, res.err)
    calls = router.calls()
    assert "pidof dnsmasq" in calls
    assert "nslookup openwrt.org 127.0.0.1" in calls
    assert "netstat -lnup" in calls


def test_callmap_apply_only_calls_helper_diff_and_confighash(router):
    """#19 apply: the helper calls during the apply ITSELF are only diff SID
    and confighash; helper apply never runs (3.10 item 4)."""
    sealed_setup(router)
    ready_for_arm(router)
    make_health_dir(router)
    before = set(router.calls_matching("helper "))
    res = router.apply(SID, 90, "none", 0, 0)
    assert res.rc == 0, (res.rc, res.err)
    new = set(router.calls_matching("helper ")) - before
    kinds = {c.split(" ", 2)[1] for c in new}
    assert kinds <= {"diff", "confighash"}, kinds
    assert "apply" not in kinds


# =====================================================================
# (b)(3) dropped calls of 3.10
# =====================================================================


@pytest.mark.parametrize(
    "req,expected_codes",
    [
        ("sh -n", ("unknown-subcommand",)),
        ("sh -n -c x", ("unknown-subcommand",)),
        ("cat", ("unknown-subcommand", "bad-character")),
        ("cat /tmp/x", ("unknown-subcommand", "bad-character")),
        ("sysupgrade -b", ("unknown-subcommand",)),
    ],
    ids=["sh-n", "sh-n-c", "cat", "cat-arg", "sysupgrade-b"],
)
def test_dropped_calls_have_no_request_form(router, req, expected_codes):
    """3.10: #1 / #9 / #10 (sh -n), #4 / #11 (helper push / cat), and #3
    (sysupgrade -b) have no request form; the grammar refuses with exit 2,
    the refused code is one of the listed, and nothing is called."""
    res = router.forced(req, role="change", timeout=15)
    assert res.rc == 2, (req, res.rc, res.err)
    assert res.out == ""
    assert _grammar_first(res) in expected_codes, (req, _grammar_first(res))
    assert router.calls() == [], (req, router.calls())


# =====================================================================
# (b)(4) the program never calls helper status|apply|confirm|abort
# =====================================================================


def _run_full_flow(router, after_setup=None):
    """Run the design flow of 3.9 / 3.10 item 4. If `after_setup` is given,
    it is called right after the test-fixture setup (so file-stability can
    snapshot)."""
    router.use_stub_helper()
    router.write("control/diff.txt", DIFF_TXT)
    if after_setup is not None:
        after_setup(router)
    router.stage()
    router.seal(SID, 90)
    router.forced(f"diff {SID}", role="change", timeout=30)
    router.forced(f"named {SID}", role="change", timeout=30)
    router.forced("fw-loaded", role="read", timeout=30)
    router.forced("logd-pid", role="read", timeout=30)
    router.forced("confighash", role="read", timeout=30)
    router.forced(f"health-snapshot {SID}", role="change", timeout=30)
    router.forced(f"hello {NONCE}", role="read", timeout=30)
    router.forced("hostname", role="read", timeout=30)
    ready_for_arm(router)
    make_health_dir(router)
    router.apply(SID, 90, "none", 0, 0)
    router.forced(f"confirm {SID}", role="change", timeout=30)
    router.forced(f"status {SID}", role="read", timeout=30)
    router.forced(f"abort {SID}", role="change", timeout=30)
    router.forced(f"health-check {SID} after-rollback",
                  role="change", timeout=30)
    router.forced(f"verify {SID} 1", role="change", timeout=30)
    return router


def test_never_helper_status_apply_confirm_abort():
    """3.10 item 4: after the full flow, calls.log has no `helper status`,
    `helper apply`, `helper confirm`, or `helper abort` line."""
    from conftest import Router

    root = HELPER_PATH.parent / "_callmap_full_flow"
    if root.exists():
        shutil.rmtree(root)
    router = Router(root)
    try:
        _run_full_flow(router)
        calls = router.calls()
        for banned in ("status", "apply", "confirm", "abort"):
            offenders = [c for c in calls if c.startswith(f"helper {banned}")]
            assert not offenders, (banned, offenders)
    finally:
        shutil.rmtree(root, ignore_errors=True)


# =====================================================================
# (b)(5) the 3.7 exit-code table
# =====================================================================


def test_exit_code_class_0_ok(router):
    router.set_fake("uci", out="newton-test\n")
    res = router.forced("hostname", role="read", timeout=15)
    assert (res.rc, res.out, res.err) == (0, "newton-test\n", "")


def test_exit_code_class_1_failed(router):
    """tar exits 4: the program does not exit 0 or 2 or 3; tar's code
    (class 1 in 3.7) is the one that surfaces."""
    tar = router.root / "bin/tar"
    tar.unlink()
    tar.write_text("#!/usr/bin/busybox sh\nexit 4\n")
    tar.chmod(0o755)
    res = router.direct("backup", timeout=15)
    assert res.rc == 4
    assert res.rc not in (0, 2, 3)
    assert res.out == ""


def test_exit_code_class_2_grammar(router):
    res = router.forced("frobnicate", role="change", timeout=15)
    assert (res.rc, res.err, res.out) == (
        2, "error unknown-subcommand\n", ""
    )


def test_exit_code_class_3_refused(router):
    res = router.forced("stage", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (3, "error role\n", "")


def test_exit_code_never_255_anywhere_in_callmap():
    """No test above exits 255. Sweep every (rc, request) pair that the
    parametrized table can produce (each on a fresh Router to avoid state
    contamination across rows)."""
    from conftest import Router

    for row in CALLMAP:
        _row, request, role, setup, _expected = row
        root = HELPER_PATH.parent / f"_callmap_255_{row[0].replace('/', '_').replace('#', 'r')}"
        if root.exists():
            shutil.rmtree(root)
        router = Router(root)
        try:
            if setup is not None:
                setup(router)
            fr = router.forced(request, role=role, timeout=30)
            assert fr.rc != 255, (row, fr.rc, fr.err)
            dr = router.direct(*request.split(), timeout=30)
            assert dr.rc != 255, (row, dr.rc, dr.err)
        finally:
            shutil.rmtree(root, ignore_errors=True)


# =====================================================================
# (b)(6) the read-only files of 2.1
# =====================================================================


READONLY_PATHS = (
    "etc/newton/device-id",
    "etc/newton/profile",
    "etc/newton/zones",
    "etc/newton/approve.key",
    "usr/libexec/newton/newton-router",
    "usr/libexec/newton/newton-safe-apply",
    "usr/libexec/newton-guard",
    "etc/init.d/newton-guard",
)


def _snapshot(router):
    zones = router.root / "etc/newton/zones"
    if not zones.exists():
        zones.write_text(
            "mgmt-interface lan\nmgmt-zone lan\nwan-zone wan\n"
        )
    return {rel: ((router.root / rel).read_bytes(),
                  (router.root / rel).stat().st_mtime)
            for rel in READONLY_PATHS}


def test_files_of_2_1_are_byte_and_mtime_stable_after_full_flow():
    """Run the full flow and assert every read-only file of design 2.1 is
    byte- and mtime-identical to its state after test-fixture setup. The
    snapshot is taken AFTER any test-fixture setup (the program itself
    does not write to these files)."""
    from conftest import Router

    root = HELPER_PATH.parent / "_callmap_file_stability"
    if root.exists():
        shutil.rmtree(root)
    router = Router(root)
    try:
        before = {}
        _run_full_flow(router, after_setup=lambda r: before.update(_snapshot(r)))
        after = _snapshot(router)
        for rel in READONLY_PATHS:
            assert after[rel][0] == before[rel][0], (rel, "bytes differ")
            assert after[rel][1] == before[rel][1], (rel, "mtime differs")
    finally:
        shutil.rmtree(root, ignore_errors=True)