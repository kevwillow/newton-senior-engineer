"""Design 9.2 group 10 and 3.5e/4.4 in part: the read subcommand.

The verdict corpus (ACCEPTED, REFUSED, IP_ACCEPTED, IP_REFUSED) lives in
read_cases.json next to this file: the same vectors are run against the
real program here (and in test_read_vectors.py) and against the MCP's
validate_read in mcp/tests/test_read_vectors.py, so the two cannot drift.
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import REPO

slow = pytest.mark.slow  # the 25 s bound test only; never skipped

CASES = json.loads((Path(__file__).parent / "read_cases.json").read_text())

# commands whose executed form differs from the request: the program adds
# fixed flags (ping/traceroute) or emits ip options/selectors in a fixed
# order; the no-argument verbs appear with a trailing space in the fake
# tool log ("$name $*").
NORMALIZED = {
    "ping -c 3 8.8.8.8": "ping -c 3 -W 2 8.8.8.8",
    "ping -c 1 1.1.1.1": "ping -c 1 -W 2 1.1.1.1",
    "traceroute 1.1.1.1": "traceroute -m 10 -q 1 -w 2 1.1.1.1",
    "iwinfo": "iwinfo ",
    "netstat": "netstat ",
    "df": "df ",
    "free": "free ",
    "uptime": "uptime ",
    "uname": "uname ",
    "logread": "logread ",
    "ip route list table all dev eth0": "ip route list dev eth0 table all",
    "ip -d -s link show dev eth0": "ip -s -d link show dev eth0",
    # boundary forms of the same two rows (3.8: fixed flags are added)
    "ping -c 5 " + "h" * 253: "ping -c 5 -W 2 " + "h" * 253,
    "traceroute " + "h" * 253: "traceroute -m 10 -q 1 -w 2 " + "h" * 253,
}

# commands whose exact refusal line was pinned by the original corpus
ERR_EXACT = {
    "uci get a b": "error arg-count",
    "uci -q get x": "error arg-count",
    "uci show -q": "error bad-arg 3",
    "uci show network.lan.proto.extra": "error bad-arg 3",
    "uci commit": "error bad-arg 2",
    "uci set x.y=1": "error bad-character",
    "cat /etc/config/../shadow": "error bad-arg 2",
    "cat /etc/shadow": "error bad-arg 2",
    "cat /etc/config/evil": "error bad-arg 2",
    "cat /etc/config/": "error bad-arg 2",
    "nft list ruleset -j": "error arg-count",
    "nft -j list ruleset": "error bad-arg 2",
    "nft add table x": "error bad-arg 2",
    "logread -f": "error arg-count",
    "logread -e": "error arg-count",
    "logread -e a -e b": "error bad-arg 4",
    "iwinfo wlan0 scan": "error bad-arg 3",
    "apk add x": "error bad-arg 2",
    "apk list -x": "error bad-arg 3",
    "ubus call system reboot": "error bad-arg 4",
    "ubus call network.interface.lan up": "error bad-arg 4",
    "ping -c 6 1.1.1.1": "error bad-arg 3",
    "ping -c 0 1.1.1.1": "error bad-arg 3",
    "ping 1.1.1.1": "error arg-count",
    "ping -c 1 -f 1.1.1.1": "error arg-count",
    "traceroute -m 99 x": "error arg-count",
    "netstat -x1": "error bad-arg 2",
    "df -z": "error bad-arg 2",
    "uname -z": "error bad-arg 2",
    "free -x": "error bad-arg 2",
    "wifi up": "error bad-arg 2",
    "frobnicate": "error bad-arg 1",
    "ifstatus -x": "error bad-arg 2",
}


def make_read_root(tmp_path):
    """A fake root plus the files the cat verbs need (conftest builds the rest)."""
    router = tmp_path / "router"
    from conftest import Router

    r = Router(router)
    r.write("etc/openwrt_release", b"DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10'\n")
    r.write("tmp/dhcp.leases", b"1760000000 02:00:00:00:00:77 192.168.1.99 host 01:02\n")
    r.write("proc/loadavg", b"0.10 0.20 0.30 1/80 1234\n")
    r.write("proc/meminfo", b"MemTotal:        1000 kB\n")
    r.write("etc/shadow", b"root:$1$secret:19000:0:99999:7:::\n")
    (router / "etc/config/evil").symlink_to("../shadow")
    return r


@pytest.fixture
def rd(tmp_path):
    return make_read_root(tmp_path)


ACCEPTED = [
    (c, NORMALIZED.get(c, c))
    for c in CASES["accepted"]
    if not c.startswith(("ip ", "cat "))
]

# cat rows: the req, the file under the fake root, its expected stdout
CAT_CASES = [
    ("read cat /etc/openwrt_release", "etc/openwrt_release",
     b"DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10'\n"),
    ("read cat /tmp/dhcp.leases", "tmp/dhcp.leases",
     b"1760000000 02:00:00:00:00:77 192.168.1.99 host 01:02\n"),
    ("read cat /proc/uptime", "proc/uptime", b"100.00 90.00\n"),
    ("read cat /proc/loadavg", "proc/loadavg", b"0.10 0.20 0.30 1/80 1234\n"),
    ("read cat /proc/meminfo", "proc/meminfo", b"MemTotal:        1000 kB\n"),
    ("read cat /etc/config/network", "etc/config/network",
     b"config interface 'lan'\n\toption proto 'static'\n"),
]


def rid(req):
    return req.replace("read ", "", 1).replace(" ", "-")


@pytest.mark.parametrize("req,call", ACCEPTED, ids=[rid(a) for a, _ in ACCEPTED])
def test_accepted_form(rd, req, call):
    res = rd.forced("read " + req, role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (0, "", ""), req
    assert rd.calls() == [call], req


@pytest.mark.parametrize(
    "req,rel,content", CAT_CASES, ids=[rid(a) for a, _, _ in CAT_CASES]
)
def test_accepted_cat(rd, req, rel, content):
    res = rd.forced(req, role="read", timeout=15)
    assert (res.rc, res.err) == (0, ""), req
    assert res.outb == content, req
    assert rd.calls() == [], req


# ---- direct mode agrees with forced mode on a sample -------------------------


DIRECT_SAMPLE = [
    "read uci show",
    "read ping -c 2 1.1.1.1",
    "read ip route show table all",
    "read logread -e dnsmasq",
    "read cat /etc/openwrt_release",
    "read uci get a b",
    "read ping 1.1.1.1",
]


@pytest.mark.parametrize("req", DIRECT_SAMPLE, ids=map(rid, DIRECT_SAMPLE))
def test_direct_mode_same_verdict(rd, req):
    via_forced = rd.forced(req, role="read", timeout=15)
    forced_calls = rd.calls()
    via_direct = rd.direct(*req.split(), timeout=15)
    assert via_direct.rc == via_forced.rc, req
    assert via_direct.out == via_forced.out, req
    assert rd.calls() == forced_calls + forced_calls, req


# ---- refusals (3.8: a form not listed is refused) ----------------------------

ERR_RE = re.compile(r"^error (bad-arg \d+|arg-count|too-many-tokens|bad-character)$")


def refused(rd, req, err=None):
    res = rd.forced(req, role="read", timeout=15)
    assert res.rc == 2, (req, res.rc, res.err)
    assert res.out == "", req
    assert ERR_RE.match(res.err.rstrip("\n")), (req, res.err)
    if err is not None:
        assert res.err.rstrip("\n") == err, (req, res.err)
    assert rd.calls() == [], req


REFUSED = [
    (c, ERR_EXACT.get(c))
    for c in CASES["refused"]
    if not c.startswith("ip ")
]
# program-only rules that are not grammar vectors (the router's own
# filesystem check; validate_read on the host cannot see the symlink)
EXTRA_REFUSED = [
    ("cat /etc/config/evil", "error bad-arg 2"),
]
REFUSED += EXTRA_REFUSED


@pytest.mark.parametrize(
    "req,err", REFUSED, ids=[rid(a) for a, _ in REFUSED]
)
def test_refused_form(rd, req, err):
    refused(rd, "read " + req, err)


def test_read_with_16_arguments_refused(rd):
    req = "read " + " ".join(["uci", "show"] + ["x"] * 14)
    assert len(req.split()) == 17
    refused(rd, req, "error too-many-tokens")


# ---- the ip grammar (fix-read-ip/spec.md, design 3.8 row ip) -----------------
# the program normalises: -4/-6, then -s, then -d, then OBJECT [ACTION]
# [dev IFACE] [table T], whatever order the req used.

IP_ACCEPTED = [(c, NORMALIZED.get(c, c)) for c in CASES["accepted"] if c.startswith("ip ")]
IP_REFUSED = [c for c in CASES["refused"] if c.startswith("ip ")]


@pytest.mark.parametrize(
    "req,call", IP_ACCEPTED, ids=[rid(a) for a, _ in IP_ACCEPTED]
)
def test_ip_accepted(rd, req, call):
    res = rd.forced("read " + req, role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (0, "", ""), req
    assert rd.calls() == [call], req


@pytest.mark.parametrize("req", IP_REFUSED, ids=map(rid, IP_REFUSED))
def test_ip_refused(rd, req):
    refused(rd, "read " + req)


def test_ip_validate_read_agrees_on_the_corpus(rd):
    """The router program and the MCP's validate_read accept the same ip forms."""
    sys.path.insert(0, str(REPO / "mcp"))
    from newton_mcp.server import NewtonError, validate_read

    accepted_commands = [a for a, _ in IP_ACCEPTED]
    for command in accepted_commands + IP_REFUSED:
        try:
            validate_read(command)
            mcp_ok = True
        except NewtonError:
            mcp_ok = False
        res = rd.forced("read " + command, role="read", timeout=15)
        program_ok = res.rc == 0 and any(
            c == "ip" or c.startswith("ip ") for c in rd.calls()
        )
        assert program_ok == mcp_ok, (command, res.rc, res.err)
        log = rd.root / "control/calls.log"
        if log.exists():
            log.write_text("")


# ---- exit codes, passthrough, volume (3.5e, M18) -----------------------------


def test_child_exit_code_passes_through(rd):
    rd.set_fake("uci", rc=7)
    res = rd.forced("read uci show", role="read", timeout=15)
    assert res.rc == 7
    assert rd.calls(exclude=()) == [
        "uci show",
        "logger -t newton-router -p daemon.info "
        "caller=agent-one door=ssh cmd=read sid=- rc=7 from=-",
    ]


def test_child_exit_255_becomes_125(rd):
    rd.set_fake("uci", rc=255)
    res = rd.forced("read uci show", role="read", timeout=15)
    assert res.rc == 125
    assert rd.calls() == ["uci show"]


def test_child_stdout_and_stderr_pass_through_unmixed(rd):
    rd.set_fake("nft", out="nft-out-line\n", err="nft-err-line\n")
    res = rd.forced("read nft list ruleset", role="read", timeout=15)
    assert (res.rc, res.out, res.err) == (0, "nft-out-line\n", "nft-err-line\n")


def test_child_big_output_arrives_complete(rd):
    blob = "a" * (1024 * 1024)
    rd.set_fake("logread", out=blob + "\n")
    res = rd.forced("read logread", role="read", timeout=25)
    assert res.rc == 0
    assert res.outb == blob.encode() + b"\n"


# ---- the bound and the program lock (4.4, M17, M18, M46) ---------------------


def lock_is_free(rd):
    lock = rd.root / "tmp/newton/flock"
    res = subprocess.run(
        ["/usr/bin/flock", "-n", str(lock), "/bin/true"],
        capture_output=True, timeout=5,
    )
    return res.returncode == 0


@slow  # runs about 26 s: the 25 s read bound plus the 1 s KILL grace
def test_hung_child_times_out_and_leaves_the_lock_free(rd):
    ping = rd.root / "bin/ping"
    ping.unlink()
    ping.write_text("#!/usr/bin/busybox sh\nexec /usr/bin/sleep 60\n")
    ping.chmod(0o755)
    start = time.monotonic()
    res = rd.forced("read ping -c 1 192.0.2.1", role="read", timeout=45)
    elapsed = time.monotonic() - start
    assert res.rc == 124, (res.rc, res.err)
    assert res.err == "error read-timeout\n"
    assert "Terminated" not in res.err
    assert res.out == ""
    assert 20 <= elapsed <= 40, elapsed
    assert lock_is_free(rd), "a leftover sleep holds the program lock"


def test_lock_free_after_a_normal_read(rd):
    res = rd.forced("read uci show", role="read", timeout=15)
    assert res.rc == 0
    assert lock_is_free(rd)


# ---- stdin (3.6: read never reads it) ----------------------------------------


def test_read_never_reads_stdin(rd):
    res = rd.direct_open_stdin("read", "uci", "show", timeout=10)
    assert (res.rc, res.out) == (0, "")
    assert rd.calls() == ["uci show"]


# ---- tool-missing: read_run must not leak the shell's "line N: not found" ----


# Each row: (read request, the fake-binary name to remove from $R/bin).
# The tool's real-world binary is not present on a router that does not ship
# the corresponding package; in the test the conftest symlink at $R/bin/<name>
# is removed so the same check fires. The fixed stderr line is required.
TOOL_MISSING = [
    ("read iwinfo", "iwinfo"),
    ("read wifi status", "wifi"),
    ("read apk list", "apk"),
    ("read nft list ruleset", "nft"),
    ("read fw4 check", "fw4"),
    ("read traceroute 1.1.1.1", "traceroute"),
]


@pytest.mark.parametrize("req,name", TOOL_MISSING, ids=lambda v: v if isinstance(v, str) else v[0])
def test_read_run_reports_tool_missing_with_clean_message(rd, req, name):
    target = rd.root / "bin" / name
    assert target.exists() or target.is_symlink(), (req, name)
    target.unlink()
    res = rd.forced(req, role="read", timeout=15)
    assert res.rc == 127, (req, res.rc, res.err)
    assert res.out == "", (req, res.out)
    assert res.err == f"error tool-missing {name}\n", (req, res.err)
    # the bare name only; no script path or line number
    assert "/" not in res.err, (req, res.err)
    assert "line" not in res.err, (req, res.err)
    # the tool's fake was never invoked
    assert rd.calls() == [], (req, rd.calls())


def test_read_run_lets_a_present_tool_through(rd):
    """The check must not regress the existing tools: uci, cat, ping all
    still flow through run_bounded as before."""
    log = rd.root / "control/calls.log"
    log.write_text("")

    res = rd.forced("read uci show", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (0, "", ""), res
    assert rd.calls() == ["uci show"], rd.calls()

    res = rd.forced("read cat /etc/openwrt_release", role="read", timeout=15)
    assert (res.rc, res.err) == (0, ""), res
    assert res.outb == b"DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10'\n", res.out

    res = rd.forced("read ping -c 1 1.1.1.1", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (0, "", ""), res
    assert rd.calls() == [
        "uci show",
        "ping -c 1 -W 2 1.1.1.1",
    ], rd.calls()


def test_read_run_reports_tool_missing_when_fake_exists_but_is_not_executable(rd):
    """A binary that exists but cannot be executed (no +x) is also missing."""
    name = "iwinfo"
    target = rd.root / "bin" / name
    target.unlink()
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o644)
    res = rd.forced("read iwinfo", role="read", timeout=15)
    assert res.rc == 127, (res.rc, res.err)
    assert res.err == f"error tool-missing {name}\n", res.err
    assert res.out == "", res.out
    assert rd.calls() == [], rd.calls()


# ---- role (3.5e: the read verbs are open to every credential) -----------------


ROLE_SAMPLE = ["read uci show", "read ping -c 1 1.1.1.1", "read ip rule list",
               "read cat /etc/openwrt_release"]


@pytest.mark.parametrize("req", ROLE_SAMPLE, ids=map(rid, ROLE_SAMPLE))
def test_change_role_and_direct_may_read(rd, req):
    res = rd.forced(req, role="change", timeout=15)
    assert res.rc == 0, (req, res.err)
    assert rd.calls() != [] or res.out != "", req
    rd.root.joinpath("control/calls.log").write_text("")
    res = rd.direct(*req.split(), timeout=15)
    assert res.rc == 0, (req, res.err)
    assert rd.calls() != [] or res.out != "", req
