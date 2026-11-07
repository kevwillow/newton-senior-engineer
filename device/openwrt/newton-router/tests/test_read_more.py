"""Additional design 3.8 read grammar and bounded-runner regressions."""

import errno
import os
import threading
import time

import pytest

from conftest import _executable
from test_read import make_read_root, rid
from test_verify import applied, lock_is_free, verify


@pytest.fixture
def rd(tmp_path):
    return make_read_root(tmp_path)


ACCEPTED = [
    # uci export/changes accept a config name, not a UCI path.
    ("read uci export network", "uci export network"),
    ("read uci changes network", "uci changes network"),
    # logread accepts each option once, in either order.
    ("read logread", "logread "),
    ("read logread -e x", "logread -e x"),
    ("read logread -l 5", "logread -l 5"),
    ("read logread -e x -l 5", "logread -e x -l 5"),
    ("read logread -l 5 -e x", "logread -l 5 -e x"),
    # The complete ubus call allowlist.
    ("read ubus call system board", "ubus call system board"),
    ("read ubus call system info", "ubus call system info"),
    ("read ubus call network.interface dump", "ubus call network.interface dump"),
    ("read ubus call network.device status", "ubus call network.device status"),
    ("read ubus call network.wireless status", "ubus call network.wireless status"),
    ("read ubus call network.interface.lan status",
     "ubus call network.interface.lan status"),
    # Narrow single-token grammars.
    ("read netstat -a", "netstat -a"),
    ("read netstat -lnup", "netstat -lnup"),
    ("read netstat -tuwxr", "netstat -tuwxr"),
    ("read nslookup x.example", "nslookup x.example"),
    ("read nslookup x.example 1.1.1.1", "nslookup x.example 1.1.1.1"),
    ("read free", "free "),
    ("read free -b", "free -b"),
    ("read free -k", "free -k"),
    ("read free -m", "free -m"),
    ("read free -g", "free -g"),
    ("read free -h", "free -h"),
]


@pytest.mark.parametrize("req,call", ACCEPTED, ids=[rid(a) for a, _ in ACCEPTED])
def test_accepted_form(rd, req, call):
    res = rd.forced(req, role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (0, "", ""), req
    assert rd.calls() == [call], req


REFUSED = [
    # uci export/changes take CFG, never a filesystem or dotted path.
    ("read uci export /etc/config/network", "error bad-arg 3"),
    ("read uci export ../x", "error bad-arg 3"),
    ("read uci changes /tmp/x", "error bad-arg 3"),
    ("read uci export network.lan", "error bad-arg 3"),
    ("read uci changes network.lan", "error bad-arg 3"),
    # logread has no follow mode and permits -e/-l at most once.
    ("read logread -f", "error arg-count"),
    ("read logread -f -e x", "error arg-count"),
    ("read logread -e x -f", "error arg-count"),
    ("read logread -F", "error arg-count"),
    ("read logread -S 10", "error bad-arg 2"),
    ("read logread -e", "error arg-count"),
    ("read logread -e x -e y", "error bad-arg 4"),
    ("read logread -l 5 -l 6", "error bad-arg 4"),
    # No ubus method outside the read-only allowlist, and no call payload.
    ("read ubus call system reboot", "error bad-arg 4"),
    ("read ubus call foo bar", "error bad-arg 3"),
    ("read ubus call network.interface dump x", "error arg-count"),
    ("read ubus call system board x", "error arg-count"),
    ("read ubus call uci get", "error bad-arg 3"),
    ("read ubus call network.interface.lan down", "error bad-arg 4"),
    ("read ubus call network.interface status", "error bad-arg 4"),
    # netstat gets one token of 1-8 letters from the explicit set.
    ("read netstat -s", "error bad-arg 2"),
    ("read netstat -e", "error bad-arg 2"),
    ("read netstat -c", "error bad-arg 2"),
    ("read netstat -1", "error bad-arg 2"),
    ("read netstat -an1", "error bad-arg 2"),
    ("read netstat -anpx -a", "error arg-count"),
    ("read netstat -aaaaaaaaa", "error bad-arg 2"),
    ("read netstat -", "error bad-arg 2"),
    # nslookup accepts only one or two non-option hosts.
    # the global request filter refuses the "=" byte before the read grammar sees the token
    ("read nslookup -type=any x", "error bad-character"),
    ("read nslookup -debug", "error bad-arg 2"),
    ("read nslookup x -type=mx", "error bad-character"),
    ("read nslookup x -y", "error bad-arg 3"),
    ("read nslookup - x", "error bad-arg 2"),
    # free accepts zero or exactly one flag from its five-flag allowlist.
    ("read free -s", "error bad-arg 2"),
    ("read free -t", "error bad-arg 2"),
    ("read free -c 3", "error arg-count"),
    ("read free -h -k", "error arg-count"),
    ("read free -b2", "error bad-arg 2"),
    ("read free --help", "error bad-arg 2"),
]


@pytest.mark.parametrize("req,err", REFUSED, ids=[rid(a) for a, _ in REFUSED])
def test_refused_form(rd, req, err):
    res = rd.forced(req, role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (2, err + "\n", ""), req
    assert rd.calls() == [], req
    if req.startswith("read logread"):
        assert not any("-f" in call for call in rd.calls()), req


@pytest.mark.parametrize("mode", ["forced", "direct"], ids=["forced", "direct"])
def test_bounded_read_child_gets_dev_null(rd, mode):
    uci = rd.root / "bin/uci"
    uci.unlink()
    _executable(
        uci,
        "#!/usr/bin/busybox sh\n"
        "data=$(cat)\n"
        "printf 'STDIN:%s\\n' \"$data\"\n",
    )

    if mode == "forced":
        res = rd.forced("read uci show", role="read", stdin=b"SECRET\n", timeout=15)
    else:
        res = rd.direct("read", "uci", "show", stdin=b"SECRET\n", timeout=15)

    assert (res.rc, res.err) == (0, "")
    assert res.out == "STDIN:\n"
    assert "SECRET" not in res.out


def test_fast_verify_watchdogs_do_not_keep_program_lock(router):
    plan = applied(router)
    for attempt in range(3):
        res = verify(router, plan.sid, 0)
        assert (res.rc, res.err, res.out) == (0, "", ""), attempt
        assert lock_is_free(router), (
            f"watchdog kept the program lock after fast verify {attempt + 1}"
        )


def test_conf_has_rejects_non_dnsmasq_c_path_but_accepts_dnsmasq_path(router):
    """Only an allowed dnsmasq config path may be opened for reading."""
    router.set_fake("pidof", out="123\n")
    forbidden = router.root / "etc/passwd"
    os.mkfifo(forbidden)
    read_seen = threading.Event()
    stop = threading.Event()

    def feed_if_opened():
        while not stop.is_set():
            try:
                fd = os.open(forbidden, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                assert exc.errno == errno.ENXIO
                time.sleep(0.005)
                continue
            read_seen.set()
            os.write(fd, b"must-not-be-read\n")
            os.close(fd)
            return

    watcher = threading.Thread(target=feed_if_opened, daemon=True)
    watcher.start()
    router.write("proc/123/cmdline", b"dnsmasq\x00-C\x00/etc/passwd\x00")

    rejected = router.forced(
        "probe",
        stdin=b"conf-has\tdnsmasq\tline\tpresent\tmust-not-be-read\n",
    )
    stop.set()
    watcher.join(timeout=1)
    assert rejected.rc == 1
    assert rejected.out.startswith("probe conf-has fail ")
    assert rejected.err == ""
    assert not read_seen.is_set(), "conf-has opened the forbidden -C path"

    allowed = "/var/etc/dnsmasq.conf.cfg01411c"
    router.write("proc/123/cmdline", f"dnsmasq\0-C\0{allowed}\0".encode())
    router.write(allowed.lstrip("/"), "allowed-line\n")
    accepted = router.forced(
        "probe",
        stdin=b"conf-has\tdnsmasq\tline\tpresent\tallowed-line\n",
    )
    assert (accepted.rc, accepted.out, accepted.err) == (
        0, "probe conf-has ok\n", "",
    )


@pytest.mark.parametrize(
    "path",
    [
        "/root/dnsmasq.conf.cfg01411c",
        "/etc/dnsmasq.conf.cfg01411c",
        "/tmp/dnsmasq.conf.cfg01411c",
        "/var/dnsmasq.conf.cfg01411c",
        "/var/etc/x/dnsmasq.conf.cfg01411c",
    ],
    ids=["root", "etc", "tmp", "var", "var-etc-subdir"],
)
def test_conf_has_ignores_a_c_path_outside_var_etc_and_tmp_etc(router, path):
    """A -C path with the right base name in the wrong directory is not read (design 4.3: the element must be
    /var/etc/dnsmasq.conf.NAME or /tmp/etc/dnsmasq.conf.NAME). The file exists, so a program that accepted the
    path would find the line and pass."""
    router.set_fake("pidof", out="123\n")
    router.write("proc/123/cmdline", f"dnsmasq\0-C\0{path}\0".encode())
    router.write(path.lstrip("/"), "secret-line\n")
    res = router.forced("probe", stdin=b"conf-has\tdnsmasq\tline\tpresent\tsecret-line\n")
    assert res.rc == 1 and res.out.startswith("probe conf-has fail "), (res.rc, res.out, res.err)
    assert res.err == ""
