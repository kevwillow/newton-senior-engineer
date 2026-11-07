"""The `read wifiscan radioN` verb (router program 1.2.0).

The verb runs one Wi-Fi scan with the router's own radio and prints the raw
ubus JSON. The contract this file pins:

  * the form is `read wifiscan radioN` with N one or two digits and exactly
    two words after `read`;
  * the radio name is resolved to a phy with `ubus call iwinfo phyname`
    and only a `phy[0-9]{1,2}` reply is accepted (anything else, and the
    ubus "not found" codes, are `no-radio`);
  * the phyname call runs BEFORE the program lock is taken: the lock is
    never held across a ubus call, so a hung rpcd cannot block the other
    verbs;
  * the program lock covers the rate-limit check and the stamp write, and
    the uptime the stamp holds is read INSIDE the lock, so a long lock
    wait cannot make the stamp stale;
  * the scan payload is one argv word, `{"device":"phyN"}`;
  * the output is the raw ubus JSON, unmodified; over 131072 bytes it is
    `scan-too-large` with nothing on stdout;
  * one scan per RADIO per 60 s (the stamp is keyed by the radio name, so
    two radio names cannot share a window); the stamp is written before the
    scan, so a failed scan counts;
  * a malformed /proc/uptime refuses the scan (it never falls back to 0);
  * the stamp is created under the program's lock, so two parallel callers
    cannot both reach ubus.

The fake ubus records every call's argv (control/ubus.argv.json) and
answers the two iwinfo methods (see tests/fakes/ubus).
"""

import fcntl
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from conftest import BUSYBOX, PROGRAM

slow = pytest.mark.slow  # the 25 s bound test only; never skipped

SCAN_JSON = '{"device":"phy1"}'


# ---- helpers ---------------------------------------------------------------


def ubus_argv(router):
    """Every ubus call's argv, in order (the fake's own record)."""
    path = router.root / "control/ubus.argv.json"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def ubus_calls(router):
    """The ubus calls in the tool log."""
    return [line for line in router.calls(exclude=()) if line.startswith("ubus ")]


def scan_calls(router):
    """The argv of every `ubus call iwinfo scan`."""
    return [a for a in ubus_argv(router) if a[1:3] == ["iwinfo", "scan"]]


def phyname_calls(router):
    """The argv of every `ubus call iwinfo phyname`."""
    return [a for a in ubus_argv(router) if a[1:3] == ["iwinfo", "phyname"]]


def clear_calls(router):
    """Forget the calls so far (the log and the argv record)."""
    (router.root / "control/calls.log").write_text("")
    argv = router.root / "control/ubus.argv.json"
    if argv.exists():
        argv.write_text("")


def one_radio(router, radio="radio0", phy="phy1"):
    """The fake answers this radio with this phy."""
    router.write("control/iwinfo.phyname.map", f"{radio} {phy}\n")


def scan_output(router, text='{"results":[]}'):
    router.write("control/ubus.out", text)


def wifiscan(router, radio="radio0", timeout=20):
    return router.forced(f"read wifiscan {radio}", role="read", timeout=timeout)


def start_wifiscan(router, radio="radio0"):
    """Start a `read wifiscan radioN` call in the background."""
    env = router._merged_env({"SSH_ORIGINAL_COMMAND": f"read wifiscan {radio}"})
    return subprocess.Popen(
        [BUSYBOX, "sh", str(router.program),
         "--caller=agent-one", "--role=read"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True,
    )


def wait_for_phyname(router, proc, timeout=30):
    """Wait until the phyname call is on the wire (or the call is over)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if phyname_calls(router):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.05)
    return False


def take_program_lock(router):
    """Take the router program's lock (the flock on tmp/newton/flock)."""
    newton = router.root / "tmp/newton"
    newton.mkdir(parents=True, exist_ok=True)
    newton.chmod(0o700)
    handle = os.open(newton / "flock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


# ---- the form --------------------------------------------------------------


@pytest.mark.parametrize("radio", ["radio0", "radio12"])
def test_accepts_a_radio_name(router, radio):
    one_radio(router, radio)
    scan_output(router)
    res = wifiscan(router, radio)
    assert (res.rc, res.err) == (0, ""), (res.rc, res.err)
    assert res.out == '{"results":[]}\n'


def test_direct_mode_agrees_with_forced_mode(router):
    one_radio(router, "radio0", "phy1")
    router.write("control/iwinfo.phyname.map", "radio0 phy1\nradio1 phy1\n")
    scan_output(router)
    forced = wifiscan(router, "radio0")
    assert forced.rc == 0, (forced.rc, forced.err)
    clear_calls(router)
    # the other radio: the window of radio0 is still open
    direct = router.direct("read", "wifiscan", "radio1", timeout=20)
    assert (direct.rc, direct.err, direct.out) == (forced.rc, "", forced.out)
    assert len(scan_calls(router)) == 1


# every refused form: the token, the expected stderr line
REFUSED = [
    ("radio", "error bad-arg 2"),
    ("radio123", "error bad-arg 2"),
    ("radio1x", "error bad-arg 2"),
    ("Radio1", "error bad-arg 2"),
    ("phy0", "error bad-arg 2"),
    ("wlan0", "error bad-arg 2"),
    ("-radio0", "error bad-arg 2"),
    ("radio" + "0" * 59, "error bad-arg 2"),
    ("radio1 extra", "error arg-count"),
    ("", "error arg-count"),
    ("radio0;id", "error bad-character"),
    ("radio0\nradio1", "error bad-character"),
    ("radio0\tradio1", "error bad-character"),
]


@pytest.mark.parametrize(
    "token,err",
    REFUSED,
    ids=[t.replace("\n", "\\n").replace("\t", "\\t") or "no-arg" for t, _ in REFUSED],
)
def test_refuses_every_other_form(router, token, err):
    one_radio(router)
    scan_output(router)
    request = "read wifiscan" + (" " + token if token else "")
    res = router.forced(request, role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (2, err + "\n", ""), (res.rc, res.err)
    assert ubus_calls(router) == [], ubus_calls(router)


# ---- the payload -----------------------------------------------------------


def test_the_scan_payload_is_one_argv_word(router):
    one_radio(router, "radio0", "phy1")
    scan_output(router)
    res = wifiscan(router)
    assert res.rc == 0, (res.rc, res.err)
    scans = scan_calls(router)
    assert len(scans) == 1, scans
    assert scans[0] == ["call", "iwinfo", "scan", SCAN_JSON], scans[0]
    assert len(scans[0]) == 4, scans[0]


def test_the_phyname_payload_is_one_argv_word(router):
    one_radio(router, "radio0", "phy1")
    scan_output(router)
    res = wifiscan(router)
    assert res.rc == 0, (res.rc, res.err)
    names = phyname_calls(router)
    assert len(names) == 1, names
    assert names[0] == ["call", "iwinfo", "phyname", '{"section":"radio0"}'], names[0]


# ---- the radio -> phy resolution -------------------------------------------


@pytest.mark.parametrize(
    "reply",
    ["phy1;x", "", "phy", "phy123", "phy1 extra", "phy-1", "wlan0",
     "phy1",  # a bare name is not what ubus prints
     '{"phyname": "phy1;x"}', '{"phyname": "phy123"}', '{"phyname": "phy1", "x": 1}'],
    ids=["junk", "empty", "no-digits", "three-digits", "two-words", "dash", "wlan",
         "bare", "json-junk", "json-three-digits", "json-extra-key"],
)
def test_a_junk_phyname_reply_is_no_radio(router, reply):
    router.write("control/iwinfo.phyname.out", reply)
    scan_output(router)
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (2, "error no-radio\n", ""), (res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


@pytest.mark.parametrize("rc", ["252", "4"], ids=["not-found", "object-missing"])
def test_a_missing_radio_is_no_radio(router, rc):
    router.write("control/iwinfo.phyname.rc", rc + "\n")
    scan_output(router)
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (2, "error no-radio\n", ""), (res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


def test_a_radio_outside_the_map_is_no_radio(router):
    """The map is the router's own radio list: a radio that is not in it
    does not exist (ubus answers rc 252)."""
    one_radio(router, "radio0", "phy1")
    scan_output(router)
    res = wifiscan(router, "radio1")
    assert (res.rc, res.err, res.out) == (2, "error no-radio\n", ""), (res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


# ---- the rate limit --------------------------------------------------------


def test_a_second_scan_inside_the_window_is_refused(router):
    one_radio(router)
    scan_output(router)
    router.set_uptime(100)
    res = wifiscan(router)
    assert res.rc == 0, (res.rc, res.err)
    clear_calls(router)
    router.set_uptime(159)  # +59 s
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (2, "error scan-rate-limited\n", ""), (
        res.rc, res.err)
    assert scan_calls(router) == [], "the refused scan scanned anyway"


def test_a_scan_after_the_window_is_allowed(router):
    one_radio(router)
    scan_output(router)
    router.set_uptime(100)
    assert wifiscan(router).rc == 0
    clear_calls(router)
    router.set_uptime(161)  # +61 s
    res = wifiscan(router)
    assert (res.rc, res.err) == (0, ""), (res.rc, res.err)
    assert len(scan_calls(router)) == 1


def test_the_radios_are_limited_independently(router):
    router.write("control/iwinfo.phyname.map", "radio0 phy0\nradio1 phy1\n")
    scan_output(router)
    router.set_uptime(100)
    assert wifiscan(router, "radio0").rc == 0
    assert wifiscan(router, "radio1").rc == 0
    clear_calls(router)
    res = wifiscan(router, "radio0")
    assert (res.rc, res.err) == (2, "error scan-rate-limited\n"), (res.rc, res.err)
    res = wifiscan(router, "radio1")
    assert (res.rc, res.err) == (2, "error scan-rate-limited\n"), (res.rc, res.err)


def test_two_radios_on_one_phy_are_limited_separately(router):
    """The window is keyed by the RADIO name, not by the phy: radio0 and
    radio1 that share a phy have their own stamps."""
    router.write("control/iwinfo.phyname.map", "radio0 phy1\nradio1 phy1\n")
    scan_output(router)
    router.set_uptime(100)
    assert wifiscan(router, "radio0").rc == 0
    assert wifiscan(router, "radio1").rc == 0
    clear_calls(router)
    assert wifiscan(router, "radio0").rc == 2
    assert wifiscan(router, "radio1").rc == 2
    assert scan_calls(router) == [], scan_calls(router)
    # the two stamps are two files, one per radio
    assert (router.root / "tmp/newton/ws.radio0").exists()
    assert (router.root / "tmp/newton/ws.radio1").exists()


def test_the_stamp_survives_a_failed_scan(router):
    one_radio(router)
    router.write("control/iwinfo.scan.rc", "1\n")
    router.set_uptime(100)
    res = wifiscan(router)
    assert res.rc == 1, (res.rc, res.err)
    stamp = router.root / "tmp/newton/ws.radio0"
    assert stamp.exists(), "the failed scan left no stamp"
    assert stamp.read_text() == "100\n", stamp.read_text()
    # the failed scan counts: the next one inside the window is refused
    router.write("control/iwinfo.scan.rc", "0\n")
    clear_calls(router)
    res = wifiscan(router)
    assert (res.rc, res.err) == (2, "error scan-rate-limited\n"), (res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


def test_a_garbage_stamp_refuses_the_scan(router):
    one_radio(router)
    scan_output(router)
    router.write("tmp/newton/ws.radio0", "not-a-number\n")
    clear_calls(router)
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (2, "error scan-rate-limited\n", ""), (
        res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


def test_an_unreadable_stamp_refuses_the_scan(router):
    if os.getuid() == 0:
        pytest.skip("running as real root: the file is still readable")
    one_radio(router)
    scan_output(router)
    router.write("tmp/newton/ws.radio0", "100\n")
    (router.root / "tmp/newton/ws.radio0").chmod(0o000)
    clear_calls(router)
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (2, "error scan-rate-limited\n", ""), (
        res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


# ---- the uptime seam -------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    ["", "garbage\n", "\n", "abc 12.00\n"],
    ids=["empty", "junk", "blank", "word"],
)
def test_a_malformed_uptime_refuses_the_scan(router, content):
    one_radio(router)
    scan_output(router)
    router.write("proc/uptime", content)
    clear_calls(router)
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (1, "error internal uptime\n", ""), (
        res.rc, res.err)
    assert scan_calls(router) == [], scan_calls(router)


def test_the_stamp_holds_the_uptime_seconds(router):
    one_radio(router)
    scan_output(router)
    router.set_uptime(4242)
    res = wifiscan(router)
    assert res.rc == 0, (res.rc, res.err)
    stamp = router.root / "tmp/newton/ws.radio0"
    assert stamp.read_text() == "4242\n", stamp.read_text()


# ---- the size cap ----------------------------------------------------------


def test_a_scan_over_the_cap_is_refused(router):
    one_radio(router)
    router.write("control/ubus.out", "x" * 131072)  # the fake adds a newline
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (1, "error scan-too-large\n", ""), (
        res.rc, res.err, len(res.out))
    assert len(res.out) == 0


def test_a_scan_at_the_cap_passes(router):
    one_radio(router)
    router.write("control/ubus.out", "x" * 131071 + "\n")
    res = wifiscan(router)
    assert (res.rc, res.err) == (0, ""), (res.rc, res.err)
    assert len(res.out) == 131072, len(res.out)


# ---- the exit codes of the existing lanes ----------------------------------


def test_a_missing_ubus_is_127(router):
    one_radio(router)
    scan_output(router)
    target = router.root / "bin/ubus"
    assert target.exists() or target.is_symlink()
    target.unlink()
    res = wifiscan(router)
    assert (res.rc, res.err, res.out) == (127, "error tool-missing ubus\n", ""), (
        res.rc, res.err)
    assert "/" not in res.err, res.err


@slow  # about 26 s: the 25 s bound plus the 1 s KILL grace
def test_a_scan_over_the_bound_is_124(router):
    one_radio(router)
    router.write("control/iwinfo.scan.sleep", "40")
    res = wifiscan(router, timeout=60)
    assert (res.rc, res.err, res.out) == (124, "error read-timeout\n", ""), (
        res.rc, res.err)
    assert len(scan_calls(router)) == 1


# ---- the sweep -------------------------------------------------------------


def _dead_pid():
    """A pid that no process can have (above the kernel's pid_max)."""
    try:
        top = int(Path("/proc/sys/kernel/pid_max").read_text())
    except (OSError, ValueError):
        top = 4194304
    return top + 1000


def test_the_sweep_leaves_the_stamp_and_the_ws_lookalike_and_sweeps_the_rd_one(router):
    """The stamp file ws.radio0 and the pid-shaped lookalike ws.<dead>.abcdef
    both stay (ws is not one of the swept scratch prefixes and the stamp has
    no pid); the rd.<dead>.abcdef lookalike is swept (rd is)."""
    dead = _dead_pid()
    newton = router.root / "tmp/newton"
    newton.mkdir(parents=True, exist_ok=True)
    (newton / "ws.radio0").write_text("100\n")
    (newton / f"ws.{dead}.abcdef").write_text("")
    (newton / f"rd.{dead}.abcdef").write_text("")
    res = router.forced("hostname", role="read", timeout=15)
    assert res.rc == 0, (res.rc, res.err)
    assert (newton / "ws.radio0").exists(), "the sweep took the stamp"
    assert (newton / f"ws.{dead}.abcdef").exists(), "the sweep took the ws lookalike"
    assert not (newton / f"rd.{dead}.abcdef").exists(), "the rd lookalike stayed"


# ---- two callers at once ---------------------------------------------------


def test_two_parallel_calls_only_one_reaches_ubus(router):
    """Two real invocations of the same verb at the same time: exactly one
    of them scans, the other is refused by the rate limit. The fake's
    phyname call sleeps, so the two callers really overlap: both are past
    the rate-limit check before either of them writes the stamp."""
    one_radio(router)
    scan_output(router)
    router.write("control/iwinfo.phyname.sleep", "1")
    router.set_uptime(100)
    env = router._merged_env({"SSH_ORIGINAL_COMMAND": "read wifiscan radio0"})
    procs = [
        subprocess.Popen(
            [BUSYBOX, "sh", str(router.program),
             "--caller=agent-one", "--role=read"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=True,
        )
        for _ in range(2)
    ]
    results = []
    for proc in procs:
        out, err = proc.communicate(timeout=90)
        results.append((proc.returncode, out.decode(), err.decode()))
    assert sorted(r[0] for r in results) == [0, 2], results
    refused = [r for r in results if r[0] == 2]
    assert refused[0][2] == "error scan-rate-limited\n", refused[0]
    assert len(scan_calls(router)) == 1, scan_calls(router)


# ---- the lock order --------------------------------------------------------


def test_the_lock_is_not_held_across_the_phyname_call(router):
    """The radio -> phy resolution must not hold the program lock.

    The fake's phyname call sleeps, so the two calls really overlap: a
    verb that needs the program lock runs meanwhile, and the fake records
    that the lock was free while it slept.  A lock held across the
    ubus call would block that verb for the whole bound.
    """
    one_radio(router)
    scan_output(router)
    router.write("control/iwinfo.phyname.sleep", "4")
    proc = start_wifiscan(router)
    try:
        assert wait_for_phyname(router, proc), "the phyname call never happened"
        other = router.forced("dnsmasq-ensure", role="change", timeout=30)
        assert other.rc == 0, (other.rc, other.err)
    finally:
        out, err = proc.communicate(timeout=120)
    assert proc.returncode == 0, (proc.returncode, err.decode())
    state = (router.root / "control/iwinfo.phyname.lock").read_text().strip()
    assert state == "free", "the program lock was held across the phyname call"


def test_the_stamp_reads_the_uptime_inside_the_lock(router):
    """The uptime the stamp holds is read after the lock is taken.

    The test holds the program lock, so the call waits for it; the
    uptime moves while it waits, so a stamp that read the uptime before
    the lock would hold the old value.
    """
    one_radio(router)
    scan_output(router)
    router.set_uptime(100)
    handle = take_program_lock(router)
    proc = start_wifiscan(router)
    try:
        assert wait_for_phyname(router, proc), "the phyname call never happened"
        # the uptime moves while the call waits for the lock
        router.set_uptime(5000)
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)
        out, err = proc.communicate(timeout=120)
    assert proc.returncode == 0, (proc.returncode, err.decode())
    stamp = router.root / "tmp/newton/ws.radio0"
    assert stamp.read_text() == "5000\n", stamp.read_text()


# ---- the shared read vectors (read_cases.json) -----------------------------

CASES = json.loads((Path(__file__).parent / "read_cases.json").read_text())


def _ids(values):
    return [v.replace(" ", "-") for v in values]


@pytest.mark.parametrize("command", CASES["wifiscan"]["accepted"],
                         ids=_ids(CASES["wifiscan"]["accepted"]))
def test_the_accepted_vector_scans(router, command):
    """The accepted vectors of the corpus reach the scan (the radio exists
    in the fake's map and the scan answers)."""
    radios = [c.split()[1] for c in CASES["wifiscan"]["accepted"]]
    router.write("control/iwinfo.phyname.map",
                 "".join(f"{r} phy1\n" for r in radios))
    scan_output(router)
    res = router.forced("read " + command, role="read", timeout=20)
    assert res.rc == 0, (command, res.rc, res.err)
    assert res.out == '{"results":[]}\n', (command, res.out)


@pytest.mark.parametrize("command", CASES["wifiscan"]["refused"],
                         ids=_ids(CASES["wifiscan"]["refused"]))
def test_the_refused_vector_is_refused(router, command):
    """Every refused vector refuses with ITS OWN error word.

    The word is pinned per vector, so a program that refused every
    vector with the same word (bad-arg, say) does not pass this test.
    """
    router.write("control/iwinfo.phyname.map", "radio0 phy1\nradio1 phy1\n")
    scan_output(router)
    res = router.forced("read " + command, role="read", timeout=20)
    assert res.rc == 2, (command, res.rc, res.err)
    assert res.out == "", (command, res.out)
    word = CASES["wifiscan"]["refused_errors"][command]
    assert res.err.split()[:2] == ["error", word], (command, res.err)
    assert ubus_calls(router) == [], (command, ubus_calls(router))


# ---- the code itself -------------------------------------------------------


def _function_body(text, name):
    """The body of a shell function of the program (the same split the lint
    test uses)."""
    start = text.index(f"{name}() {{")
    return text[start:text.index("\n}\n", start)]


def test_the_wifiscan_code_builds_no_shell_string():
    """The radio name never reaches a shell string (design 3.3, hard rule 3):
    no eval, no sh -c, no backtick in the verb's own code."""
    text = PROGRAM.read_text()
    assert "read_wifiscan() {" in text, "the program has no read_wifiscan verb"
    body = _function_body(text, "read_wifiscan")
    assert "eval" not in body, body
    assert "sh -c" not in body, body
    assert "`" not in body, body


def test_the_stamp_name_is_not_the_scratch_shape():
    """The stamp is ws.<radio>; the sweep removes <two letters>.<pid>.<six
    random characters>, so the stamp is never taken and never looks like a
    stale scratch file."""
    text = PROGRAM.read_text()
    assert "ws.$radio" in text, "the stamp name is gone"
    body = _function_body(text, "sweep_scratch")
    assert "??.*.??????" in body, body
