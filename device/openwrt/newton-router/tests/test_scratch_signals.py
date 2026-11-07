"""Signal traps and scratch sweep.

BusyBox ash does not run the EXIT trap when a signal kills the shell, so
without explicit traps a SIGHUP/SIGINT/SIGTERM/SIGPIPE to the program
leaks the `rd.XXXXXX` and `re.XXXXXX` files (and the syslog line never
carries the status). This file covers:

  1. each of the four signals ends the call through the EXIT trap, the
     scratch files go, and the syslog line carries `rc=128+signum`;
  2. a normal call is not disturbed by the new traps;
  3. the start-up sweep removes scratch files left by dead calls and
     never touches a live call's files, the lock/hello/last files, or
     a name that does not match the scratch shape;
  4. a stage call killed with SIGKILL (no EXIT trap) leaves scratch
     files, and the next call sweeps them;
  5. a static check on the program text: every mktemp template carries
     `$PROG_PID`, there are at least 30 of them, and the set of
     two-letter prefixes equals the set in the sweep_scratch case
     (a new scratch kind cannot escape the sweep);
  6. the sweep is silent on a refused call.
"""

import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest

from conftest import BUSYBOX, PROGRAM, SID


# ---- helpers --------------------------------------------------------------


def _default_signals():
    """Runs in the child before exec. A pytest started with nohup, or as a
    background job, hands down ignored SIGHUP and SIGINT, and a shell cannot
    trap a signal that was ignored on entry; the program then keeps running
    and the test would time out. An sshd child has the default dispositions,
    so restore them."""
    for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGPIPE):
        signal.signal(s, signal.SIG_DFL)



def _scratch_files_for_pid(root, pid):
    """Every `XX.<pid>.XXXXXX` file in tmp/newton whose pid part is the
    given number (the dead pid; the live one is checked separately)."""
    out = []
    for p in (root / "tmp/newton").iterdir():
        parts = p.name.split(".")
        if len(parts) == 3 and parts[0].isalpha() and parts[0].islower() \
                and parts[1] == str(pid) and len(parts[2]) == 6:
            out.append(p)
    return out


def _dead_pid():
    """A pid that no process can have: above the kernel's pid_max. (The pid of a
    process that just ended could be handed to a new process before the router call
    on a busy host, and the sweep then rightly keeps the file.)"""
    try:
        top = int(Path("/proc/sys/kernel/pid_max").read_text())
    except (OSError, ValueError):
        top = 4194304
    return top + 1000


def _is_dead(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


# ---- 1. signal ends the call and removes scratch files --------------------


@pytest.mark.parametrize(
    "sig,expected_rc",
    [
        (signal.SIGHUP, 129),
        (signal.SIGINT, 130),
        (signal.SIGTERM, 143),
        (signal.SIGPIPE, 141),
    ],
    ids=["HUP", "INT", "TERM", "PIPE"],
)
def test_signal_ends_the_call_and_removes_scratch(router, sig, expected_rc):
    """Each of the four signals ends the call through the EXIT trap, the
    rd.* and re.* files are removed, and the syslog line carries the
    status (128 + signum)."""
    router.set_fake("logread", out="line\n" * 10, sleep=20)
    env = router._merged_env({"SSH_ORIGINAL_COMMAND": "read logread"})
    proc = subprocess.Popen(
        [BUSYBOX, "sh", str(router.program),
         "--caller=agent-one", "--role=change"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True, preexec_fn=_default_signals,
    )
    try:
        newton = router.root / "tmp/newton"
        # Poll for at least one rd.* and one re.* file (up to 15 s: a loaded host starts slowly)
        rd_seen = re_seen = False
        deadline = time.time() + 15.0
        while time.time() < deadline and not (rd_seen and re_seen):
            try:
                entries = list(newton.iterdir())
            except FileNotFoundError:
                entries = []
            for p in entries:
                if p.name.startswith("rd."):
                    rd_seen = True
                if p.name.startswith("re."):
                    re_seen = True
            if not (rd_seen and re_seen):
                time.sleep(0.05)
        assert rd_seen, "no rd.* file appeared in tmp/newton within 15 s"
        assert re_seen, "no re.* file appeared in tmp/newton within 15 s"
        proc.send_signal(sig)
        # Must not wait for the 20 s fake: the trap fires and the
        # program exits at once through the EXIT trap.
        rc = proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert rc == expected_rc, (sig.name, rc, expected_rc)
    leftover = sorted(
        p.name for p in (router.root / "tmp/newton").iterdir()
        if p.name.startswith("rd.") or p.name.startswith("re.")
    )
    assert not leftover, (sig.name, leftover)
    lines = router.syslog()
    assert lines, "no syslog line was written"
    last = lines[-1]
    assert "cmd=read" in last, last
    assert f"rc={expected_rc}" in last, last


# ---- 2. a signal does not break a normal call -----------------------------


def test_signal_does_not_break_a_normal_call(router):
    """A read logread with no delay finishes 0, prints the fake's
    output, and leaves no scratch file. The new traps must fire only
    on actual signals."""
    router.set_fake("logread", out="L\n")
    res = router.forced("read logread", role="read", timeout=15)
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert res.out == "L\n", (res.out, res.err)
    leftover = [p.name for p in (router.root / "tmp/newton").iterdir()]
    for name in leftover:
        if name in ("flock", "hello", "last"):
            continue
        pytest.fail(f"unexpected file in tmp/newton after a normal call: {name!r}")


# ---- 3. stale scratch of dead calls is swept at start-up -----------------


def test_stale_scratch_of_dead_calls_is_swept(router, tmp_path):
    """The sweep removes the scratch files of dead calls, keeps the
    files of a live call, and never touches the lock/hello/last files
    or a name that does not match the scratch shape."""
    dead = _dead_pid()
    live = os.getpid()
    newton = router.root / "tmp/newton"
    newton.mkdir(parents=True, exist_ok=True)
    # Scratch files of dead calls (must go)
    (newton / f"rd.{dead}.AbCdEf").write_text("")
    (newton / f"ch.{dead}.ZzZz12").write_text("")
    (newton / f"pb.{dead}.123456").write_text("")
    # A scratch file of a live call (must stay)
    (newton / f"rd.{live}.AbCdEf").write_text("")
    # Names that must stay (not the scratch shape)
    (newton / "rd.abc.AbCdEf").write_text("")       # pid is not digits
    (newton / f"zz.{dead}.AbCdEf").write_text("")  # prefix is not in the case
    (newton / f"rd.{dead}.short").write_text("")   # tail is not 6 chars
    # Real non-scratch files (must stay)
    (newton / "flock").write_text("")
    (newton / "hello").write_text("")
    (newton / "last").write_text("")

    res = router.forced("hostname", role="read", timeout=15)
    assert res.rc == 0, (res.rc, res.out, res.err)
    gone = [f"rd.{dead}.AbCdEf", f"ch.{dead}.ZzZz12", f"pb.{dead}.123456"]
    stayed = [
        f"rd.{live}.AbCdEf",
        "rd.abc.AbCdEf",
        f"zz.{dead}.AbCdEf",
        f"rd.{dead}.short",
        "flock", "hello", "last",
    ]
    for name in gone:
        assert not (newton / name).exists(), f"expected gone: {name}"
    for name in stayed:
        assert (newton / name).exists(), f"expected to stay: {name}"


# ---- 4. SIGKILL mid-call leaves files that the next call sweeps ----------


def test_kill_mid_call_leaves_files_that_the_next_call_sweeps(router):
    """A stage call killed with SIGKILL via NEWTON_ROUTER_CRASH_AT=1
    leaves scratch files (the EXIT trap cannot run on SIGKILL). The
    next hostname call must sweep them on entry."""
    router.use_stub_helper()
    router.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
    router.write("control/next-sid", SID + "\n")
    res = router.forced(
        "stage", caller="agent-one", role="change",
        stdin=b"set dhcp.cfg01.domain=lan\n",
        env={"NEWTON_ROUTER_CRASH_AT": "1"}, timeout=40,
    )
    assert res.rc == -9, (res.rc, res.out, res.err)
    newton = router.root / "tmp/newton"
    # Find a scratch-shaped file whose pid is dead (the killed program)
    dead_pid = None
    for p in newton.iterdir():
        parts = p.name.split(".")
        if len(parts) == 3 and parts[0].isalpha() and parts[0].islower() \
                and parts[1].isdigit() and len(parts[2]) == 6 \
                and _is_dead(int(parts[1])):
            dead_pid = int(parts[1])
            break
    assert dead_pid is not None, "no scratch file of a dead pid was left"
    # The next call must sweep it
    res2 = router.forced("hostname", role="read", timeout=15)
    assert res2.rc == 0, (res2.rc, res2.out, res2.err)
    # After the call, no scratch-shaped file of that dead pid is left
    for p in newton.iterdir():
        parts = p.name.split(".")
        if len(parts) == 3 and parts[1] == str(dead_pid):
            pytest.fail(f"dead scratch file still present: {p.name}")


# ---- 5. every mktemp template carries the program pid --------------------

MKTEMP_RE = re.compile(r'mktemp\s+"\$R/tmp/newton/([a-z]{2})\.\$PROG_PID\.XXXXXX"')


def test_every_mktemp_template_carries_the_program_pid():
    """Static check on the program text: every `mktemp "..."` template
    in the program has the `$PROG_PID` segment, there are at least 30
    of them, and the set of two-letter prefixes equals the set in the
    sweep_scratch case (a new scratch kind cannot escape the sweep)."""
    text = PROGRAM.read_text()
    matches = MKTEMP_RE.findall(text)
    assert len(matches) >= 30, (
        f"only {len(matches)} mktemp templates match; want >= 30"
    )
    every_mktemp = re.findall(r'mktemp\s+"', text)
    assert len(every_mktemp) == len(matches), (
        f"{len(every_mktemp)} mktemp calls but {len(matches)} templates carry the pid"
    )
    in_templates = set(matches)
    # Find the case list in sweep_scratch
    m = re.search(
        r'case "\$b" in\s*\n\s*((?:[a-z]{2}\.\*\|)+[a-z]{2}\.\*)\)\s*;;',
        text,
    )
    assert m, "the sweep_scratch case list was not found"
    in_case = set(re.findall(r'\b([a-z]{2})\.\*', m.group(1)))
    assert in_templates == in_case, (
        f"prefixes in mktemp templates {sorted(in_templates)} "
        f"differ from prefixes in sweep_scratch case {sorted(in_case)}"
    )


# ---- 6. the sweep is silent even on a refused call -----------------------


def test_sweep_runs_before_the_request_is_refused(router):
    """A stale rd.<dead>.AbCdEf is also removed by a call that is
    refused (`bogus-subcommand`), and that refused call prints exactly
    `error unknown-subcommand` on stderr and nothing on stdout (the
    sweep is silent)."""
    dead = _dead_pid()
    newton = router.root / "tmp/newton"
    newton.mkdir(parents=True, exist_ok=True)
    (newton / f"rd.{dead}.AbCdEf").write_text("")
    res = router.forced("bogus-subcommand", role="change", timeout=15)
    assert res.rc == 2, (res.rc, res.out, res.err)
    assert res.out == "", (res.out, res.err)
    assert res.err == "error unknown-subcommand\n", (res.out, res.err)
    assert not (newton / f"rd.{dead}.AbCdEf").exists(), (
        f"expected the stale rd.{dead}.AbCdEf to be swept"
    )
