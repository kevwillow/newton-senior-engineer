"""Unit tests for the controller-loss runs of lab/newton-lab-test.py.

Fakes only: no network, no Proxmox, no router.  The apply is a fake host
script that stands in for scripts/owrt-change.sh: it spawns children whose
argv carries the words the runner's watcher looks for ("newton-router verify
<sid> 0", "newton-router confirm <sid>"), so the real watcher code finds
them in /proc and kills the whole process group.

What is proved here (rule 10 of docs/design/13-CHANGE-PROTOCOL.md: the
device ends in the pre-change state or in the confirmed state, never in
between):

* the group is killed at the point the scenario named (verify-1, verify-2,
  confirm), and at no other point;
* a point the run never reaches fails the scenario;
* the state after the kill is read from the router's own status line, and
  a state between the two ends fails the scenario;
* the guard's own label decides whether the end state is accepted: a
  rolled-back device must have put the old settings back (`guard=restored:...`)
  and a confirmed one must have no guard left (`guard=idle`);
* a status run that fails fails the scenario: the state of the device is
  then unknown;
* the record says whether the watcher timed out;
* every cleanup of the apply kills the whole process group, the children of
  the controller included;
* the RUNNING value is recorded either way;
* every load-time rule of the `controller_loss` field refuses the scenario
  before any device is touched;
* the runner waits the scenario timeout plus 30 s after the kill, so the
  guard's own deadline has surely passed.
"""
from __future__ import annotations

import select
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl

LAB_DIR = Path(__file__).resolve().parent.parent
PULSAR_DIR = LAB_DIR / "scenarios-pulsar"

SID = "a" * 32
BASEHASH = "b" * 64


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


PLAN_OUT = (
    f"STAGED session={SID}\n"
    f"BASEHASH {BASEHASH}\n"
    "----- diff -----\n"
    "set dhcp.cl01=host\n"
    "----------------\n"
)

# The router's own status line, as `owrt-change.sh status` prints it: the
# router's line first, then the host's own RUNNING line.
STATUS_ROLLED_BACK = (
    f"rolled-back sid={SID} guard=restored:deadline rpcd=- config=base "
    f"boot=same running=match\n"
    f"RUNNING session={SID} match\n"
)
STATUS_PENDING_GUARD = (
    f"rolled-back sid={SID} guard=pending rpcd=- config=post boot=same\n"
)
# The router put the old settings back, but the running network does not
# match them: the device is not in the pre-change state.
STATUS_ROLLED_BACK_DIFFERS = (
    f"rolled-back sid={SID} guard=restored:deadline rpcd=- config=base "
    f"boot=same running=differs\n"
    f"RUNNING session={SID} differs\n"
)
# The router put the old settings back, but its status line carries no
# running field, so the host printed no RUNNING line: nothing says that the
# running network matches the restored files.
STATUS_ROLLED_BACK_NO_RUNNING = (
    f"rolled-back sid={SID} guard=restored:abort rpcd=- config=- boot=-\n"
)
STATUS_CONFIRMED = (
    f"confirmed sid={SID} guard=idle rpcd=- config=post boot=same\n"
)
# The guard could not put the old settings back: the device did not reach
# the pre-change state, so it is in between.
STATUS_FAILED_GUARD = (
    f"rolled-back sid={SID} guard=failed:restore rpcd=- config=post "
    f"boot=same\n"
)
# A confirmed device whose guard is still pending: the change is confirmed
# but the guard has not settled, so the end state is not proven.
STATUS_CONFIRMED_PENDING_GUARD = (
    f"confirmed sid={SID} guard=pending rpcd=- config=post boot=same\n"
)

LAB_TOML = """
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"

[devices.lab-r1]
vmid = 9102
vm_name = "lab-r1"
host = "10.109.0.11"
user = "root"
snapshot = "baseline"

[vars]
"""


# The fake host script.  It stands in for scripts/owrt-change.sh: it runs
# the router's own program over ssh, so the child it spawns carries the
# words the watcher looks for in its argv, and it records every step it
# reached, so a test can tell which step the kill stopped at.
FAKE_HOST = r'''#!/usr/bin/env python3
"""A fake owrt-change.sh for the controller-loss tests.

It spawns a child whose argv carries the words the runner's watcher looks
for ("newton-router verify <sid> 0" or "newton-router confirm <sid>") and
records every step it reached in FAKE_LOG, so a test can tell which step the
kill stopped at.  The steps come from FAKE_STEPS ("verify", "verify",
"confirm"), FAKE_GAP is the pause between two steps and FAKE_TAIL the pause
after the last one.

FAKE_HANG=1 makes the host hang before it spawns any child at all, and
FAKE_NOISE_BYTES writes that many bytes to the host's stdout before the
first child: a host that writes more than a pipe buffer blocks there when
its output goes to a pipe.
"""
import os
import subprocess
import sys
import time

LOG = os.environ["FAKE_LOG"]
STEPS = [s for s in os.environ.get(
    "FAKE_STEPS", "verify,verify,confirm").split(",") if s]
GAP = float(os.environ.get("FAKE_GAP", "0.2"))
TAIL = float(os.environ.get("FAKE_TAIL", "30"))
HANG = os.environ.get("FAKE_HANG") == "1"
NOISE = int(os.environ.get("FAKE_NOISE_BYTES", "0"))
PROG = "/usr/libexec/newton/newton-router"
SID = sys.argv[3] if len(sys.argv) > 3 else "sid"


def record(step):
    with open(LOG, "a") as fh:
        fh.write(step + "\n")
        fh.flush()


def spawn(words):
    """A child whose argv carries `words`; it sleeps, so the watcher sees it."""
    child = subprocess.Popen([words, "60"], executable="/bin/sleep")
    children.append(child)


children = []
record("start")
record("argv " + " ".join(sys.argv[1:]))
record("env OWRT_EXPECT_DEVICE=" + os.environ.get("OWRT_EXPECT_DEVICE", ""))
if NOISE:
    # a lot of output before the first child: with a pipe this blocks here
    sys.stdout.write("x" * NOISE)
    sys.stdout.flush()
if HANG:
    # the host hangs before any point: the watcher must not wait for ever
    record("hang")
    time.sleep(3600)
    sys.exit(0)
for index, step in enumerate(STEPS):
    if step == "verify":
        words = "ssh root@router " + PROG + " verify " + SID + " 0"
    else:
        words = "ssh root@router " + PROG + " confirm " + SID
    record("step-%d-%s" % (index, step))
    spawn(words)
    time.sleep(GAP)
record("after-steps")
time.sleep(TAIL)
record("end")
for child in children:
    child.kill()
'''

# The fake host for the cleanup test: it starts one child in its own
# process group (the way the wrapper starts its ssh) and writes the child's
# pid into FAKE_PID_FILE, so a test can check that the child is gone after
# the runner's cleanup.
FAKE_HOST_WITH_CHILD = r'''#!/usr/bin/env python3
"""A fake owrt-change.sh that starts one child and writes its pid."""
import os
import subprocess
import time

PID_FILE = os.environ["FAKE_PID_FILE"]

child = subprocess.Popen(["/bin/sleep", "60"])
with open(PID_FILE, "w") as fh:
    fh.write(str(child.pid))
    fh.flush()
time.sleep(60)
'''


@pytest.fixture
def lab(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text(LAB_TOML)
    return nl.load_lab(path)


@pytest.fixture
def fake_host(tmp_path):
    """The fake owrt-change.sh: a real script, so the real watcher code
    finds its children in /proc."""
    path = tmp_path / "fake-owrt-change.sh"
    path.write_text(FAKE_HOST)
    path.chmod(0o755)
    return path


def _scenario(tmp_path, name: str, *, point: str, expect: str,
              posts: bool = True) -> "nl.Scenario":
    """One controller-loss scenario, written to disk and loaded through the
    runner's own loader."""
    d = tmp_path / "scenarios"
    d.mkdir(exist_ok=True)
    body = f"""
name = "{name}"
description = "controller loss at {point}"
target = "lab-r1"
reset = []
expect = "{expect}"
timeout = 60
controller_loss = "{point}"
batch = "set dhcp.cl01=host"
"""
    if posts:
        body += """
[[post]]
device = "lab-r1"
cmd = "uci -q get dhcp.cl01.ip"
expect_rc = 1
expect_stdout = "^$"
"""
    (d / f"{name}.toml").write_text(body)
    return nl.load_scenarios(d)[0]


def _fake_run(host: Path, status_stdout: str, calls: list,
              status_rc: int = 0):
    """The runner's own subprocess wrapper, faked: the plan and the status
    are answered from here, and every other call (a probe or a post over
    ssh) answers like a device on which the option is not there."""
    def fake_run(args, **kw):
        args = list(args)
        calls.append(args)
        if args and args[0] == str(host):
            verb = args[1] if len(args) > 1 else ""
            if verb == "plan":
                return _cp(stdout=PLAN_OUT)
            if verb == "status":
                return _cp(stdout=status_stdout, returncode=status_rc)
            return _cp()
        if args and "uci -q get" in args[-1]:
            return _cp(stdout="", returncode=1)
        return _cp(stdout="")
    return fake_run


class _Watchdog(Exception):
    """The watcher polled for ever without ever seeing the point: the test
    stops instead of waiting for ever."""


class _Clock:
    """A monotonic clock that jumps forward on every read: the watcher's
    own deadline passes at once, so the test waits for no real seconds."""

    def __init__(self, step: float = 1000.0) -> None:
        self.now = 0.0
        self.step = step
        self.reads = 0

    def __call__(self) -> float:
        value = self.now
        self.reads += 1
        self.now += self.step
        return value


def _alive(pid: int) -> bool:
    """True when the pid is a live process (a zombie is dead)."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    try:
        rest = data[data.rindex(b")") + 1:].split()
    except ValueError:
        return False
    return bool(rest) and rest[0] != b"Z"


def _run_loss(lab, scen, fake_host, tmp_path, monkeypatch, *,
              status_stdout: str, steps: str = "verify,verify,confirm",
              gap: str = "0.2", tail: str = "30",
              slept: list | None = None, max_polls: int | None = None,
              noise_bytes: int = 0, hang: bool = False,
              status_rc: int = 0):
    """Run one controller-loss scenario against the fake host script.

    Returns the record, the steps the fake host reached and the calls the
    runner made."""
    log = tmp_path / "fake-steps.log"
    log.write_text("")
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_STEPS", steps)
    monkeypatch.setenv("FAKE_GAP", gap)
    monkeypatch.setenv("FAKE_TAIL", tail)
    monkeypatch.setenv("FAKE_HANG", "1" if hang else "0")
    monkeypatch.setenv("FAKE_NOISE_BYTES", str(noise_bytes))
    if slept is not None or max_polls is not None:
        polls: list[float] = []

        def sleeper(seconds):
            # record the sleep, and really wait for the short poll pauses
            # only: the wait after the kill is never really slept here
            polls.append(seconds)
            if max_polls is not None and len(polls) > max_polls:
                raise _Watchdog(
                    f"the watcher polled {len(polls)} times and never saw "
                    f"the point")
            if slept is not None:
                slept.append(seconds)
                if 0 < seconds < 1:
                    select.select([], [], [], seconds)
        monkeypatch.setattr(nl, "_cl_sleep", sleeper)
    calls: list = []
    with mock.patch.object(nl, "OWRT_CHANGE", fake_host), \
         mock.patch.object(nl, "_run",
                           side_effect=_fake_run(fake_host, status_stdout,
                                                 calls, status_rc)):
        rec = nl.run_scenario(lab, scen)
    return rec, log.read_text().splitlines(), calls


# ---------- the kill points ----------

def test_verify_1_kills_the_group_at_the_first_verify_child(lab, tmp_path,
                                                              fake_host,
                                                              monkeypatch):
    """The controller is lost at the first verify round: the group dies
    there, and the fake host never reached its second step."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                               status_stdout=STATUS_ROLLED_BACK)
    assert rec["controller_loss"]["point"] == "verify-1"
    assert "newton-router verify " in rec["controller_loss"]["killed_pid_cmd"]
    assert SID in rec["controller_loss"]["killed_pid_cmd"]
    # one distinct verify pid was seen: the first one
    assert len(rec["controller_loss"]["seen"]) == 1
    assert "step-0-verify" in steps
    assert "step-1-verify" not in steps
    assert rec["passed"] is True


def test_verify_2_kills_the_group_at_the_second_verify_child(lab, tmp_path,
                                                               fake_host,
                                                               monkeypatch):
    """The controller is lost at the second verify round: the first round
    ran, and the confirm never started."""
    scen = _scenario(tmp_path, "cl-02", point="verify-2",
                     expect="rolled_back")
    rec, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                               status_stdout=STATUS_ROLLED_BACK)
    assert rec["controller_loss"]["point"] == "verify-2"
    # two distinct verify pids were seen: the first one did not kill the
    # group, the second one did
    assert len(rec["controller_loss"]["seen"]) == 2
    assert "step-0-verify" in steps
    assert "step-1-verify" in steps
    assert "step-2-confirm" not in steps
    assert rec["passed"] is True


def test_confirm_kills_the_group_at_the_confirm_child(lab, tmp_path,
                                                       fake_host, monkeypatch):
    """The controller is lost at the confirm: the verify rounds ran and the
    confirm child is the one that was killed."""
    scen = _scenario(tmp_path, "cl-03", point="confirm",
                     expect="rolled_back_or_confirmed", posts=False)
    rec, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                               status_stdout=STATUS_CONFIRMED)
    assert rec["controller_loss"]["point"] == "confirm"
    assert "newton-router confirm " in rec["controller_loss"]["killed_pid_cmd"]
    assert "step-2-confirm" in steps
    assert "after-steps" not in steps
    assert rec["passed"] is True
    assert rec["end_state"] == "confirmed"


def test_the_killed_controller_leaves_its_return_code_in_the_record(
        lab, tmp_path, fake_host, monkeypatch):
    """The record says what the killed controller returned (SIGKILL: -9)."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_ROLLED_BACK)
    assert rec["controller_loss"]["host_rc"] == -9


def test_the_apply_runs_with_the_same_wrapper_router_and_session(
        lab, tmp_path, fake_host, monkeypatch):
    """The watched apply is the apply the runner runs today: the same
    wrapper, the same router, the session the plan printed and the
    scenario's own timeout."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    _, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                            status_stdout=STATUS_ROLLED_BACK)
    argv = [line for line in steps if line.startswith("argv ")]
    assert argv == [f"argv apply root@10.109.0.11 {SID} 60"]
    env = [line for line in steps if line.startswith("env ")]
    assert env == ["env OWRT_EXPECT_DEVICE=lab-r1"]


def test_the_status_runs_as_a_new_process_for_the_plan_session(
        lab, tmp_path, fake_host, monkeypatch):
    """The status is a new run of the wrapper, for the session the plan
    printed."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    _, _, calls = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                            status_stdout=STATUS_ROLLED_BACK)
    status_calls = [c for c in calls if c[1] == "status"]
    assert len(status_calls) == 1
    assert status_calls[0][0] == str(fake_host)
    assert status_calls[0][2] == "root@10.109.0.11"
    assert status_calls[0][3] == SID


def test_a_point_that_is_never_reached_fails_the_scenario(lab, tmp_path,
                                                           fake_host,
                                                           monkeypatch):
    """The apply ends before the point is reached: the scenario fails with
    the reason that says so, and the record says what the watcher saw."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                               status_stdout=STATUS_ROLLED_BACK,
                               steps="confirm", tail="0.05")
    assert rec["controller_loss"]["reason"] == \
        "controller-loss-point-not-reached"
    assert rec["passed"] is False
    assert rec["controller_loss"]["seen"] == []
    assert "step-0-confirm" in steps


# ---------- the watcher must end ----------

def test_the_record_says_whether_the_watcher_timed_out(lab, tmp_path,
                                                       fake_host, monkeypatch):
    """The record carries the watcher's own answer: a host that hangs
    before the point makes the watcher time out, and the record says so."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                          status_stdout=STATUS_ROLLED_BACK)
    assert rec["controller_loss"]["timed_out"] is False

    clock = _Clock()
    monkeypatch.setattr(nl.time, "monotonic", clock)
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                          status_stdout=STATUS_ROLLED_BACK, hang=True,
                          max_polls=200)
    assert rec["controller_loss"]["timed_out"] is True


def test_a_host_that_never_reaches_the_point_times_the_watcher_out(
        lab, tmp_path, fake_host, monkeypatch):
    """A host that hangs before the point: the watcher stops at its own
    deadline, kills the group, says it timed out, and the scenario fails
    with the reason that says the point was not reached."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    clock = _Clock()
    monkeypatch.setattr(nl.time, "monotonic", clock)
    rec, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                               status_stdout=STATUS_ROLLED_BACK,
                               hang=True, max_polls=200)
    loss = rec.get("controller_loss", {})
    assert loss.get("reason") == "controller-loss-point-not-reached", \
        rec.get("error")
    assert rec["passed"] is False
    # the group died: the host that hung was killed, not left behind
    assert loss["host_rc"] == -9
    # the host never reached a point
    assert "step-0-verify" not in steps

    # the watcher on its own: its record says that it timed out
    proc = subprocess.Popen([str(fake_host), "apply", "root@10.109.0.11",
                             SID, "60"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = clock.now + 60.0
        watch = nl._watch_for_loss_point(proc, proc.pid, "verify-1", deadline)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert watch["reached"] is False
    assert watch["timed_out"] is True
    assert watch["seen"] == []
    # the group is dead: the host was killed
    assert proc.returncode == -9


def test_a_host_that_writes_a_megabyte_before_its_first_verify_child(
        lab, tmp_path, fake_host, monkeypatch):
    """The host writes more than a pipe buffer before it spawns its first
    verify child: its output goes to a file, so the host reaches the point
    and the group is killed there."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, steps, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                               status_stdout=STATUS_ROLLED_BACK,
                               noise_bytes=1024 * 1024, max_polls=200)
    assert rec["passed"] is True, rec.get("error")
    assert rec["controller_loss"]["point"] == "verify-1"
    # one distinct verify pid was seen: the first one
    assert len(rec["controller_loss"]["seen"]) == 1
    assert "step-0-verify" in steps


# ---------- the cleanup kills the whole group ----------

def test_a_cleanup_after_an_exception_kills_the_whole_group(lab, tmp_path,
                                                            monkeypatch):
    """The watcher fails: the cleanup kills the whole process group, so the
    child the host started is gone too, not only the host itself."""
    host = tmp_path / "fake-host-with-child.sh"
    host.write_text(FAKE_HOST_WITH_CHILD)
    host.chmod(0o755)
    pid_file = tmp_path / "child.pid"
    monkeypatch.setenv("FAKE_PID_FILE", str(pid_file))

    def failing_watcher(proc, pgid, point, deadline):
        # wait for the host's child to exist, then fail: the cleanup of
        # the runner must kill the group, the child included
        for _ in range(500):
            if pid_file.exists() and pid_file.read_text().strip():
                break
            select.select([], [], [], 0.01)
        raise RuntimeError("the watcher failed")

    monkeypatch.setattr(nl, "_watch_for_loss_point", failing_watcher)
    monkeypatch.setattr(nl, "OWRT_CHANGE", host)
    target = lab.devices["lab-r1"]
    with pytest.raises(RuntimeError):
        nl.apply_batch_watched(lab, target, SID, 60)
    child_pid = int(pid_file.read_text().strip())
    for _ in range(200):
        if not _alive(child_pid):
            break
        select.select([], [], [], 0.01)
    assert not _alive(child_pid), \
        f"the child {child_pid} of the killed group is still alive"


# ---------- the state after the kill ----------

def test_a_rolled_back_device_passes_and_records_the_running_value(
        lab, tmp_path, fake_host, monkeypatch):
    """The router says it restored the old settings and that the running
    network matches them: the scenario passes and the RUNNING value is in
    the record."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_ROLLED_BACK)
    assert rec["passed"] is True
    assert rec["outcome"] == "rolled_back"
    assert rec["end_state"] == "rolled_back"
    assert rec["controller_loss"]["running"] == "match"
    assert rec["controller_loss"]["running_line"] == f"RUNNING session={SID} match"
    assert rec["controller_loss"]["router_line"].startswith(
        f"rolled-back sid={SID} ")
    assert rec["controller_loss"]["guard"] == "restored:deadline"


def test_a_device_in_between_fails_the_scenario(lab, tmp_path, fake_host,
                                                monkeypatch):
    """The router's guard is still pending: the device is in between, and
    the scenario fails with the reason that says so."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_PENDING_GUARD)
    assert rec["controller_loss"]["reason"] == "controller-loss-in-between"
    assert rec["passed"] is False
    assert rec["controller_loss"]["router_line"] == \
        f"rolled-back sid={SID} guard=pending rpcd=- config=post boot=same"


def test_a_guard_that_failed_fails_the_scenario(lab, tmp_path, fake_host,
                                                monkeypatch):
    """The guard could not put the old settings back: the device did not
    reach the pre-change state, so it is in between and the run fails."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                          status_stdout=STATUS_FAILED_GUARD)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-in-between"
    assert rec["controller_loss"]["guard"] == "failed:restore"
    assert rec["controller_loss"].get("guard_ok") is False


def test_a_confirmed_device_with_a_pending_guard_fails(lab, tmp_path,
                                                        fake_host,
                                                        monkeypatch):
    """A confirmed device whose guard is still pending is not proven to be
    in the confirmed state, so the run fails."""
    scen = _scenario(tmp_path, "cl-03", point="confirm",
                     expect="rolled_back_or_confirmed", posts=False)
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                          status_stdout=STATUS_CONFIRMED_PENDING_GUARD)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-in-between"
    assert rec["controller_loss"]["guard"] == "pending"
    assert rec["controller_loss"].get("guard_ok") is False


def test_a_confirmed_device_fails_a_rolled_back_scenario(lab, tmp_path,
                                                          fake_host,
                                                          monkeypatch):
    """A confirmed change under expect = 'rolled_back' is not a state this
    scenario accepts: it fails."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_CONFIRMED)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-in-between"


def test_a_confirmed_device_passes_a_rolled_back_or_confirmed_scenario(
        lab, tmp_path, fake_host, monkeypatch):
    """Under expect = 'rolled_back_or_confirmed' the confirmed state is one
    of the two the scenario accepts, and the record says which one."""
    scen = _scenario(tmp_path, "cl-03", point="confirm",
                     expect="rolled_back_or_confirmed", posts=False)
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_CONFIRMED)
    assert rec["passed"] is True
    assert rec["outcome"] == "rolled_back_or_confirmed"
    assert rec["end_state"] == "confirmed"
    # no post check runs: the end state is one of two
    assert rec["post"] == []


def test_a_rolled_back_device_without_a_running_line_fails(lab, tmp_path,
                                                          fake_host,
                                                          monkeypatch):
    """The router's status line carries no running field, so the host
    printed no RUNNING line: nothing says the running network matches the
    restored files, so the run fails and the reason says so."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_ROLLED_BACK_NO_RUNNING)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-running-none"
    assert rec["controller_loss"]["running"] == "none"


def test_a_rolled_back_device_whose_running_network_differs_fails(
        lab, tmp_path, fake_host, monkeypatch):
    """The router put the old settings back, but the running network does
    not match them: the device is not in the pre-change state, so the run
    fails and the reason names the running value it saw."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=STATUS_ROLLED_BACK_DIFFERS)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-running-differs"
    assert rec["controller_loss"]["running"] == "differs"


def test_the_running_value_is_recorded_even_when_the_state_is_wrong(
        lab, tmp_path, fake_host, monkeypatch):
    """The RUNNING value is measured on every run, so the live run records
    it whether the state was accepted or not."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    status = (f"rolled-back sid={SID} guard=pending rpcd=- config=post "
              f"boot=same running=differs\n"
              f"RUNNING session={SID} differs\n")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=status)
    assert rec["passed"] is False
    assert rec["controller_loss"]["running"] == "differs"


def test_a_status_without_a_line_for_this_session_fails(lab, tmp_path,
                                                         fake_host,
                                                         monkeypatch):
    """The status of another session is not this session's state."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    status = ("rolled-back sid=" + "c" * 32 +
              " guard=restored:deadline rpcd=- config=base boot=same\n")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                           status_stdout=status)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-in-between"
    assert rec["controller_loss"]["router_line"] == ""


def test_a_status_run_that_fails_fails_the_scenario(lab, tmp_path, fake_host,
                                                    monkeypatch):
    """The status run after the kill fails: the state of the device is
    unknown, so the run fails with the reason that says so."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                          status_stdout=STATUS_ROLLED_BACK, status_rc=1)
    assert rec["passed"] is False
    assert rec["controller_loss"]["reason"] == "controller-loss-status-failed"
    assert rec["controller_loss"]["status_rc"] == 1


# ---------- the temp file of the client checks ----------

def test_the_spec_file_is_removed_when_the_loss_run_raises(lab, tmp_path,
                                                           fake_host,
                                                           monkeypatch):
    """The controller-loss run raises: the temp file of the client checks is
    removed anyway, so a failed run leaves nothing behind."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    spec_path = tmp_path / "vantage-spec.json"
    spec_path.write_text("{}")
    scen.client_checks = [{"claim": "the option is set"}]
    # the helper takes the claims the vantage runs as its third argument now
    # (the scenario's own client checks and, when the scenario carries rules,
    # the claims of those rules after them)
    monkeypatch.setattr(nl, "client_check_env",
                        lambda s, sid, claims=None: ({}, spec_path))

    def failing_loss(*args, **kwargs):
        raise RuntimeError("the loss run failed")

    monkeypatch.setattr(nl, "run_controller_loss", failing_loss)
    rec, _, _ = _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
                          status_stdout=STATUS_ROLLED_BACK)
    assert "the loss run failed" in (rec.get("error") or ""), rec
    assert not spec_path.exists(), "the spec file was left behind"


# ---------- the wait after the kill ----------

def test_the_runner_waits_the_timeout_plus_thirty_seconds_from_the_kill(
        lab, tmp_path, fake_host, monkeypatch):
    """The guard restores at its own deadline, so the runner waits the
    scenario timeout plus 30 s from the kill before it reads the status."""
    scen = _scenario(tmp_path, "cl-01", point="verify-1",
                     expect="rolled_back")
    slept: list = []
    _run_loss(lab, scen, fake_host, tmp_path, monkeypatch,
              status_stdout=STATUS_ROLLED_BACK, slept=slept)
    assert slept, "the runner did not sleep at all"
    # the poll pauses are short; the wait after the kill is the long one
    assert max(slept) == pytest.approx(60 + 30, abs=1.0)
    assert max(slept) > 30


# ---------- the load-time rules ----------

def _errors_for(lab, tmp_path, name: str, body: str) -> list[str]:
    d = tmp_path / "scenarios"
    d.mkdir(exist_ok=True)
    (d / f"{name}.toml").write_text(body)
    scen = nl.load_scenarios(d)[0]
    return nl.validate_scenarios(lab, [scen])


def test_an_unknown_controller_loss_value_is_refused(lab, tmp_path):
    errors = _errors_for(lab, tmp_path, "cl-bad", """
name = "cl-bad"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 60
controller_loss = "verify-9"
batch = "set dhcp.cl01=host"
""")
    assert any("controller_loss 'verify-9' is not one of" in e for e in errors)


def test_controller_loss_with_no_install_access_is_refused(lab, tmp_path):
    errors = _errors_for(lab, tmp_path, "cl-bad", """
name = "cl-bad"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 60
access = "no-install"
controller_loss = "verify-1"
batch = "set dhcp.cl01=host"
""")
    assert any("installed transport" in e for e in errors)


def test_controller_loss_with_a_refusal_noop_or_none_expect_is_refused(
        lab, tmp_path):
    for expect in ("refused", "noop", "none"):
        errors = _errors_for(lab, tmp_path, f"cl-{expect}", f"""
name = "cl-{expect}"
target = "lab-r1"
reset = []
expect = "{expect}"
timeout = 60
controller_loss = "verify-1"
batch = "set dhcp.cl01=host"
""")
        assert any(f"expects '{expect}'" in e for e in errors), (expect, errors)


def test_a_verify_point_with_another_expect_is_refused(lab, tmp_path):
    for point in ("verify-1", "verify-2"):
        errors = _errors_for(lab, tmp_path, f"cl-{point}", f"""
name = "cl-{point}"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
controller_loss = "{point}"
batch = "set dhcp.cl01=host"
""")
        assert any("needs expect = 'rolled_back'" in e for e in errors), \
            (point, errors)


def test_the_confirm_point_with_another_expect_is_refused(lab, tmp_path):
    errors = _errors_for(lab, tmp_path, "cl-confirm", """
name = "cl-confirm"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 60
controller_loss = "confirm"
batch = "set dhcp.cl01=host"
""")
    assert any("needs expect = 'rolled_back_or_confirmed'" in e
               for e in errors)


def test_rolled_back_or_confirmed_is_only_valid_with_the_confirm_point(
        lab, tmp_path):
    errors = _errors_for(lab, tmp_path, "cl-bad", """
name = "cl-bad"
target = "lab-r1"
reset = []
expect = "rolled_back_or_confirmed"
timeout = 60
batch = "set dhcp.cl01=host"
""")
    assert any("only valid with controller_loss = 'confirm'" in e
               for e in errors)


def test_the_password_lane_needs_the_confirm_point_too(lab, tmp_path):
    """The password lane has an expectation of its own, and the rules of
    the `controller_loss` field read it as well: an expectation of
    'rolled_back_or_confirmed' without the confirm point is refused there
    too."""
    errors = _errors_for(lab, tmp_path, "cl-bad", """
name = "cl-bad"
target = "lab-r1"
reset = []
expect = "rolled_back"
expect_password = "rolled_back_or_confirmed"
timeout = 60
batch = "set dhcp.cl01=host"
""")
    assert any("expect_password = 'rolled_back_or_confirmed' is only valid "
               "with controller_loss = 'confirm'" in e for e in errors), errors


def test_the_confirm_point_refuses_a_scenario_with_posts(lab, tmp_path):
    errors = _errors_for(lab, tmp_path, "cl-confirm", """
name = "cl-confirm"
target = "lab-r1"
reset = []
expect = "rolled_back_or_confirmed"
timeout = 60
controller_loss = "confirm"
batch = "set dhcp.cl01=host"

[[post]]
device = "lab-r1"
cmd = "uci -q get dhcp.cl01.ip"
expect_rc = 1
expect_stdout = "^$"
""")
    assert any("runs no [[post]] checks" in e for e in errors)


def test_a_good_controller_loss_scenario_has_no_error(lab, tmp_path):
    errors = _errors_for(lab, tmp_path, "cl-ok", """
name = "cl-ok"
target = "lab-r1"
reset = []
expect = "rolled_back"
timeout = 60
controller_loss = "verify-1"
batch = "set dhcp.cl01=host"

[[post]]
device = "lab-r1"
cmd = "uci -q get dhcp.cl01.ip"
expect_rc = 1
expect_stdout = "^$"
""")
    assert errors == []


# ---------- the three Pulsar scenarios ----------

PULSAR_SCENARIOS = ("p-cl-01-lost-before-first-verify",
                     "p-cl-02-lost-in-second-verify",
                     "p-cl-03-lost-in-confirm")


def test_the_three_pulsar_scenarios_load_clean():
    """The three live runs load through the runner's own loader, with the
    field and the expect their point asks for."""
    loaded = {s.name: s for s in nl.load_scenarios(PULSAR_DIR)}
    for name in PULSAR_SCENARIOS:
        assert name in loaded, sorted(loaded)
    cl01 = loaded["p-cl-01-lost-before-first-verify"]
    assert cl01.controller_loss == "verify-1"
    assert cl01.expect == "rolled_back"
    assert cl01.target == "pulsar"
    assert len(cl01.post) == 1
    cl02 = loaded["p-cl-02-lost-in-second-verify"]
    assert cl02.controller_loss == "verify-2"
    assert cl02.expect == "rolled_back"
    assert len(cl02.post) == 1
    cl03 = loaded["p-cl-03-lost-in-confirm"]
    assert cl03.controller_loss == "confirm"
    assert cl03.expect == "rolled_back_or_confirmed"
    assert cl03.post == []
    assert cl03.reset_after == ["pulsar"]


def test_the_three_pulsar_scenarios_carry_their_own_lease():
    """Each scenario has a lease of its own, so the three never collide
    with p-01 or with each other."""
    loaded = {s.name: s for s in nl.load_scenarios(PULSAR_DIR)}
    names = set()
    macs = set()
    for name in PULSAR_SCENARIOS:
        batch = loaded[name].batch
        for line in batch.splitlines():
            if ".name=" in line:
                names.add(line.split("=")[-1].strip("'"))
            if ".mac=" in line:
                macs.add(line.split("=")[-1].strip("'"))
    assert len(names) == 3, names
    assert len(macs) == 3, macs
    p01 = {s.name: s for s in nl.load_scenarios(PULSAR_DIR)}
    assert "02:00:00:00:00:77" not in macs
    assert "labtest" not in names
    assert p01["p-01-static-lease"].target == "pulsar"
