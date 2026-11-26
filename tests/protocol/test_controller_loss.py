"""controller loss in the middle of a change (rule 10 of the change protocol).

Rule 10 of the change protocol: when the controller (the host,
``scripts/owrt-change.sh``) is lost in the middle of a change, the router
ends in the pre-change state or the confirmed state, never in between.

The harness is the e2e one of ``test_owrt_change_e2e.py``: the fake ssh runs
the REAL router program against a fake router root, so plan, apply, verify
and confirm all happen for real.  This file adds the one thing that harness
has no seam for: the controller is LOST (SIGKILL, the whole process group,
the way ``tests/protocol/router_setup_env.py`` kills one) at an exact point
of one apply run.

The kill comes from the fake ssh side, so every point is exact and no sleep
waits for it:

* the hook watches the remote command the host is running and counts the
  commands that start with a given prefix;
* the router program runs the command for real;
* then the hook SIGKILLs the controller's process group - before the answer
  is handed over ("before-answer") or after the answer is on the wire but
  before the ssh exits ("after-answer"), so the controller never starts the
  next command.

The confirm point uses the router program's own crash hook
(``NEWTON_ROUTER_CRASH_AT=1``, the seam of
``device/openwrt/newton-router/tests/test_flow.py::test_6_7_program_killed_
between_rpcd_confirm_and_guard_confirm``): the confirm stops after the rpcd
confirm and before the guard confirm, and the host is lost when that ssh
call ends.

The other confirm point loses the host after the router's confirm ran to
the end: no crash hook, the router confirms and the guard releases its
transaction, and the host dies when that ssh call ends.  That is the
other end state rule 10 allows: the router ends confirmed, so the change
stays live.

After every kill a NEW controller comes back: the router's clock is moved
past the guard deadline (the way ``test_i_failure_branch_for_real_confirm_
too_late`` does) and ``owrt-change.sh status <sid>`` runs as a fresh host
process.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owrt_change_e2e import (  # noqa: E402,F401
    APPLIED_DHCP,
    BUSYBOX,
    ORIGINAL_DHCP,
    PROG_PATH,
    SCRIPT,
    _parse_plan_stdout,
    _prep_plannable,
    _sid_from_staged,
    e2e,
)

#: The fake router's answer to "does the router run the settings the guard
#: put back?" after it restored the pre-change config at its deadline.
#: MEASURED on this fake router: the router program's
#: running field answers "match" when the helper's health check passes, and
#: on this fake router it does: the check asks the router for the list of
#: running services and compares it with the snapshot the apply took, and
#: the fake service list (dnsmasq running) and the fake ucode answer the
#: same before and after the guard's restore, so nothing looks stopped and
#: the comparison passes.  It is not a proof that a real router runs the
#: restored settings - it is what this fake router answers, pinned.
RUNNING_VALUE = "match"


# ----- the fake ssh with the controller-loss hook -------------------------
#
# The body is the e2e fake ssh (the fake ssh of test_owrt_change_e2e.py)
# plus the hook.  The hook never guesses: it matches the remote command the
# host is running, counts the matches on disk (every ssh call is its own
# process) and kills the controller's process group at the Nth match.

FAKE_SSH_BODY = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import os
    import signal
    import subprocess
    import sys
    from pathlib import Path

    PROGRAM = Path(os.environ["FAKE_SSH_PROGRAM"])
    ROUTER_ROOT = Path(os.environ["FAKE_SSH_ROUTER_ROOT"])
    BUSYBOX = os.environ["FAKE_SSH_BUSYBOX"]
    CONNECT_FLAG = Path(os.environ.get("FAKE_SSH_CONNECT_FLAG", "/nonexistent"))

    # The controller-loss hook (this test file only).
    #   KILL_PREFIX: the remote command prefix the hook watches for
    #   KILL_NTH:    the Nth command with that prefix is the loss point
    #   KILL_MODE:   "before-answer" - the router ran the command, the
    #                answer is never handed over, the controller dies
    #                "after-answer"  - the router ran the command and its
    #                answer is on the wire, the controller dies before the
    #                ssh exits, so it never sees the end of the answer and
    #                never starts the next command
    #   KILL_COUNTER: the file the hook counts the matches in
    #   KILL_LOG:     the file the hook records the loss in
    #   TEST_PGID:    the process group of the test runner: the hook
    #                refuses to kill that one
    # The router program's own crash hook, for the confirm point:
    #   CRASH_PREFIX: the command prefix that gets NEWTON_ROUTER_CRASH_AT
    KILL_PREFIX = os.environ.get("FAKE_SSH_KILL_PREFIX", "")
    KILL_NTH = int(os.environ.get("FAKE_SSH_KILL_NTH", "1"))
    KILL_MODE = os.environ.get("FAKE_SSH_KILL_MODE", "after-answer")
    KILL_COUNTER = os.environ.get("FAKE_SSH_KILL_COUNTER", "")
    KILL_LOG = os.environ.get("FAKE_SSH_KILL_LOG", "")
    TEST_PGID = os.environ.get("FAKE_SSH_TEST_PGID", "")
    CRASH_PREFIX = os.environ.get("FAKE_SSH_CRASH_PREFIX", "")
    CRASH_AT = os.environ.get("FAKE_SSH_CRASH_AT", "1")

    try:
        dest_idx = next(i for i, a in enumerate(sys.argv[1:], 1) if "@" in a)
    except StopIteration:
        sys.stderr.write("fake ssh: destination not found\\n")
        sys.exit(127)
    cmd = " ".join(sys.argv[dest_idx + 1:])

    stdin_bytes = sys.stdin.buffer.read()

    if CONNECT_FLAG.exists():
        sys.stderr.write("ssh: connect to host 192.0.2.1 port 22: Connection timed out\\n")
        sys.exit(255)

    env = {
        "PATH": "/usr/bin:/bin",
        "NEWTON_ROUTER_ROOT": str(ROUTER_ROOT),
        "LC_ALL": "C",
        "SSH_ORIGINAL_COMMAND": cmd,
    }
    if CRASH_PREFIX and cmd.startswith(CRASH_PREFIX):
        env["NEWTON_ROUTER_CRASH_AT"] = CRASH_AT
    argv = [BUSYBOX, "sh", str(PROGRAM), "--caller=host-e2e", "--role=change"]

    try:
        proc = subprocess.run(
            argv, input=stdin_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=60,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write("fake ssh: program timeout\\n")
        sys.exit(124)

    out_bytes = proc.stdout
    err_bytes = proc.stderr
    if cmd.startswith("/usr/libexec/newton/newton-router hello "):
        out_text = out_bytes.decode("utf-8", "replace")
        out_text = out_text.replace(" mode=test ", " mode=prod ")
        out_bytes = out_text.encode("utf-8")

    # The controller-loss hook.
    if KILL_PREFIX and cmd.startswith(KILL_PREFIX):
        count = 0
        if KILL_COUNTER and os.path.exists(KILL_COUNTER):
            try:
                with open(KILL_COUNTER) as f:
                    count = int(f.read().strip() or "0")
            except ValueError:
                count = 0
        count += 1
        if KILL_COUNTER:
            with open(KILL_COUNTER, "w") as f:
                f.write(str(count))
        if count == KILL_NTH:
            pgid = os.getpgid(0)
            if TEST_PGID and pgid == int(TEST_PGID):
                sys.stderr.write("fake ssh: refusing to kill the test runner's own process group\\n")
                sys.exit(99)
            if KILL_LOG:
                with open(KILL_LOG, "a") as f:
                    f.write("lost n=%d mode=%s pgid=%d cmd=%s\\n" % (count, KILL_MODE, pgid, cmd))
            if KILL_MODE == "before-answer":
                os.killpg(pgid, signal.SIGKILL)
                os._exit(137)
            sys.stdout.buffer.write(out_bytes)
            sys.stdout.buffer.flush()
            os.killpg(pgid, signal.SIGKILL)
            os._exit(137)

    sys.stdout.buffer.write(out_bytes)
    sys.stderr.buffer.write(err_bytes)
    sys.exit(proc.returncode)
    """
)


# ----- the controller runner -----------------------------------------------


def _run_controller(e2e, args, env, *, timeout=300):
    """Run the host script in its own process group.

    ``start_new_session=True`` gives the run a process group of its own, the
    one the fake ssh SIGKILLs: the host script, the shell it runs its
    command substitutions in and the ssh itself all die together, and the
    test runner's group is never touched.
    """
    fake_ssh = str(e2e.root / "bin" / "ssh")
    unshare_cmd = [
        "unshare", "-Urm", "--", "bash", "-c",
        'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
        "noop", fake_ssh, *args,
    ]
    proc = subprocess.Popen(
        unshare_cmd, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        pytest.fail("the controller run did not finish within %ss" % timeout)
    return proc.returncode, out


@pytest.fixture
def controller(e2e):
    """The e2e fixture plus a fake ssh that can lose the controller, and a
    runner that starts the host in its own process group."""
    ssh = e2e.root / "bin" / "ssh"
    ssh.write_text(
        FAKE_SSH_BODY.replace(
            'BUSYBOX = os.environ["FAKE_SSH_BUSYBOX"]',
            "BUSYBOX = " + repr(BUSYBOX),
        )
    )
    ssh.chmod(0o755)

    counter = e2e.root / "kill-counter"
    kill_log = e2e.root / "kill.log"
    for stale in (counter, kill_log):
        if stale.exists():
            stale.unlink()

    def run_apply(sid, *, kill_prefix=None, nth=1, mode="after-answer",
                  crash_prefix=None, timeout=300):
        """One apply run that loses the controller at the given point."""
        env = e2e.env.copy()
        env["FAKE_SSH_KILL_COUNTER"] = str(counter)
        env["FAKE_SSH_KILL_LOG"] = str(kill_log)
        env["FAKE_SSH_TEST_PGID"] = str(os.getpgid(0))
        if kill_prefix:
            env["FAKE_SSH_KILL_PREFIX"] = kill_prefix
            env["FAKE_SSH_KILL_NTH"] = str(nth)
            env["FAKE_SSH_KILL_MODE"] = mode
        if crash_prefix:
            env["FAKE_SSH_CRASH_PREFIX"] = crash_prefix
            env["FAKE_SSH_CRASH_AT"] = "1"
        args = [str(SCRIPT), "apply", "root@lab-r1", sid, "60"]
        return _run_controller(e2e, args, env, timeout=timeout)

    def losses():
        """The lines the hook recorded (one per loss)."""
        if not kill_log.exists():
            return []
        return kill_log.read_text().splitlines()

    return types.SimpleNamespace(
        e2e=e2e,
        run_apply=run_apply,
        losses=losses,
    )


# ----- the scenario -------------------------------------------------------


def _plan_one(e2e):
    """Plan one change on the fake router; returns the session id."""
    _prep_plannable(e2e)
    e2e.ready_for_arm()
    e2e.router.set_fake("pidof", out="411\n")
    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")
    res = e2e.run_plan(changes=changes, timeout=60)
    assert res.returncode == 0, (res.returncode, res.stdout)
    meta, _ = _parse_plan_stdout(res.stdout)
    sid = _sid_from_staged(meta["STAGED"])
    assert sid and len(sid) == 32, (sid, res.stdout)
    return sid


def _pre_change_bytes(e2e):
    """The config files as they are before the apply (the bytes the router
    must be back to)."""
    before = e2e.snap_cfg()
    assert before["dhcp"] == ORIGINAL_DHCP, before
    return before


def _new_controller_status(e2e, sid):
    """The new controller: the router's clock past the guard deadline, then
    the status of the session as a fresh host process."""
    e2e.router.set_uptime(200)
    res = e2e.run_status(sid)
    assert res.returncode == 0, (res.returncode, res.stdout)
    return res


def _router_line(res):
    """The router's own status line in the host's status output."""
    lines = [l for l in res.stdout.splitlines() if l.startswith("rolled-back sid=")]
    assert len(lines) == 1, res.stdout
    return lines[0]


def _confirmed_line(res):
    """The router's own confirmed status line in the host's status output."""
    lines = [l for l in res.stdout.splitlines() if l.startswith("confirmed sid=")]
    assert len(lines) == 1, res.stdout
    return lines[0]


def _running_line(res):
    """The host's own RUNNING line."""
    lines = [l for l in res.stdout.splitlines() if l.startswith("RUNNING session=")]
    assert len(lines) == 1, res.stdout
    return lines[0]


# =========================================================================
# TESTS
# =========================================================================


def test_a_controller_lost_after_the_apply_before_the_first_verify(controller):
    """The controller is lost after the router answered the apply and
    before it sent the first verify.

    The router holds the change with its rollback armed; the new controller
    finds the guard restored the pre-change config at its deadline.
    """
    e2e = controller.e2e
    sid = _plan_one(e2e)
    before = _pre_change_bytes(e2e)

    rc, out = controller.run_apply(
        sid, kill_prefix=f"{PROG_PATH} apply ", nth=1, mode="after-answer")
    assert rc == -9, (rc, out)          # SIGKILL
    # the loss happened at the apply, and only there
    losses = controller.losses()
    assert len(losses) == 1, losses
    assert "mode=after-answer" in losses[0], losses
    assert f"cmd={PROG_PATH} apply {sid} " in losses[0], losses
    # the change was applied on the router and not confirmed
    assert e2e.snap_cfg()["dhcp"] == APPLIED_DHCP, e2e.snap_cfg()

    res = _new_controller_status(e2e, sid)

    # 1. the config is byte for byte the pre-change bytes
    assert e2e.snap_cfg() == before, e2e.snap_cfg()
    # 2. the router's own line names the guard's restore at its deadline
    assert _router_line(res) == (
        f"rolled-back sid={sid} guard=restored:deadline rpcd=- config=base "
        f"boot=same running={RUNNING_VALUE}"
    ), res.stdout
    # 3. the host's own RUNNING line
    assert _running_line(res) == f"RUNNING session={sid} {RUNNING_VALUE}", res.stdout
    # 4. no guard transaction is pending any more
    guard_line = e2e.router.guard_status()
    assert not guard_line.startswith("pending"), guard_line
    assert guard_line.startswith(f"restored {sid} "), guard_line


def test_b_controller_lost_during_the_second_verify_round(controller):
    """The controller is lost during the second verify round: the router has run the
    second verify and the host dies before it reads the answer.

    The change is applied and unverified enough to confirm; the new
    controller finds the pre-change config and the guard idle of
    transactions.
    """
    e2e = controller.e2e
    sid = _plan_one(e2e)
    before = _pre_change_bytes(e2e)

    rc, out = controller.run_apply(
        sid, kill_prefix=f"{PROG_PATH} verify ", nth=2, mode="before-answer")
    assert rc == -9, (rc, out)          # SIGKILL
    losses = controller.losses()
    assert len(losses) == 1, losses
    assert "n=2" in losses[0], losses
    assert "mode=before-answer" in losses[0], losses
    assert f"cmd={PROG_PATH} verify {sid} " in losses[0], losses
    # the change is applied on the router, not confirmed
    assert e2e.snap_cfg()["dhcp"] == APPLIED_DHCP, e2e.snap_cfg()
    # the router ran the second verify (its record holds two passes)
    record = (e2e.router.root / "tmp/owrt-safe-apply.lock"
              / f"{sid}.txn" / "verified")
    assert record.read_text().split()[1] == "2", record.read_text()

    res = _new_controller_status(e2e, sid)

    assert e2e.snap_cfg() == before, e2e.snap_cfg()
    assert _router_line(res) == (
        f"rolled-back sid={sid} guard=restored:deadline rpcd=- config=base "
        f"boot=same running={RUNNING_VALUE}"
    ), res.stdout
    assert _running_line(res) == f"RUNNING session={sid} {RUNNING_VALUE}", res.stdout
    guard_line = e2e.router.guard_status()
    assert not guard_line.startswith("pending"), guard_line
    assert guard_line.startswith(f"restored {sid} "), guard_line


def test_c_controller_lost_during_the_confirm(controller):
    """The controller is lost during the confirm: the router's confirm stops
    after the rpcd confirm and before the guard confirm (the router
    program's own crash hook), and the host is lost when that ssh call
    ends.

    The rpcd has confirmed, so its own rollback is gone: only the guard can
    still put the pre-change config back, and it does so at its deadline.
    """
    e2e = controller.e2e
    sid = _plan_one(e2e)
    before = _pre_change_bytes(e2e)

    rc, out = controller.run_apply(
        sid, kill_prefix=f"{PROG_PATH} confirm ", nth=1, mode="after-answer",
        crash_prefix=f"{PROG_PATH} confirm ")
    assert rc == -9, (rc, out)          # SIGKILL
    losses = controller.losses()
    assert len(losses) == 1, losses
    assert f"cmd={PROG_PATH} confirm {sid}" in losses[0], losses
    # the router's confirm stopped after the rpcd confirm
    txn = e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn"
    assert (txn / "rpcd-confirmed").read_text().strip() == "ok"
    # the change is live on the router (the rpcd confirmed it)
    assert e2e.snap_cfg()["dhcp"] == APPLIED_DHCP, e2e.snap_cfg()

    res = _new_controller_status(e2e, sid)

    assert e2e.snap_cfg() == before, e2e.snap_cfg()
    assert _router_line(res) == (
        f"rolled-back sid={sid} guard=restored:deadline rpcd=- config=base "
        f"boot=same running={RUNNING_VALUE}"
    ), res.stdout
    assert _running_line(res) == f"RUNNING session={sid} {RUNNING_VALUE}", res.stdout
    guard_line = e2e.router.guard_status()
    assert not guard_line.startswith("pending"), guard_line
    assert guard_line.startswith(f"restored {sid} "), guard_line


def test_d_control_the_same_run_without_a_loss_confirms(controller):
    """The control: the same run, with no loss, confirms and the config
    holds the changed bytes."""
    e2e = controller.e2e
    sid = _plan_one(e2e)

    res = e2e.run_apply(sid, timeout=60)
    assert res.returncode == 0, (res.returncode, res.stdout)
    assert "CONFIRMED" in res.stdout, res.stdout
    assert e2e.snap_cfg()["dhcp"] == APPLIED_DHCP, e2e.snap_cfg()
    # the guard is idle: the confirm released its transaction
    assert e2e.router.guard_status().startswith("idle"), e2e.router.guard_status()
    # no loss happened
    assert controller.losses() == [], controller.losses()


def test_e_controller_lost_after_the_confirm_answered_stays_confirmed(controller):
    """The controller is lost after the router's confirm answered: the
    router's confirm ran to the end (no crash hook) and the host died when
    that ssh call ended, before it read the answer.

    Rule 10 allows two end states: the pre-change one or the confirmed one.
    The router confirmed, so the change is confirmed: the config holds the
    changed bytes, the guard did not restore, and the router's own line
    says confirmed.
    """
    e2e = controller.e2e
    sid = _plan_one(e2e)

    rc, out = controller.run_apply(
        sid, kill_prefix=f"{PROG_PATH} confirm ", nth=1, mode="after-answer")
    assert rc == -9, (rc, out)          # SIGKILL
    # the loss happened at the confirm, and only there
    losses = controller.losses()
    assert len(losses) == 1, losses
    assert "mode=after-answer" in losses[0], losses
    assert f"cmd={PROG_PATH} confirm {sid}" in losses[0], losses
    # the router's confirm ran to the end: the change is live on the router
    assert e2e.snap_cfg()["dhcp"] == APPLIED_DHCP, e2e.snap_cfg()

    res = _new_controller_status(e2e, sid)

    # 1. the config holds the changed bytes (the control test's end state)
    assert e2e.snap_cfg()["dhcp"] == APPLIED_DHCP, e2e.snap_cfg()
    # 2. no guard transaction is pending any more
    guard_line = e2e.router.guard_status()
    assert not guard_line.startswith("pending"), guard_line
    # 3. the router's own line says the change is confirmed
    assert _confirmed_line(res) == (
        f"confirmed sid={sid} guard=idle rpcd=- config=- boot=-"
    ), res.stdout
    # 4. the host printed no RUNNING line: the guard did not restore, so the
    #    router has no running field to report
    assert not any(l.startswith("RUNNING session=")
                   for l in res.stdout.splitlines()), res.stdout
