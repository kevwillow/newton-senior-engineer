"""the owner script run of scripts/newton-router-setup.

The owner runs ONE command: ``newton-router-setup DEV owner-run SID``.
It shows the plan and the script, asks for the approval itself, asks for
the router's admin password, sends the script over the admin lane with
the fixed remote command ``sh -s`` and nothing but the script on stdin,
and ends with the read-back.

What is proved here:

  * a plan whose script does not match the hash it binds, a missing
    approval, a device with installed access and a modified record each
    stop before anything is sent to the router;
  * the remote command is exactly ``sh -s`` and the script arrives
    whole on stdin;
  * ``--print`` shows the script and its hash, and sends nothing;
  * the login-failure lines still print;
  * ``--reached yes`` follows the NEWTON-APPLYING line;
  * a second owner-finish only reads and reports;
  * one step: the right passphrase (and the right TOTP code) approves
    and runs; a wrong one, a lockout, a mismatched confirmation line
    and no TTY each stop before ssh and mint nothing; an approval that
    is already on disk skips both prompts; the passphrase never reaches
    the argv, the environment, the output, run.json or the audit; and
    the approval prompt comes before the admin-password prompt;
  * the uninstall removes the owner scripts of that device and of no
    other device.

No router is contacted: the ssh lane is the fake one of the harness and
the read-back is answered by a stub.
"""

import hashlib
import json
import os
import pty
import re
import shutil
import signal
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: E402,F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_install import (  # noqa: E402
    GOOD_PW,
    seed_known_hosts,
)
from test_router_setup_noinstall import (  # noqa: E402
    seed_acl,
    seed_https,
)

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"

sys.path.insert(0, str(REPO / "mcp"))
sys.path.insert(0, str(REPO / "mcp" / "tests"))

from newton_mcp import approve  # noqa: E402
from newton_mcp import owner_flow  # noqa: E402
from newton_mcp import owner_records  # noqa: E402
from newton_mcp.server import Device  # noqa: E402

import noinstall_answers  # noqa: E402

#: The pin of the fake certificate: the shape matters, the value does
#: not, and no lab certificate's fingerprint belongs in git.
PIN = "A" * 43 + "="

#: The plan id of the fake plans is fixed, so the tests can name it.
SID = "3f9a1c0be2d44b17a1c3d5e7f9012345"
RSID = "9e8d7c6b5a4938271605f4e3d2c1b0a9"

#: The change of the test: the lan lease limit.
BATCH = "set dhcp.lan.limit='250'"

#: The passphrase of the test device.
PASSPHRASE = "owner-run-test-passphrase"

#: The session the owner script opens: 32 lowercase hex characters.
SESSION = "0123456789abcdef0123456789abcdef"

GROUPS = (
    ("read", "luci-base"),
    ("write", "luci-base"),
)

STUB_TEMPLATE = '''#!__PYTHON__
"""The fake newton-rpcd of the owner-run tests.

The owner commands are the REAL ones (the repo's own rpcd_cli), so the
plan, the script, the backup and the approval are checked by the code
that ships.  Only the read-back is answered here: the read-back needs
the router, and the test has none.
"""
import json
import os
import sys

sys.path.insert(0, __MCP_DIR__)

from newton_mcp import owner_verify
from newton_mcp.rpcd_cli import main as rpcd_main

HERE = os.path.dirname(os.path.abspath(__file__))
GROUPS = __GROUPS__
PIN = __PIN__

argv = sys.argv[1:]
with open(os.path.join(HERE, "rpcd-calls.jsonl"), "a") as fh:
    fh.write(json.dumps(argv) + "\\n")

command = argv[0] if argv else ""
if command == "groups":
    for kind, group in GROUPS:
        print(kind + " " + group)
    sys.exit(0)
if command == "pin":
    print(__PIN__)
    sys.exit(0)
if command == "verify":
    print("PASS login and groups")
    sys.exit(0)
if command == "verify-refused":
    print("PASS the login is refused")
    sys.exit(0)
if command == "owner-finish":
    VERDICT = os.environ.get("NEWTON_STUB_VERDICT", "confirmed")

    def finish(*args, **kwargs):
        with open(os.path.join(HERE, "readback-calls.txt"), "a") as fh:
            fh.write("finish\\n")
        token = kwargs.get("confirm_token")
        if token:
            with open(os.path.join(HERE, "confirm-token.txt"), "a") as fh:
                fh.write(str(token) + "\\n")
        if VERDICT == "unknown":
            return owner_verify.Verdict(
                state=owner_verify.UNKNOWN,
                checks=("reachable",),
                deadline=0.0,
                notes=("the owner did not keep it",),
                not_verified=("Newton cannot read the rpcd config",),
                owner_keep=False,
            )
        if VERDICT == "not-applied":
            return owner_verify.Verdict(
                state=owner_verify.NOT_APPLIED,
                checks=("reachable",),
                deadline=0.0,
                notes=("the change was never applied",),
                not_verified=("Newton cannot read the rpcd config",),
                owner_keep=False,
            )
        return owner_verify.Verdict(
            state=owner_verify.CONFIRMED,
            checks=("reachable",),
            deadline=0.0,
            notes=("the change was read back",),
            not_verified=("Newton cannot read the rpcd config",),
        )

    def settle(*args, **kwargs):
        with open(os.path.join(HERE, "readback-calls.txt"), "a") as fh:
            fh.write("settle\\n")
        if VERDICT == "unknown":
            return owner_verify.Verdict(
                state=owner_verify.UNKNOWN, checks=(), deadline=0.0,
                notes=("the owner did not keep it",),
                not_verified=("Newton cannot read the rpcd config",),
                owner_keep=False,
            )
        return owner_verify.Verdict(
            state=owner_verify.ROLLED_BACK, checks=(), deadline=0.0)

    owner_verify.finish = finish
    owner_verify.settle = settle
sys.exit(rpcd_main(argv))
'''


# -- the fakes ---------------------------------------------------------------


class FakeSession:
    """The rpcd session of the fake router."""

    def __init__(self, answers, timeout_s):
        self.answers = answers
        self.timeout_s = timeout_s
        self.spent = False

    def call(self, obj, fn, args=None):
        value = self.answers.get((obj, fn), self.answers.get(("*", "*"), {}))
        if callable(value):
            value = value(obj, fn, dict(args or {}))
        if isinstance(value, list):
            code = value[0]
            if code:
                from newton_mcp.adapters.openwrt_rpcd import RpcdCallFailed
                raise RpcdCallFailed(int(code))
            return value[1] if len(value) > 1 else {}
        if isinstance(value, int) and not isinstance(value, bool):
            from newton_mcp.adapters.openwrt_rpcd import RpcdCallFailed
            raise RpcdCallFailed(value)
        return value

    def mark_spent(self):
        return None


class FakeClient:
    """The rpcd client of the fake router."""

    def __init__(self, answers):
        self.answers = answers
        self.sessions = []

    def login(self, username, password, timeout_s):
        session = FakeSession(self.answers, timeout_s)
        self.sessions.append(session)
        return session

    def call(self, session, obj, fn, args=None):
        return session.call(obj, fn, args)


class FakeService:
    """The little of NewtonService the owner flow uses."""

    def __init__(self, state, devices):
        self.state = Path(state)
        self.devices = devices
        self.audits = []

    def device(self, name, allow_noinstall=False):
        device = self.devices[name]
        if device.access == "no-install" and not allow_noinstall:
            raise AssertionError("a no-install device needs allow_noinstall")
        return device

    def audit(self, tool, device, result):
        self.audits.append((tool, device, result))


def _answers():
    """The measured answers of the lab router, for the backup."""
    def answer(obj, fn, args):
        key = "uci.get." + str(args.get("config", ""))
        return noinstall_answers.answer(key)

    return {
        ("file", "list"): {"entries": []},
        ("system", "board"): noinstall_answers.answer("system.board")[1],
        ("uci", "get"): answer,
    }


def _explanation():
    return {
        "intent": "set the lan lease limit",
        "steps": ["set the lan lease limit"],
        "expect": [
            {"kind": "uci_equals", "path": "dhcp.lan.limit", "equals": "250"}
        ],
        "risk": "the lan leases change for the devices on this network",
    }


def _password_file(env):
    """The rpcd password file of the device: mode 0600, a regular file."""
    path = env.tmp / "rpcd-password"
    path.write_text("synthetic-password\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _device(name, host, password_file):
    return Device(
        name=name,
        platform="openwrt",
        host=host,
        user="root",
        profile="lab",
        access="no-install",
        https_host=host,
        https_port=443,
        https_spki=PIN,
        rpcd_password_file=password_file,
    )


def write_rpcd_stub(env):
    """The fake newton-rpcd: the real owner commands, a fixed read-back."""
    text = (
        STUB_TEMPLATE
        .replace("__PYTHON__", sys.executable)
        .replace("__MCP_DIR__", repr(str(REPO / "mcp")))
        .replace("__GROUPS__", repr(GROUPS))
        .replace("__PIN__", repr(PIN))
    )
    path = env.tmp / "newton-rpcd"
    path.write_text(text)
    path.chmod(0o755)
    return path


def set_inventory(env, device="r1", access="no-install", host="10.1.2.3"):
    """The inventory of a no-install device."""
    password = _password_file(env)
    body = (
        '[devices.%s]\nplatform = "openwrt"\nhost = "%s"\nuser = "root"\n'
        'profile = "lab"\nauth = "password"\n' % (device, host)
    )
    # the MCP loader reads the same inventory: a password auth needs a
    # password file (mode 0600), even when the device is a no-install one
    body += 'password_file = "%s"\n' % password
    if access == "no-install":
        body += 'access = "no-install"\n'
        body += 'rpcd_password_file = "%s"\n' % password
        body += 'https_spki = "%s"\n' % PIN
    env.inventory.write_text(body)
    env.inventory.chmod(0o644)
    return password


def build_plan(env, device="r1", host="10.1.2.3", batch=BATCH):
    """The real owner plan of the test device, in the test's state dir.

    The plan, the script, the backup, the two records and the run
    record are the ones the real flow writes: the run of the setup tool
    is checked against them.
    """
    password = _password_file(env)
    service = FakeService(
        env.state_dir, {device: _device(device, host, password)}
    )
    client = FakeClient(_answers())

    def factory(_device):
        return client

    result = owner_flow.plan(
        service,
        device,
        batch,
        explanation=_explanation(),
        owner_confirmed_in_chat=True,
        client_factory=factory,
    )
    return result


def rpcd_calls(env):
    """Every call the fake newton-rpcd recorded."""
    path = env.tmp / "rpcd-calls.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def readback_calls(env):
    """Every read-back the fake newton-rpcd answered."""
    path = env.tmp / "readback-calls.txt"
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line]


def script_lines(env, sid, session=SESSION):
    """Tell the fake router what the owner script printed.

    The fake router is not root and has no uci staging, so it cannot
    run the owner script for real.  The test says what the script
    printed; the script's own bytes still travel over the lane (the
    tool hashes them, and the harness records the digest).
    """
    env.router.update_state(owner_script_lines=[
        "NEWTON-APPLYING plan=%s" % sid,
        "NEWTON-CHECKED plan=%s" % sid,
        "NEWTON-STAGED plan=%s" % sid,
        "NEWTON-APPLIED plan=%s window=180 session=%s" % (sid, session),
    ])


def ssh_commands(result):
    """The remote commands of the ssh calls of a run."""
    return [
        call.get("command") for call in result.calls if call.get("tool") == "ssh"
    ]


def run_owner(env, *args, typed=(GOOD_PW,), extra=None, device=None):
    """An owner run with the fake newton-rpcd on the seam."""
    seam = {"NEWTON_SETUP_RPCD": str(write_rpcd_stub(env))}
    if extra:
        seam.update(extra)
    return env.run(device or env.device, *args, typed=typed, env=seam)


def _wait_for(buffer, prompt, proc, limit=60.0):
    """Wait until a prompt shows up in the output of the run.

    False when the run ended before the prompt showed up: the run
    refused something and never asked the question.
    """
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if prompt in bytes(buffer).decode("utf-8", "replace"):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.05)
    raise AssertionError("the prompt %r never showed up" % prompt)


def run_owner_tty(env, *args, answers=(), typed=(GOOD_PW,), extra=None):
    """An owner run on a real terminal.

    The approval is asked for on stdin, so stdin has to be a terminal:
    the run gets a pty, and the pty does not echo (the passphrase must
    not appear in the output).  The answers are written when their
    prompt shows up, because getpass flushes the pending input when it
    turns the echo off.
    """
    seam = {"NEWTON_SETUP_RPCD": str(write_rpcd_stub(env))}
    if extra:
        seam.update(extra)
    master, slave = pty.openpty()
    attributes = termios.tcgetattr(slave)
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attributes)
    env.typed_file.write_text("".join(line + "\n" for line in typed))
    argv = [str(TOOL)] + [env.device] + [str(a) for a in args]
    proc = subprocess.Popen(
        argv,
        env=env.base_env(seam),
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
    )
    os.close(slave)
    buffer = bytearray()

    def reader():
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                return
            if not data:
                return
            buffer.extend(data)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    for prompt, answer in answers:
        if not _wait_for(buffer, prompt, proc):
            break
        os.write(master, answer.encode("utf-8"))
    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise AssertionError("the owner run did not finish")
    thread.join(timeout=5)
    os.close(master)
    text = bytes(buffer).decode("utf-8", "replace")

    class Result:
        pass

    result = Result()
    result.rc = proc.returncode
    result.out = text
    result.err = ""
    result.calls = env.router.calls()
    env.last_result = result
    return result


def write_fingerprint(env, device="r1", passphrase=PASSPHRASE):
    """The host-side approval fingerprint of the device."""
    path = env.state_dir / "approval-fp" / device
    path.parent.mkdir(parents=True, exist_ok=True)
    k_hex = approve.derive_k(passphrase.encode("utf-8"), device)
    path.write_text("v1 %s\n" % approve.approval_fingerprint(k_hex), encoding="ascii")
    path.chmod(0o600)
    return path


def write_approval(env, plan, device="r1", passphrase=PASSPHRASE, monkeypatch=None,
                   sid=None):
    """The approval of the plan, as newton-approve writes it."""
    if monkeypatch is not None:
        monkeypatch.setenv("NEWTON_STATE_DIR", str(env.state_dir))
    sid = plan["session_id"] if sid is None else sid
    record = json.loads(
        (env.state_dir / "plans" / f"{sid}.json").read_text(encoding="utf-8")
    )
    k_hex = approve.derive_k(passphrase.encode("utf-8"), device)
    approval = approve.mint_approval(
        sid, record, record["router_digest"], k_hex, "owner"
    )
    approve.write_approval(sid, approval)
    return approval


def approval_answers(sid, secret):
    """The answers of the one-step approval: the confirmation line and
    the proof."""
    return [
        ("to approve: ", "approve %s\n" % sid[:8]),
        ("admin password)", secret + "\n"),
    ]


def script_of(env, sid):
    """The bytes of the script of a plan."""
    return (env.state_dir / "owner-scripts" / sid / "script.sh").read_bytes()


# -- 1. the run --------------------------------------------------------------


def test_the_owner_run_sends_the_script_over_the_admin_lane(setup_env, monkeypatch):
    """The script goes to the router with the fixed remote command `sh -s`
    and nothing but the script on stdin; the run ends with the
    read-back."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    script_lines(env, sid)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 0, result.out + result.err
    commands = ssh_commands(result)
    assert commands == ["sh -s"], commands
    script = script_of(env, sid)
    digests = [
        call.get("stdin_sha256")
        for call in result.calls
        if call.get("tool") == "ssh"
    ]
    assert digests == [hashlib.sha256(script).hexdigest()], digests
    assert "[1/5] script bytes match the approved sha256" in result.out
    assert "[5/5]" in result.out


def test_a_mistyped_password_leaves_no_verdict_and_the_retry_confirms(
    setup_env, monkeypatch
):
    """The review's scenario: the owner mistypes the router password.

    The lane dies after the script was sent, so Newton does not know
    whether the script reached the router: the read-back reads the
    router over HTTPS and decides.  The verdict of that run never
    decides the next one.

    The owner approves the plan again (the token reached the router, so
    the approval is spent) and types the password again.  This run reads
    the router again and confirms the change: the verdict of the dead
    run never decides this one.
    """
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    script_lines(env, sid)
    first = run_owner(
        env,
        "owner-run",
        sid,
        typed=("not-the-password",),
        extra={"NEWTON_STUB_VERDICT": "not-applied"},
    )
    assert first.rc == 0, first.out + first.err
    assert "the lane to the router was lost" in first.out, first.out
    assert "NOT APPLIED" in first.out, first.out
    run = json.loads(
        (env.state_dir / "owner-scripts" / sid / "run.json").read_text(
            encoding="utf-8"
        )
    )
    assert run["verdict"]["state"] == "NOT APPLIED", run
    # the retry: the router is read again, and the change is confirmed
    # the approval of the dead run is spent, so the owner approves the
    # plan again before the second run
    write_approval(env, plan, monkeypatch=monkeypatch)
    (env.tmp / "readback-calls.txt").unlink(missing_ok=True)
    second = run_owner(env, "owner-run", sid, typed=(GOOD_PW,))
    assert second.rc == 0, second.out + second.err
    assert readback_calls(env) == ["finish"], readback_calls(env)
    assert "[5/5]" in second.out, second.out
    assert "CONFIRMED" in second.out, second.out
    assert "NOT APPLIED" not in second.out, second.out


def test_the_session_never_reaches_a_record_a_receipt_or_the_output(
    setup_env, monkeypatch
):
    """The confirm-only token is used and forgotten.

    It goes from the script's line to the read-back, on stdin, and
    nowhere else: not in the output, not in the argv, not in run.json,
    not in a receipt, not in the audit.
    """
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    script_lines(env, sid)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 0, result.out + result.err
    # the token really reached the read-back: the canary is not vacuous
    token_file = env.tmp / "confirm-token.txt"
    assert token_file.exists(), "the token never reached the read-back"
    assert token_file.read_text(encoding="utf-8").strip() == SESSION
    # and it is nowhere else
    assert SESSION not in result.out, result.out
    assert SESSION not in result.err, result.err
    for call in rpcd_calls(env):
        assert SESSION not in json.dumps(call), call
    for path in sorted(env.state_dir.rglob("*")):
        if not path.is_file():
            continue
        held = path.read_text(encoding="utf-8", errors="replace")
        assert SESSION not in held, path


def test_a_script_that_does_not_match_its_hash_stops_before_ssh(
    setup_env, monkeypatch
):
    """A script that was changed on disk is refused before anything is
    sent: the owner must approve the bytes Newton checked."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    script = env.state_dir / "owner-scripts" / sid / "script.sh"
    script.write_bytes(script.read_bytes() + b"# a line that was added\n")
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "the owner script was not checked" in result.out


def test_a_missing_approval_stops_before_ssh(setup_env, monkeypatch):
    """No approval on disk and no terminal: nothing is sent."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "not an interactive terminal" in result.out
    approvals = env.state_dir / "approvals"
    assert not approvals.exists() or list(approvals.glob("*.json")) == []


def test_a_modified_record_stops_before_ssh(setup_env, monkeypatch):
    """A record whose window was edited does not match the hash it
    carries: the run stops before anything is sent."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    record_path = env.state_dir / "plans" / f"{sid}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["timeout_s"] = 600
    record_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "the owner script was not checked" in result.out


def test_an_installed_device_is_refused(setup_env):
    """An owner script is for a no-install router."""
    env = setup_env
    set_inventory(env, access="installed")
    result = run_owner(env, "owner-run", "0" * 32)
    assert result.rc == 1
    assert result.out.splitlines()[-1] == (
        "STOPPED owner-run r1: an owner script is for a no-install router; "
        "this device uses installed access"
    )


def test_print_shows_the_script_and_sends_nothing(setup_env, monkeypatch):
    """--print shows the script and the hash of its bytes; nothing is
    sent, no approval is claimed and nothing changes."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", sid, "--print")
    assert result.rc == 0, result.out + result.err
    assert ssh_commands(result) == []
    script = script_of(env, sid).decode("utf-8")
    assert script in result.out
    assert hashlib.sha256(script_of(env, sid)).hexdigest() in result.out
    assert calls_of(env, "owner-check") == []
    approvals = env.state_dir / "approvals"
    assert approvals.exists()
    assert list(approvals.glob("*.json")), "the approval must not be claimed"
    assert not list(approvals.glob("*.claimed"))


def test_the_login_failure_lines_still_print(setup_env, monkeypatch):
    """A refused admin login is reported the way the admin lane reports it, and
    the read-back decides what the router did with the change."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    env.router.update_state(root_password="another-password")
    result = run_owner(env, "owner-run", sid, typed=("wrong-password",))
    assert "FAIL admin login to root@10.1.2.3 failed" in result.out
    assert "the lane to the router was lost" in result.out
    assert ["owner-finish", "r1", sid, "--reached", "yes"] in calls_of(
        env, "owner-finish"
    )


def test_the_second_owner_finish_only_reads_and_reports(
    setup_env, monkeypatch
):
    """A second owner-finish reads the run record and reports; it does
    not read the router again."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    script_lines(env, sid)
    first = run_owner(env, "owner-run", sid)
    assert first.rc == 0, first.out + first.err
    assert len(readback_calls(env)) == 1
    second = run_owner(env, "owner-finish", sid)
    assert second.rc == 0, second.out + second.err
    assert "[5/5]" in second.out
    assert len(readback_calls(env)) == 1, readback_calls(env)


def calls_of(env, command):
    """Every recorded call of one newton-rpcd command."""
    return [call for call in rpcd_calls(env) if call and call[0] == command]


# -- 2. one step: the approval is asked for in the same command ---------------


def test_one_step_the_right_passphrase_approves_and_runs(setup_env, monkeypatch):
    """No approval on disk: the run asks for the passphrase itself,
    approves and runs."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_fingerprint(env)
    seed_known_hosts(env)
    answers = approval_answers(sid, PASSPHRASE)
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 0, result.out + result.err
    assert "[1/5] script bytes match the approved sha256" in result.out
    assert ssh_commands(result) == ["sh -s"]
    approvals = env.state_dir / "approvals"
    assert list(approvals.glob("*.json")) or list(approvals.glob("*.used")), (
        sorted(path.name for path in approvals.iterdir())
    )


def test_one_step_a_wrong_passphrase_stops_before_ssh(setup_env, monkeypatch):
    """A wrong passphrase stops the run before anything is sent, and no
    approval is written."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_fingerprint(env)
    seed_known_hosts(env)
    answers = approval_answers(sid, "not-the-passphrase")
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "wrong approval answer" in result.out
    approvals = env.state_dir / "approvals"
    assert not approvals.exists() or list(approvals.glob("*.json")) == []


def test_one_step_a_mismatched_confirmation_stops_before_ssh(
    setup_env, monkeypatch
):
    """A confirmation line that does not match stops the run before
    anything is sent."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_fingerprint(env)
    seed_known_hosts(env)
    answers = [
        ("to approve: ", "approve xxxxxxxx\n"),
        ("admin password)", PASSPHRASE + "\n"),
    ]
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "confirmation did not match" in result.out


def test_one_step_a_locked_device_stops_before_ssh(setup_env, monkeypatch):
    """A locked-out device cannot be approved: the run stops before
    anything is sent."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_fingerprint(env)
    seed_known_hosts(env)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(env.state_dir))
    from newton_mcp import approval_proof

    for _ in range(3):
        approval_proof.record_failure("r1")
    answers = approval_answers(sid, PASSPHRASE)
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "too many wrong answers" in result.out


def test_one_step_the_right_totp_code_approves_and_runs(setup_env, monkeypatch):
    """At the totp level the run asks for the six-digit code."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    seed_known_hosts(env)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(env.state_dir))
    from newton_mcp import approval_proof

    seed = b"0123456789abcdef"
    k_hex = approve.derive_k(PASSPHRASE.encode("utf-8"), "r1")
    approval_proof.store_totp("r1", seed, k_hex)
    approval_proof.set_level("r1", "totp")
    code = approval_proof.totp_code(seed, approval_proof.totp_counter())
    answers = approval_answers(sid, code)
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 0, result.out + result.err
    assert ssh_commands(result) == ["sh -s"]


def test_an_approval_on_disk_skips_both_prompts(setup_env, monkeypatch):
    """An approval that is already on disk is used as it is: no plan is
    shown, no passphrase is asked for."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 0, result.out + result.err
    assert "to approve" not in result.out
    assert "approval passphrase" not in result.out


def test_the_passphrase_never_reaches_the_argv_the_output_or_the_records(
    setup_env, monkeypatch
):
    """The passphrase is read on the terminal and dropped: it is in no
    argument, in no file of the state directory and in no output."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_fingerprint(env)
    seed_known_hosts(env)
    env.register_secrets(PASSPHRASE)
    answers = approval_answers(sid, PASSPHRASE)
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 0, result.out + result.err
    assert PASSPHRASE not in result.out
    assert PASSPHRASE not in result.err
    for call in result.calls:
        for argument in call.get("argv", []):
            assert PASSPHRASE not in argument
    run_record = env.state_dir / "owner-scripts" / sid / "run.json"
    assert PASSPHRASE not in run_record.read_text(encoding="utf-8")
    approvals = env.state_dir / "approvals"
    for path in approvals.glob("*.json"):
        assert PASSPHRASE not in path.read_text(encoding="utf-8")
    assert env.leaks() == []


def test_the_approval_prompt_comes_before_the_admin_password_prompt(
    setup_env, monkeypatch
):
    """The owner approves first and types the router's password after."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_fingerprint(env)
    seed_known_hosts(env)
    answers = approval_answers(sid, PASSPHRASE)
    result = run_owner_tty(env, "owner-run", sid, answers=answers)
    assert result.rc == 0, result.out + result.err
    approval_at = result.out.find("to approve")
    password_at = result.out.find("root password:")
    assert approval_at > 0, result.out
    assert password_at > approval_at, result.out


# -- 3. the uninstall --------------------------------------------------------


def test_the_uninstall_removes_the_owner_scripts_of_that_device_only(
    setup_env, monkeypatch
):
    """The uninstall removes the owner scripts, the backups and the plan
    records of the device it runs for, and of no other device."""
    env = setup_env
    seed_known_hosts(env)
    seed_acl(env)
    seed_https(env)
    set_inventory(env, device="r1")
    first = build_plan(env, device="r1")
    # a second device with its own owner script
    second_password = _password_file(env)
    body = env.inventory.read_text()
    body += (
        '[devices.r2]\nplatform = "openwrt"\nhost = "10.1.2.4"\n'
        'user = "root"\nprofile = "lab"\nauth = "password"\n'
        'access = "no-install"\n'
        'rpcd_password_file = "%s"\n'
        'https_spki = "%s"\n'
        'password_file = "%s"\n' % (second_password, PIN, second_password)
    )
    env.inventory.write_text(body)
    env.inventory.chmod(0o644)
    second = build_plan(env, device="r2", host="10.1.2.4")

    scripts = env.state_dir / "owner-scripts"
    assert (scripts / first["session_id"]).is_dir()
    assert (scripts / second["session_id"]).is_dir()

    result = run_owner(env, "uninstall", device="r1")
    assert result.rc == 0, result.out + result.err
    assert not (scripts / first["session_id"]).exists()
    assert (scripts / second["session_id"]).is_dir()
    plans = env.state_dir / "plans"
    assert not (plans / f"{first['session_id']}.json").exists()
    assert (plans / f"{second['session_id']}.json").exists()


# -- 4. the lines of the script ----------------------------------------------


MAPPING_SCRIPT = r'''
set -u
export TOOL
export NEWTON_STATE_DIR
export RPCD_STUB
export FAKE_LINES
export FAKE_RC
. "$TOOL"
DEVICE=r1
ACTION=owner-run
OWNER_SID=0123456789abcdef0123456789abcdef
OWNER_PRINT=0
TMP_DIR=$(mktemp -d)
ADMIN_MODE=plain-key
STATE_NOTE='router unchanged'
RPCD="$RPCD_STUB"
rsh_owner_script() {
	printf '%s\n' "$FAKE_LINES"
	return "${FAKE_RC:-0}"
}
action_owner_run
'''


def stdin_of(env):
    """Every line the fake newton-rpcd read on stdin."""
    path = env.tmp / "rpcd-stdin.txt"
    if not path.exists():
        return []
    return path.read_text().splitlines()


def run_mapping(env, lines, rc=0):
    """The owner run with a fake lane: the lines the script prints are
    the ones the test says, and the lane ends with the status the test
    says."""
    stub = env.tmp / "rpcd-stub"
    stub.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "__ARGS__"\n'
        'IFS= read -r line || line=""\n'
        'printf "%s\\n" "$line" >> "__STDIN__"\n'.replace(
            "__ARGS__", str(env.tmp / "rpcd-args.txt")
        ).replace("__STDIN__", str(env.tmp / "rpcd-stdin.txt"))
    )
    stub.chmod(0o755)
    environment = {
        "TOOL": str(TOOL),
        "NEWTON_STATE_DIR": str(env.state_dir),
        "RPCD_STUB": str(stub),
        "FAKE_LINES": lines,
        "FAKE_RC": str(rc),
    }
    proc = subprocess.run(
        ["bash", "-c", MAPPING_SCRIPT],
        env={**os.environ, **environment},
        capture_output=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    args = env.tmp / "rpcd-args.txt"
    recorded = args.read_text().splitlines() if args.exists() else []
    return proc, recorded


KILL_SCRIPT = r'''
set -u
export TOOL
export NEWTON_STATE_DIR
export NEWTON_INVENTORY
export RPCD_STUB
export FAKE_LINES
export REAL_SID
export LANE_MARKER
. "$TOOL"
DEVICE=r1
ACTION=owner-run
OWNER_SID="$REAL_SID"
OWNER_PRINT=0
TMP_DIR=$(mktemp -d)
ADMIN_MODE=plain-key
STATE_NOTE='router unchanged'
RPCD="$RPCD_STUB"
mkfifo "$TMP_DIR/never" || exit 3
trap cleanup EXIT
rsh_owner_script() {
	printf '%s\n' "$FAKE_LINES"
	# the script is on its way: the marker says so
	: >"$LANE_MARKER"
	# the lane stays open: the run is killed while it waits for it
	exec 3<"$TMP_DIR/never"
}
action_owner_run
'''


def _status_of(env, sid):
    """What the no-install status says about a run of the owner script."""
    from newton_mcp import noinstall_flow

    password = _password_file(env)
    service = FakeService(
        env.state_dir, {"r1": _device("r1", "10.1.2.3", password)}
    )
    return noinstall_flow.status(service, "r1", sid)


def run_killed(env, sid, lines):
    """An owner run that is killed while the lane waits.

    The run is killed after the script was sent (the lane marker says
    so): the read-back never ran in the foreground.
    """
    marker = env.tmp / "lane-started"
    environment = {
        "TOOL": str(TOOL),
        "NEWTON_STATE_DIR": str(env.state_dir),
        "NEWTON_INVENTORY": str(env.inventory),
        "RPCD_STUB": str(write_rpcd_stub(env)),
        "FAKE_LINES": lines,
        "REAL_SID": sid,
        "LANE_MARKER": str(marker),
        "NEWTON_STUB_VERDICT": "unknown",
    }
    proc = subprocess.Popen(
        ["bash", "-c", KILL_SCRIPT],
        env={**os.environ, **environment},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    # the lane marker says the script was sent: the run waits for it
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if marker.exists():
            break
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise AssertionError(
                "the run ended before it sent the script: %s %s"
                % (out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
            )
        time.sleep(0.05)
    else:
        proc.kill()
        proc.communicate()
        raise AssertionError("the run never sent the script")
    os.kill(proc.pid, signal.SIGTERM)
    out, err = proc.communicate(timeout=60)
    return proc.returncode, out.decode("utf-8", "replace"), err.decode(
        "utf-8", "replace"
    )


def test_the_lines_of_the_script_map_to_the_owner_lines(setup_env):
    """NEWTON-CHECKED, NEWTON-STAGED and NEWTON-APPLIED become the
    second, third and fourth line of the run, and NEWTON-STOP is the
    reason."""
    env = setup_env
    lines = "\n".join([
        "NEWTON-APPLYING plan=0123456789abcdef0123456789abcdef",
        "NEWTON-CHECKED plan=0123456789abcdef0123456789abcdef",
        "NEWTON-STAGED plan=0123456789abcdef0123456789abcdef",
        "NEWTON-APPLIED plan=0123456789abcdef0123456789abcdef window=180",
    ])
    proc, recorded = run_mapping(env, lines)
    assert proc.returncode == 0, proc.stderr.decode()
    out = proc.stdout.decode()
    assert "[2/5] router unchanged since the plan, nothing pending" in out
    assert "[3/5] change staged in a private session (nothing changed yet)" in out
    assert "[4/5] APPLIED. Undo timer: 180 s. Newton is checking now." in out
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded


def test_the_session_of_the_script_goes_to_the_read_back_on_stdin(setup_env):
    """The confirm-only token goes in on stdin, never in the argv.

    The token is the session the script opened: it is the only session
    rpcd lets confirm a root script's apply (measured, a3m-01), and it
    must not reach the argv, the environment, a file or a log.
    """
    env = setup_env
    token = "fedcba9876543210fedcba9876543210"
    lines = "\n".join([
        "NEWTON-APPLYING plan=0123456789abcdef0123456789abcdef",
        "NEWTON-APPLIED plan=0123456789abcdef0123456789abcdef "
        f"window=180 session={token}",
    ])
    proc, recorded = run_mapping(env, lines)
    out = proc.stdout.decode()
    assert token not in out, out
    assert token not in "\n".join(recorded), recorded
    assert token in stdin_of(env), stdin_of(env)


def test_a_line_that_is_not_a_session_is_no_token(setup_env):
    """Only 32 lowercase hex characters are a session.

    Anything else is not a session, and it is not handed to the
    read-back: a token that is not a session can confirm nothing.
    """
    env = setup_env
    lines = "\n".join([
        "NEWTON-APPLYING plan=0123456789abcdef0123456789abcdef",
        "NEWTON-APPLIED plan=0123456789abcdef0123456789abcdef "
        "window=180 session=NOT-A-SESSION",
    ])
    proc, recorded = run_mapping(env, lines)
    assert proc.returncode == 0, proc.stderr.decode()
    assert "NOT-A-SESSION" not in stdin_of(env), stdin_of(env)


def test_the_empty_leftover_of_a_refused_change_is_a_note(setup_env):
    """An empty snapshot directory is a NOTE, not a stop.

    The router keeps the empty directory (measured, a3m-04): it does
    not block Newton, and Newton removes nothing.
    """
    env = setup_env
    lines = "\n".join([
        "NEWTON-APPLYING plan=0123456789abcdef0123456789abcdef",
        "NEWTON-NOTE: the router has an empty leftover from a refused "
        "change (/var/run/rpcd/snapshot-files); it does not block Newton",
    ])
    proc, recorded = run_mapping(env, lines)
    out = proc.stdout.decode()
    assert (
        "NOTE the router has an empty leftover from a refused change "
        "(/var/run/rpcd/snapshot-files); it does not block Newton" in out
    ), out


def test_the_stop_of_the_script_is_the_reason(setup_env):
    """A NEWTON-STOP line is the reason the run stops with."""
    env = setup_env
    lines = "\n".join([
        "NEWTON-APPLYING plan=0123456789abcdef0123456789abcdef",
        "NEWTON-STOP: the router changed since the plan: dhcp.lan.limit",
    ])
    proc, recorded = run_mapping(env, lines)
    out = proc.stdout.decode()
    assert "the router changed since the plan: dhcp.lan.limit" in out
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded


def test_a_script_without_the_applying_line_still_reads_back(setup_env):
    """A script that printed no NEWTON-APPLYING line may still have
    touched the router.

    The host cannot prove from the output that nothing happened: the
    script prints NEWTON-APPLYING before it touches anything, but a
    lane that dies may swallow the line.  The read-back decides, and
    the approval is spent.
    """
    env = setup_env
    proc, recorded = run_mapping(env, "NEWTON-CHECKED plan=0123456789abcdef0123456789abcdef")
    assert proc.returncode == 0, proc.stderr.decode()
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded
    assert "--reached no" not in "\n".join(recorded), recorded


# -- 5. the lane that died ---------------------------------------------------


def test_a_lost_lane_after_the_script_reached_the_router_still_reads_back(
    setup_env,
):
    """The lane died after the script reached the router: the read-back
    still runs, because the change may be live and the verdict decides
    what the router did with it."""
    env = setup_env
    lines = "\n".join([
        "NEWTON-APPLYING plan=0123456789abcdef0123456789abcdef",
        "NEWTON-APPLIED plan=0123456789abcdef0123456789abcdef window=180",
    ])
    proc, recorded = run_mapping(env, lines, rc=255)
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded
    assert "--reached no" not in "\n".join(recorded), recorded


def test_a_lost_lane_before_the_script_reached_the_router_settles_the_approval(
    setup_env,
):
    """The lane died before the script reached the router: the approval
    may have reached it after all, so the read-back decides what the
    router did with the change."""
    env = setup_env
    lines = "NEWTON-CHECKED plan=0123456789abcdef0123456789abcdef"
    proc, recorded = run_mapping(env, lines, rc=255)
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded
    assert "--reached no" not in "\n".join(recorded), recorded
    out = proc.stdout.decode()
    assert "the lane to the router was lost" in out, out


def test_a_lost_lane_that_timed_out_settles_the_approval(setup_env):
    """A lane that timed out (124) is the same case: the change may be
    live, so the read-back decides."""
    env = setup_env
    lines = "NEWTON-CHECKED plan=0123456789abcdef0123456789abcdef"
    proc, recorded = run_mapping(env, lines, rc=124)
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded
    assert "the lane to the router was lost" in proc.stdout.decode()


# -- 5b. the lane that died without a verdict ------------------------


def test_a_lane_that_died_before_the_applying_line_still_reads_back(setup_env):
    """The exit status of the lane does not say what the script did.

    A lane that ends with a status that is neither 255 nor 124, and a
    script that printed no NEWTON-APPLYING line: the script may have
    touched the router anyway, so the read-back runs and the approval
    is spent.
    """
    env = setup_env
    proc, recorded = run_mapping(env, "", rc=1)
    assert proc.returncode == 0, proc.stderr.decode()
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached yes" in (
        "\n".join(recorded)
    ), recorded
    assert "--reached no" not in "\n".join(recorded), recorded


def test_the_precondition_stop_of_the_script_is_not_reached(setup_env):
    """The script's own precondition stop comes before the
    NEWTON-APPLYING line.

    It proves the script stopped before it touched anything, so the
    approval is restored and the owner may run the plan again.  It is
    the only stop that proves that: every other stop of the script
    comes after the applying line.
    """
    env = setup_env
    lines = "NEWTON-STOP: this must run as root"
    proc, recorded = run_mapping(env, lines, rc=1)
    assert proc.returncode == 0, proc.stderr.decode()
    assert "owner-finish r1 0123456789abcdef0123456789abcdef --reached no" in (
        "\n".join(recorded)
    ), recorded


def test_the_read_back_runs_once_after_the_script_was_sent(setup_env, monkeypatch):
    """The read-back runs once.

    The finish is marked as done when it ran, so the cleanup of an
    exit never runs it a second time.
    """
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    script_lines(env, sid)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 0, result.out + result.err
    finishes = calls_of(env, "owner-finish")
    assert len(finishes) == 1, finishes
    assert finishes[0][-2:] == ["--reached", "yes"], finishes


def test_a_kill_after_the_script_was_sent_settles_the_approval(
    setup_env, monkeypatch
):
    """A run that is killed after the script was sent settles the
    approval.

    The token may have reached the router, so the approval is spent and
    the read-back says what the router did with the change.  The
    approval is never left claimed: a claimed approval is an apply that
    may still be running, and nothing is running any more.
    """
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    rc, out, err = run_killed(env, sid, "NEWTON-APPLYING plan=%s" % sid)
    assert rc != 0, "the run was killed: %s %s" % (out, err)
    assert "[5/5]" not in out, out
    approvals = env.state_dir / "approvals"
    claimed = approvals / f"{sid}.claimed"
    assert not claimed.exists(), "the approval must not stay claimed"
    assert (approvals / f"{sid}.used").exists(), "the approval is spent"
    run = json.loads(
        (env.state_dir / "owner-scripts" / sid / "run.json").read_text(
            encoding="utf-8"
        )
    )
    assert run["verdict"]["state"] == "UNKNOWN", run
    status = _status_of(env, sid)
    assert status["result"] == "unknown", status


# -- 6. the restore plan ----------------------------------------------------


def test_the_restore_plan_runs_with_its_own_approval(setup_env, monkeypatch):
    """The restore plan keeps its own backup and needs its own approval,
    and its script reaches the router."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    rsid = plan["restore_session_id"]
    write_approval(env, plan, sid=rsid, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", rsid)
    assert result.rc == 0, result.out + result.err
    commands = ssh_commands(result)
    assert commands == ["sh -s"], commands
    script = script_of(env, rsid)
    digests = [
        call.get("stdin_sha256")
        for call in result.calls
        if call.get("tool") == "ssh"
    ]
    assert digests == [hashlib.sha256(script).hexdigest()], digests


def test_the_approval_of_the_apply_plan_does_not_release_the_restore(
    setup_env, monkeypatch
):
    """The approval of the apply plan does not release the restore plan:
    the restore needs an approval of its own."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    rsid = plan["restore_session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    result = run_owner(env, "owner-run", rsid)
    assert result.rc == 1
    assert ssh_commands(result) == []
    assert "the owner script was not checked" in result.out


# -- 7. the state word and the notes ----------------------------------------


def test_the_fifth_line_ends_with_the_state_word(setup_env, monkeypatch):
    """The fifth line ends with the state word, and the notes and the
    not_verified list follow it."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    script_lines(env, sid)
    result = run_owner(env, "owner-run", sid)
    assert result.rc == 0, result.out + result.err
    lines = result.out.splitlines()
    fifth = [line for line in lines if line.startswith("[5/5]")]
    assert len(fifth) == 1, lines
    assert fifth[0].endswith(" CONFIRMED"), fifth
    after = lines[lines.index(fifth[0]) + 1:]
    assert "note: the change was read back" in after, after
    assert "not verified: Newton cannot read the rpcd config" in after, after


def test_an_unknown_run_is_re_checked_and_never_confirms(setup_env, monkeypatch):
    """A run that ended in UNKNOWN is re-checked against the router on the
    next owner-finish, and the re-check never confirms."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    unknown = {"NEWTON_STUB_VERDICT": "unknown"}
    script_lines(env, sid)
    first = run_owner(env, "owner-run", sid, extra=unknown)
    assert first.rc == 0, first.out + first.err
    assert readback_calls(env) == ["finish", "settle"], readback_calls(env)
    second = run_owner(env, "owner-finish", sid, extra=unknown)
    assert second.rc == 0, second.out + second.err
    # the re-check reads the router again, and it does not confirm
    assert readback_calls(env) == ["finish", "settle", "settle"], readback_calls(env)
    fifth = [line for line in second.out.splitlines() if line.startswith("[5/5]")]
    assert fifth and fifth[0].endswith(" UNKNOWN"), second.out
    # the notes of the first run are kept
    assert "note: the owner did not keep it" in second.out, second.out


def test_a_final_verdict_is_not_re_checked(setup_env, monkeypatch):
    """A run that ended in a final state is not re-checked: the change is
    not confirmed twice."""
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    first = run_owner(env, "owner-run", sid)
    assert first.rc == 0, first.out + first.err
    second = run_owner(env, "owner-finish", sid)
    assert second.rc == 0, second.out + second.err
    assert len(readback_calls(env)) == 1, readback_calls(env)
    fifth = [line for line in second.out.splitlines() if line.startswith("[5/5]")]
    assert fifth and fifth[0].endswith(" CONFIRMED"), second.out


# -- 8. a run that never sent the script -----------------------


def test_a_run_that_never_sent_the_script_clears_the_start_of_the_run(
    setup_env, monkeypatch
):
    """A run that stopped before the script was sent may be aborted.

    The approval is settled as "not reached" and the start of the run
    is cleared: the plan ran nothing, so the owner may drop it.
    """
    env = setup_env
    set_inventory(env)
    plan = build_plan(env)
    sid = plan["session_id"]
    write_approval(env, plan, monkeypatch=monkeypatch)
    seed_known_hosts(env)
    # no typed line: the admin password cannot be read, so the run
    # stops before the script is sent
    result = run_owner(env, "owner-run", sid, typed=())

    assert ["owner-finish", "r1", sid, "--reached", "no"] in calls_of(
        env, "owner-finish"
    )
    run_path = env.state_dir / "owner-scripts" / sid / "run.json"
    run = json.loads(run_path.read_text(encoding="utf-8"))
    assert "started_at" not in run, run
    assert ssh_commands(result) == []


