"""Self-tests of the fake router harness.

These run the fakes directly through the wrappers written by install_fakes;
the tool itself is never run.
"""

import base64
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_harness import (FakeRouter, advance_clock, install_fakes,  # noqa: E402
                                  is_vulnerable)

HOST = "10.1.2.3"
DEST = "root@10.1.2.3"


def free_port():
    """A free TCP port on 127.0.0.1 (bound to port 0, then released)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_listener(port, timeout=5):
    """Block until something accepts on 127.0.0.1:port; returns a connection."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1)
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise AssertionError("no listener on %d: %s" % (port, last))


def reap(proc):
    """Terminate a child, wait, then kill; returns its exit code."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    proc.stdout.close() if proc.stdout else None
    proc.stderr.close() if proc.stderr else None
    return proc.returncode


class Rig:
    """A router plus the fake wrappers, run through subprocess."""

    def __init__(self, tmp_path):
        self.router = FakeRouter.create(tmp_path / "router")
        self.tmp = tmp_path
        self.bindir = tmp_path / "fakes"
        install_fakes(self.bindir, self.router.root)

    def run(self, tool, args, input=None, env=None, timeout=30):
        full_env = {
            "PATH": "%s:%s" % (self.bindir, os.environ["PATH"]),
            "FAKE_ROUTER_ROOT": str(self.router.root),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        full_env.update(env or {})
        return subprocess.run(
            [str(self.bindir / tool)] + list(args),
            input=input,
            stdin=None if input is not None else subprocess.DEVNULL,
            capture_output=True,
            env=full_env,
            timeout=timeout,
        )

    def key(self, name, comment="test-key"):
        """Make a key pair with the fake ssh-keygen; return (path, blob)."""
        path = self.tmp / name
        proc = self.run("ssh-keygen",
                        ["-q", "-t", "ed25519", "-N", "", "-C", comment,
                         "-f", str(path)])
        assert proc.returncode == 0, proc.stderr
        blob = path.with_name(path.name + ".pub").read_text().split()[1]
        return path, blob

    def ssh(self, args, input=None, env=None, timeout=30):
        base = ["-F", "/dev/null", "-o", "ConnectTimeout=8"]
        return self.run("ssh", base + list(args), input=input, env=env,
                        timeout=timeout)

    def start(self, args, env=None):
        """Start the fake ssh as a child (forwarding sessions)."""
        full_env = {
            "PATH": "%s:%s" % (self.bindir, os.environ["PATH"]),
            "FAKE_ROUTER_ROOT": str(self.router.root),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        full_env.update(env or {})
        return subprocess.Popen(
            [str(self.bindir / "ssh")] +
            ["-F", "/dev/null", "-o", "ConnectTimeout=8"] + list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=full_env)

    def key_args(self, key):
        return ["-i", str(key), "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey",
                "-o", "PasswordAuthentication=no"]

    def calls(self):
        return self.router.calls()

    def last_call(self):
        return self.calls()[-1]


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


# -- ssh-keygen ---------------------------------------------------------------

def test_keygen_make(rig):
    key = rig.tmp / "k1"
    proc = rig.run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "",
                                  "-C", "newton-router-agent", "-f", str(key)])
    assert proc.returncode == 0
    lines = key.read_text().splitlines()
    assert lines[0] == "FAKE-OPENSSH-PRIVATE-KEY"
    assert len(lines) == 2
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    blob = lines[1]
    assert blob.startswith("AAAAC3NzaC1lZDI1NTE5AAAAI") and len(blob) == 25 + 40
    assert key.with_name("k1.pub").read_text() == \
        "ssh-ed25519 %s newton-router-agent\n" % blob
    call = rig.last_call()
    assert call["tool"] == "ssh-keygen" and call["rc"] == 0
    assert call["argv"][:2] == ["-q", "-t"]


def test_keygen_y(rig):
    key, blob = rig.key("k2")
    proc = rig.run("ssh-keygen", ["-y", "-f", str(key)])
    assert proc.returncode == 0
    assert proc.stdout == b"ssh-ed25519 %s\n" % blob.encode()


def test_keygen_l(rig):
    kh = rig.tmp / "known_hosts"
    line = "%s %s" % (HOST, rig.router.state()["host_key"])
    kh.write_text(line + "\n")
    digest = base64.b64encode(
        hashlib.sha256(line.encode()).digest()).decode().rstrip("=")
    proc = rig.run("ssh-keygen", ["-l", "-f", str(kh)])
    assert proc.returncode == 0
    assert proc.stdout.decode() == "256 SHA256:%s %s (ED25519)\n" % (digest, HOST)


def test_keygen_F(rig):
    trusted = rig.tmp / "trusted"
    line = "%s ssh-ed25519 AAAAHOSTKEY0000001 extra" % HOST
    trusted.write_text("# a comment\n%s\n" % line)
    proc = rig.run("ssh-keygen", ["-F", HOST, "-f", str(trusted)])
    assert proc.returncode == 0
    out = proc.stdout.decode()
    assert "# Host %s found: line 2" % HOST in out
    assert line in out
    proc = rig.run("ssh-keygen", ["-F", "9.9.9.9", "-f", str(trusted)])
    assert proc.returncode == 1
    assert proc.stdout == b""


# -- key lane: login and execution --------------------------------------------

def test_unrestricted_key_runs_command_and_returns_exit_code(rig):
    key, blob = rig.key("admin")
    rig.router.add_authorized_key("ssh-ed25519 %s agent-laptop" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo hi; exit 7"])
    assert proc.returncode == 7
    assert proc.stdout == b"hi\n"
    call = rig.last_call()
    assert call["tool"] == "ssh"
    assert call["principal"] == "key:agent-laptop"
    assert call["rc"] == 7


def test_forced_command_gets_argv_and_original_command(rig):
    key, blob = rig.key("agent")
    prog = rig.tmp / "prog-source"
    prog.write_text(
        "#!%s\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:],"
        " 'orig': os.environ.get('SSH_ORIGINAL_COMMAND')}))\n"
        % sys.executable)
    rig.router.write("/usr/libexec/newton/prog", prog.read_text(), mode=0o755)
    rig.router.add_authorized_key(
        'command="/usr/libexec/newton/prog --mode forced",restrict '
        "ssh-ed25519 %s newton-router-agent" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "hello deadbeef"])
    assert proc.returncode == 0
    payload = json.loads(proc.stdout.decode())
    assert payload["argv"] == ["--mode", "forced"]
    assert payload["orig"] == "hello deadbeef"
    # no client command: forced command still runs, without SSH_ORIGINAL_COMMAND
    proc = rig.ssh(rig.key_args(key) + [DEST])
    assert proc.returncode == 0
    payload = json.loads(proc.stdout.decode())
    assert payload["argv"] == ["--mode", "forced"]
    assert payload["orig"] is None


def test_drop_commands_knob_closes_the_connection_without_running(rig):
    """State knob drop_commands: a router command that contains one of the
    substrings is not run, the fake ssh exits 255 (a link that drops at
    that moment); other commands run as before."""
    key, blob = rig.key("admin")
    rig.router.add_authorized_key("ssh-ed25519 %s agent-laptop" % blob)
    rig.router.update_state(drop_commands=["dropped-marker"])
    proc = rig.ssh(rig.key_args(key)
                   + [DEST, 'touch "$FAKE_ROUTER_FS/tmp/dropped-marker"'])
    assert proc.returncode == 255
    assert b"Connection closed" in proc.stderr
    assert not rig.router.path("tmp/dropped-marker").exists()
    assert rig.last_call().get("dropped") is True
    proc = rig.ssh(rig.key_args(key)
                   + [DEST, 'touch "$FAKE_ROUTER_FS/tmp/other-marker"'])
    assert proc.returncode == 0
    assert rig.router.path("tmp/other-marker").exists()


def test_forced_command_missing_program_is_127(rig):
    key, blob = rig.key("x1")
    rig.router.add_authorized_key(
        'command="/usr/libexec/newton/no-such-program" ssh-ed25519 %s c' % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "hello"])
    assert proc.returncode == 127


def test_line_with_unknown_option_is_ignored(rig):
    key, blob = rig.key("x2")
    rig.router.add_authorized_key(
        'nope="x",restrict ssh-ed25519 %s newton-router-x' % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo hi"])
    assert proc.returncode == 255
    assert b"Permission denied" in proc.stderr
    assert rig.last_call()["principal"] == "none"


def test_unknown_key_denied(rig):
    key, _ = rig.key("x3")
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo hi"])
    assert proc.returncode == 255
    assert b"Permission denied" in proc.stderr


def test_ghost_blob_authenticates(rig):
    key, blob = rig.key("ghost")
    rig.router.update_state(ghost_blobs=[blob])
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo spooky"])
    assert proc.returncode == 0
    assert proc.stdout == b"spooky\n"
    assert rig.last_call()["principal"] == "key:ghost"


def test_deny_restricted_when_plain_absent(rig):
    key, blob = rig.key("x4")
    rig.router.update_state(deny_restricted_when_plain_absent=True)
    rig.router.write("/usr/libexec/newton/prog", "#!/bin/sh\necho ran\n", 0o755)
    rig.router.add_authorized_key(
        'command="/usr/libexec/newton/prog" ssh-ed25519 %s newton-router-x' % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "hello"])
    assert proc.returncode == 255
    assert b"Connection closed" in proc.stderr
    # a plain line present: the restricted login works again
    rig.router.add_authorized_key("ssh-ed25519 AAAAOTHERPLAINKEY000001 plain")
    proc = rig.ssh(rig.key_args(key) + [DEST, "hello"])
    assert proc.returncode == 0
    assert proc.stdout == b"ran\n"


# -- host key policy ----------------------------------------------------------

def _kh_rig(rig, strict, lines, key):
    kh = rig.tmp / "known_hosts"
    kh.write_text("".join(l + "\n" for l in lines))
    args = rig.key_args(key) + [
        "-o", "UserKnownHostsFile=%s" % kh,
        "-o", "StrictHostKeyChecking=%s" % strict,
        DEST, "echo ok",
    ]
    return rig.ssh(args), kh


def test_accept_new_writes_the_line(rig):
    key, blob = rig.key("kh1")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc, kh = _kh_rig(rig, "accept-new", [], key)
    assert proc.returncode == 0
    assert kh.read_text() == "%s %s\n" % (HOST, rig.router.state()["host_key"])


def test_strict_yes_unknown_host_fails(rig):
    key, blob = rig.key("kh2")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc, _ = _kh_rig(rig, "yes", [], key)
    assert proc.returncode == 255
    assert b"Host key verification failed." in proc.stderr


def test_changed_host_key_fails(rig):
    key, blob = rig.key("kh3")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    lines = ["%s ssh-ed25519 AAAADIFFERENTKEY0000001" % HOST]
    proc, _ = _kh_rig(rig, "yes", lines, key)
    assert proc.returncode == 255
    assert b"REMOTE HOST IDENTIFICATION HAS CHANGED" in proc.stderr


# -- password lane ------------------------------------------------------------

def _password_env(rig, password):
    apdir = rig.tmp / "ap"
    apdir.mkdir(exist_ok=True)
    askpass = apdir / "askpass"
    askpass.write_text("#!%s\nimport sys\nsys.stdout.write(%r + '\\n')\n"
                       % (sys.executable, password))
    askpass.chmod(0o755)
    return {"SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "x"}, apdir


def test_password_lane_success(rig):
    env, _ = _password_env(rig, rig.router.state()["root_password"])
    args = ["-o", "BatchMode=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1", DEST, "echo via-password"]
    proc = rig.ssh(args, env=env)
    assert proc.returncode == 0
    assert proc.stdout == b"via-password\n"
    assert rig.last_call()["principal"] == "password"
    assert rig.last_call()["lane"] == "password"


def test_password_lane_wrong_password(rig):
    env, _ = _password_env(rig, "not-the-password")
    proc = rig.ssh([DEST, "echo no"], env=env)
    assert proc.returncode == 255
    assert b"Permission denied" in proc.stderr


def test_password_lane_disabled(rig):
    rig.router.update_state(password_auth=False)
    env, _ = _password_env(rig, rig.router.state()["root_password"])
    proc = rig.ssh([DEST, "echo no"], env=env)
    assert proc.returncode == 255


# -- execution environment ----------------------------------------------------

def test_stdin_and_binary_stdout(rig):
    key, blob = rig.key("x5")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    payload = bytes(range(256)) + b"\x00\xffbinary\n"
    proc = rig.ssh(rig.key_args(key) + [DEST, "cat"], input=payload)
    assert proc.returncode == 0
    assert proc.stdout == payload
    call = rig.last_call()
    assert call["stdin_len"] == len(payload)
    assert call["stdin_sha256"] == hashlib.sha256(payload).hexdigest()


def test_router_environment_and_path(rig):
    key, blob = rig.key("x6")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    cmd = 'test -n "$FAKE_ROUTER_FS" && command -v ucode && ! command -v git'
    proc = rig.ssh(rig.key_args(key) + [DEST, cmd])
    assert proc.returncode == 0, proc.stderr


def test_unsupported_option_logged(rig):
    proc = rig.ssh(["-X", DEST, "echo hi"])
    assert proc.returncode == 254
    call = rig.last_call()
    assert call["unsupported"] == "-X"
    assert call["rc"] == 254


def test_unsupported_o_option_logged(rig):
    proc = rig.ssh(["-o", "ForwardX11=yes", DEST, "echo hi"])
    assert proc.returncode == 254
    assert rig.last_call()["unsupported"] == "-o ForwardX11"


def test_syntax_error_logged(rig):
    key, blob = rig.key("x8")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "if; then"])
    assert proc.returncode == 254
    call = rig.last_call()
    assert call.get("syntax_error") is True
    assert call["rc"] == 254


def test_scp_and_sftp_fail_for_now(rig):
    for tool in ("scp", "sftp"):
        proc = rig.run(tool, ["-P", "22", "%s:/tmp/x" % DEST, str(rig.tmp / "f")])
        assert proc.returncode == 255


# -- leak scan --------------------------------------------------

SECRET = "zz-secret-zz"


def test_leak_scan_argv(rig):
    rig.router.register_secrets(SECRET)
    key, blob = rig.key("l1")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo %s" % SECRET])
    assert proc.returncode == 0
    assert "argv" in rig.last_call()["leaks"]


def test_leak_scan_environment(rig):
    rig.router.register_secrets(SECRET)
    key, blob = rig.key("l2")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo clean"],
                   env={"LEAKY": "prefix-%s-suffix" % SECRET})
    assert proc.returncode == 0
    assert "env:LEAKY" in rig.last_call()["leaks"]


def test_leak_scan_askpass_directory_file(rig):
    rig.router.register_secrets(SECRET)
    env, apdir = _password_env(rig, rig.router.state()["root_password"])
    (apdir / "notes.txt").write_text("scratch %s scratch\n" % SECRET)
    os.mkfifo(apdir / "pipe")
    proc = rig.ssh([DEST, "echo ok"], env=env)
    assert proc.returncode == 0
    leaks = rig.last_call()["leaks"]
    assert "askpass-file:notes.txt" in leaks
    # the FIFO in the same directory is never opened, so it cannot be listed
    assert not any("pipe" in l for l in leaks)


def test_leak_scan_clean_call(rig):
    rig.router.register_secrets(SECRET)
    key, blob = rig.key("l3")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "echo nothing to see"])
    assert proc.returncode == 0
    assert rig.last_call()["leaks"] == []


# -- FakeRouter itself ----------------------------------------------------------

def test_router_layout_and_state_defaults(rig):
    router = rig.router
    ak = router.path("etc/dropbear/authorized_keys")
    assert stat.S_IMODE(ak.stat().st_mode) == 0o600
    assert ak.read_text() == ""
    assert router.read("/etc/openwrt_release").strip() == \
        "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.0'".strip()
    state = router.state()
    assert state["root_password"] == "root-pw-for-tests"
    assert state["password_auth"] is True
    assert state["host"] == HOST
    assert state["host_key"] == "ssh-ed25519 AAAAC3FAKEHOSTKEY0001"
    assert state["overlay_free_kib"] == 20000
    assert state["ghost_blobs"] == []
    assert (router.root / "clock").read_text() == "0"
    assert json.loads((router.root / "timers.json").read_text()) == []
    assert json.loads((router.root / "secrets.json").read_text()) == []
    assert (router.root / "bin" / "uci").exists()
    assert (router.root / "hostbin" / "awk").exists()


def test_router_snapshot_and_write(rig):
    router = rig.router
    router.write("/etc/newton/profile", "lab\n", mode=0o600)
    router.add_authorized_key("ssh-ed25519 AAA c")
    snap = router.snapshot()
    entry = snap["etc/newton/profile"]
    assert entry["mode"] == "0o600"
    assert entry["sha256"] == hashlib.sha256(b"lab\n").hexdigest()
    assert snap["etc/dropbear/authorized_keys"]["mode"] == "0o600"
    assert not any(p.startswith("tmp") for p in snap)
    assert "state.json" not in snap
    # a second snapshot with no writes is identical
    assert router.snapshot() == snap


def test_router_uci_and_ubus_stubs(rig):
    rig.router.update_state(
        uci={"dropbear.@dropbear[0].PasswordAuth": "on"},
        ubus_sessions="abc123 root\n")
    env = {"PATH": "%s:%s" % (rig.router.root / "bin",
                              rig.router.root / "hostbin")}
    proc = subprocess.run(
        ["%s/bin/uci" % rig.router.root, "-q",
         "get", "dropbear.@dropbear[0].PasswordAuth"],
        capture_output=True, env=env, timeout=10)
    assert (proc.returncode, proc.stdout) == (0, b"on\n")
    proc = subprocess.run(
        ["%s/bin/uci" % rig.router.root, "-q", "get", "no.such.key"],
        capture_output=True, env=env, timeout=10)
    assert (proc.returncode, proc.stdout) == (1, b"")
    proc = subprocess.run(
        ["%s/bin/ubus" % rig.router.root, "call", "session", "list"],
        capture_output=True, env=env, timeout=10)
    assert proc.stdout == b"abc123 root\n\n"


# -- vulnerable knob (a list of names) ---------------------------

def test_is_vulnerable_accepts_list_and_dict():
    assert is_vulnerable({"vulnerable": ["forwarding"]}, "forwarding")
    assert not is_vulnerable({"vulnerable": ["forwarding"]}, "pty")
    assert is_vulnerable({"vulnerable": {"forwarding": True}}, "forwarding")
    assert not is_vulnerable({"vulnerable": {"forwarding": False}},
                             "forwarding")
    assert not is_vulnerable({"vulnerable": []}, "forwarding")
    assert not is_vulnerable({}, "forwarding")


def test_default_state_vulnerable_is_list(rig):
    assert rig.router.state()["vulnerable"] == []


# -- virtual clock and timers (design 8.3) ------------------------

PLAIN_LINE = "ssh-ed25519 AAAAPLAINKEY00000000000000000001 agent-laptop"
RESTRICTED_LINE = ('command="/usr/libexec/newton/newton-router",restrict '
                   "ssh-ed25519 AAAARESTRICTEDKEY0000000000001 "
                   "newton-router-agent")


def deadman_text(nonce, rr, seconds=90):
    """The design 8.3 dead-man switch with RR (the router fs prefix) already
    expanded, as the tool builds it on the host."""
    return (
        "sleep " + str(seconds) + "; "
        'grep -q "^' + nonce + ' " ' + rr + '/tmp/newton/hello 2>/dev/null || '
        "{ cp -p " + rr + "/etc/dropbear/authorized_keys.newton-prev "
        + rr + "/etc/dropbear/authorized_keys; "
        'logger -t newton-setup "key swap not proven in 90 s; '
        'authorized_keys restored"; }'
    )


def register_timer(rig, command_text):
    """Run the setsid stub exactly as the tool's router command would."""
    return subprocess.run(
        [str(rig.router.root / "bin" / "setsid"), "sh", "-c", command_text],
        capture_output=True, timeout=10,
        env={"PATH": "/usr/bin:/bin"})


def arm_deadman(rig, nonce):
    """Back up authorized_keys and register the dead-man switch."""
    rig.router.write("/etc/dropbear/authorized_keys.newton-prev",
                     PLAIN_LINE + "\n", mode=0o600)
    return register_timer(rig, deadman_text(nonce, str(rig.router.root / "fs")))


def test_setsid_sleep_registers_timer_and_returns_at_once(rig):
    proc = arm_deadman(rig, "aa" * 16)
    assert proc.returncode == 0
    timers = rig.router.timers()
    assert len(timers) == 1
    assert timers[0]["due"] == 90
    assert "RR" not in timers[0]["env"]
    assert "authorized_keys.newton-prev" in timers[0]["command"]
    assert rig.router.clock() == 0


def test_fake_ssh_returns_after_a_background_setsid_job_registered(rig):
    """The tool starts the dead-man switch with `setsid sh -c '...' </dev/null
    >/dev/null 2>&1 &`: the router shell exits at once and the python setsid
    stub registers its timer a moment later.  The fake ssh must not return
    before that timer exists, or the tool's next fake-sleep races it
    ."""
    key, blob = rig.key("admin")
    rig.router.add_authorized_key("ssh-ed25519 %s agent-laptop" % blob)
    rig.router.write("/etc/dropbear/authorized_keys.newton-prev",
                     PLAIN_LINE + "\n", mode=0o600)
    for index in range(8):
        inner = deadman_text("%032x" % index, str(rig.router.root / "fs"))
        command = "setsid sh -c '%s' </dev/null >/dev/null 2>&1 &" % inner
        proc = rig.ssh(rig.key_args(key) + [DEST, command])
        assert proc.returncode == 0
        assert len(rig.router.timers()) == index + 1, index


def test_deadman_fires_once_and_restores_without_proof(rig):
    nonce = "bb" * 16
    rig.router.write("/etc/dropbear/authorized_keys",
                     PLAIN_LINE + "\n" + RESTRICTED_LINE + "\n", mode=0o600)
    arm_deadman(rig, nonce)
    advance_clock(rig.router.root, 89)
    assert len(rig.router.timers()) == 1
    assert rig.router.authorized_keys() == [PLAIN_LINE, RESTRICTED_LINE]
    advance_clock(rig.router.root, 1)
    assert rig.router.timers() == []
    assert rig.router.clock() == 90
    assert rig.router.authorized_keys() == [PLAIN_LINE]
    syslog = rig.router.read("/tmp/syslog")
    assert syslog.count("authorized_keys restored") == 1
    # firing again changes nothing (the timer is gone)
    advance_clock(rig.router.root, 30)
    assert rig.router.authorized_keys() == [PLAIN_LINE]
    assert rig.router.clock() == 120
    assert rig.router.read("/tmp/syslog").count("authorized_keys restored") == 1


def test_deadman_with_proof_line_changes_nothing(rig):
    nonce = "cc" * 16
    rig.router.write("/etc/dropbear/authorized_keys",
                     RESTRICTED_LINE + "\n", mode=0o600)
    rig.router.write("/etc/dropbear/authorized_keys.newton-prev",
                     PLAIN_LINE + "\n", mode=0o600)
    rig.router.write("/tmp/newton/hello",
                     "%s newton-router-agent uptime\n" % nonce)
    arm_deadman(rig, nonce)
    advance_clock(rig.router.root, 95)
    assert rig.router.timers() == []
    assert rig.router.authorized_keys() == [RESTRICTED_LINE]
    assert not (rig.router.root / "fs/tmp/syslog").exists()


def test_fake_sleep_fires_the_deadman(rig):
    nonce = "dd" * 16
    rig.router.write("/etc/dropbear/authorized_keys",
                     PLAIN_LINE + "\n" + RESTRICTED_LINE + "\n", mode=0o600)
    arm_deadman(rig, nonce)
    env = {"FAKE_ROUTER_ROOT": str(rig.router.root), "PATH": os.environ["PATH"]}
    proc = subprocess.run([str(rig.bindir / "fake-sleep"), "95"],
                          capture_output=True, timeout=10, env=env)
    assert proc.returncode == 0
    assert rig.router.timers() == []
    assert rig.router.clock() == 95
    assert rig.router.authorized_keys() == [PLAIN_LINE]
    assert not (rig.bindir / "sleep").exists()
    assert rig.last_call()["tool"] == "sleep"
    assert rig.last_call()["argv"] == ["95"]


def test_decimal_sleep_timer(rig):
    proc = register_timer(
        rig, "sleep 2.5; echo fired > %s/tmp/decimal" % (rig.router.root / "fs"))
    assert proc.returncode == 0
    assert rig.router.timers()[0]["due"] == 2.5
    advance_clock(rig.router.root, 2)
    assert not (rig.router.root / "fs/tmp/decimal").exists()
    assert len(rig.router.timers()) == 1
    advance_clock(rig.router.root, 0.5)
    assert rig.router.timers() == []
    assert rig.router.clock() == 2.5
    assert rig.router.read("/tmp/decimal") == "fired\n"


def test_setsid_other_form_runs_in_foreground(rig):
    proc = register_timer(rig, "logger -t test-setsid foreground-ran")
    assert proc.returncode == 0
    assert rig.router.timers() == []
    assert "foreground-ran" in rig.router.read("/tmp/syslog")


# -- forwarding sessions ----------------------------------

def restricted_rig(rig, vulnerable=None):
    """A router with one restricted key; returns its key path."""
    key, blob = rig.key("fwd")
    rig.router.add_authorized_key(
        'command="/usr/libexec/newton/newton-router",restrict '
        "ssh-ed25519 %s newton-router-agent" % blob)
    if vulnerable is not None:
        rig.router.update_state(vulnerable=vulnerable)
    return key


def forward_args(key, *extra):
    return (["-o", "UserKnownHostsFile=/dev/null"] + key +
            ["-N"] + list(extra) + [DEST])


def test_L_denied_immediate_eof(rig):
    key = restricted_rig(rig)
    port = free_port()
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-L", "127.0.0.1:%d:127.0.0.1:22" % port))
    try:
        conn = wait_listener(port)
        conn.settimeout(5)
        assert conn.recv(64) == b""
        conn.close()
    finally:
        assert reap(proc) == 255


def test_L_allowed_shows_banner(rig):
    key = restricted_rig(rig, vulnerable=["forwarding"])
    port = free_port()
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-L", "127.0.0.1:%d:127.0.0.1:22" % port))
    try:
        conn = wait_listener(port)
        conn.settimeout(5)
        assert conn.recv(64) == b"SSH-2.0-FAKE\r\n"
        conn.close()
    finally:
        assert reap(proc) == 255


def test_L_allowed_with_vulnerable_dict(rig):
    key = restricted_rig(rig, vulnerable={"forwarding": True})
    port = free_port()
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-L", "127.0.0.1:%d:127.0.0.1:22" % port))
    try:
        conn = wait_listener(port)
        conn.settimeout(5)
        assert conn.recv(64).startswith(b"SSH-2.0-FAKE")
        conn.close()
    finally:
        reap(proc)


def _nc_socks(port, timeout=10):
    return subprocess.run(
        ["nc", "-X", "5", "-x", "127.0.0.1:%d" % port, "127.0.0.1", "22"],
        capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)


def test_D_denied_no_ssh_bytes(rig):
    key = restricted_rig(rig)
    port = free_port()
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-D", "127.0.0.1:%d" % port))
    try:
        wait_listener(port).close()
        out = _nc_socks(port).stdout
        assert b"SSH-" not in out
    finally:
        reap(proc)


def test_D_allowed_shows_banner(rig):
    key = restricted_rig(rig, vulnerable=["forwarding"])
    port = free_port()
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-D", "127.0.0.1:%d" % port))
    try:
        wait_listener(port).close()
        assert b"SSH-2.0-FAKE" in _nc_socks(port).stdout
    finally:
        reap(proc)


def test_R_denied_exit_on_forward_failure(rig):
    key = restricted_rig(rig)
    proc = rig.ssh(forward_args(
        rig.key_args(key), "-R", "2200:127.0.0.1:22",
        "-o", "ExitOnForwardFailure=yes"), timeout=10)
    assert proc.returncode == 255
    assert (b"Error: remote port forwarding failed for listen port 2200"
            in proc.stderr)


def test_R_denied_without_exit_on_forward_failure_keeps_running(rig):
    key = restricted_rig(rig)
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-R", "2200:127.0.0.1:22"))
    time.sleep(1.0)
    try:
        assert proc.poll() is None
    finally:
        assert reap(proc) == 255


def test_sigterm_ends_forwarding_session(rig):
    key = restricted_rig(rig, vulnerable=["forwarding"])
    port = free_port()
    proc = rig.start(forward_args(rig.key_args(key),
                                  "-L", "127.0.0.1:%d:127.0.0.1:22" % port))
    try:
        wait_listener(port).close()
        time.sleep(0.2)
        proc.terminate()
        assert proc.wait(timeout=2) == 255
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        proc.stdout.close()
        proc.stderr.close()


# -- scp and sftp ------------------------------------------------

def test_scp_sftp_restricted_principal_fails(rig):
    key, blob = rig.key("scp1")
    rig.router.add_authorized_key(
        'command="/usr/libexec/newton/newton-router",restrict '
        "ssh-ed25519 %s newton-router-agent" % blob)
    local = rig.tmp / "payload"
    local.write_text("data\n")
    common = ["-P", "22", "-i", str(key), "-F", "/dev/null",
              "-o", "UserKnownHostsFile=/dev/null",
              "-o", "StrictHostKeyChecking=yes",
              "-o", "ConnectTimeout=8"]
    proc = rig.run("scp", ["-O"] + common + [str(local), "%s:/tmp/x" % DEST])
    assert proc.returncode == 255
    assert b"scp: Connection closed" in proc.stderr
    proc = rig.run("sftp", common + ["-b", "-", DEST], input=b"put x y\n")
    assert proc.returncode == 255
    assert b"Connection closed" in proc.stderr
    assert rig.last_call()["principal"] == "key:newton-router-agent"
    assert rig.last_call()["stdin_len"] == len(b"put x y\n")


def test_scp_sftp_unrestricted_principal_succeeds(rig):
    key, blob = rig.key("scp2")
    rig.router.add_authorized_key("ssh-ed25519 %s agent-laptop" % blob)
    local = rig.tmp / "payload"
    local.write_text("data\n")
    common = ["-P", "22", "-i", str(key), "-F", "/dev/null",
              "-o", "UserKnownHostsFile=/dev/null",
              "-o", "StrictHostKeyChecking=yes",
              "-o", "ConnectTimeout=8"]
    assert rig.run("scp", common + [str(local),
                                    "%s:/tmp/x" % DEST]).returncode == 0
    assert rig.run("sftp", common + ["-b", "-", DEST],
                   input=b"ls\n").returncode == 0
    # no effect: nothing was written through scp/sftp
    assert not (rig.router.root / "fs/tmp/x").exists()


def test_scp_unsupported_option(rig):
    key, blob = rig.key("scp3")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc = rig.run("scp", ["-Z", str(rig.tmp / "f"), "%s:/tmp/x" % DEST])
    assert proc.returncode == 254
    assert rig.last_call()["unsupported"] == "-Z"


# -- keygen combined short flags (B2 ii) -----------------------------------------

def test_keygen_combined_flags(rig):
    key, blob = rig.key("kc")
    assert rig.run("ssh-keygen", ["-yf", str(key)]).stdout == \
        b"ssh-ed25519 %s\n" % blob.encode()
    kh = rig.tmp / "known_hosts"
    line = "%s %s" % (HOST, rig.router.state()["host_key"])
    kh.write_text(line + "\n")
    digest = base64.b64encode(
        hashlib.sha256(line.encode()).digest()).decode().rstrip("=")
    assert rig.run("ssh-keygen", ["-lf", str(kh)]).stdout.decode() == \
        "256 SHA256:%s %s (ED25519)\n" % (digest, HOST)
    new = rig.tmp / "kc2"
    assert rig.run("ssh-keygen",
                   ["-qt", "ed25519", "-N", "", "-C", "newton-router-p",
                    "-f", str(new)]).returncode == 0
    assert new.read_text().splitlines()[0] == "FAKE-OPENSSH-PRIVATE-KEY"


# -- hostbin extras (B2 iii) ------------------------------------------------------

def test_hostbin_has_sh_and_applets_but_never_sleep(rig):
    hostbin = rig.router.root / "hostbin"
    assert os.readlink(hostbin / "sh") == "/bin/sh"
    assert not (hostbin / "sleep").exists()
    listing = subprocess.run(["/usr/bin/busybox", "--list"],
                             capture_output=True, text=True,
                             timeout=10).stdout.split()
    for name in ("basename", "dirname", "readlink", "stat", "xargs", "cmp",
                 "diff", "expr", "seq", "uniq", "od", "hexdump"):
        assert (hostbin / name).exists() == (name in listing), name
    assert "seq" in listing  # the sanity anchor for this host


def test_unexpanded_rr_in_a_router_command_is_refused(rig):
    key, blob = rig.key("rr1")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    proc = rig.ssh(rig.key_args(key) + [DEST, "cat ${RR}/etc/openwrt_release"])
    assert proc.returncode == 254
    assert rig.last_call()["unexpanded_rr"] is True



def test_rr_inside_a_longer_word_is_not_refused(rig):
    # a sha512-crypt hash is random base64 after each "$"; "$RRClsq..."
    # is another word, not the RR variable, and must not fail a run
    key, blob = rig.key("rr2")
    rig.router.add_authorized_key("ssh-ed25519 %s c" % blob)
    rig.ssh(rig.key_args(key) + [DEST, "echo '$6$salt$RRClsq1' >/dev/null"])
    assert not rig.last_call().get("unexpanded_rr")

# -- fake curl: the Proxmox API -----------------------------

import urllib.parse  # noqa: E402

from router_setup_harness import DEFAULT_STATE  # noqa: E402

PVE = DEFAULT_STATE["pve"]
TOKEN = PVE["token"]
PIN = PVE["pin"]
PVE_URL = "https://pve.test:8006/api2/json/nodes/Apollo"
SNAP_URL = PVE_URL + "/qemu/9102/snapshot"
EXPECTED_UPID = ("UPID:Apollo:0001ABCD:00000001:6700AAAA:qmsnapshot:9102:"
                 "claude@pve!newton:")


def set_pve(rig, **kw):
    """Merge kw into the router's pve knob."""
    pve = rig.router.pve()
    pve.update(kw)
    rig.router.update_state(pve=pve)


def curl(rig, args, config=None):
    """Run the fake curl; config is the list of header lines sent to -K -."""
    data = None
    if config is not None:
        data = "".join('header = "%s"\n' % h for h in config).encode()
    return rig.run("curl", list(args), input=data)


def curl_config(method="POST", form=None, url=SNAP_URL):
    """A well-formed request the way the runner builds it (config on stdin)."""
    args = ["-sk", "--fail", "--max-time", "30", "--pinnedpubkey", PIN,
            "-K", "-", "-X", method]
    for item in form or []:
        args += ["--data-urlencode", item]
    args.append(url)
    return args, ["Authorization: %s" % TOKEN]


def test_pve_state_defaults(rig):
    pve = rig.router.pve()
    assert pve["token"] == TOKEN
    assert pve["pin"] == PIN
    assert pve["node"] == "Apollo"
    assert pve["vms"] == {"9102": {"snapshots": []}}
    assert pve["task_polls"] == 1
    assert pve["task_exit"] == "OK"
    assert pve["fail"] is None
    assert rig.router.snapshots("9102") == []
    assert rig.router.snapshots("999") == []


def test_curl_snapshot_records_and_returns_upid(rig):
    args, config = curl_config(form=["snapname=baseline-newton-1-0-0"])
    proc = curl(rig, args, config)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.decode())["data"] == EXPECTED_UPID
    assert rig.router.snapshots("9102") == ["baseline-newton-1-0-0"]
    call = rig.last_call()
    assert call["tool"] == "curl" and call["rc"] == 0
    assert call["url"] == SNAP_URL and call["method"] == "POST"
    stdin = ('header = "Authorization: %s"\n' % TOKEN).encode()
    assert call["stdin_len"] == len(stdin)
    assert call["stdin_sha256"] == hashlib.sha256(stdin).hexdigest()
    assert call["leaks"] == []


def test_curl_task_poll_sequence(rig):
    set_pve(rig, task_polls=2)
    status_url = PVE_URL + "/tasks/%s/status" % \
        urllib.parse.quote(EXPECTED_UPID, safe="")
    args, config = curl_config(method="GET", url=status_url)
    replies = [json.loads(curl(rig, args, config).stdout.decode())["data"]
               for _ in range(3)]
    assert replies == [
        {"status": "running"},
        {"status": "running"},
        {"status": "stopped", "exitstatus": "OK"},
    ]


def test_curl_wrong_token_changes_nothing(rig):
    before = rig.router.state()
    args = curl_config()[0]
    proc = curl(rig, args, ["Authorization: PVEAPIToken=claude@pve!newton=wrong"])
    assert proc.returncode == 22
    assert proc.stderr
    assert rig.router.state() == before
    assert rig.router.snapshots("9102") == []


def test_curl_wrong_pin_changes_nothing(rig):
    before = rig.router.state()
    args, config = curl_config()
    proc = curl(rig, ["-sk", "--fail", "--max-time", "30",
                      "--pinnedpubkey", "sha256//WRONGPIN=", "-K", "-",
                      "-X", "POST", SNAP_URL], config)
    assert proc.returncode == 22
    assert rig.router.state() == before


def test_curl_bad_snapshot_name(rig):
    for name in ("1bad", "has space", "-x", ""):
        args, config = curl_config(form=["snapname=%s" % name])
        proc = curl(rig, args, config)
        assert proc.returncode == 22, name
        assert json.loads(proc.stdout.decode())["data"] is None
    assert rig.router.snapshots("9102") == []


def test_curl_unknown_vm_and_node(rig):
    for url in (PVE_URL.replace("Apollo", "Zeus") + "/qemu/9102/snapshot",
                PVE_URL + "/qemu/999/snapshot"):
        args, config = curl_config(url=url)
        proc = curl(rig, args, config)
        assert proc.returncode == 22, url
        assert json.loads(proc.stdout.decode())["data"] is None
    assert rig.router.snapshots("9102") == []


def test_curl_duplicate_snapshot_name(rig):
    args, config = curl_config(form=["snapname=snap-a"])
    assert curl(rig, args, config).returncode == 0
    proc = curl(rig, args, config)
    assert proc.returncode == 22
    assert rig.router.snapshots("9102") == ["snap-a"]


def test_curl_fail_knob(rig):
    set_pve(rig, fail="pve is down for maintenance")
    args, config = curl_config()
    proc = curl(rig, args, config)
    assert proc.returncode == 22
    assert b"pve is down for maintenance" in proc.stderr
    assert rig.router.snapshots("9102") == []


def test_curl_token_in_argv_is_a_leak_but_config_is_not(rig):
    rig.router.register_secrets(TOKEN)
    # the token in a -H argument shows up as an argv leak
    proc = curl(rig, ["-sk", "--fail", "--pinnedpubkey", PIN,
                      "-H", "Authorization: %s" % TOKEN,
                      "-X", "POST", "-d", "snapname=leaky", SNAP_URL])
    assert proc.returncode == 0
    assert "argv" in rig.last_call()["leaks"]
    # the same request through -K - does not
    args, config = curl_config(form=["snapname=clean"])
    proc = curl(rig, args, config)
    assert proc.returncode == 0
    assert rig.last_call()["leaks"] == []
    assert rig.router.snapshots("9102") == ["leaky", "clean"]


def test_curl_unsupported_option(rig):
    for args in ([ "--compressed", SNAP_URL],
                 ["-Z", SNAP_URL],
                 ["-K", "cfg", SNAP_URL],
                 ["-sk", SNAP_URL, SNAP_URL]):
        proc = curl(rig, args)
        assert proc.returncode == 254, args
        assert rig.last_call()["unsupported"]
    assert rig.router.snapshots("9102") == []
