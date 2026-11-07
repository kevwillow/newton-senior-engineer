"""Self-tests of router_setup_env: the fixture code
files, build_src, SetupEnv (run, leaks, snapshot, calls_since) and the two
pytest fixtures.  The real tool is never run; a stand-in script replaces it."""

import hashlib
import hmac
import io
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

Failed = pytest.fail.Exception

sys.path.insert(0, str(Path(__file__).resolve().parent))

from router_setup_env import (FIXTURES, SetupEnv, build_src,  # noqa: E402
                              pulsar_env, setup_env)  # noqa: F401

NONCE = "0123456789abcdef0123456789abcdef"
NONCE2 = "fedcba9876543210fedcba9876543210"
HOST = "10.1.2.3"

CODE_MAP = (
    ("device/openwrt/newton-router/newton-router",
     "usr/libexec/newton/newton-router"),
    ("scripts/owrt-safe-apply.sh",
     "usr/libexec/newton/newton-safe-apply"),
    ("device/openwrt/newton-guard/newton-guard",
     "usr/libexec/newton-guard"),
    ("device/openwrt/newton-guard/newton-guard.init",
     "etc/init.d/newton-guard"),
)


# -- helpers -----------------------------------------------------------------

def ssh(env, args, stdin=b"", key=None, options=(), extra_env=None):
    """Run the fake ssh like the tool would."""
    cmd = [str(env.fakes / "ssh"), "-F", "/dev/null"]
    for opt in options:
        cmd += ["-o", opt]
    if key is not None:
        cmd += ["-i", str(key)]
    cmd += ["root@%s" % HOST] + list(args)
    env_ = dict(os.environ)
    if extra_env:
        env_.update(extra_env)
    return subprocess.run(cmd, input=stdin, capture_output=True,
                          env=env_, timeout=60)


def make_key(env, name):
    """A key pair through the fake ssh-keygen; returns (path, pub line)."""
    path = env.tmp / name
    proc = subprocess.run(
        [str(env.fakes / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
         "-C", name, "-f", str(path)], capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return path, path.with_name(path.name + ".pub").read_text().strip()


def install_code(env, program="ok", version="1.0.0"):
    """build_src and install the four files into the router fs."""
    src = build_src(env.tmp / "code", program=program, version=version)
    for rel, router_path in CODE_MAP:
        env.router.write(router_path, (src / rel).read_text(), mode=0o755)
    return src


def add_restricted(env, name, caller, role):
    """Put a restricted forced-command line on the router; returns the key."""
    key, pub = make_key(env, name)
    keytype, blob = pub.split()[0], pub.split()[1]
    env.router.add_authorized_key(
        'restrict,command="/usr/libexec/newton/newton-router '
        '--caller=%s --role=%s" %s %s newton-router-%s'
        % (caller, role, keytype, blob, caller))
    return key


def direct_env(tmp_path, program="ok", version="1.0.0"):
    """A SetupEnv with an unrestricted admin key and the code installed."""
    env = SetupEnv(tmp_path)
    key, pub = make_key(env, "admin")
    env.router.add_authorized_key(pub)
    install_code(env, program=program, version=version)
    env.admin_key = key
    return env


def rr(env):
    """The NEWTON_SETUP_REMOTE_ROOT value (the router fs)."""
    return str(env.router.root / "fs")


CANON = "/usr/libexec/newton/newton-router"


def prog(env):
    """The router path of the fixture program, RR-prefixed like the tool."""
    return rr(env) + "/usr/libexec/newton/newton-router"


def parse_hello(text):
    """The key=value words of a hello line."""
    fields = {}
    for word in text.split()[2:]:
        key, _, value = word.partition("=")
        fields[key] = value
    return fields


def stand_in_tool(env, body):
    """Write the stand-in tool script; returns its path."""
    path = env.tmp / "stand-in"
    path.write_text(body)
    path.chmod(0o755)
    return path


# -- build_src -------------------------------------------------

def test_build_src_layout(tmp_path):
    src = build_src(tmp_path / "src")
    fixture_of = {
        "device/openwrt/newton-router/newton-router": "newton-router",
        "scripts/owrt-safe-apply.sh": "newton-safe-apply",
        "device/openwrt/newton-guard/newton-guard": "newton-guard",
        "device/openwrt/newton-guard/newton-guard.init": "newton-guard.init",
    }
    for rel, fixture in fixture_of.items():
        target = src / rel
        assert target.read_bytes() == (FIXTURES / fixture).read_bytes()
        assert stat.S_IMODE(target.stat().st_mode) & 0o111
    program = (src / "device/openwrt/newton-router/newton-router").read_text()
    assert program.startswith("#!/usr/bin/python3\n")
    assert not any(line.startswith("# FIXTURE-VERSION")
                   for line in program.splitlines())
    assert not any(line.startswith("# FIXTURE-BROKEN")
                   for line in program.splitlines())


def test_build_src_markers(tmp_path):
    src = build_src(tmp_path / "src", program="broken", version="9.9.9")
    program = (src / "device/openwrt/newton-router/newton-router").read_text()
    assert "# FIXTURE-VERSION 9.9.9\n" in program
    assert "# FIXTURE-BROKEN\n" in program
    # the other three files are untouched by the markers
    guard = (src / "device/openwrt/newton-guard/newton-guard")
    assert guard.read_bytes() == (FIXTURES / "newton-guard").read_bytes()


# -- hello through the fake ssh (design 2.6) --------------------

def test_hello_direct_fields(tmp_path):
    env = direct_env(tmp_path)
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    assert proc.returncode == 0, proc.stderr
    line = proc.stdout.decode().strip()
    assert line.split()[:2] == ["hello", NONCE]
    fields = parse_hello(line)
    assert fields["api"] == "1"
    assert fields["version"] == "1.0.0"
    assert fields["mode"] == "prod"
    for name, router_path in (("prog", "usr/libexec/newton/newton-router"),
                              ("helper", "usr/libexec/newton/newton-safe-apply"),
                              ("guard", "usr/libexec/newton-guard"),
                              ("init", "etc/init.d/newton-guard")):
        expect = hashlib.sha256(
            env.router.path(router_path).read_bytes()).hexdigest()
        assert fields[name] == expect
    assert fields["device"] == "-"
    assert fields["profile"] == "prod"
    assert fields["approval-key"] == "missing"
    assert fields["guard-state"] == "idle"
    assert fields["busy"] == "-"
    assert fields["caller"] == "root"
    assert fields["role"] == "change"
    assert fields["door"] == "root"
    assert fields["tty"] == "0"
    assert fields["agent"] == "0"
    assert fields["from"] == "127.0.0.1"
    # direct mode never writes the hello log
    assert not env.router.path("tmp/newton/hello").exists()


def test_hello_direct_state_files(tmp_path):
    env = direct_env(tmp_path)
    env.router.write("etc/newton/device-id", "r1\n")
    env.router.write("etc/newton/profile", "lab\n")
    env.router.write("etc/newton/approve.key", "ab" * 32 + "\n")
    env.router.write("etc/newton/guard-state", "restored t=5\n")
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    fields = parse_hello(proc.stdout.decode())
    assert fields["device"] == "r1"
    assert fields["profile"] == "lab"
    assert fields["approval-key"] == "present"
    assert fields["guard-state"] == "restored"
    # the 2.1 rule: anything else than lab means prod
    env.router.write("etc/newton/profile", "junk\n")
    fields = parse_hello(ssh(env, [prog(env), "hello", NONCE],
                             key=env.admin_key).stdout.decode())
    assert fields["profile"] == "prod"


def test_hello_forced(tmp_path):
    env = direct_env(tmp_path)
    key = add_restricted(env, "agent", "lab-agent", "read")
    (env.router.root / "clock").write_text("777\n")
    # the request may carry the canonical program path (shifted off, design 3.2
    # step 6) or not; a prefixed path of the fake fs is not the program path
    proc = ssh(env, ["/usr/libexec/newton/newton-router", "hello", NONCE], key=key)
    assert proc.returncode == 0, proc.stderr
    bare = ssh(env, ["hello", NONCE], key=key)
    assert bare.returncode == 0, bare.stderr
    assert bare.stdout == proc.stdout
    wrong = ssh(env, [prog(env), "hello", NONCE], key=key)
    assert wrong.returncode == 2 and b"error bad-character" in wrong.stderr
    fields = parse_hello(proc.stdout.decode())
    assert fields["caller"] == "lab-agent"
    assert fields["role"] == "read"
    assert fields["door"] == "ssh"
    assert env.router.path("tmp/newton/hello").read_text() == \
        "%s lab-agent 777\n" * 2 % (NONCE, NONCE)


def test_hello_forced_log_keeps_64_lines(tmp_path):
    env = direct_env(tmp_path)
    key = add_restricted(env, "agent", "lab-agent", "change")
    for i in range(70):
        nonce = "%032x" % i
        proc = ssh(env, [CANON, "hello", nonce], key=key)
        assert proc.returncode == 0, proc.stderr
    lines = env.router.path("tmp/newton/hello").read_text().splitlines()
    assert len(lines) == 64
    assert lines[0].split()[0] == "%032x" % 6
    assert lines[-1].split()[0] == "%032x" % 69


def test_hello_mode_test_with_setenv(tmp_path):
    env = direct_env(tmp_path)
    env.router.update_state(vulnerable=["setenv"])
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key,
               options=["SetEnv=NEWTON_ROUTER_ROOT=/tmp"])
    assert parse_hello(proc.stdout.decode())["mode"] == "test"


def test_hello_agent_flag(tmp_path):
    env = direct_env(tmp_path)
    cmd = [str(env.fakes / "ssh"), "-F", "/dev/null", "-A",
           "-i", str(env.admin_key), "root@%s" % HOST,
           prog(env), "hello", NONCE]
    env_ = dict(os.environ, SSH_AUTH_SOCK="/tmp/agent.sock")
    proc = subprocess.run(cmd, capture_output=True, env=env_, timeout=60)
    assert parse_hello(proc.stdout.decode())["agent"] == "1"


def test_hello_missing_code_file(tmp_path):
    env = direct_env(tmp_path)
    env.router.path("usr/libexec/newton-guard").unlink()
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    assert proc.returncode == 1
    fields = parse_hello(proc.stdout.decode())
    assert fields["guard"] == "missing"
    assert fields["prog"] != "missing"


def test_hello_version_marker(tmp_path):
    env = direct_env(tmp_path, version="2.3.4")
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    assert parse_hello(proc.stdout.decode())["version"] == "2.3.4"


def test_fixture_lie_overrides_hello_words(tmp_path):
    env = direct_env(tmp_path)
    env.router.write("etc/newton/fixture-lie",
                     "prog=%s\nmode=test\n" % ("0" * 64))
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    fields = parse_hello(proc.stdout.decode())
    assert fields["prog"] == "0" * 64
    assert fields["mode"] == "test"


# -- probe, approval-selftest, backup (design 3.5) --------------

def test_probe(tmp_path):
    env = direct_env(tmp_path)
    proc = ssh(env, [prog(env), "probe"], stdin=b"fail\n", key=env.admin_key)
    assert proc.returncode == 1
    assert proc.stdout.decode().strip() == "probe fail fail planted"
    proc = ssh(env, [prog(env), "probe"], stdin=b"uptime\n", key=env.admin_key)
    assert proc.returncode == 2
    assert proc.stderr.decode().strip() == "error bad-probe 1 unknown-probe"


def test_approval_selftest_direct(tmp_path):
    env = direct_env(tmp_path)
    env.router.write("etc/newton/approve.key", "5f" * 32 + "\n")
    proc = ssh(env, [prog(env), "approval-selftest", NONCE],
               key=env.admin_key)
    assert proc.returncode == 0, proc.stderr
    expect = hmac.new(bytes.fromhex("5f" * 32),
                      b"newton-selftest-v1\n" + NONCE.encode() + b"\n",
                      hashlib.sha256).hexdigest()
    assert proc.stdout.decode().strip() == \
        "approval-selftest %s %s" % (NONCE, expect)


def test_fixture_lie_overrides_selftest_hmac(tmp_path):
    env = direct_env(tmp_path)
    env.router.write("etc/newton/approve.key", "5f" * 32 + "\n")
    env.router.write("etc/newton/fixture-lie", "selftest=%s\n" % ("a" * 64))
    proc = ssh(env, [prog(env), "approval-selftest", NONCE],
               key=env.admin_key)
    assert proc.returncode == 0
    assert proc.stdout.decode().strip() == \
        "approval-selftest %s %s" % (NONCE, "a" * 64)


def test_approval_selftest_refusals(tmp_path):
    env = direct_env(tmp_path)
    key = add_restricted(env, "agent", "lab-agent", "change")
    proc = ssh(env, [CANON, "approval-selftest", NONCE], key=key)
    assert proc.returncode == 3
    assert proc.stderr.decode().strip() == "error direct-only"
    proc = ssh(env, [prog(env), "approval-selftest", NONCE],
               key=env.admin_key)
    assert proc.returncode == 3
    assert proc.stderr.decode().strip() == "error approval-key-missing"
    env.router.write("etc/newton/approve.key", "nothex\n")
    proc = ssh(env, [prog(env), "approval-selftest", NONCE],
               key=env.admin_key)
    assert proc.returncode == 3
    assert proc.stderr.decode().strip() == "error approval-key-missing"


def test_backup_change_role(tmp_path):
    env = direct_env(tmp_path)
    env.router.write("etc/config/network", "config interface 'lan'\n")
    proc = ssh(env, [prog(env), "backup"], key=env.admin_key)
    assert proc.returncode == 0, proc.stderr
    with tarfile.open(mode="r:gz", fileobj=io.BytesIO(proc.stdout)) as tar:
        names = tar.getnames()
    assert "etc/config" in names
    assert "etc/config/network" in names


def test_backup_read_role_denied(tmp_path):
    env = direct_env(tmp_path)
    key = add_restricted(env, "reader", "lab-reader", "read")
    proc = ssh(env, [CANON, "backup"], key=key)
    assert proc.returncode == 3
    assert proc.stderr.decode().strip() == "error role"


# -- grammar errors and the broken marker ----------------------

def test_grammar_errors(tmp_path):
    env = direct_env(tmp_path)
    forced_key = add_restricted(env, "agent", "lab-agent", "change")
    # forced key, no client command: no SSH_ORIGINAL_COMMAND
    proc = ssh(env, [], key=forced_key)
    assert proc.returncode == 2
    assert proc.stderr.decode().strip() == "error empty-request"
    cases = [
        ([prog(env), "frobnicate"], "error unknown-subcommand"),
        ([prog(env), "hello"], "error arg-count"),
        ([prog(env), "hello", NONCE, NONCE2], "error arg-count"),
        ([prog(env), "hello", "zz"], "error bad-arg 1"),
        ([prog(env), "hello=a"], "error bad-character"),
    ]
    for args, message in cases:
        proc = ssh(env, args, key=env.admin_key)
        assert proc.returncode == 2, (args, proc.stderr)
        assert proc.stderr.decode().strip() == message, args
    # a half-mode key line cannot travel as an ssh command (its words look
    # like ssh options), so run the program directly for bad-key-line
    proc = subprocess.run(
        [env.router.path("usr/libexec/newton/newton-router"),
         "--caller=x", "--role=change"],
        capture_output=True, timeout=30,
        env=dict(os.environ, FAKE_ROUTER_FS=str(env.router.root / "fs")))
    assert proc.returncode == 2
    assert proc.stderr.decode().strip() == "error bad-key-line"


def test_broken_program(tmp_path):
    env = direct_env(tmp_path, program="broken")
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    assert proc.returncode == 3
    assert proc.stdout == b""
    assert proc.stderr == b""


# -- guard and init scripts ------------------------------------

def test_guard_script(tmp_path):
    env = direct_env(tmp_path)
    guard = rr(env) + "/usr/libexec/newton-guard"
    proc = ssh(env, [guard, "status"], key=env.admin_key)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.decode().strip() == "idle"
    env.router.write("etc/newton/guard-state", "restored t=5 boot\nsecond line\n")
    proc = ssh(env, [guard, "status"], key=env.admin_key)
    assert proc.stdout.decode() == "restored t=5 boot\n"
    proc = ssh(env, [guard, "restore"], key=env.admin_key)
    assert proc.stdout.decode().strip() == "restore"
    proc = ssh(env, [guard, "confirm"], key=env.admin_key)
    assert proc.stdout.decode().strip() == "confirm"


def test_guard_init_script(tmp_path):
    env = direct_env(tmp_path)
    init = rr(env) + "/etc/init.d/newton-guard"
    assert ssh(env, [init, "enable"], key=env.admin_key).returncode == 0
    link = env.router.path("etc/rc.d/S09newton-guard")
    assert link.is_symlink()
    assert os.readlink(link) == "../init.d/newton-guard"
    assert ssh(env, [init, "disable"], key=env.admin_key).returncode == 0
    assert not link.exists()


# -- SetupEnv.run with a stand-in tool --------------------------

def test_run_seams_typed_and_calls(tmp_path):
    env = direct_env(tmp_path)
    body = """#!/bin/sh
set -eu
: "${NEWTON_SETUP_SEAMS:?}" "${NEWTON_SETUP_BIN:?}" "${NEWTON_SETUP_TTY:?}"
: "${NEWTON_SETUP_SLEEP:?}" "${NEWTON_SETUP_SRC:?}" "${NEWTON_SETUP_REMOTE_ROOT:?}"
: "${NEWTON_INVENTORY:?}" "${NEWTON_KEYS_DIR:?}" "${NEWTON_LAB_TOML:?}" "${NEWTON_TRUSTED_KNOWN_HOSTS:?}"
a=$(sed -n 1p "$NEWTON_SETUP_TTY")
b=$(sed -n 2p "$NEWTON_SETUP_TTY")
echo "INFO typed=$a/$b"
"$NEWTON_SETUP_SLEEP" 5
ssh -F /dev/null -i %s root@%s "$NEWTON_SETUP_REMOTE_ROOT/usr/libexec/newton/newton-router" hello %s
echo "DONE stand-in %s"
""" % (env.admin_key, HOST, NONCE, env.device)
    env.tool = stand_in_tool(env, body)
    result = env.run("r1", "check", typed=("alpha", "beta"))
    assert result.rc == 0
    assert result.lines("INFO ") == ["INFO typed=alpha/beta"]
    assert result.lines("DONE ") == ["DONE stand-in r1"]
    tools = [call["tool"] for call in result.calls]
    assert "sleep" in tools and "ssh" in tools
    assert env.router.clock() >= 5
    # the second run sees only its own calls
    result2 = env.run("r1", "check")
    assert result2.calls
    assert all(call["n"] > result.calls[-1]["n"] for call in result2.calls)


def test_run_times_out_and_kills_the_group(tmp_path):
    env = direct_env(tmp_path)
    env.tool = stand_in_tool(env, "#!/bin/sh\nsleep 30\n")
    with pytest.raises(Failed):
        env.run("r1", "check", timeout=2)


def test_run_fails_on_bad_fake_calls(tmp_path):
    env = direct_env(tmp_path)
    bodies = {
        "unsupported": "#!/bin/sh\nssh -Y root@%s true\n" % HOST,
        "syntax_error": '#!/bin/sh\nssh -F /dev/null -i %s root@%s '
                        '"if then fi"\n' % (env.admin_key, HOST),
        "unexpanded_rr": "#!/bin/sh\nssh -F /dev/null -i %s root@%s "
                         "'${RR}true'\n" % (env.admin_key, HOST),
    }
    for kind, body in bodies.items():
        env.tool = stand_in_tool(env, body)
        with pytest.raises(Failed):
            env.run("r1", "check")


def test_calls_since(tmp_path):
    env = direct_env(tmp_path)
    env.calls_since()  # swallow the setup calls (the fake ssh-keygen)
    assert env.calls_since() == []
    ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    second = env.calls_since()
    assert len(second) == 1
    assert second[0]["tool"] == "ssh"
    assert env.calls_since() == []


# -- leaks -----------------------------------------------------

def test_leaks_finds_planted_secrets(tmp_path):
    env = direct_env(tmp_path)
    secret = "s3cret-typed-value"
    env.register_secrets(secret)
    # a planted file under the tmp tree
    (env.tmp / "scratch.txt").write_text("leak " + secret + "\n")
    # the tool output leaks the typed secret
    env.tool = stand_in_tool(env, '#!/bin/sh\nsed -n 1p "$NEWTON_SETUP_TTY"\n')
    result = env.run("r1", "check", typed=(secret,))
    assert secret in result.out
    # an argv leak through the fake ssh
    subprocess.run([str(env.fakes / "ssh"), "-F", "/dev/null",
                    "root@%s" % HOST, "echo", secret],
                   capture_output=True, timeout=30)
    found = env.leaks()
    assert "file:scratch.txt" in found
    assert "output" in found
    assert any(":argv" in item for item in found)
    assert not any("secrets.json" in item for item in found)
    # approve.key holding the secret is ignored
    env.router.write("etc/newton/approve.key", secret + "\n")
    assert not any("approve.key" in item for item in env.leaks())


def test_leaks_empty_without_a_leak(tmp_path):
    env = direct_env(tmp_path)
    env.register_secrets("quiet-secret")
    env.tool = stand_in_tool(env, '#!/bin/sh\necho "INFO nothing"\n')
    env.run("r1", "check", typed=("quiet-secret",))
    assert env.leaks() == []


# -- snapshot --------------------------------------------------

def test_snapshot_stable_and_changed(tmp_path):
    env = direct_env(tmp_path)
    before = env.router.snapshot()
    assert env.router.snapshot() == before
    # a direct hello writes nothing outside tmp/
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.admin_key)
    assert proc.returncode == 0
    assert env.router.snapshot() == before
    env.router.write("etc/newton/device-id", "r1\n")
    after = env.router.snapshot()
    assert after != before
    assert "etc/newton/device-id" in after


# -- the pytest fixtures ---------------------------------------

def test_setup_env_fixture(setup_env):
    env = setup_env
    assert env.device == "r1"
    assert env.profile == "lab"
    text = env.inventory.read_text()
    assert "[devices.r1]" in text
    assert 'profile = "lab"' in text
    assert 'auth = "password"' in text
    assert env.keys_dir.is_dir()
    assert env.lab_toml.read_text() == ""
    assert env.known_hosts.name == "r1.known_hosts"
    assert not env.known_hosts.exists()
    assert env.plain_key is None
    # the typed-input file lives outside the scanned tmp tree
    assert not env.typed_file.resolve().is_relative_to(env.tmp.resolve())


def test_pulsar_env_fixture(pulsar_env):
    env = pulsar_env
    assert env.device == "pulsar"
    assert env.profile == "prod"
    assert env.plain_key is not None and env.plain_key.exists()
    pub = Path(str(env.plain_key) + ".pub").read_text().strip()
    assert pub in env.router.authorized_keys()
    install_code(env)
    proc = ssh(env, [prog(env), "hello", NONCE], key=env.plain_key)
    assert proc.returncode == 0, proc.stderr
    assert parse_hello(proc.stdout.decode())["mode"] == "prod"


def test_leaks_ignores_the_fake_routers_own_config(tmp_path):
    # state.json holds root_password by design; registering it must not make
    # every run report a leak
    env = SetupEnv(tmp_path)
    env.register_secrets(env.router.state()["root_password"])
    assert env.leaks() == []


def test_default_tool_follows_router_setup_tool_env(tmp_path):
    # ROUTER_SETUP_TOOL redirects DEFAULT_TOOL (a snapshot of the tool)
    code = "import router_setup_env as e; print(e.DEFAULT_TOOL)"
    here = str(Path(__file__).resolve().parent)
    env = dict(os.environ, PYTHONPATH=here, ROUTER_SETUP_TOOL=str(tmp_path / "snap"))
    out = subprocess.run([sys.executable, "-c", code], env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == str(tmp_path / "snap")
    env.pop("ROUTER_SETUP_TOOL")
    out = subprocess.run([sys.executable, "-c", code], env=env,
                         capture_output=True, text=True, timeout=60)
    assert out.stdout.strip().endswith("scripts/newton-router-setup")
