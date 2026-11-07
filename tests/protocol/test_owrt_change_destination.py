"""INJ-1 and U-8 for scripts/owrt-change.sh.

INJ-1: the ssh destination is an argv word of every ssh call.  A
destination that does not look like `user@host` is refused before any ssh
call, and the ssh argv carries `--` before the destination so a value that
starts with a dash can never be read as an option.

U-8: the router-supplied hello tokens reach the die text only through
`oneline`, so a token cannot forge a line, smuggle a control character or
grow the message without bound.

The fake ssh is the one of test_owrt_change.py, reduced to what these
checks need: it records its argv and answers the hello call with the reply
the test hands it.  Like the other tests of the script, the fake is
bind-mounted over /usr/bin/ssh inside a private user+mount namespace
(the script resolves ssh through that path, never through PATH).
"""

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "owrt-change.sh"
PROG = "/usr/libexec/newton/newton-router"

FAKE_SSH = """\
#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["STUB_ROOT"])
argv = sys.argv[1:]
with (root / "ssh-argv.log").open("a") as handle:
    handle.write(json.dumps(argv) + "\\n")
dest = argv.index("--") + 1 if "--" in argv else None
if dest is None:
    for index, arg in enumerate(argv):
        if "@" in arg:
            dest = index
            break
if dest is None:
    sys.stderr.write("fake ssh: no destination in argv\\n")
    sys.exit(127)
cmd = " ".join(argv[dest + 1:])
reply = os.environ.get("FAKE_HELLO_HEX", "")
if reply and " hello " in cmd:
    nonce = cmd.split()[-1].encode("utf-8")
    sys.stdout.buffer.write(bytes.fromhex(reply).replace(b"{nonce}", nonce) + b"\\n")
    sys.exit(0)
sys.stderr.write("fake ssh: unreachable\\n")
sys.exit(255)
"""


def _unshare_ssh_or_skip():
    """The script resolves ssh via /usr/bin/ssh (with /bin/ssh fallback).
    The fake ssh must therefore be exposed there; bind-mount the fake onto
    /usr/bin/ssh inside a fresh user+mount namespace.  Skip when
    ``unshare -Urm`` is not available (no fake can be installed at
    /usr/bin/ssh without it)."""
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable; cannot bind-mount a fake ssh over /usr/bin/ssh")
    probe = subprocess.run(
        [unshare, "-Urm", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Urm is unavailable: {reason}")


@pytest.fixture
def host(tmp_path):
    _unshare_ssh_or_skip()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    ssh = bindir / "ssh"
    ssh.write_text(textwrap.dedent(FAKE_SSH))
    ssh.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    # the script refuses a state dir parent that is group- or
    # world-writable without the sticky bit
    os.chmod(state, 0o700)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(tmp_path),
            "XDG_STATE_HOME": str(state),
            "OWRT_AUDIT_LOG": str(tmp_path / "audit.log"),
            "OWRT_BACKUP_DIR": str(tmp_path / "backups"),
            "OWRT_SRC_ROOT": str(SCRIPT.parents[1]),
            "STUB_ROOT": str(tmp_path),
            "PATH": str(bindir) + os.pathsep + env.get("PATH", ""),
        }
    )
    for key in (
        "OWRT_SSH_PASSWORD_FILE",
        "OWRT_SSH_PROXY",
        "OWRT_LOCAL_CHECK",
        "OWRT_APPROVAL_TOKEN",
        "OWRT_SSH_KEY",
        "OWRT_KNOWN_HOSTS",
        "OWRT_EXPECT_DEVICE",
        "OWRT_EXPECT_PROFILE",
    ):
        env.pop(key, None)

    def run(*args, extra_env=None, timeout_s=60):
        run_env = env.copy()
        if extra_env:
            run_env.update(extra_env)
        argv = [
            "unshare", "-Urm", "--", "bash", "-c",
            'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
            "noop", str(ssh), str(SCRIPT), *args,
        ]
        return subprocess.run(
            argv, env=run_env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=timeout_s,
        )

    def ssh_argv():
        log = tmp_path / "ssh-argv.log"
        if not log.exists():
            return []
        return [json.loads(line)
                for line in log.read_text().splitlines() if line.strip()]

    return {"run": run, "ssh_argv": ssh_argv, "root": tmp_path, "env": env}


def hello_reply(**overrides):
    """The hello reply the fake ssh sends: one line, `hello <nonce>` and
    the key=value fields the handshake reads.  {nonce} is replaced by the
    nonce the script asked for."""
    fields = {
        "api": "1",
        "version": "1.0.0",
        "mode": "prod",
        # a sha that is not the controller's: the handshake compares it
        "prog": "0" * 64,
        "helper": "0" * 64,
        "guard": "0" * 64,
        "init": "0" * 64,
        "device": "lab-r1",
        "profile": "prod",
        "guard-state": "idle",
        "busy": "-",
        "caller": "root",
    }
    fields.update(overrides)
    return "hello {nonce} " + " ".join("%s=%s" % item for item in fields.items())


def run_with_hello(host, reply, *args):
    """Run the script with the fake ssh answering the hello call."""
    return host["run"](
        *args, extra_env={"FAKE_HELLO_HEX": reply.encode("utf-8").hex()}
    )


# --- INJ-1: the destination is shape-checked before any ssh call ---------

@pytest.mark.parametrize(
    "destination",
    [
        "-oProxyCommand=x@h",
        "root@-h",
        "root@h;id",
        "root@h h",
        "root@",
        "@h",
    ],
)
def test_bad_destination_is_refused_before_any_ssh_call(host, destination):
    r = host["run"]("backup", destination)
    assert r.returncode != 0
    assert "router destination must look like [user@]host" in r.stdout
    assert host["ssh_argv"]() == []


def test_destination_with_a_newline_is_refused_before_any_ssh_call(host):
    """A control character in any argument is refused above the audit log
    and every ssh call."""
    r = host["run"]("backup", "root@h\nid")
    assert r.returncode == 2
    assert "control character" in r.stdout
    assert host["ssh_argv"]() == []


@pytest.mark.parametrize(
    "destination", ["root@192.0.2.1", "root@router1.example.invalid", "router1", "192.0.2.1"]
)
def test_good_destination_reaches_ssh_with_a_double_dash(host, destination):
    r = host["run"]("backup", destination)
    assert host["ssh_argv"](), "the script never called ssh"
    argv = host["ssh_argv"]()[0]
    assert "--" in argv
    # the destination is the word right after the end-of-options marker
    assert argv[argv.index("--") + 1] == destination
    assert argv.index("--") == len(argv) - 3


# --- U-8: the hello tokens reach the die text through oneline ------------

def test_api_token_in_the_die_text_goes_through_oneline(host):
    r = run_with_hello(
        host, hello_reply(api="2\u2028x"), "backup", "root@192.0.2.1"
    )
    assert r.returncode != 0
    # the U+2028 became a space, so the token is one line of one field
    assert "api=2 x" in r.stdout
    assert "\u2028" not in r.stdout


def test_mode_token_in_the_die_text_goes_through_oneline(host):
    r = run_with_hello(
        host, hello_reply(mode="lab\u2028x"), "backup", "root@192.0.2.1"
    )
    assert r.returncode != 0
    assert "mode=lab x" in r.stdout
    assert "\u2028" not in r.stdout


def test_version_token_in_the_die_text_goes_through_oneline(host):
    r = run_with_hello(
        host, hello_reply(version="1.0.0\u202ev\u2028x"), "backup", "root@192.0.2.1"
    )
    assert r.returncode != 0
    assert "v x" in r.stdout
    assert "\u2028" not in r.stdout


def test_long_hello_token_is_cut_to_120_characters(host):
    """oneline caps a field at 120 characters, so a long token cannot grow
    the die text without bound."""
    r = run_with_hello(
        host, hello_reply(version="z" * 200), "backup", "root@192.0.2.1"
    )
    assert r.returncode != 0
    assert r.stdout.count("z") == 120


def test_hash_prefix_in_the_mismatch_text_goes_through_oneline(host):
    """The 8-character prefix of a router-reported hash is router text too."""
    r = run_with_hello(
        host,
        hello_reply(prog="0000 abc" + "0" * 55),
        "backup",
        "root@192.0.2.1",
    )
    assert r.returncode != 0
    assert "prog 0000 abc..." in r.stdout
    assert " " not in r.stdout
