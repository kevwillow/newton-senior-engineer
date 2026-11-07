"""The shared SSH CLI runner for non-OpenWrt read-only getters."""

from __future__ import annotations

import dataclasses
from contextlib import contextmanager
import json
import os
import re
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from newton_mcp.adapters.getters import GetterError, fill_command, load_getters
from newton_mcp.adapters.ssh_cli import (
    RATE_LIMIT_S,
    STDERR_CAP,
    STATUSES,
    RunnerRefused,
    SshCliRunner,
    build_argv,
)


PASSWORD = "PW-synthetic-9f3c"

FAKE_SSH = r'''#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time


def record(extra=None):
    value = {
        "argv": sys.argv,
        "env": dict(os.environ),
        "askpass_present": "SSH_ASKPASS" in os.environ,
        "askpass_exists_when_started": (
            os.path.isfile(os.environ["SSH_ASKPASS"])
            if "SSH_ASKPASS" in os.environ
            else False
        ),
        "auth_socket_present": "SSH_AUTH_SOCK" in os.environ,
        "stdin_is_devnull": (
            os.fstat(0).st_rdev == os.stat("/dev/null").st_rdev
        ),
        "stdin_is_tty": os.isatty(0),
        "stdout_is_tty": os.isatty(1),
    }
    if extra:
        value.update(extra)
    with open(os.environ["NEWTON_FAKE_RECORD"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value) + "\n")


mode = os.environ.get("NEWTON_FAKE_MODE", "cisco")
if mode == "cisco":
    record()
    sys.stdout.write("Cisco IOS XE 17.9\n")
elif mode == "nothing":
    record()
elif mode == "spaces":
    record()
    sys.stdout.write("   \n")
elif mode == "invalid":
    record()
    sys.stdout.write("% Invalid input detected at '^' marker.\n")
elif mode == "invalid-ansi":
    record()
    sys.stdout.write("% Inv\x1b[0malid input\n")
elif mode == "row-error":
    record()
    sys.stdout.write("VLAN configuration failed on aggregate interface\n")
elif mode in {"success-missing", "success-present"}:
    record()
    if mode == "success-present":
        sys.stdout.write("Model ABC firmware 17.9\n")
    else:
        sys.stdout.write("firmware 17.9\n")
elif mode == "exit-one":
    record()
    sys.stdout.write("partial output before failure\n")
    sys.exit(1)
elif mode == "kex":
    record()
    sys.stderr.write("kex_exchange_identification: Connection closed\n")
    sys.exit(255)
elif mode == "connection-refused":
    record()
    sys.stderr.write("Connection refused\n")
    sys.exit(255)
elif mode == "permission-denied":
    record()
    sys.stderr.write("user@h: Permission denied (publickey,password).\n")
    sys.exit(255)
elif mode == "host-key":
    record()
    sys.stderr.write("Host key verification failed.\n")
    sys.exit(255)
elif mode == "grandchild-timeout":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    record({"grandchild_pid": child.pid})
    time.sleep(60)
elif mode == "grandchild-exit":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    sys.stdout.write("ok\n")
    record({"grandchild_pid": child.pid})
    sys.exit(0)
elif mode == "escaped-grandchild":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    record({"grandchild_pid": child.pid})
    time.sleep(60)
elif mode == "stream":
    record()
    while True:
        sys.stdout.write("line of output\n")
        sys.stdout.flush()
        time.sleep(0.002)
elif mode == "partial":
    record()
    sys.stdout.write("x" * 5000)
    sys.stdout.flush()
    time.sleep(60)
elif mode == "stderr-flood":
    record()
    sys.stderr.write("e" * 1048576)
    sys.stderr.flush()
    sys.stdout.write("ok\n")
elif mode == "stderr-flood-exit-one":
    record()
    sys.stderr.write("e" * 1048576)
    sys.stderr.flush()
    sys.stdout.write("partial\n")
    sys.exit(1)
elif mode == "escaped-stream":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    record({"grandchild_pid": child.pid})
    while True:
        sys.stdout.write("line of output\n")
        sys.stdout.flush()
        time.sleep(0.002)
else:
    raise SystemExit("unknown fake mode")
'''


@dataclasses.dataclass(frozen=True)
class Target:
    name: str
    platform: str
    host: str
    user: str
    auth: str
    port: int
    password_file: Path | None
    proxy_command: str | None
    key_file: Path | None
    known_hosts: Path | None


class FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def write_getters(path: Path) -> Path:
    path.write_text(
        """
platform = "junos"

[[getter]]
id = "version"
command = "show version"
timeout_s = 3
max_bytes = 16384
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["^."]
error_markers = ["VLAN configuration failed"]

[[getter]]
id = "interfaces"
command = "show interfaces {iface} | no-more"
timeout_s = 3
max_bytes = 4096
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["^."]
params = {iface = "^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$"}

[[getter]]
id = "admins"
command = "show version"
timeout_s = 3
max_bytes = 16384
enabled = true
verified = "unverified"
why = "Synthetic test row."
expect = ["^Model ABC"]
""",
        encoding="utf-8",
    )
    return path


def make_target(
    known_hosts: Path,
    **changes: Any,
) -> Target:
    values: dict[str, Any] = {
        "name": "lab-r1",
        "platform": "junos",
        "host": "router.test",
        "user": "admin",
        "auth": "key",
        "port": 22,
        "password_file": None,
        "proxy_command": None,
        "key_file": None,
        "known_hosts": known_hosts,
    }
    values.update(changes)
    return Target(**values)


def install_fake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "cisco",
) -> tuple[Path, Path]:
    fake = tmp_path / "fake-ssh"
    fake.write_text(FAKE_SSH, encoding="utf-8")
    fake.chmod(0o755)
    record = tmp_path / "fake-record.jsonl"
    monkeypatch.setenv("NEWTON_FAKE_RECORD", str(record))
    monkeypatch.setenv("NEWTON_FAKE_MODE", mode)
    return fake, record


def records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def make_runner(
    tmp_path: Path,
    fake: Path,
    clock: Callable[[], float],
) -> SshCliRunner:
    return SshCliRunner(tmp_path / "state", ssh=str(fake), clock=clock)


@contextmanager
def pipe_on_stdin() -> None:
    """Replace fd 0 with a pipe so ``stdin=None`` inheritance is detectable.

    pytest puts /dev/null on fd 0 for the run, so a child that INHERITS stdin
    also sees /dev/null and ``stdin_is_devnull`` passes either way. Setting
    fd 0 to a pipe makes ``stdin=None`` produce a pipe in the child (caught
    by the existing ``stdin_is_devnull`` assertions in the password-mode tests),
    and proves the precondition that fd 0 is not /dev/null at run time.
    """
    read_end, write_end = os.pipe()
    saved = os.dup(0)
    os.dup2(read_end, 0)
    try:
        assert (
            os.fstat(0).st_rdev != os.stat("/dev/null").st_rdev
        ) or stat.S_ISFIFO(os.fstat(0).st_mode)
        yield
    finally:
        os.dup2(saved, 0)
        os.close(saved)
        os.close(read_end)
        os.close(write_end)


def assert_grandchild_gone(pid: int) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        try:
            state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[2]
        except OSError:
            return
        if state == "Z":
            return
        time.sleep(0.02)
    raise AssertionError(f"grandchild {pid} survived")


def wait_for_grandchild_pid(record_path: Path) -> int:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        recorded = records(record_path)
        if recorded:
            return int(recorded[0]["grandchild_pid"])
        time.sleep(0.01)
    raise AssertionError("fake ssh did not record the escaped grandchild pid")


def test_mv1_5_01_key_argv_is_exact_and_process_input_is_bare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Key mode uses the exact locked argv and a noninteractive child."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    key_file = tmp_path / "synthetic-key"
    key_file.write_text("private key placeholder\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(
        known_hosts,
        key_file=key_file,
        proxy_command="nc --proxy-host jump.test %h %p",
    )
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    with pipe_on_stdin():
        result = make_runner(tmp_path, fake, FakeClock()).run(
            target, getters["interfaces"], {"iface": "ge-0/0/0"}
        )
    assert result.status == "ok"
    recorded = records(record_path)
    assert len(recorded) == 1
    argv = recorded[0]["argv"]
    assert argv == [
        str(fake),
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "RequestTTY=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "LogLevel=ERROR",
        "-p",
        "22",
        "-i",
        str(key_file),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ProxyCommand=nc --proxy-host jump.test %h %p",
        "admin@router.test",
        "--",
        "show interfaces ge-0/0/0 | no-more",
    ]
    assert argv[-2] == "--"
    assert argv[-1] == fill_command(getters["interfaces"], {"iface": "ge-0/0/0"})
    assert sum("ge-0/0/0" in item for item in argv) == 1
    assert recorded[0]["stdin_is_devnull"] is True
    assert recorded[0]["stdout_is_tty"] is False
    assert recorded[0]["askpass_present"] is False
    assert recorded[0]["auth_socket_present"] is False


def test_mv1_5_02_password_argv_askpass_and_secret_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Password mode asks once without exposing the password value."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    password_file = tmp_path / "password"
    password_file.write_text(PASSWORD + "\n", encoding="utf-8")
    password_file.chmod(0o600)
    fake, record_path = install_fake(tmp_path, monkeypatch)
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/synthetic-agent-socket")
    target = make_target(
        known_hosts,
        auth="password",
        password_file=password_file,
    )
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    with pipe_on_stdin():
        result = make_runner(tmp_path, fake, FakeClock()).run(
            target, getters["version"], {}
        )
    assert result.status == "ok"
    recorded = records(record_path)
    assert len(recorded) == 1
    argv = recorded[0]["argv"]
    assert argv == [
        str(fake),
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "RequestTTY=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "LogLevel=ERROR",
        "-p",
        "22",
        "-o",
        "PreferredAuthentications=password,keyboard-interactive",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "PubkeyAuthentication=no",
        "admin@router.test",
        "--",
        "show version",
    ]
    assert PASSWORD not in argv
    assert PASSWORD not in "".join(str(value) for value in recorded[0]["env"].values())
    child = recorded[0]
    assert child["askpass_present"] is True
    assert child["askpass_exists_when_started"] is True
    assert child["auth_socket_present"] is False
    askpass = Path(child["env"]["SSH_ASKPASS"])
    assert askpass.exists() is False
    assert child["env"].get("SSH_ASKPASS_REQUIRE") == "force"
    assert child["env"].get("DISPLAY") == "x"
    assert child["stdin_is_devnull"] is True
    assert child["stdout_is_tty"] is False


def test_mv1_5_03_askpass_is_removed_after_ssh_auth_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Password mode cleans its askpass helper on exit 255 too."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    password_file = tmp_path / "password"
    password_file.write_text(PASSWORD + "\n", encoding="utf-8")
    password_file.chmod(0o600)
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="permission-denied"
    )
    target = make_target(
        known_hosts,
        auth="password",
        password_file=password_file,
    )
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, getters["version"], {}
    )
    assert result.status == "auth_failed"
    child = records(record_path)[0]
    assert Path(child["env"]["SSH_ASKPASS"]).exists() is False


@pytest.mark.parametrize(
    ("case", "changes", "expected"),
    [
        ("openwrt", {"platform": "openwrt"}, "OpenWrt must use its existing transport"),
        ("unknown-platform", {"platform": "cisco"}, "platform is not in the capability registry"),
        ("known-hosts-none-key", {"known_hosts": None}, "a known_hosts file is required"),
        (
            "known-hosts-none-password",
            {"auth": "password", "known_hosts": None},
            "a known_hosts file is required",
        ),
        ("known-hosts-missing", {"known_hosts": Path("/no/such/hosts")}, "known_hosts must be an existing regular file"),
        (
            "known-hosts-missing-password",
            {"auth": "password", "known_hosts": Path("/no/such/hosts")},
            "known_hosts must be an existing regular file",
        ),
        ("known-hosts-symlink", {"known_hosts": None}, "known_hosts must be an existing regular file"),
        (
            "known-hosts-symlink-password",
            {"auth": "password", "known_hosts": None},
            "known_hosts must be an existing regular file",
        ),
        ("known-hosts-directory", {"known_hosts": None}, "known_hosts must be an existing regular file"),
        (
            "known-hosts-directory-password",
            {"auth": "password", "known_hosts": None},
            "known_hosts must be an existing regular file",
        ),
        ("host-option", {"host": "-oProxyCommand=x"}, "host fails the hostname grammar"),
        ("host-space", {"host": "router test"}, "host fails the hostname grammar"),
        ("user-dash", {"user": "-x"}, "user fails the username grammar"),
        ("port-zero", {"port": 0}, "port must be an integer from 1 through 65535"),
        ("port-boolean", {"port": True}, "port must be an integer from 1 through 65535"),
        ("auth-agent", {"auth": "agent"}, "auth must be key or password"),
        ("password-file-missing", {"auth": "password"}, "password_file must be an existing regular file"),
        ("key-file-directory", {"key_file": Path("/tmp")}, "key_file must be an existing regular file"),
        ("proxy-newline", {"proxy_command": "nc\nbad"}, "proxy_command contains a line break or NUL"),
    ],
)
def test_mv1_5_04_build_refusals_happen_before_a_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    changes: dict[str, Any],
    expected: str,
) -> None:
    """Malformed targets are refused before ssh starts.

    Each row pins the exact refusal fragment the runner must raise; password
    rows for known_hosts also receive a valid 0600 password file so the only
    thing wrong is known_hosts (a spoofed device must not harvest a password).
    """
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    if case == "password-file-missing":
        changes = {**changes, "password_file": tmp_path / "missing-password"}
    elif changes.get("auth") == "password":
        # password-mode known_hosts cases need a valid password_file so the
        # only thing wrong is known_hosts
        password_file = tmp_path / "password"
        password_file.write_text(PASSWORD + "\n", encoding="utf-8")
        password_file.chmod(0o600)
        changes = {**changes, "password_file": password_file}
    if case == "known-hosts-symlink":
        link = tmp_path / "known-hosts-link"
        link.symlink_to(known_hosts)
        changes = {**changes, "known_hosts": link}
    elif case == "known-hosts-symlink-password":
        link = tmp_path / "known-hosts-link-password"
        link.symlink_to(known_hosts)
        changes = {**changes, "known_hosts": link}
    elif case == "known-hosts-directory":
        directory = tmp_path / "directory"
        directory.mkdir()
        changes = {**changes, "known_hosts": directory}
    elif case == "known-hosts-directory-password":
        directory = tmp_path / "directory-password"
        directory.mkdir()
        changes = {**changes, "known_hosts": directory}
    elif case == "key-file-directory":
        directory = tmp_path / "key-directory"
        directory.mkdir()
        changes = {**changes, "key_file": directory}
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(changes.pop("known_hosts", known_hosts), **changes)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    clock = FakeClock()
    runner = make_runner(tmp_path, fake, clock)
    with pytest.raises(RunnerRefused) as caught:
        runner.run(target, getters["version"], {})
    assert expected in str(caught.value)
    assert target.name in str(caught.value)
    assert records(record_path) == []
    clock.advance(RATE_LIMIT_S)


def test_mv1_5_05_command_newlines_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The filled command itself cannot carry line breaks."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    with pytest.raises(RunnerRefused):
        build_argv(target, "show version\nshow secrets")
    runner = make_runner(tmp_path, fake, FakeClock())
    bad_getter = dataclasses.replace(getters["version"], command="show version\r")
    with pytest.raises(RunnerRefused):
        runner.run(target, bad_getter, {})
    assert records(record_path) == []


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_stdout", "expected_exit"),
    [
        ("cisco", "ok", "Cisco IOS XE 17.9\n", 0),
        ("nothing", "empty", "", 0),
        ("spaces", "empty", "   \n", 0),
        ("invalid", "device_error", "% Invalid input detected at '^' marker.\n", 0),
        ("invalid-ansi", "device_error", "% Inv\x1b[0malid input\n", 0),
        ("row-error", "device_error", None, 0),
        ("success-missing", "ok", "firmware 17.9\n", 0),
        ("success-present", "ok", "Model ABC firmware 17.9\n", 0),
        ("exit-one", "device_error", "partial output before failure\n", 1),
        ("kex", "unreachable", "", 255),
    ],
)
def test_mv1_5_06_status_pipeline_first_match_wins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_status: str,
    expected_stdout: str | None,
    expected_exit: int | None,
) -> None:
    """Output markers and exit status map to the fixed result states."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(tmp_path, monkeypatch, mode=mode)
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    getter = getters["admins"] if mode.startswith("success") else getters["version"]
    result = make_runner(tmp_path, fake, FakeClock()).run(target, getter, {})
    assert result.status == expected_status
    assert result.exit_code == expected_exit
    if expected_stdout is not None:
        assert result.stdout == expected_stdout
    assert result.truncated is False


def test_mv1_5_07_connection_refused_does_not_disable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordinary unreachability remains retryable."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(tmp_path, monkeypatch, mode="connection-refused")
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    state = tmp_path / "state"
    runner = SshCliRunner(state, ssh=str(fake), clock=FakeClock())
    result = runner.run(target, getters["version"], {})
    assert result.status == "unreachable"
    assert runner.is_disabled(target.name) is False
    assert not (state / "ssh-disabled" / target.name).exists()


def test_mv1_5_08_permission_failure_disables_until_operator_reenables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth failure writes a durable operator-only disable marker."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="permission-denied"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    state = tmp_path / "state"
    clock = FakeClock()
    runner = SshCliRunner(state, ssh=str(fake), clock=clock)
    result = runner.run(target, getters["version"], {})
    assert result.status == "auth_failed"
    marker = state / "ssh-disabled" / target.name
    assert marker.read_text(encoding="utf-8") == "disabled\n"
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600

    clock.advance(RATE_LIMIT_S)
    with pytest.raises(RunnerRefused, match="operator must re-enable"):
        runner.run(target, getters["version"], {})
    assert len(records(record_path)) == 1
    restarted = SshCliRunner(state, ssh=str(fake), clock=clock)
    assert restarted.is_disabled(target.name) is True
    with pytest.raises(RunnerRefused, match="operator must re-enable"):
        restarted.run(target, getters["version"], {})

    monkeypatch.setenv("NEWTON_FAKE_MODE", "cisco")
    clock.advance(RATE_LIMIT_S)
    runner.reenable(target.name)
    assert runner.is_disabled(target.name) is False
    assert runner.run(target, getters["version"], {}).status == "ok"


def test_mv1_5_09_host_key_failure_disables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A host-key mismatch is treated like authentication failure."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(tmp_path, monkeypatch, mode="host-key")
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    runner = make_runner(tmp_path, fake, FakeClock())
    result = runner.run(target, getters["version"], {})
    assert result.status == "auth_failed"
    assert runner.is_disabled(target.name) is True


def test_mv1_5_10_rate_limit_is_per_device(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepted starts set a five-second per-device rate marker."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(known_hosts)
    other = make_target(known_hosts, name="lab-r2")
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    clock = FakeClock()
    runner = make_runner(tmp_path, fake, clock)
    assert runner.run(target, getters["version"], {}).status == "ok"
    clock.advance(RATE_LIMIT_S - 0.1)
    with pytest.raises(RunnerRefused, match="rate limited"):
        runner.run(target, getters["version"], {})
    assert len(records(record_path)) == 1

    clock.advance(0.1)
    assert runner.run(other, getters["version"], {}).status == "ok"
    assert len(records(record_path)) == 2


def test_mv1_5_11_refused_rate_call_does_not_move_timestamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused rapid retry does not extend the wait."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    clock = FakeClock()
    runner = make_runner(tmp_path, fake, clock)
    assert runner.run(target, getters["version"], {}).status == "ok"
    clock.advance(4.9)
    with pytest.raises(RunnerRefused, match="rate limited"):
        runner.run(target, getters["version"], {})
    clock.advance(0.1)
    assert runner.run(target, getters["version"], {}).status == "ok"
    assert len(records(record_path)) == 2


def test_mv1_5_12_deadline_kills_a_grandchild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deadline kills the whole process group, not only ssh."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="grandchild-timeout"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    started = time.monotonic()
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, getters["version"], {}
    )
    elapsed = time.monotonic() - started
    assert elapsed < 6.0
    assert result.status == "timed_out"
    assert result.exit_code is None
    assert_grandchild_gone(records(record_path)[0]["grandchild_pid"])


def test_mv1_5_13_grandchild_holding_stdout_is_killed_after_parent_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deadline applies while descendants hold output pipes."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="grandchild-exit"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    started = time.monotonic()
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, getters["version"], {}
    )
    assert time.monotonic() - started < 7.0
    assert result.status == "timed_out"
    assert result.exit_code is None
    assert_grandchild_gone(records(record_path)[0]["grandchild_pid"])


def test_mv1_5_20_escaped_grandchild_cannot_keep_read_loop_alive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deadline drain stops even when a setsid child holds pipes."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="escaped-grandchild"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    getter = dataclasses.replace(getters["version"], timeout_s=2)
    outcome: dict[str, Any] = {}

    def call_run() -> None:
        try:
            outcome["result"] = make_runner(tmp_path, fake, FakeClock()).run(
                target, getter, {}
            )
        except BaseException as error:  # surfaced by the main test thread
            outcome["error"] = error

    thread = threading.Thread(target=call_run, daemon=True)
    started = time.monotonic()
    thread.start()
    pid: int | None = None
    try:
        pid = wait_for_grandchild_pid(record_path)
        thread.join(timeout=15)
        assert thread.is_alive() is False
        if "error" in outcome:
            raise outcome["error"]
        result = outcome["result"]
        assert time.monotonic() - started < 8.0
        assert result.status == "timed_out"
    finally:
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        thread.join(timeout=2.0)


def test_mv1_5_21_escaped_grandchild_cannot_keep_cap_read_loop_alive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stdout-cap drain also stops when a setsid child holds pipes."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch, mode="escaped-stream")
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    getter = dataclasses.replace(
        getters["interfaces"], timeout_s=10, max_bytes=1024
    )
    outcome: dict[str, Any] = {}

    def call_run() -> None:
        try:
            outcome["result"] = make_runner(tmp_path, fake, FakeClock()).run(
                target, getter, {"iface": "ge-0/0/0"}
            )
        except BaseException as error:  # surfaced by the main test thread
            outcome["error"] = error

    thread = threading.Thread(target=call_run, daemon=True)
    started = time.monotonic()
    thread.start()
    pid: int | None = None
    try:
        pid = wait_for_grandchild_pid(record_path)
        thread.join(timeout=15)
        assert thread.is_alive() is False
        if "error" in outcome:
            raise outcome["error"]
        result = outcome["result"]
        assert time.monotonic() - started < 5.0
        assert result.truncated is True
        assert result.status == "ok"
    finally:
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        thread.join(timeout=2.0)


def test_mv1_5_14_streaming_output_is_byte_capped_at_a_line_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An endless stream stops early and drops its partial line."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(tmp_path, monkeypatch, mode="stream")
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    started = time.monotonic()
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, getters["interfaces"], {"iface": "ge-0/0/0"}
    )
    assert time.monotonic() - started < 3.0
    assert result.truncated is True
    assert result.status == "ok"
    assert len(result.stdout.encode("utf-8")) <= 4096
    assert result.stdout.endswith("\n")
    assert result.exit_code is None


def test_mv1_5_15_cap_with_no_newline_discards_the_partial_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A capped partial line cannot leak half a device message."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(tmp_path, monkeypatch, mode="partial")
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    partial_getter = dataclasses.replace(getters["interfaces"], max_bytes=1024)
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, partial_getter, {"iface": "ge-0/0/0"}
    )
    assert result.truncated is True
    assert result.stdout == ""
    assert result.status == "empty"


def test_mv1_5_16_stderr_flood_is_drained_and_capped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stderr is read even when too large to preserve."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(tmp_path, monkeypatch, mode="stderr-flood")
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    started = time.monotonic()
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, getters["version"], {}
    )
    assert time.monotonic() - started < 5.0
    assert result.status == "ok"
    assert result.stdout == "ok\n"
    assert len(result.stderr.encode("utf-8")) <= STDERR_CAP


def test_mv1_5_22_stderr_truncation_does_not_hide_a_failed_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a stdout cap may skip the exit-code check."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, _ = install_fake(
        tmp_path, monkeypatch, mode="stderr-flood-exit-one"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    result = make_runner(tmp_path, fake, FakeClock()).run(
        target, getters["version"], {}
    )
    assert result.status == "device_error"
    assert result.exit_code == 1
    assert result.truncated is True


def test_mv1_5_17_fill_errors_propagate_and_do_not_stamp_the_device(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fill failures run nothing and never consume the rate slot."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    clock = FakeClock()
    runner = make_runner(tmp_path, fake, clock)
    with pytest.raises(GetterError):
        runner.run(target, getters["interfaces"], {"iface": "eth0;reboot"})
    assert records(record_path) == []
    clock.advance(4.9)
    assert runner.run(
        target, getters["interfaces"], {"iface": "ge-0/0/0"}
    ).status == "ok"
    assert len(records(record_path)) == 1


def test_mv1_5_18_invalid_device_name_cannot_escape_the_marker_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Marker names are constrained before any marker path is used."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(known_hosts, name="../x")
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    state = tmp_path / "state"
    runner = SshCliRunner(state, ssh=str(fake), clock=FakeClock())
    with pytest.raises(RunnerRefused):
        runner.run(target, getters["version"], {})
    assert records(record_path) == []
    assert not (tmp_path / "ssh-disabled").exists()
    assert not (tmp_path / "x").exists()


def test_mv1_5_24_is_disabled_fails_closed_when_marker_path_is_broken(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A marker path that cannot be lstat'd still disables the device."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="permission-denied"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    state = tmp_path / "state"
    state.mkdir()

    # Case A: state/ssh-disabled is a regular file (lstat raises ENOTDIR).
    (state / "ssh-disabled").write_text("not a directory\n", encoding="utf-8")
    runner = SshCliRunner(state, ssh=str(fake), clock=FakeClock())
    assert runner.is_disabled(target.name) is True
    with pytest.raises(RunnerRefused, match="operator must re-enable"):
        runner.run(target, getters["version"], {})
    assert records(record_path) == []
    (state / "ssh-disabled").unlink()

    # Case B: state/ssh-disabled is a directory chmod 0o000 (lstat raises EACCES).
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory mode bits")
    (state / "ssh-disabled").mkdir(mode=0o700)
    (state / "ssh-disabled").chmod(0o000)
    try:
        runner_eacces = SshCliRunner(state, ssh=str(fake), clock=FakeClock())
        assert runner_eacces.is_disabled(target.name) is True
        with pytest.raises(RunnerRefused, match="operator must re-enable"):
            runner_eacces.run(target, getters["version"], {})
        assert records(record_path) == []
    finally:
        (state / "ssh-disabled").chmod(0o700)


def test_mv1_5_25_marker_write_failure_still_disables_in_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed marker write still disables the device in memory."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(
        tmp_path, monkeypatch, mode="permission-denied"
    )
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o500)
    try:
        if os.geteuid() == 0:
            pytest.skip("root bypasses directory mode bits")
        clock = FakeClock()
        runner = SshCliRunner(state, ssh=str(fake), clock=clock)
        result = runner.run(target, getters["version"], {})
        assert result.status == "auth_failed"
        assert runner.is_disabled(target.name) is True
        clock.advance(RATE_LIMIT_S)
        with pytest.raises(RunnerRefused, match="operator must re-enable"):
            runner.run(target, getters["version"], {})
        assert len(records(record_path)) == 1
        runner.reenable(target.name)
        assert runner.is_disabled(target.name) is False
    finally:
        state.chmod(0o700)


def test_mv1_5_26_wrong_param_keys_or_values_do_not_burn_rate_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused fill never records a rate timestamp."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    fake, record_path = install_fake(tmp_path, monkeypatch)
    target = make_target(known_hosts)
    getters = load_getters("junos", write_getters(tmp_path / "getters.toml"))
    clock = FakeClock()
    runner = make_runner(tmp_path, fake, clock)

    with pytest.raises(GetterError):
        runner.run(target, getters["version"], {"wrong": "v"})
    assert records(record_path) == []

    with pytest.raises(GetterError):
        runner.run(
            target, getters["interfaces"], {"iface": "eth0;reboot"}
        )
    assert records(record_path) == []

    assert runner.run(
        target, getters["version"], {}
    ).status == "ok"
    assert len(records(record_path)) == 1


def test_mv1_5_19_source_guard_forbids_shell_and_pty_execution() -> None:
    """Runner source keeps argv-only execution and group kill primitives."""
    assert STATUSES == (
        "ok",
        "empty",
        "device_error",
        "auth_failed",
        "timed_out",
        "unreachable",
    )
    source = Path(__file__).parents[1].joinpath(
        "newton_mcp", "adapters", "ssh_cli.py"
    ).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "os.system" not in source
    assert ".format(" not in source
    assert "import pty" not in source
    assert "from pty" not in source
    assert re.search(r"\bpty\b", source) is None
    assert "openpty" not in source
    assert "forkpty" not in source
    assert "start_new_session=True" in source
    assert "os.killpg" in source


@pytest.mark.parametrize(
    "platform", ["vyos", "junos", "routeros", "eos", "iosxe", "fortios"]
)
def test_mv1_11b_01_only_vyos_gets_the_fixed_op_mode_wrapper(
    tmp_path: Path, platform: str
) -> None:
    """A VyOS exec channel has no op mode, so a fixed wrapper path leads."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    argv = build_argv(make_target(known_hosts, platform=platform), "show version")
    expected = (
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper show version"
        if platform == "vyos"
        else "show version"
    )
    assert argv[-2:] == ["--", expected]


def test_mv1_11b_02_vyos_wrapper_does_not_bypass_the_line_break_check(
    tmp_path: Path,
) -> None:
    """The prefix is added only after the command passed its checks."""
    known_hosts = tmp_path / "known-hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    with pytest.raises(RunnerRefused):
        build_argv(make_target(known_hosts, platform="vyos"), "show version\nreboot")
