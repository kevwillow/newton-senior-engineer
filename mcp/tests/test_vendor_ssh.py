"""The SSH write transport for vendor write sessions.

The transport runs one fresh ssh process per session.  Every test injects a
fake ``popen``, so no process starts and no device is contacted.


"""

from __future__ import annotations

import dataclasses
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.adapters import ssh_cli
from newton_mcp.adapters import vendor_ssh as vendor_ssh_module
from newton_mcp.adapters.ssh_cli import RunnerRefused
from newton_mcp.adapters.vendor_ssh import SshSessionRunner
from newton_mcp.adapters.vendor_write import SessionSpec


REMOTE = "vbash -s"
SCRIPT = "source /opt/vyatta/etc/functions/script-template\nconfigure\nexit\n"


@dataclasses.dataclass(frozen=True)
class Target:
    """The inventory fields the transport reads."""

    name: str
    platform: str
    host: str
    user: str
    auth: str = "key"
    port: int = 22
    password_file: Path | None = None
    proxy_command: str | None = None
    key_file: Path | None = None
    known_hosts: Path | None = None


class CaptureInput:
    """A fake stdin pipe that records the bytes written to it."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, data: bytes) -> int:
        self.data.extend(data)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    """A fake ssh process: records its argv and stdin, returns canned output."""

    def __init__(
        self,
        argv: list[str],
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
        options: dict[str, Any] | None = None,
    ) -> None:
        self.argv = list(argv)
        self.options = options or {}
        self.pid = 4242
        self.returncode = returncode
        self.killed = False
        self.communicated = 0
        self._stdout = stdout
        self._stderr = stderr
        self._hang = hang
        self.stdin = CaptureInput()
        self.stdout = self._pipe(stdout, hold=hang)
        self.stderr = self._pipe(stderr, hold=hang)

    def _pipe(self, data: bytes, *, hold: bool) -> Any:
        read_fd, write_fd = os.pipe()
        if data:
            os.write(write_fd, data)
        if hold:
            self._held_writers = getattr(self, "_held_writers", [])
            self._held_writers.append(write_fd)
        else:
            os.close(write_fd)
        return os.fdopen(read_fd, "rb", buffering=0)

    @property
    def stdin_data(self) -> bytes:
        return bytes(self.stdin.data)

    def communicate(
        self,
        input: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes, bytes]:
        """Answer like Popen.communicate, including the timeout refusal."""
        self.communicated += 1
        if input is not None:
            self.stdin.write(input)
            if self._hang:
                raise subprocess.TimeoutExpired(cmd=self.argv, timeout=timeout)
        return self._stdout, self._stderr

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class FakePopen:
    """A fake ``subprocess.Popen`` that records every launch."""

    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.hang = hang
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.processes: list[FakeProcess] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeProcess:
        self.calls.append((list(argv), kwargs))
        process = FakeProcess(
            list(argv),
            stdout=self.stdout,
            stderr=self.stderr,
            returncode=self.returncode,
            hang=self.hang,
            options=kwargs,
        )
        self.processes.append(process)
        return process


class SingleProcessPopen:
    """A fake ``subprocess.Popen`` that always hands back one process."""

    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeProcess:
        self.calls.append((list(argv), kwargs))
        return self.process


class ChunkedStdout:
    """A fake ``os.read`` that hands out small chunks and counts the bytes.

    The count is what pins the kill position: the session must be killed
    when the bytes read reach the cap, not before and not a chunk later.
    """

    def __init__(self, fd: int, chunk: bytes) -> None:
        self.fd = fd
        self.chunk = chunk
        self.total = 0
        self.reads: list[int] = []
        self._real_read = os.read

    def read(self, fd: int, size: int) -> bytes:
        if fd == self.fd:
            self.total += len(self.chunk)
            self.reads.append(self.total)
            return self.chunk
        return self._real_read(fd, size)


@pytest.fixture
def target(tmp_path: Path) -> Target:
    """A VyOS write target with a key file, a known_hosts and a proxy."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    key_file = tmp_path / "newton-key"
    key_file.write_text("synthetic private key placeholder\n", encoding="utf-8")
    return Target(
        name="vy1",
        platform="vyos",
        host="192.0.2.9",
        user="newton",
        key_file=key_file,
        known_hosts=known_hosts,
        proxy_command="nc --proxy-host jump.test %h %p",
    )


def test_argv_is_the_locked_read_only_argv_plus_the_remote(
    target: Target,
) -> None:
    """The write argv is the locked option set and the bare remote."""
    popen = FakePopen(stdout=b"NEWTON-COMMITTED rc=0\n")
    runner = SshSessionRunner(target, popen=popen)

    out = runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))

    assert out.status == "ok"
    argv, kwargs = popen.calls[0]
    assert argv == [
        "ssh",
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={target.known_hosts}",
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
        str(target.key_file),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"ProxyCommand={target.proxy_command}",
        "newton@192.0.2.9",
        "--",
        REMOTE,
    ]
    # The remote command is already complete: no VyOS op wrapper is added.
    assert argv[-1] == REMOTE
    assert "vyatta-op-cmd-wrapper" not in argv[-1]
    assert argv[-2] == "--"
    assert kwargs["start_new_session"] is True
    assert kwargs["stdin"] is subprocess.PIPE
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE


def test_the_script_reaches_the_process_on_stdin(target: Target) -> None:
    """The script is written to stdin as utf-8."""
    popen = FakePopen(stdout=b"ok\n")
    runner = SshSessionRunner(target, popen=popen)

    runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))

    assert popen.processes[0].stdin_data == SCRIPT.encode("utf-8")


def test_stdout_is_capped_and_stderr_at_8192(target: Target) -> None:
    """Both streams are capped, stdout at the runner's own cap."""
    popen = FakePopen(
        stdout=b"line one\nline two\n",
        stderr=b"e\n" * 5000,
    )
    runner = SshSessionRunner(target, popen=popen, stdout_cap=12)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert out.stdout == "line one\n"
    assert len(out.stdout) <= 12
    # The stdout cap kills the process group, and a killed group stops the
    # reading of BOTH pipes, so the stderr is only what was read
    # before the kill.  It is never longer than the cap.
    assert len(out.stderr) <= ssh_cli.STDERR_CAP


def test_the_stderr_reaches_its_own_cap(target: Target) -> None:
    """A stderr over the cap is capped and kills the group."""
    popen = FakePopen(stdout=b"ok\n", stderr=b"e\n" * 5000)
    runner = SshSessionRunner(target, popen=popen, stdout_cap=4096)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert len(out.stderr) == ssh_cli.STDERR_CAP
    assert out.status == "output_cap"


def test_a_timeout_is_timed_out_and_kills_the_process_group(
    target: Target,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session that runs out of time is killed and reported."""
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        os, "killpg", lambda pid, sig: killed.append((pid, sig))
    )
    popen = FakePopen(hang=True)
    runner = SshSessionRunner(target, popen=popen, timeout_s=1)

    out = runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))

    assert out.status == "timed_out"
    assert out.exit_code is None
    assert killed == [(popen.processes[0].pid, signal.SIGKILL)]


def test_exit_255_with_auth_text_is_auth_failed(target: Target) -> None:
    """An ssh authentication failure is auth_failed."""
    popen = FakePopen(
        stderr=b"newton@192.0.2.9: Permission denied (publickey).\n",
        returncode=255,
    )
    runner = SshSessionRunner(target, popen=popen)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert out.status == "auth_failed"
    assert out.exit_code == 255
    assert "Permission denied" in out.stderr


def test_exit_255_without_auth_text_is_unreachable(
    target: Target,
) -> None:
    """Any other ssh failure is unreachable, not an auth failure."""
    popen = FakePopen(
        stderr=b"ssh: connect to host 192.0.2.9 port 22: Connection refused\n",
        returncode=255,
    )
    runner = SshSessionRunner(target, popen=popen)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert out.status == "unreachable"
    assert out.exit_code == 255


def test_a_device_failure_never_raises(target: Target) -> None:
    """A non-zero exit is a result, not an exception."""
    popen = FakePopen(stdout=b"device said no\n", returncode=1)
    runner = SshSessionRunner(target, popen=popen)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert out.status == "ok"
    assert out.exit_code == 1
    assert out.stdout == "device said no\n"


@pytest.mark.parametrize(
    "remote",
    [
        "vbash -s\nrm -rf /",
        "vbash -s\rmore",
        "vbash -s\x00more",
        "",
    ],
)
def test_a_unsafe_remote_is_refused_before_any_process(
    target: Target,
    remote: str,
) -> None:
    """A line break, a NUL or an empty remote never reaches ssh."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    with pytest.raises(RunnerRefused):
        runner(SessionSpec(remote=remote, stdin=SCRIPT))

    assert popen.calls == []


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("openwrt", "OpenWrt must use its existing transport"),
        ("acme", "platform is not in the capability registry"),
    ],
)
def test_only_registered_non_openwrt_platforms_are_served(
    target: Target,
    platform: str,
    expected: str,
) -> None:
    """The write transport never serves OpenWrt or an unknown box."""
    popen = FakePopen()
    runner = SshSessionRunner(
        dataclasses.replace(target, platform=platform),
        popen=popen,
    )

    with pytest.raises(RunnerRefused) as caught:
        runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))

    assert expected in str(caught.value)
    assert popen.calls == []


def test_every_call_starts_a_fresh_process(target: Target) -> None:
    """One process per session, never a reused channel."""
    popen = FakePopen(stdout=b"ok\n")
    runner = SshSessionRunner(target, popen=popen)

    runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))
    runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))

    assert len(popen.calls) == 2
    assert popen.processes[0] is not popen.processes[1]


def test_the_output_is_decoded_with_replacement(target: Target) -> None:
    """Device bytes that are not utf-8 become a replacement char."""
    popen = FakePopen(stdout=b"caf\xe9\n")
    runner = SshSessionRunner(target, popen=popen)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert out.stdout == "caf\ufffd\n"


def test_the_read_only_argv_builder_is_unchanged(
    target: Target,
) -> None:
    """Build_argv keeps its exact bytes after the refactor."""
    vyos_argv = ssh_cli.build_argv(target, "show version")

    assert vyos_argv[-3:] == [
        "newton@192.0.2.9",
        "--",
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper show version",
    ]
    assert ssh_cli.base_argv(target) == vyos_argv[:-3]

    junos_argv = ssh_cli.build_argv(
        dataclasses.replace(target, platform="junos"),
        "show version",
    )
    assert junos_argv[-3:] == ["newton@192.0.2.9", "--", "show version"]
    assert ssh_cli.base_argv(
        dataclasses.replace(target, platform="junos")
    ) == junos_argv[:-3]


def test_a_session_with_no_remote_command_runs_the_cli(
    target: Target,
) -> None:
    """A Junos session has no remote command: the script is stdin.

    The login shell of a Junos device is the CLI, so the session is one
    ssh with the CLI script on stdin and nothing after the "--".
    """
    popen = FakePopen(stdout=b"ok\n")
    junos = dataclasses.replace(target, platform="junos")
    runner = SshSessionRunner(junos, popen=popen)

    out = runner(SessionSpec(remote="", stdin=SCRIPT))

    assert out.status == "ok"
    argv, kwargs = popen.calls[0]
    assert argv[-1] == "newton@192.0.2.9"
    assert "--" not in argv
    assert kwargs["stdin"] is subprocess.PIPE
    assert popen.processes[0].stdin_data == SCRIPT.encode("utf-8")


def test_an_empty_remote_needs_a_cli_login_shell(target: Target) -> None:
    """No remote command is for the CLI platforms only.

    For every other platform the script would run in the login shell of
    the device, which is a shell and not a CLI, and a session with
    nothing on stdin would wait for a human.
    """
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)
    with pytest.raises(RunnerRefused) as caught:
        runner(SessionSpec(remote="", stdin=SCRIPT))
    assert "CLI login shell" in str(caught.value)
    assert popen.calls == []

    popen = FakePopen()
    junos = dataclasses.replace(target, platform="junos")
    runner = SshSessionRunner(junos, popen=popen)
    with pytest.raises(RunnerRefused) as caught:
        runner(SessionSpec(remote="", stdin=""))
    assert "nothing on stdin" in str(caught.value)
    assert popen.calls == []


def test_popen_environment_does_not_offer_an_agent_socket(
    target: Target,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The write transport removes SSH_AUTH_SOCK from Popen."""
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    popen = FakePopen(stdout=b"ok\n")
    runner = SshSessionRunner(target, popen=popen)

    runner(SessionSpec(remote=REMOTE, stdin=SCRIPT))

    _, kwargs = popen.calls[0]
    assert "SSH_AUTH_SOCK" not in kwargs["env"]


def test_stdout_cap_kills_the_group_without_reading_to_end(
    target: Target,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The group is killed AT the cap, not before and not later."""
    cap = 12
    process = FakeProcess(["ssh"], stdout=b"x" * 4096)
    popen = SingleProcessPopen(process)
    runner = SshSessionRunner(target, popen=popen, stdout_cap=cap)
    reader = ChunkedStdout(process.stdout.fileno(), b"x" * 4)
    killed_at: list[int] = []

    def record_kill(candidate: FakeProcess) -> None:
        killed_at.append(reader.total)
        candidate.kill()

    monkeypatch.setattr(vendor_ssh_module.os, "read", reader.read)
    monkeypatch.setattr(vendor_ssh_module, "_kill_group", record_kill)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    # The kill happens in the read where the bytes read reach the cap:
    # not in the first read (that would be killing too early) and not in
    # a later one (that would be reading past the cap).
    assert killed_at == [cap]
    assert reader.reads == [4, 8, 12]
    assert out.status == "output_cap"
    assert len(out.stdout) <= cap


def test_a_session_killed_at_the_cap_is_not_ok(
    target: Target,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session killed at the output cap is output_cap, not ok."""
    process = FakeProcess(["ssh"], stdout=b"x" * 4096)
    popen = SingleProcessPopen(process)
    runner = SshSessionRunner(target, popen=popen, stdout_cap=12)
    reader = ChunkedStdout(process.stdout.fileno(), b"ab\n")
    killed: list[FakeProcess] = []

    def record_kill(candidate: FakeProcess) -> None:
        killed.append(candidate)
        candidate.kill()

    monkeypatch.setattr(vendor_ssh_module.os, "read", reader.read)
    monkeypatch.setattr(vendor_ssh_module, "_kill_group", record_kill)

    out = runner(SessionSpec(remote=REMOTE, stdin=""))

    assert out.status == "output_cap"
    assert out.status != "ok"
    assert killed == [process]
    assert out.exit_code == -9
    assert len(out.stdout) <= 12


def test_a_cap_kill_stops_the_reading_of_both_pipes(
    target: Target,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cap kill does not wait for the stderr EOF until the timeout."""
    # The stderr pipe never ends: only a runner that stops reading after
    # the kill comes back before the timeout.
    process = FakeProcess(["ssh"], stdout=b"x" * 4096, hang=True)
    popen = SingleProcessPopen(process)
    runner = SshSessionRunner(target, popen=popen, stdout_cap=12, timeout_s=10)
    reader = ChunkedStdout(process.stdout.fileno(), b"x" * 4)
    killed: list[FakeProcess] = []

    def record_kill(candidate: FakeProcess) -> None:
        killed.append(candidate)
        candidate.kill()

    monkeypatch.setattr(vendor_ssh_module.os, "read", reader.read)
    monkeypatch.setattr(vendor_ssh_module, "_kill_group", record_kill)

    started = time.monotonic()
    out = runner(SessionSpec(remote=REMOTE, stdin=""))
    elapsed = time.monotonic() - started

    assert out.status == "output_cap"
    assert killed == [process]
    assert elapsed < 3.0
