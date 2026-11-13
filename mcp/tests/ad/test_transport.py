"""The transport that fetches one collector document.

The session is the forced-command session of the vendor transport: no
remote command and no input, because the collector on the far side is
the whole session.  Every test injects a fake ``popen``, so no process
starts and no device is contacted.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad import transport
from newton_mcp.adapters.vendor_ssh import SshSessionRunner


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


class FakeProcess:
    """A fake ssh process: records its argv and returns canned output."""

    def __init__(
        self,
        argv: list[str],
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        hold: bool = False,
    ) -> None:
        self.argv = list(argv)
        self.returncode = returncode
        self.pid = 4242
        self.killed = False
        self.stdin = None
        self.stdout = self._pipe(stdout, hold=hold)
        self.stderr = self._pipe(stderr, hold=hold)

    def _pipe(self, data: bytes, *, hold: bool) -> Any:
        read_fd, write_fd = os.pipe()
        if data:
            os.write(write_fd, data)
        if hold:
            self._held = getattr(self, "_held", [])
            self._held.append(write_fd)
        else:
            os.close(write_fd)
        return os.fdopen(read_fd, "rb", buffering=0)

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
        hold: bool = False,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.hold = hold
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeProcess:
        self.calls.append((list(argv), kwargs))
        return FakeProcess(
            list(argv),
            stdout=self.stdout,
            stderr=self.stderr,
            returncode=self.returncode,
            hold=self.hold,
        )


@pytest.fixture
def target(tmp_path: Path) -> Target:
    """An AD collector target with a key file and a known_hosts."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    key_file = tmp_path / "newton-key"
    key_file.write_text("synthetic private key placeholder\n", encoding="utf-8")
    return Target(
        name="dc1",
        platform="ad-windows",
        host="192.0.2.10",
        user="newton-audit@win.newton.test",
        key_file=key_file,
        known_hosts=known_hosts,
    )


def test_the_document_comes_back_as_bytes(target: Target) -> None:
    """A session that answered hands the stdout back unchanged."""
    popen = FakePopen(stdout=b'{"v": 1}\n')

    raw = transport.fetch(target, popen=popen)

    assert raw == b'{"v": 1}\n'


def test_the_session_carries_no_remote_command_and_no_input(
    target: Target,
) -> None:
    """The forced command on the far side is the whole session."""
    popen = FakePopen(stdout=b"{}")

    transport.fetch(target, popen=popen)

    argv, kwargs = popen.calls[0]
    assert argv[-1] == "newton-audit@win.newton.test@192.0.2.10"
    assert "--" not in argv
    assert kwargs["stdin"] is not None


def test_the_caps_are_the_ones_the_spec_names(
    target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stdout cap is 64 MiB and the timeout is 360 s."""
    seen: dict[str, Any] = {}

    class RecordingRunner:
        def __init__(self, device: Any, **options: Any) -> None:
            seen.update(options)

        def __call__(self, spec: Any) -> Any:
            raise AssertionError("the session must not run in this test")

    monkeypatch.setattr(transport, "SshSessionRunner", RecordingRunner)

    with pytest.raises(AssertionError):
        transport.fetch(target)

    assert seen["stdout_cap"] == 64 * 1024 * 1024
    assert seen["timeout_s"] == 360


def test_a_non_zero_exit_is_a_transport_error(target: Target) -> None:
    """A session that answered with an error is not a document."""
    popen = FakePopen(stdout=b"partial", returncode=1)

    with pytest.raises(transport.AdTransportError) as caught:
        transport.fetch(target, popen=popen)

    assert str(caught.value) == transport.FAILED_MESSAGE


def test_the_message_of_a_failure_never_carries_device_text(
    target: Target,
) -> None:
    """The stderr of a failed session never reaches the message."""
    popen = FakePopen(
        stdout=b"",
        stderr=b"Permission denied (publickey).\r\n",
        returncode=255,
    )

    with pytest.raises(transport.AdTransportError) as caught:
        transport.fetch(target, popen=popen)

    message = str(caught.value)
    assert message == transport.MESSAGES["auth_failed"]
    assert "Permission denied" not in message


def test_an_unreachable_host_has_its_own_message(target: Target) -> None:
    """An ssh that could not reach the box is not an auth failure."""
    popen = FakePopen(
        stdout=b"",
        stderr=b"ssh: connect to host 192.0.2.10 port 22: No route to host\n",
        returncode=255,
    )

    with pytest.raises(transport.AdTransportError) as caught:
        transport.fetch(target, popen=popen)

    assert str(caught.value) == transport.MESSAGES["unreachable"]


def test_a_session_that_times_out_has_its_own_message(
    target: Target, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session that ran out of time is not a document."""
    monkeypatch.setattr(transport, "TIMEOUT_S", 1)
    popen = FakePopen(stdout=b"", hold=True)

    with pytest.raises(transport.AdTransportError) as caught:
        transport.fetch(target, popen=popen)

    assert str(caught.value) == transport.MESSAGES["timed_out"]


def test_a_refused_session_is_a_transport_error(
    target: Target,
) -> None:
    """A session refused before it started is a transport error."""
    broken = dataclasses.replace(target, known_hosts=None)

    with pytest.raises(transport.AdTransportError) as caught:
        transport.fetch(broken)

    assert str(caught.value) == transport.REFUSED_MESSAGE


def test_every_status_has_a_fixed_message() -> None:
    """The message of a status is fixed and never carries device text."""
    assert set(transport.MESSAGES) == {
        "timed_out",
        "auth_failed",
        "unreachable",
        "output_cap",
    }
    for message in transport.MESSAGES.values():
        assert message
        assert "\n" not in message
    assert transport.MESSAGES["output_cap"] != transport.FAILED_MESSAGE


def test_the_transport_uses_the_vendor_session_runner() -> None:
    """The transport runs the locked ssh invocation of the vendor lane."""
    assert transport.SshSessionRunner is SshSessionRunner
