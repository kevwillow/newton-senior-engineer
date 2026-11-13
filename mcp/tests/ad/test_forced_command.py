"""The forced-command transport of the AD collectors.

A collector host runs a forced command: the session carries no remote
command and no input at all, and the forced command on the far side is
the collector.  Anything else on such a platform is refused before a
process starts.

No process starts in any test here: the transport is given a fake
``popen``.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.adapters import registry
from newton_mcp.adapters.ssh_cli import RunnerRefused
from newton_mcp.adapters.vendor_ssh import (
    FORCED_COMMAND_PLATFORMS,
    SshSessionRunner,
)
from newton_mcp.adapters.vendor_write import SessionSpec


SCRIPT = "print('collector document')\n"


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

    def __init__(self, argv: list[str]) -> None:
        self.argv = list(argv)
        self.returncode = 0
        self.stdin = None
        self.stdout = None
        self.stderr = None

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


class FakePopen:
    """A fake ``subprocess.Popen`` that records every launch."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> FakeProcess:
        self.calls.append((list(argv), kwargs))
        return FakeProcess(list(argv))


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
        user="newton-audit",
        key_file=key_file,
        known_hosts=known_hosts,
    )


@pytest.fixture
def ad_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """The AD platforms are in the capability registry.

    The transport served them before the registry knew them; the
    registry holds them now, so the test checks that instead of adding
    them for the run.
    """
    assert "ad-windows" in registry.PLATFORMS
    assert "ad-samba" in registry.PLATFORMS


def test_the_forced_command_platforms_are_the_two_of_the_spec() -> None:
    """The allow list holds the two AD platforms and nothing else."""
    assert FORCED_COMMAND_PLATFORMS == frozenset({"ad-windows", "ad-samba"})


def test_a_session_without_a_remote_command_and_without_input_runs(
    target: Target,
    ad_registry: None,
) -> None:
    """The session is the locked options and the destination."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    out = runner(SessionSpec(remote="", stdin=""))

    assert out.status == "ok"
    argv, kwargs = popen.calls[0]
    assert argv[-1] == "newton-audit@192.0.2.10"
    assert "--" not in argv
    assert kwargs["stdin"] is subprocess.PIPE


def test_the_samba_collector_runs_the_same_way(
    target: Target,
    ad_registry: None,
) -> None:
    """Both collectors are forced-command platforms."""
    popen = FakePopen()
    samba = dataclasses.replace(target, platform="ad-samba")
    runner = SshSessionRunner(samba, popen=popen)

    runner(SessionSpec(remote="", stdin=""))

    argv, _ = popen.calls[0]
    assert argv[-1] == "newton-audit@192.0.2.10"
    assert "--" not in argv


def test_a_remote_command_is_refused(target: Target) -> None:
    """A forced command takes no remote command."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    with pytest.raises(RunnerRefused) as caught:
        runner(SessionSpec(remote="collector.ps1", stdin=""))

    assert "forced command" in str(caught.value)
    assert popen.calls == []


def test_input_is_refused(target: Target) -> None:
    """A forced command takes no input."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    with pytest.raises(RunnerRefused) as caught:
        runner(SessionSpec(remote="", stdin=SCRIPT))

    assert "forced command" in str(caught.value)
    assert popen.calls == []


def test_a_remote_command_and_input_are_refused(target: Target) -> None:
    """Both at once is refused as well."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    with pytest.raises(RunnerRefused):
        runner(SessionSpec(remote="collector.ps1", stdin=SCRIPT))

    assert popen.calls == []


def test_another_platform_behaves_exactly_as_before(target: Target) -> None:
    """A platform that is not a forced-command one is unchanged."""
    popen = FakePopen()
    vyos = dataclasses.replace(target, platform="vyos")
    runner = SshSessionRunner(vyos, popen=popen)

    with pytest.raises(RunnerRefused) as caught:
        runner(SessionSpec(remote="", stdin=SCRIPT))

    assert "CLI login shell" in str(caught.value)
    assert popen.calls == []


def test_the_junos_rule_is_unchanged(target: Target) -> None:
    """A Junos session still runs the script on stdin."""
    popen = FakePopen()
    junos = dataclasses.replace(target, platform="junos")
    runner = SshSessionRunner(junos, popen=popen)

    out = runner(SessionSpec(remote="", stdin=SCRIPT))

    assert out.status == "ok"
    argv, _ = popen.calls[0]
    assert argv[-1] == "newton-audit@192.0.2.10"
    assert "--" not in argv


def test_the_ad_platforms_are_in_the_registry_now() -> None:
    """The capability registry holds the AD platforms."""
    assert "ad-windows" in registry.PLATFORMS
    assert "ad-samba" in registry.PLATFORMS


def test_the_locked_options_are_still_the_locked_options(
    target: Target,
    ad_registry: None,
) -> None:
    """The forced-command session carries the same option set."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    runner(SessionSpec(remote="", stdin=""))

    argv, _ = popen.calls[0]
    assert argv[0] == "ssh"
    assert "-o" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "BatchMode=yes" in argv
    assert argv[-1] == "newton-audit@192.0.2.10"


def test_the_environment_does_not_offer_an_agent_socket(
    target: Target,
    ad_registry: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The session never offers an agent socket to the collector."""
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    runner(SessionSpec(remote="", stdin=""))

    _, kwargs = popen.calls[0]
    assert "SSH_AUTH_SOCK" not in kwargs["env"]


def test_a_target_without_a_known_hosts_is_refused(target: Target) -> None:
    """The target validation of the shared options still runs."""
    popen = FakePopen()
    broken = dataclasses.replace(target, known_hosts=None)
    runner = SshSessionRunner(broken, popen=popen)

    with pytest.raises(RunnerRefused):
        runner(SessionSpec(remote="", stdin=""))

    assert popen.calls == []


def test_a_refusal_happens_before_any_process_is_started(
    target: Target,
) -> None:
    """The refusal happens before a process is started."""
    popen = FakePopen()
    runner = SshSessionRunner(target, popen=popen)

    with pytest.raises(RunnerRefused):
        runner(SessionSpec(remote="collector.ps1", stdin=SCRIPT))

    assert popen.calls == []
