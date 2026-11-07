"""MV-3: ssh resolution refuses PATH lookup, picks /usr/bin/ssh or /bin/ssh.

The Python host that runs Newton must spawn ssh from a fixed allowlist
(``/usr/bin/ssh``, ``/bin/ssh``) and never look it up through ``PATH``.  A
fake ``ssh`` placed on PATH (operator mistake, hostile ``~/.bashrc``,
poorly written installer) must never be reached, and a system with neither
of those two binaries installed must refuse cleanly without spawning
anything.

Tests exercise the resolver on its own and through each spawn site (the
``server.read`` lane, ``scans.run_vantage``, and
``SshCliRunner.run``) by monkeypatching the candidate tuple and PATH,
and by spying on ``subprocess.run`` / ``subprocess.Popen``.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.scans as scans
import newton_mcp.server as server
import newton_mcp.ssh_path as ssh_path
from newton_mcp.adapters.getters import load_getters
from newton_mcp.adapters.ssh_cli import RunnerRefused, SshCliRunner


@pytest.fixture(autouse=True)
def _clear_ssh_path_cache():
    """Drop the resolve_ssh cache before AND after every test in this file.

    The module-level cache survives across tests in the same process, so a
    test that asserts what ``resolve_ssh`` returns must start from an
    empty cache and must not leave a stale entry for the next test.
    """
    ssh_path.reset_cache()
    yield
    ssh_path.reset_cache()


def _make_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _make_non_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o644)
    return path


def _put_path_first(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    current = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{current}")


# --- marker-ssh is the only executable ever placed first on PATH; it is
# the tripwire that proves the PATH lookup never fired.  A test that ends
# with this marker present means an ssh-aliased binary ran instead of the
# resolved absolute path.
_MARKER_SSH = "#!/bin/sh\ntouch \"$NEWTON_FAKE_MARKER\"\nexit 0\n"


def _make_marker_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    pathdir = tmp_path / "pathdir"
    pathdir.mkdir()
    ssh = pathdir / "ssh"
    _make_executable(ssh, _MARKER_SSH)
    marker = tmp_path / "marker"
    monkeypatch.setenv("NEWTON_FAKE_MARKER", str(marker))
    return ssh, marker


def _make_candidate_ssh(tmp_path: Path) -> Path:
    candidates_dir = tmp_path / "candidates"
    candidates_dir.mkdir()
    ssh = candidates_dir / "ssh"
    _make_executable(ssh)
    return ssh


# ---------------------------------------------------------------------------
# (a) ``resolve_ssh`` returns an absolute path from the fixed list when a
# candidate exists (monkeypatch SSH_CANDIDATES to tmp files: executable,
# non-executable, directory, missing).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("layout", "expected_kind"),
    [
        ("executable-first", "executable"),
        ("executable-second", "executable"),
        ("executable-third", "executable"),
        ("non-executable-only", "missing"),
        ("directory-only", "missing"),
        ("directory-then-executable", "executable"),
        ("missing-then-executable", "executable"),
        ("mixed-bad-only", "missing"),
    ],
)
def test_resolve_ssh_returns_an_absolute_path_when_a_candidate_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    layout: str,
    expected_kind: str,
) -> None:
    executable = _make_executable(tmp_path / "good-ssh")
    non_executable = _make_non_executable(tmp_path / "no-x-ssh")
    directory = tmp_path / "dir-ssh"
    directory.mkdir()
    missing = "/no/such/ssh-for-resolve-ssh-test"
    layout_to_paths = {
        "executable-first": [executable, non_executable, directory, missing],
        "executable-second": [directory, executable, missing],
        "executable-third": [missing, directory, non_executable, executable],
        "non-executable-only": [non_executable],
        "directory-only": [directory],
        "directory-then-executable": [directory, executable],
        "missing-then-executable": [missing, executable],
        "mixed-bad-only": [non_executable, directory, missing],
    }
    ssh_path.SSH_CANDIDATES = tuple(str(path) for path in layout_to_paths[layout])
    if expected_kind == "missing":
        with pytest.raises(ssh_path.SshNotFound) as exc_info:
            ssh_path.resolve_ssh()
        assert str(exc_info.value) == (
            "ssh not found in /usr/bin/ssh or /bin/ssh; "
            "refusing to look it up through PATH"
        )
        return
    path = ssh_path.resolve_ssh()
    assert path == str(executable)
    assert os.path.isabs(path)


# ---------------------------------------------------------------------------
# (b) ``resolve_ssh`` raises ``SshNotFound`` with the canonical message when
# no candidate is an executable regular file.
# ---------------------------------------------------------------------------


def test_resolve_ssh_raises_ssh_not_found_with_the_canonical_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    non_executable = _make_non_executable(tmp_path / "no-x")
    directory = tmp_path / "dir"
    directory.mkdir()
    missing = "/no/such/ssh-XXXX"
    ssh_path.SSH_CANDIDATES = (
        str(non_executable),
        str(directory),
        missing,
    )
    with pytest.raises(ssh_path.SshNotFound) as exc_info:
        ssh_path.resolve_ssh()
    assert isinstance(exc_info.value, RuntimeError)
    assert str(exc_info.value) == (
        "ssh not found in /usr/bin/ssh or /bin/ssh; "
        "refusing to look it up through PATH"
    )


# ---------------------------------------------------------------------------
# Subprocess spies.  fake_run replaces ``subprocess.run``; fake_popen
# replaces ``subprocess.Popen`` with a process that closes its pipes
# immediately so the adapter's read loop exits without blocking.
# ---------------------------------------------------------------------------


class _CallLog:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, dict[str, Any]]] = []


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> _CallLog:
    log = _CallLog()

    def spy(args: Any, *positional: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        log.calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(subprocess, "run", spy)
    return log


@pytest.fixture
def fake_popen(monkeypatch: pytest.MonkeyPatch) -> _CallLog:
    log = _CallLog()

    class _PipedFake:
        def __init__(self, argv: Any, kwargs: dict[str, Any]) -> None:
            log.calls.append((argv, kwargs))
            self.argv = argv
            self.pid = 1
            self.returncode = 0
            r_stdout, w_stdout = os.pipe()
            r_stderr, w_stderr = os.pipe()
            os.close(w_stdout)
            os.close(w_stderr)
            self.stdout = os.fdopen(r_stdout, "rb", closefd=True)
            self.stderr = os.fdopen(r_stderr, "rb", closefd=True)

        def wait(self, timeout: Any = None) -> int:
            return 0

        def kill(self) -> None:
            return None

    def spy(argv: Any, *args: Any, **kwargs: Any) -> Any:
        return _PipedFake(argv, kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    return log


# ---------------------------------------------------------------------------
# (c) a fake ssh placed first on PATH is NEVER reached: the marker file is
# absent and the recorded argv[0] is the absolute path from SSH_CANDIDATES.
# ---------------------------------------------------------------------------


def _configured_inventory(tmp_path: Path) -> Path:
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\n'
        'platform = "openwrt"\n'
        'host = "192.0.2.1"\n'
        'user = "root"\n'
    )
    inventory.chmod(0o644)
    return inventory


def test_path_lookup_does_not_reach_a_fake_ssh_on_path_for_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_run: _CallLog,
) -> None:
    monkeypatch.setenv("NEWTON_INVENTORY", str(_configured_inventory(tmp_path)))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    marker_ssh, marker = _make_marker_ssh(tmp_path, monkeypatch)
    candidate_ssh = _make_candidate_ssh(tmp_path)
    _put_path_first(monkeypatch, marker_ssh.parent)
    ssh_path.SSH_CANDIDATES = (str(candidate_ssh),)

    result = server.newton_read("quasar", "ip link show dev br-lan")

    assert "error" not in result, result
    assert result["exit_code"] == 0
    assert not marker.exists(), (
        f"marker created at {marker}: the PATH-placed fake ssh ran"
    )
    assert len(fake_run.calls) == 1
    argv = fake_run.calls[0][0]
    assert argv[0] == str(candidate_ssh)
    assert os.path.isabs(argv[0])


def test_path_lookup_does_not_reach_a_fake_ssh_on_path_for_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_run: _CallLog,
) -> None:
    marker_ssh, marker = _make_marker_ssh(tmp_path, monkeypatch)
    candidate_ssh = _make_candidate_ssh(tmp_path)
    _put_path_first(monkeypatch, marker_ssh.parent)
    ssh_path.SSH_CANDIDATES = (str(candidate_ssh),)

    key = tmp_path / "key"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("synthetic\n")
    known_hosts.write_text("synthetic\n")
    key.chmod(0o600)
    known_hosts.chmod(0o600)
    vantage = scans.Vantage(
        name="v",
        host="scan.example.invalid",
        user="newton",
        key_file=key,
        known_hosts=known_hosts,
        proxy_command=None,
        role="outside",
        devices=("router",),
    )
    completed = scans.run_vantage(
        vantage,
        ["scan", "quick", "outside", "198.51.100.9"],
    )

    assert completed.returncode == 0
    assert not marker.exists(), (
        f"marker created at {marker}: the PATH-placed fake ssh ran"
    )
    assert len(fake_run.calls) == 1
    argv = fake_run.calls[0][0]
    assert argv[0] == str(candidate_ssh)
    assert os.path.isabs(argv[0])


@dataclasses.dataclass(frozen=True)
class _AdapterTarget:
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


def _adapter_getters(tmp_path: Path) -> Any:
    getters_path = tmp_path / "getters.toml"
    getters_path.write_text(
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
error_markers = []
""",
        encoding="utf-8",
    )
    return load_getters("junos", getters_path)


def test_path_lookup_does_not_reach_a_fake_ssh_on_path_for_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_popen: _CallLog,
) -> None:
    marker_ssh, marker = _make_marker_ssh(tmp_path, monkeypatch)
    candidate_ssh = _make_candidate_ssh(tmp_path)
    _put_path_first(monkeypatch, marker_ssh.parent)
    ssh_path.SSH_CANDIDATES = (str(candidate_ssh),)

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    target = _AdapterTarget(
        name="lab-r1",
        platform="junos",
        host="router.test",
        user="admin",
        auth="key",
        port=22,
        password_file=None,
        proxy_command=None,
        key_file=None,
        known_hosts=known_hosts,
    )
    getters = _adapter_getters(tmp_path)
    runner = SshCliRunner(tmp_path / "state")
    result = runner.run(target, getters["version"], {})

    assert not marker.exists(), (
        f"marker created at {marker}: the PATH-placed fake ssh ran"
    )
    assert len(fake_popen.calls) == 1
    argv = fake_popen.calls[0][0]
    assert argv[0] == str(candidate_ssh)
    assert os.path.isabs(argv[0])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# (d) with no candidates, every spawn site refuses and never spawns.
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    ssh_path.SSH_CANDIDATES = ()


def test_no_candidates_read_refuses_and_spawns_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    empty_candidates: None,
    fake_run: _CallLog,
) -> None:
    monkeypatch.setenv("NEWTON_INVENTORY", str(_configured_inventory(tmp_path)))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    result = server.newton_read("quasar", "ip link show dev br-lan")

    assert "error" in result
    assert (
        "ssh not found in /usr/bin/ssh or /bin/ssh; "
        "refusing to look it up through PATH"
    ) in result["error"]
    assert "PATH" in result["error"]
    assert fake_run.calls == [], fake_run.calls


def test_no_candidates_scan_run_refuses_and_spawns_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    empty_candidates: None,
    fake_run: _CallLog,
) -> None:
    key = tmp_path / "key"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("synthetic\n")
    known_hosts.write_text("synthetic\n")
    key.chmod(0o600)
    known_hosts.chmod(0o600)
    vantage = scans.Vantage(
        name="v",
        host="scan.example.invalid",
        user="newton",
        key_file=key,
        known_hosts=known_hosts,
        proxy_command=None,
        role="outside",
        devices=("router",),
    )
    with pytest.raises(scans.ScanError) as exc_info:
        scans.run_vantage(
            vantage,
            ["scan", "quick", "outside", "198.51.100.9"],
        )
    assert (
        "ssh not found in /usr/bin/ssh or /bin/ssh; "
        "refusing to look it up through PATH"
    ) in str(exc_info.value)
    assert fake_run.calls == [], fake_run.calls


def test_no_candidates_adapter_run_refuses_and_spawns_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    empty_candidates: None,
    fake_popen: _CallLog,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    target = _AdapterTarget(
        name="lab-r1",
        platform="junos",
        host="router.test",
        user="admin",
        auth="key",
        port=22,
        password_file=None,
        proxy_command=None,
        key_file=None,
        known_hosts=known_hosts,
    )
    getters = _adapter_getters(tmp_path)
    runner = SshCliRunner(tmp_path / "state")
    with pytest.raises(RunnerRefused) as exc_info:
        runner.run(target, getters["version"], {})
    assert (
        "ssh not found in /usr/bin/ssh or /bin/ssh; "
        "refusing to look it up through PATH"
    ) in str(exc_info.value)
    assert "lab-r1" in str(exc_info.value)
    assert fake_popen.calls == [], fake_popen.calls


# ---------------------------------------------------------------------------
# (e) MV-3: the SERVER-built SshCliRunner (NewtonService.get_state) must
# resolve ssh from the fixed list, not pass the bare "ssh" string through
# PATH.  ``SSH_BINARY`` is None in production (tests monkeypatch it with a
# fake path); here we deliberately leave it alone and let the runner fall
# back to ``resolve_ssh()``.  A PATH-placed tripwire ssh and a single Popen
# spy prove the lookup never fired.
# ---------------------------------------------------------------------------


def test_server_built_runner_resolves_ssh_and_skips_path_for_get_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_popen: _CallLog,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.20 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    marker_ssh, marker = _make_marker_ssh(tmp_path, monkeypatch)
    candidate_ssh = _make_candidate_ssh(tmp_path)
    _put_path_first(monkeypatch, marker_ssh.parent)
    ssh_path.SSH_CANDIDATES = (str(candidate_ssh),)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    devices = {
        "jx1": server.Device(
            name="jx1",
            platform="junos",
            host="192.0.2.20",
            user="newton",
            experimental_readonly=True,
            known_hosts=known_hosts,
        ),
    }
    monkeypatch.setattr(server, "load_inventory", lambda: devices)
    monkeypatch.setattr(server, "_RUNNERS", {})
    monkeypatch.setattr(server, "_SEEN_IFACES", {})

    result = server.newton_get_state(device="jx1", getter="version")

    assert "error" not in result, result
    assert result["status"] in {"ok", "empty", "device_error", "mismatch"}, result
    assert not marker.exists(), (
        f"marker created at {marker}: the PATH-placed fake ssh ran"
    )
    assert len(fake_popen.calls) == 1, fake_popen.calls
    argv = fake_popen.calls[0][0]
    assert argv[0] == str(candidate_ssh), argv
    assert os.path.isabs(argv[0]), argv
