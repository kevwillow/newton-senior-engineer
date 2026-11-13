"""Shared SSH CLI transport for non-OpenWrt read-only getters."""

from __future__ import annotations

import errno
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Protocol

from .. import receipts as _receipts
from .. import ssh_path as _ssh_path
from ..envelope import _strip_controls
from . import registry
from .getters import Getter, fill_command, shape_matches


RATE_LIMIT_S = 5.0
HARD_TIMEOUT_S = 30
STDERR_CAP = 8192
# VyOS runs exec-channel commands in vbash, which has no op mode; this fixed
# wrapper runs one op-mode command. It exits 0 on a bad command, so the getter's
# error_markers ("Invalid command") classify it. Lab-observed on VyOS rolling.
_VYOS_OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"
STATUSES = ("ok", "empty", "device_error", "auth_failed", "timed_out", "unreachable")

# The host and user grammar every ssh lane shares: the value is pasted
# into the ssh argv as ``<user>@<host>``, so it must never look like an
# option (``-oProxyCommand=...``) and must never carry a space, a
# semicolon or a line break.  These are public so the inventory loaders
# (server.py, scans.py) refuse the same shapes instead of copying the
# patterns.
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")
# The AD platforms log in with a user principal name.  The ssh client
# refuses the ``domain\user`` form (measured on the Windows DC), so the
# inventory holds ``newton-audit@win.newton.test`` and ssh splits the
# destination at its last ``@``.  The Samba collector logs in with a
# plain user name, so both forms are accepted here.
AD_USER_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(@[A-Za-z0-9][A-Za-z0-9.-]{0,251})?$"
)
# the old private names stay as aliases so nothing else breaks
_HOST_RE = HOST_RE
_USER_RE = USER_RE
_DEVICE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
# proxy_command runs inside ssh's /bin/sh -c, so its value is a shell
# string. Bound it to a small charset (paths, flags, %h/%p, user@host)
# and a 512-char cap so nothing outside this class can reach ProxyCommand.
PROXY_COMMAND_RE = re.compile(r"[A-Za-z0-9 _./:@%~=,+-]{1,512}")
_AUTH_RE = re.compile(
    r"Permission denied|Too many authentication failures|Authentication failed|"
    r"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|"
    r"No [A-Za-z0-9-]+ host key is known",
    re.IGNORECASE,
)
_CHUNK_SIZE = 4096
_WAIT_S = 2.0
_DRAIN_GRACE_S = 1.0


class RunnerRefused(RuntimeError):
    """A pre-flight refusal raised before an SSH process can start."""


class SshTarget(Protocol):
    """The inventory fields needed by the SSH CLI runner."""

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


@dataclass(frozen=True)
class RunResult:
    """One raw getter result.

    ``stdout`` is byte-capped but otherwise raw device text. the sanitising step cleans it
    before anything is model-bound; this module must not shortcut that step.
    """

    status: str
    stdout: str
    stderr: str
    truncated: bool
    exit_code: int | None


def _refuse(name: str, rule: str) -> NoReturn:
    raise RunnerRefused(f"{name}: refused: {rule}")


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _mode_of(path: Path) -> int:
    """The file's own permission bits, or -1 when it cannot be read."""
    try:
        return stat.S_IMODE(path.lstat().st_mode)
    except OSError:
        return -1


def _owned_by_caller(path: Path) -> bool:
    """True when the file's own owner is the user running this process."""
    try:
        return path.lstat().st_uid == os.geteuid()
    except OSError:
        return False


def _has_forbidden_text(value: str) -> bool:
    return "\n" in value or "\r" in value or "\x00" in value


def _check_platform(target: SshTarget) -> None:
    """Refuse a platform this transport does not serve."""
    name = target.name
    if type(target.platform) is not str or target.platform not in registry.PLATFORMS:
        _refuse(name, "platform is not in the capability registry")
    if target.platform == "openwrt":
        _refuse(name, "OpenWrt must use its existing transport")


def user_grammar(platform: str) -> re.Pattern[str]:
    """The user grammar of one platform.

    The AD platforms log in with a user principal name; every other
    platform logs in with a plain user name.
    """
    if platform in registry.AD_PLATFORMS or platform in registry.AD_WRITE_PLATFORMS:
        return AD_USER_RE
    return USER_RE


def base_argv(target: SshTarget) -> list[str]:
    """Build the locked OpenSSH options for a target.

    Everything up to but excluding the destination and the remote command
    is here: the validation of the target and the option list.  The read
    path appends the destination and the filled command (see
    ``build_argv``); the vendor write path appends the destination and the
    remote command it already built (see ``adapters.vendor_ssh``).
    """
    name = target.name
    _check_platform(target)
    if target.known_hosts is None:
        _refuse(name, "a known_hosts file is required")
    known_hosts = Path(target.known_hosts)
    if not _is_regular_file(known_hosts):
        _refuse(name, "known_hosts must be an existing regular file")
    if type(target.host) is not str or HOST_RE.fullmatch(target.host) is None:
        _refuse(name, "host fails the hostname grammar")
    if type(target.user) is not str or user_grammar(target.platform).fullmatch(target.user) is None:
        _refuse(name, "user fails the username grammar")
    if type(target.port) is not int or isinstance(target.port, bool):
        _refuse(name, "port must be an integer from 1 through 65535")
    if not 1 <= target.port <= 65535:
        _refuse(name, "port must be an integer from 1 through 65535")
    if target.auth not in {"key", "password"}:
        _refuse(name, "auth must be key or password")

    key_file: Path | None = None
    if target.auth == "key" and target.key_file is not None:
        key_file = Path(target.key_file)
        if not _is_regular_file(key_file):
            _refuse(name, "key_file must be an existing regular file")
    if target.auth == "password":
        if target.password_file is None:
            _refuse(name, "password auth requires a password file")
        password_path = Path(target.password_file)
        if not _is_regular_file(password_path):
            _refuse(name, "password_file must be an existing regular file")
        # the password file is a credential; only the owner may read it.
        if _mode_of(password_path) != 0o600:
            _refuse(name, "password_file must have mode 0600")
        if not _owned_by_caller(password_path):
            _refuse(name, "password_file must be owned by the server user")

    proxy_command = target.proxy_command
    if proxy_command is not None:
        if type(proxy_command) is not str or _has_forbidden_text(proxy_command):
            _refuse(name, "proxy_command contains a line break or NUL")
        if PROXY_COMMAND_RE.fullmatch(proxy_command) is None:
            _refuse(name, "proxy_command contains characters outside [A-Za-z0-9 _./:@%~=,+-]")

    batch = "yes" if target.auth == "key" else "no"
    argv = [
        "ssh",
        "-F",
        "/dev/null",
        "-T",
        "-o",
        f"BatchMode={batch}",
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
        str(target.port),
    ]
    if key_file is not None:
        argv.extend(["-i", str(key_file), "-o", "IdentitiesOnly=yes"])
    if target.auth == "password":
        argv.extend(
            [
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
                "-o",
                "NumberOfPasswordPrompts=1",
                "-o",
                "PubkeyAuthentication=no",
            ]
        )
    if proxy_command is not None:
        argv.extend(["-o", f"ProxyCommand={proxy_command}"])
    return argv


def build_argv(target: SshTarget, command: str) -> list[str]:
    """Build the locked OpenSSH argv for one filled read-only command."""
    name = target.name
    _check_platform(target)
    if type(command) is not str or _has_forbidden_text(command):
        _refuse(name, "command contains a line break or NUL")
    argv = base_argv(target)
    if target.platform == "vyos":
        command = f"{_VYOS_OP_WRAPPER} {command}"
    argv.extend([f"{target.user}@{target.host}", "--", command])
    return argv


def _marker_path(state_dir: Path, name: str) -> Path:
    if type(name) is not str or _DEVICE_NAME_RE.fullmatch(name) is None:
        _refuse(name if type(name) is str else "unknown", "invalid device name")
    return state_dir / "ssh-disabled" / name


def _cap(
    raw: bytes,
    maximum: int,
    already_truncated: bool = False,
) -> tuple[bytes, bool]:
    if not already_truncated and len(raw) <= maximum:
        return raw, False
    kept = raw[:maximum]
    newline = kept.rfind(b"\n")
    if newline < 0:
        return b"", True
    return kept[: newline + 1], True


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _read_and_wait(
    process: subprocess.Popen[bytes],
    deadline: float,
    stdout_limit: int,
) -> tuple[bytes, bytes, bool, bool]:
    """Read both pipes, enforce both caps, and reap the process group."""
    selector = selectors.DefaultSelector()
    assert process.stdout is not None
    assert process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    open_streams = 2
    stdout = bytearray()
    stderr = bytearray()
    stdout_truncated = False
    deadline_hit = False
    cap_hit = False
    killed_at: float | None = None
    try:
        while open_streams != 0:
            now = time.monotonic()
            remaining = deadline - now
            if not deadline_hit and remaining <= 0:
                deadline_hit = True
                _kill_group(process)
                killed_at = now
            killed = deadline_hit or cap_hit
            if killed:
                assert killed_at is not None
                grace_remaining = _DRAIN_GRACE_S - (time.monotonic() - killed_at)
                if grace_remaining <= 0:
                    break
                wait_for = min(0.05, grace_remaining)
            else:
                wait_for = max(0.0, min(remaining, 0.25))
            events = selector.select(wait_for)
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, _CHUNK_SIZE)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if chunk == b"":
                    selector.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                if key.fileobj is process.stdout:
                    if not stdout_truncated:
                        room = stdout_limit - len(stdout)
                        stdout.extend(chunk[:room])
                        if len(chunk) > room:
                            stdout_truncated = True
                            cap_hit = True
                            _kill_group(process)
                            if killed_at is None:
                                killed_at = time.monotonic()
                else:
                    if len(stderr) <= STDERR_CAP:
                        stderr.extend(chunk)
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    try:
        process.wait(timeout=_WAIT_S)
    except subprocess.TimeoutExpired:
        deadline_hit = True
        _kill_group(process)
        try:
            process.wait(timeout=_WAIT_S)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    return (
        bytes(stdout),
        bytes(stderr),
        stdout_truncated,
        deadline_hit,
    )


def _write_disable_marker(state_dir: Path, name: str) -> None:
    marker = _marker_path(state_dir, name)
    # refuse before the mkdir below when the state dir or its parent is unsafe
    refusal = _receipts.check_state_write_path(marker, state_dir)
    if refusal is not None:
        raise OSError(refusal)
    marker.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(marker.parent, 0o700)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | no_follow
    descriptor = os.open(marker, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write("disabled\n")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _result_status(
    getter: Getter,
    stdout_text: str,
    stderr_text: str,
    return_code: int | None,
    truncated: bool,
    timed_out: bool,
) -> tuple[str, bool]:
    if timed_out:
        return "timed_out", False
    if return_code == 255 and _AUTH_RE.search(stderr_text) is not None:
        return "auth_failed", True
    if return_code == 255:
        return "unreachable", False
    combined = _strip_controls(stdout_text + "\n" + stderr_text)
    if any(marker.search(combined) is not None for marker in getter.error_markers):
        return "device_error", False
    if truncated:
        return "empty" if stdout_text.strip() == "" else "ok", False
    if return_code != 0:
        return "device_error", False
    return "empty" if stdout_text.strip() == "" else "ok", False


MISMATCH_CAVEAT = "output did not match the documented shape; treat as unreliable"


def shape_of(getter: Getter, status: str, stdout_text: str) -> str:
    """Return matched, mismatch or not_checked; never changes the status."""
    if status != "ok":
        return "not_checked"
    text = _strip_controls(stdout_text)
    if shape_matches(getter.expect, text):
        return "matched"
    return "mismatch"


class SshCliRunner:
    """Run one allowlisted getter over a locked OpenSSH invocation."""

    def __init__(
        self,
        state_dir: Path,
        *,
        ssh: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._ssh = ssh
        self._clock = clock
        self._lock = threading.Lock()
        self._last_started: dict[str, float] = {}
        self._disabled_in_memory: set[str] = set()

    def is_disabled(self, name: str) -> bool:
        """Return whether an operator-visible auth failure marker exists."""
        if name in self._disabled_in_memory:
            return True
        try:
            marker = _marker_path(self._state_dir, name)
            marker.lstat()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True
        except RunnerRefused:
            return False

    def reenable(self, name: str) -> None:
        """Remove the disable marker after an operator has investigated it."""
        self._disabled_in_memory.discard(name)
        marker = _marker_path(self._state_dir, name)
        try:
            marker.unlink()
        except FileNotFoundError:
            return

    def run(
        self,
        target: SshTarget,
        getter: Getter,
        params: Mapping[str, str],
    ) -> RunResult:
        """Fill, validate, execute, cap, and classify one getter."""
        if self.is_disabled(target.name):
            _refuse(
                target.name,
                "device is disabled after an auth failure; operator must re-enable",
            )
        if self._ssh is None:
            try:
                self._ssh = _ssh_path.resolve_ssh()
            except _ssh_path.SshNotFound as exc:
                _refuse(target.name, str(exc))
        _marker_path(self._state_dir, target.name)
        command = fill_command(getter, params)
        argv = build_argv(target, command)
        argv[0] = self._ssh
        with self._lock:
            started_at = self._clock()
            previous = self._last_started.get(target.name)
            if (
                previous is not None
                and started_at - previous < RATE_LIMIT_S
            ):
                _refuse(
                    target.name,
                    "device is rate limited for five seconds between accepted runs",
                )
            self._last_started[target.name] = started_at
        env = os.environ.copy()
        env.pop("SSH_AUTH_SOCK", None)
        askpass: Path | None = None
        if target.auth == "password":
            assert target.password_file is not None
            descriptor, askpass_name = tempfile.mkstemp(prefix="newton-askpass-")
            askpass = Path(askpass_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    stream.write(
                        "#!/bin/sh\ncat -- "
                        + shlex.quote(str(target.password_file))
                        + "\n"
                    )
                os.chmod(askpass, 0o700)
                env["SSH_ASKPASS"] = str(askpass)
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env["DISPLAY"] = "x"
            except BaseException:
                askpass.unlink(missing_ok=True)
                askpass = None
                raise

        try:
            process: subprocess.Popen[bytes] = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=env,
                close_fds=True,
            )
            deadline = time.monotonic() + min(getter.timeout_s, HARD_TIMEOUT_S)
            stdout_raw, stderr_raw, stdout_truncated, timed_out = _read_and_wait(
                process, deadline, getter.max_bytes
            )
        finally:
            if askpass is not None:
                askpass.unlink(missing_ok=True)
        stdout_bytes, stdout_cap_truncated = _cap(
            stdout_raw, getter.max_bytes, stdout_truncated
        )
        stderr_bytes, stderr_truncated = _cap(stderr_raw, STDERR_CAP)
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        truncated = (
            stdout_truncated
            or stdout_cap_truncated
            or stderr_truncated
            or timed_out
        )
        exit_code = None if timed_out or stdout_truncated else process.returncode
        status, disable = _result_status(
            getter,
            stdout_text,
            stderr_text,
            exit_code,
            (stdout_truncated or stdout_cap_truncated) and not timed_out,
            timed_out,
        )
        if disable:
            self._disabled_in_memory.add(target.name)
            try:
                _write_disable_marker(self._state_dir, target.name)
            except OSError as error:
                errno_name = errno.errorcode.get(
                    error.errno, str(error.errno)
                )
                stderr_text = (
                    stderr_text
                    + f"\nnewton: disable marker not written: {errno_name}\n"
                )
        return RunResult(
            status=status,
            stdout=stdout_text,
            stderr=stderr_text,
            truncated=truncated,
            exit_code=exit_code,
        )
