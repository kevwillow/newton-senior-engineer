"""The SSH transport for vendor write sessions.

One fresh ssh process per session.  The option list comes from the shared
``ssh_cli.base_argv`` helper, so a write session carries exactly the
locked options the read-only getter transport carries: host-key pinning,
no agent forwarding, no X11, no control master, batch mode for key auth
and the proxy option when the inventory sets one.

The remote command is already complete: the write scripts are built by
``adapters.vendor_write`` from re-rendered tokens, never by the agent.
A line break or a NUL is refused before a process starts, because the
remote command reaches the device's login shell.

A session may also run with NO remote command, with the script on stdin.
That is how a Junos device is driven: the login shell of the device is
the CLI, so the script is read by the CLI (measured on 26.2R1.7).  It is
allowed for the platforms whose login shell is the CLI and refused for
the others, where the script would run in a shell of the device.

The runner never raises for a device failure.  The result is always a
``vendor_change.RunOut`` whose status is one of ``ok``, ``timed_out``,
``auth_failed``, ``unreachable`` or ``output_cap``; ``RunnerRefused`` is
for a pre-flight refusal only (a refused target, a refused remote, or an
ssh that cannot be started at all).

A session that was killed because its output reached a cap did not
answer, so it is never reported as ``ok``: its status is ``output_cap``.
Every caller of a session result only trusts the word ``ok``, so the new
word fails safe everywhere it is read.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any, cast

from ..vendor_change import RunOut, RunStatus
from .ssh_cli import (
    STDERR_CAP,
    RunnerRefused,
    SshTarget,
    _AUTH_RE,
    _cap,
    _kill_group,
    base_argv,
)
from .vendor_write import SessionSpec


DEFAULT_TIMEOUT_S = 120
DEFAULT_STDOUT_CAP = 256 * 1024
_CHUNK_SIZE = 4096
_WAIT_S = 2.0
# How long the runner waits for the killed process to be reaped.
_REAP_S = 2.0

# The platforms whose login shell is the CLI of the device.  A session
# with no remote command runs the script on stdin in that shell, so the
# script is read by the CLI and not by a shell: this is how a Junos
# device is driven (measured on 26.2R1.7, measure/tr/junos-confirm.txt).
#
# The list is an allow list and not a deny list: for every other platform
# a session with no remote command would run the script in the login
# shell of the device, which is a shell and not a CLI.
CLI_SHELL_PLATFORMS = frozenset({"junos"})


def _has_forbidden_text(value: str) -> bool:
    """True when the text carries a line break or a NUL."""
    return "\n" in value or "\r" in value or "\x00" in value


def _status(
    timed_out: bool,
    capped: bool,
    exit_code: int | None,
    stderr_text: str,
) -> str:
    """Map one finished session to its status word.

    The words are the ones ``vendor_change.RunOut`` allows, plus
    ``output_cap``: a session that was killed because its output reached
    the cap never answered the device, so it is not ``ok``.  A session
    that answered is ``ok`` (the exit code says whether the device was
    happy), an ssh that could not reach the box is ``unreachable``, an
    ssh that was refused is ``auth_failed`` and a session that ran out of
    time is ``timed_out``.
    """
    if timed_out:
        return "timed_out"
    if capped:
        # "output_cap" is a new status word.  vendor_change.RunStatus does
        # not list it yet (that file is not this module's to edit), so the
        # word is cast into the set the driver reads.
        return cast(RunStatus, "output_cap")
    if exit_code == 255:
        if _AUTH_RE.search(stderr_text) is not None:
            return "auth_failed"
        return "unreachable"
    return "ok"


class SshSessionRunner:
    """Run one vendor write session over a locked OpenSSH invocation."""

    def __init__(
        self,
        target: SshTarget,
        *,
        popen: Callable[..., Any] = subprocess.Popen,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        stdout_cap: int = DEFAULT_STDOUT_CAP,
    ) -> None:
        self._target = target
        self._popen = popen
        self._timeout_s = timeout_s
        self._stdout_cap = stdout_cap

    def __call__(self, spec: SessionSpec) -> RunOut:
        """Run one session and return its result; never raise for the device."""
        argv = self._argv(spec)
        env = os.environ.copy()
        # The write session uses the inventory key only: an agent socket
        # must never be offered to a device that is about to be changed.
        env.pop("SSH_AUTH_SOCK", None)
        try:
            process = self._popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                env=env,
                close_fds=True,
            )
        except OSError as exc:
            raise RunnerRefused(
                f"{self._target.name}: refused: ssh could not be started"
            ) from exc
        (
            stdout_raw,
            stderr_raw,
            timed_out,
            stdout_truncated,
            stderr_truncated,
        ) = self._communicate(process, spec.stdin)
        stdout_bytes, _ = _cap(stdout_raw, self._stdout_cap, stdout_truncated)
        stderr_bytes, _ = _cap(stderr_raw, STDERR_CAP, stderr_truncated)
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        exit_code = None if timed_out else process.returncode
        return RunOut(
            status=_status(
                timed_out,
                stdout_truncated or stderr_truncated,
                exit_code,
                stderr_text,
            ),
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
        )

    def _argv(self, spec: SessionSpec) -> list[str]:
        """Build the argv of one session: the shared options and the remote.

        A session with a remote command carries it after the "--", so the
        command reaches the device whole.  A session with NO remote
        command runs the script on stdin in the login shell of the
        device: that is only done for a platform whose login shell is
        the CLI, or the script would run in a shell of the device.
        """
        target = self._target
        remote = spec.remote
        if type(remote) is not str:
            raise RunnerRefused(
                f"{target.name}: refused: the remote command is not text"
            )
        if remote and _has_forbidden_text(remote):
            raise RunnerRefused(
                f"{target.name}: refused: the remote command contains a "
                "line break or NUL"
            )
        argv = base_argv(target)
        if not remote:
            if target.platform not in CLI_SHELL_PLATFORMS:
                raise RunnerRefused(
                    f"{target.name}: refused: the remote command is empty and "
                    "this platform does not run a CLI login shell"
                )
            if not spec.stdin:
                raise RunnerRefused(
                    f"{target.name}: refused: the remote command is empty and "
                    "there is nothing on stdin"
                )
            argv.append(f"{target.user}@{target.host}")
            return argv
        argv.extend([f"{target.user}@{target.host}", "--", remote])
        return argv

    def _communicate(
        self,
        process: Any,
        stdin_text: str,
    ) -> tuple[bytes, bytes, bool, bool, bool]:
        """Write the script and read both pipes incrementally under caps."""
        data = stdin_text.encode("utf-8") if stdin_text else b""
        writer = threading.Thread(
            target=self._write_stdin,
            args=(process, data),
            daemon=True,
        )
        writer.start()

        selector = selectors.DefaultSelector()
        stdout_stream = getattr(process, "stdout", None)
        stderr_stream = getattr(process, "stderr", None)
        open_streams = 0
        if stdout_stream is not None:
            selector.register(stdout_stream, selectors.EVENT_READ)
            open_streams += 1
        if stderr_stream is not None:
            selector.register(stderr_stream, selectors.EVENT_READ)
            open_streams += 1

        stdout = bytearray()
        stderr = bytearray()
        stdout_truncated = False
        stderr_truncated = False
        stdout_done = False
        stderr_done = False
        stdout_total = 0
        stderr_total = 0
        timed_out = False
        capped = False
        deadline = time.monotonic() + self._timeout_s
        try:
            while open_streams:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _kill_group(process)
                    break
                events = selector.select(min(remaining, 0.25))
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
                        if key.fileobj is stdout_stream:
                            stdout_done = True
                        else:
                            stderr_done = True
                        continue
                    if key.fileobj is stdout_stream:
                        if stdout_done:
                            continue
                        room = max(0, self._stdout_cap - len(stdout))
                        stdout.extend(chunk[:room])
                        stdout_total += len(chunk)
                        if stdout_total >= self._stdout_cap:
                            # The cap is reached: the group is killed now,
                            # in the read that reached it.
                            stdout_truncated = True
                            stdout_done = True
                            capped = True
                            _kill_group(process)
                            break
                    else:
                        if stderr_done:
                            continue
                        room = max(0, STDERR_CAP - len(stderr))
                        stderr.extend(chunk[:room])
                        stderr_total += len(chunk)
                        if stderr_total >= STDERR_CAP:
                            stderr_truncated = True
                            stderr_done = True
                            capped = True
                            _kill_group(process)
                            break
                if capped:
                    # The group is dead, so both pipes stop here.  A pipe
                    # whose writer escaped the group would otherwise hold
                    # the session until the whole timeout.
                    break
                if stdout_done and stderr_done:
                    break
        finally:
            selector.close()
            for stream in (stdout_stream, stderr_stream):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

        writer.join(timeout=_REAP_S)
        try:
            process.wait(timeout=_WAIT_S)
        except subprocess.TimeoutExpired:
            _kill_group(process)
            try:
                process.wait(timeout=_WAIT_S)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        return (
            bytes(stdout),
            bytes(stderr),
            timed_out,
            stdout_truncated,
            stderr_truncated,
        )

    @staticmethod
    def _write_stdin(process: Any, data: bytes) -> None:
        stream = getattr(process, "stdin", None)
        if stream is None:
            return
        try:
            if data:
                stream.write(data)
                stream.flush()
        except (BrokenPipeError, OSError, TypeError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass
