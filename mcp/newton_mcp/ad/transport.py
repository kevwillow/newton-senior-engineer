"""Fetch one collector document from an AD device (SPEC-1.3 section 9).

The AD platforms run a forced command: the session carries no remote
command and no input at all, and the collector on the far side prints
one JSON document on stdout.  The session is the locked ssh invocation
of the vendor transport, with the caps the spec names: 64 MiB of stdout
and 360 s.

A session that did not answer is a transport error with a fixed message
per status.  The message never carries any text of the device: the
stderr of a failed session is device text, and device text never
reaches a log or a model.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..adapters.ssh_cli import RunnerRefused, SshTarget
from ..adapters.vendor_ssh import SshSessionRunner
from ..adapters.vendor_write import SessionSpec


# The caps of one collector session (SPEC-1.3 section 9).
STDOUT_CAP = 64 * 1024 * 1024
TIMEOUT_S = 360

# The message of a session that did not answer, one per status.  The
# words are fixed: no text of the device is ever part of them.
MESSAGES: dict[str, str] = {
    "timed_out": "the collector did not answer in time",
    "auth_failed": "the collector refused the audit key",
    "unreachable": "the collector host did not answer",
    "output_cap": "the collector document was too large",
}

# The message of a session that answered with a non-zero exit code and
# of a status this module does not know.
FAILED_MESSAGE = "the collector failed"

# The message of a session that was refused before a process started.
REFUSED_MESSAGE = "the collector session was refused before it started"


class AdTransportError(Exception):
    """The collector document could not be fetched.

    The message is fixed per status: it never carries any text of the
    device.
    """


def fetch(
    device: SshTarget,
    *,
    popen: Callable[..., Any] | None = None,
) -> bytes:
    """Fetch the collector document of one AD device.

    The session carries no remote command and no input: the forced
    command on the far side is the collector, and the collector takes
    no input (SPEC-1.3 section 7).

    ``popen`` is the seam the tests use: the fake process launcher of
    the vendor transport tests.  Without it the locked ssh invocation
    of the host runs.
    """
    if popen is None:
        runner = SshSessionRunner(
            device, stdout_cap=STDOUT_CAP, timeout_s=TIMEOUT_S
        )
    else:
        runner = SshSessionRunner(
            device,
            stdout_cap=STDOUT_CAP,
            timeout_s=TIMEOUT_S,
            popen=popen,
        )
    try:
        out = runner(SessionSpec(remote="", stdin=""))
    except RunnerRefused as exc:
        raise AdTransportError(REFUSED_MESSAGE) from exc
    if out.status != "ok":
        raise AdTransportError(MESSAGES.get(out.status, FAILED_MESSAGE))
    if out.exit_code != 0:
        raise AdTransportError(FAILED_MESSAGE)
    return out.stdout.encode("utf-8")
