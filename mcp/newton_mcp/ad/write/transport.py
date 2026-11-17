"""The transport to the AD write helper (SPEC-1.4-REQUEST section 1).

One ssh session per request: the request goes on stdin, the session
carries no remote command (the forced command on the far side is the
write helper itself) and the answer is one JSON object.

The session is the locked runner of the repository (``SshSessionRunner``),
so the ssh options, the host-key pinning and the no-forwarding rules are
the ones every other transport uses.  Nothing here builds a shell string:
the request is data on stdin and never reaches an argv.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from ...adapters.vendor_ssh import SshSessionRunner
from ...adapters.vendor_write import SessionSpec
from ...vendor_change import RunOut
from .request import CODES, MAX_REQUEST_BYTES


#: The biggest answer the transport reads.
STDOUT_CAP = 64 * 1024

#: How long one session may take.
TIMEOUT_S = 120


class TransportError(Exception):
    """The helper did not answer with one JSON object.

    The code is the word of the contract: ``error`` for a broken answer
    and ``unavailable`` when the helper's answer was not received (the
    session failed, timed out or overran its cap).  Either can follow a
    request the helper received: it may have acted, so neither code means
    nothing was sent.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _one_object(text: str) -> dict[str, Any]:
    """The one JSON object of the answer, or an error."""
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        raise TransportError("error", "the helper did not answer with one JSON object") from None
    if not isinstance(value, dict):
        raise TransportError("error", "the helper did not answer with one JSON object")
    code = value.get("code")
    if not isinstance(code, str) or code not in CODES:
        raise TransportError("error", "the helper did not answer with a code of the contract")
    return value


def _payload(request: Mapping[str, Any]) -> str:
    """The request as one JSON object, or a schema error when it is too big."""
    payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True)
    if len(payload.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise TransportError("schema", "the request is bigger than 64 KiB")
    return payload


def preflight(target: Any, request: Mapping[str, Any]) -> None:
    """Every check ``send`` makes before anything leaves the Newton host.

    It raises the ``TransportError`` (code schema) or the ``RunnerRefused``
    that ``send`` would raise there, and opens no session.
    """
    payload = _payload(request)
    runner = SshSessionRunner(target, stdout_cap=STDOUT_CAP, timeout_s=TIMEOUT_S)
    runner.preflight(SessionSpec(remote="", stdin=payload))


def send(
    target: Any,
    request: Mapping[str, Any],
    *,
    runner: Callable[[SessionSpec], RunOut] | None = None,
) -> dict[str, Any]:
    """Send one request to one write helper and return its answer.

    The request is written as one JSON object on stdin.  The answer is
    one JSON object; anything else raises ``TransportError``.
    """
    payload = _payload(request)
    if runner is None:
        runner = SshSessionRunner(target, stdout_cap=STDOUT_CAP, timeout_s=TIMEOUT_S)
    out = runner(SessionSpec(remote="", stdin=payload))
    if out.status != "ok":
        raise TransportError("unavailable", "the write helper did not answer")
    if out.exit_code != 0:
        raise TransportError("error", "the write helper failed")
    return _one_object(out.stdout)
