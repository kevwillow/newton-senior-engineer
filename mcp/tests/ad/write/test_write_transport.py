"""The AD write transport (SPEC-1.4-REQUEST section 1).

The request goes on stdin of one ssh session, with no remote command: the
forced command on the far side is the write helper.  The answer is one
JSON object; anything else is an error.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from newton_mcp.ad.write import transport
from newton_mcp.vendor_change import RunOut


DEVICE: Any = None


def _out(
    stdout: str = '{"v":1,"code":"ok"}',
    *,
    status: str = "ok",
    exit_code: int | None = 0,
) -> RunOut:
    return RunOut(status=status, stdout=stdout, stderr="", exit_code=exit_code)


def test_the_request_goes_on_stdin_with_no_remote_command() -> None:
    """The session carries the request and no command."""
    seen: dict[str, Any] = {}

    def runner(spec: Any) -> RunOut:
        seen["spec"] = spec
        return _out()

    transport.send(DEVICE, {"v": 1, "mode": "status"}, runner=runner)

    assert seen["spec"].remote == ""
    assert json.loads(seen["spec"].stdin) == {"v": 1, "mode": "status"}


def test_the_session_caps_the_output_and_times_out() -> None:
    """The stdout cap is 64 KiB and the timeout is 120 seconds."""
    seen: dict[str, Any] = {}

    class FakeRunner:
        def __init__(self, target: Any, **kwargs: Any) -> None:
            seen.update(kwargs)

        def __call__(self, spec: Any) -> RunOut:
            return _out()

    original = transport.SshSessionRunner
    transport.SshSessionRunner = FakeRunner  # type: ignore[assignment]
    try:
        transport.send(DEVICE, {"v": 1})
    finally:
        transport.SshSessionRunner = original  # type: ignore[assignment]

    assert seen["stdout_cap"] == 64 * 1024
    assert seen["timeout_s"] == 120


def test_the_answer_is_one_json_object() -> None:
    """One object comes back."""
    out = transport.send(DEVICE, {"v": 1}, runner=lambda spec: _out())

    assert out == {"v": 1, "code": "ok"}


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "not json",
        "{} {}",
        "[]",
        '{"v":1,"code":"ok"} {"v":1,"code":"ok"}',
    ],
)
def test_anything_but_one_json_object_is_an_error(stdout: str) -> None:
    """A broken answer is an error, never a silent success."""
    with pytest.raises(transport.TransportError) as caught:
        transport.send(DEVICE, {"v": 1}, runner=lambda spec: _out(stdout))

    assert caught.value.code == "error"


def test_an_answer_without_a_code_is_an_error() -> None:
    """The answer carries the code of the contract."""
    with pytest.raises(transport.TransportError) as caught:
        transport.send(DEVICE, {"v": 1}, runner=lambda spec: _out('{"v":1}'))

    assert caught.value.code == "error"


def test_an_answer_with_an_unknown_code_is_an_error() -> None:
    """Only the codes of the contract are answers."""
    with pytest.raises(transport.TransportError) as caught:
        transport.send(DEVICE, {"v": 1}, runner=lambda spec: _out('{"v":1,"code":"maybe"}'))

    assert caught.value.code == "error"


def test_a_session_that_did_not_answer_is_unavailable() -> None:
    """A failed session is not an answer."""
    with pytest.raises(transport.TransportError) as caught:
        transport.send(
            DEVICE,
            {"v": 1},
            runner=lambda spec: _out(status="timed_out", exit_code=None),
        )

    assert caught.value.code == "unavailable"


def test_a_helper_that_crashed_is_an_error() -> None:
    """The helper exits 0 whatever the outcome; another exit is a crash."""
    with pytest.raises(transport.TransportError) as caught:
        transport.send(DEVICE, {"v": 1}, runner=lambda spec: _out(exit_code=3))

    assert caught.value.code == "error"


def test_the_request_is_never_larger_than_the_cap() -> None:
    """The request goes on stdin as one JSON object."""
    seen: dict[str, Any] = {}

    def runner(spec: Any) -> RunOut:
        seen["spec"] = spec
        return _out()

    transport.send(DEVICE, {"v": 1, "mode": "read", "device": "lab-win"}, runner=runner)

    assert len(seen["spec"].stdin.encode("utf-8")) <= transport.MAX_REQUEST_BYTES
