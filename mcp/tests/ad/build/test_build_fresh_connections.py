"""The build reads a server over a fresh connection (rule 6).

Every request of the build runs over an ssh session of its own: the
read-back of a stage never rides on the session that wrote it.  These
tests count the sessions the transport opens and prove that the read-back
opens a new one after the write.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import transport as build_transport
from newton_mcp.vendor_change import RunOut

from test_build_run import Build, state_dir  # type: ignore[import-not-found]  # noqa: F401


class Sessions:
    """The sessions the transport opened, in the order it opened them."""

    def __init__(self) -> None:
        self.opened: list[tuple[int, str, str, str]] = []

    def carry(self, session: int, device: str, action: str, stage: str) -> None:
        """One request over one session."""
        self.opened.append((session, device, action, stage))


class _SshOverFake(build_transport.SshHelperTransport):
    """The real transport of the build (the payload encoded, the size
    checked, the answer parsed) over a fake ssh runner.

    The runner opens one session per request and hands the payload to the
    fake helper of its server, as the real runner hands the request on
    stdin to the helper.
    """

    def __init__(self, fake: Any, sessions: Sessions) -> None:
        self.fake = fake
        self.helpers = fake.helpers
        self.requests = fake.requests
        self.sessions = sessions
        self._counter = 0
        targets = {
            device: build_transport.HelperTarget(
                name=device,
                host="192.0.2.1",
                port=22,
                key_file=Path("/nonexistent/key"),
                known_hosts=Path("/nonexistent/kh"),
            )
            for device in fake.helpers
        }
        super().__init__(targets, runner_for=self._runner_for_target)

    def _runner_for_target(self, target: build_transport.HelperTarget) -> Any:
        self._counter += 1
        session = self._counter

        def run(spec: Any) -> Any:
            request = json.loads(spec.stdin)
            self.sessions.carry(
                session, target.name, str(request.get("action")), str(request.get("stage"))
            )
            try:
                answer = self.fake.send(target.name, request)
            except build_transport.HelperUnavailable:
                return RunOut(status="unreachable", stdout="", stderr="", exit_code=255)
            return RunOut(status="ok", stdout=json.dumps(answer), stderr="", exit_code=0)

        return run

    def actions(self, device: str | None = None) -> list[tuple[str, str, str]]:
        return self.fake.actions(device)


def _over_ssh(monkeypatch: pytest.MonkeyPatch) -> Build:
    """The build with the real transport over a fake ssh runner."""
    build = Build(monkeypatch)
    build.transport = _SshOverFake(build.transport, Sessions())  # type: ignore[assignment]
    return build


def test_the_read_back_of_a_stage_reads_the_server_over_a_new_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read-back of a stage never rides on the session that wrote it.

    The run of the stage went to the server over a session of its own,
    and the read-back of the stage opened a new session after the write.
    """
    build = _over_ssh(monkeypatch)

    state = build.drive()

    assert state["state"] == "done", state
    order = build.transport.sessions.opened  # type: ignore[attr-defined]
    write = next(
        index
        for index, (session, device, action, stage) in enumerate(order)
        if device == "build1" and stage == "1" and action == "run"
    )
    read = next(
        index
        for index, (session, device, action, stage) in enumerate(order)
        if index > write and device == "build1" and stage == "1" and action == "status"
    )
    # the read-back opened a new session after the write, never the
    # session that wrote the stage
    assert order[read][0] > order[write][0]
    # every request of the run opened a session of its own
    assert len({session for session, _, _, _ in order}) == len(order)
