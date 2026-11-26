"""The AD change verifies over fresh sessions (the change protocol, rule 6).

Every request of the write path opens an ssh session of its own: the
read-back of the after-image on every domain controller runs over a
session of its own, never over the session that wrote the change.  These
tests count the sessions the transport opens and prove that the read-back
opens a new one after the write.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import harness
import pytest

from newton_mcp.ad.write import apply as ad_apply, transport
from newton_mcp.vendor_change import RunOut

from test_write_apply import _approved_plan, _lab


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


class Sessions:
    """The sessions the transport opened, in the order it opened them."""

    def __init__(self) -> None:
        self.opened: list[tuple[int, str, str]] = []
        self.connections = 0

    def connect(self) -> int:
        """A new session: the runner the transport built opens one."""
        self.connections += 1
        return self.connections

    def carry(self, session: int, device: str, mode: str) -> None:
        """One request over one session."""
        self.opened.append((session, device, mode))

    def of(self, device: str, mode: str) -> list[int]:
        """The sessions of one DC that carried one mode, in order."""
        return [
            session
            for session, one_device, one_mode in self.opened
            if one_device == device and one_mode == mode
        ]


class _Runner:
    """The ssh runner of the transport, faked.

    One session per runner, as the real runner opens one ssh connection
    and runs the request on it: the session hands its stdin to the fake
    helper of its DC and answers with the answer of the helper.
    """

    def __init__(
        self, target: Any, sessions: Sessions, lab: harness.Lab, **kwargs: Any
    ) -> None:
        self.target = target
        self.sessions = sessions
        self.lab = lab
        self.session = sessions.connect()

    def preflight(self, spec: Any) -> None:
        """The pre-flight of the runner starts no process: no request."""

    def __call__(self, spec: Any) -> RunOut:
        body = json.loads(spec.stdin)
        self.sessions.carry(self.session, self.target.name, str(body["mode"]))
        answer = self.lab.send(self.target, body)
        return RunOut(status="ok", stdout=json.dumps(answer), stderr="", exit_code=0)


def _runner_factory(sessions: Sessions, lab: harness.Lab) -> Any:
    """The runner the transport builds for every request."""

    def factory(target: Any, **kwargs: Any) -> _Runner:
        return _Runner(target, sessions, lab, **kwargs)

    return factory


def test_the_read_back_of_every_dc_runs_over_a_session_of_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read-back of the after-image opens a new session after the write.

    The write went to the domain controller over a session of its own,
    and the read-back of the after-image on the domain controller and on
    the second one each opened a session of its own, after the write.
    """
    lab = _lab()
    plan_id = _approved_plan(lab)
    sessions = Sessions()
    monkeypatch.setattr(transport, "SshSessionRunner", _runner_factory(sessions, lab))

    result = ad_apply.apply_change(plan_id, devices=lab.devices, timeout_s=0.0)

    assert result["state"] == "confirmed"
    writes = sessions.of("win-dc1", "apply")
    reads = sessions.of("win-dc1", "read")
    assert len(writes) == 1
    assert len(reads) == 1
    # the read-back opened a new session after the write, never the
    # session that wrote the change
    assert reads[0] > writes[0]
    # the second domain controller is read over a session of its own, and
    # its read came after the write
    assert len(sessions.of("win-dc2", "read")) == 1
    assert sessions.of("win-dc2", "read")[0] > writes[0]
    # every request of the apply opened a session of its own
    assert len({session for session, _, _ in sessions.opened}) == len(sessions.opened)
