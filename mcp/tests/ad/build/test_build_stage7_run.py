"""Stage 7 of a two-DC run, option B (PLAN-1.5 task 8 part B; DESIGN-1.5
"The second DC (stage 7)"; MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2,
2026-11-15").

The measured sequence: DC1's helper provisions DC2 (``djoin /provision``)
and answers the blob; the runner carries it to DC2's helper, which joins
(``djoin /requestODJ``) and reboots; once DC2 answers that it is a
member, DC1's helper installs the replica over WinRM with Kerberos from
its own password task and restarts DC2; once DC2 answers done (it is a
DC, its read-backs passed), DC1's helper reads the replication back.

The blob is the only secret Newton carries: it reaches only DC2's run
request, it is never written under the state directory and never logged.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from fake_build_helper import FAKE_ODJ  # type: ignore[import-not-found]
from newton_mcp import approve
from newton_mcp.ad.build import plan
from newton_mcp.ad.build import run as build_run
from newton_mcp.ad.build import transport as build_transport
from test_build_run import PLAN_ID, Build, state_dir  # type: ignore[import-not-found]  # noqa: F401

ODJ_BYTES = base64.b64decode(FAKE_ODJ)


def _stage7(build: Build) -> list[tuple[str, str]]:
    return [(d, a) for d, s, a in build.transport.actions() if s == "7" and a in ("run", "status")]


def _runs7(build: Build) -> list[str]:
    return [d for d, s, a in build.transport.actions() if s == "7" and a == "run"]


def _to_stage7(build: Build) -> dict[str, Any]:
    """Drive the run until it stops for stage 7's approval, and approve it."""
    state = build.run()
    while state["state"] == build_run.STOPPED_FOR_APPROVAL and state["stage"] != "7":
        assert build.approve_stage(state["stage"]) == 0
        state = build.run()
    assert state["state"] == build_run.STOPPED_FOR_APPROVAL and state["stage"] == "7", state
    assert build.approve_stage("7") == 0
    return state


def test_the_replica_runs_provision_join_install_read_in_that_order(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    state = build.drive()
    assert state["state"] == "done", state
    assert _runs7(build) == ["build1", "build2", "build1", "build1"]
    steps = _stage7(build)
    first_dc2_run = steps.index(("build2", "run"))
    second_dc1_run = [i for i, step in enumerate(steps) if step == ("build1", "run")][1]
    third_dc1_run = [i for i, step in enumerate(steps) if step == ("build1", "run")][2]
    # DC2 is asked for its status between its join and DC1's install, and
    # between the install and DC1's read-back.
    assert ("build2", "status") in steps[first_dc2_run:second_dc1_run]
    assert ("build2", "status") in steps[second_dc1_run:third_dc1_run]
    assert build.helpers["build2"].promoted
    assert "7" in build.helpers["build1"].completed() and "7" in build.helpers["build2"].completed()
    assert state["finished"]["build2"] == list(plan.DC2_GRAPH)


def test_the_blob_reaches_only_dc2s_run_request(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    assert build.drive()["state"] == "done"
    carrying = [(d, r) for d, r in build.transport.requests if "odj" in r]
    assert len(carrying) == 1
    device, request = carrying[0]
    assert (device, request["stage"], request["action"]) == ("build2", "7", "run")
    assert request["odj"] == FAKE_ODJ
    for d, r in build.transport.requests:
        if r is not request:
            assert FAKE_ODJ not in json.dumps(r)


def test_the_blob_is_never_written_under_the_state_directory(
    monkeypatch: pytest.MonkeyPatch, state_dir: Path  # noqa: F811
) -> None:
    written: list[bytes] = []
    real = approve._atomic_write

    def spy(path: Any, value: Any) -> None:
        real(path, value)
        written.append(Path(path).read_bytes())

    monkeypatch.setattr(approve, "_atomic_write", spy)
    build = Build(monkeypatch, two=True)
    assert build.drive()["state"] == "done"
    assert written
    needles = (FAKE_ODJ.encode(), FAKE_ODJ[:64].encode(), ODJ_BYTES[2:66])
    for blob in written + [p.read_bytes() for p in state_dir.rglob("*") if p.is_file()]:
        for needle in needles:
            assert needle not in blob
    assert all("odj" not in receipt for receipt in json.loads(approve.build_run_state_path(PLAN_ID).read_text())["receipts"])


class _SshOverFake(build_transport.SshHelperTransport):
    """The real ``SshHelperTransport.send`` (the payload encoded, the size
    checked, the answer parsed), with a fake ssh runner under it that hands
    each session's stdin to the fake helper of its server (F8 of the part
    B triage)."""

    def __init__(self, fake: Any) -> None:
        self.fake = fake
        self.helpers = fake.helpers
        self.requests = fake.requests
        self.sessions: list[str] = []
        targets = {
            device: build_transport.HelperTarget(
                name=device, host="192.0.2.1", port=22, key_file=Path("/nonexistent/key"), known_hosts=Path("/nonexistent/kh")
            )
            for device in fake.helpers
        }
        super().__init__(targets, runner_for=self._runner_for_target)

    def _runner_for_target(self, target: build_transport.HelperTarget) -> Any:
        from newton_mcp.vendor_change import RunOut

        def run(spec: Any) -> Any:
            self.sessions.append(target.name)
            try:
                answer = self.fake.send(target.name, json.loads(spec.stdin))
            except build_transport.HelperUnavailable:
                return RunOut(status="unreachable", stdout="", stderr="", exit_code=255)
            return RunOut(status="ok", stdout=json.dumps(answer), stderr="", exit_code=0)

        return run

    def actions(self, device: str | None = None) -> list[tuple[str, str, str]]:
        return self.fake.actions(device)


def _over_ssh(monkeypatch: pytest.MonkeyPatch) -> Build:
    build = Build(monkeypatch, two=True)
    build.transport = _SshOverFake(build.transport)  # type: ignore[assignment]
    return build


def test_the_blob_is_never_logged(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    build = _over_ssh(monkeypatch)
    assert build.drive()["state"] == "done"
    sessions = build.transport.sessions  # type: ignore[attr-defined]
    assert sessions.count("build2") >= 1 and len(sessions) == len(build.transport.requests)
    assert any("odj" in r for _, r in build.transport.requests)
    for needle in (FAKE_ODJ[:64], FAKE_ODJ[-64:], repr(ODJ_BYTES[2:66])[2:-1]):
        assert needle not in caplog.text
    for record in caplog.records:
        assert FAKE_ODJ[:64] not in repr(record.args)


def test_the_runner_holds_no_blob_after_the_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    """The runner's own objects hold no reference to the blob once DC2's run
    request is sent: what the runner keeps is the run state and its
    receipts, and neither has it."""
    seen: list[Any] = []
    real_init = build_run._Runner.__init__

    def keep(self: Any, *args: Any, **kwargs: Any) -> None:
        real_init(self, *args, **kwargs)
        seen.append(self)

    monkeypatch.setattr(build_run._Runner, "__init__", keep)
    build = _over_ssh(monkeypatch)
    assert build.drive()["state"] == "done"
    assert seen
    for runner in seen:
        assert FAKE_ODJ not in json.dumps(runner.state)
        for value in vars(runner).values():
            if isinstance(value, (bytes, bytearray)):
                # the base64 and the decoded blob (F8 of the part B triage)
                assert FAKE_ODJ.encode() not in value and ODJ_BYTES[2:66] not in value
            else:
                assert FAKE_ODJ not in repr(value)
                assert repr(ODJ_BYTES[2:66])[2:-1] not in repr(value)


def test_a_provision_answer_without_the_blob_stops_and_sends_dc2_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build1"].odj_missing = True
    state = build.run()
    assert state["state"] == "stopped"
    assert state["reason"] == "answer_invalid"
    assert _runs7(build) == ["build1"]


@pytest.mark.parametrize("phase, runs", [("provision", ["build1"]), ("install", ["build1", "build2", "build1"])])
def test_a_stage_7_answer_without_its_phase_check_stops(monkeypatch: pytest.MonkeyPatch, phase: str, runs: list[str]) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build1"].no_check.add(phase)
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "unexpected_status", "build1")
    assert _runs7(build) == runs


def test_a_stopped_provision_stops_the_run_and_sends_dc2_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build1"].replica_stop["provision"] = "op_failed"
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "op_failed", "build1")
    assert _runs7(build) == ["build1"]


def test_a_failed_join_stops_the_run_and_dc1_installs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build2"].replica_stop["join"] = "op_failed"
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "op_failed", "build2")
    assert _runs7(build) == ["build1", "build2"]


@pytest.mark.parametrize("status", ["started", "done"])
def test_a_join_that_does_not_reboot_stops_and_dc1_installs_nothing(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build2"].join_answer = status
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "unexpected_status", "build2")
    assert _runs7(build) == ["build1", "build2"]


def test_a_dropped_join_is_connection_lost_and_dc1_installs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build2"].drop_run.add("7")
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "connection_lost", "build2")
    assert _runs7(build) == ["build1", "build2"]


def test_a_dc2_that_never_answers_member_is_reboot_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build2"].never_member = True
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "reboot_timeout", "build2")
    assert _runs7(build) == ["build1", "build2"]


def test_a_failed_install_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build1"].replica_stop["install"] = "readback_failed"
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "readback_failed", "build1")
    assert _runs7(build) == ["build1", "build2", "build1"]


def test_a_dc2_that_is_no_dc_after_the_promotion_stops_and_dc1_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build2"].replica_stop["promoted"] = "readback_failed"
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "readback_failed", "build2")
    assert _runs7(build) == ["build1", "build2", "build1"]


def test_a_failed_replication_read_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    build.helpers["build1"].replica_stop["read"] = "readback_failed"
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "readback_failed", "build1")
    assert "7" not in state["finished"].get("build1", [])
    assert "7" not in state["finished"].get("build2", [])


def test_a_replica_interrupted_mid_way_stops_and_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A runner killed inside stage 7 (the blob it held is gone with it)
    does not pick the sequence up again: the run stops and goes on only
    through a resume plan."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)

    class Killed(BaseException):
        pass

    real = build.transport.send
    sent: list[str] = []

    def kill_at_join(device: str, request: Any) -> Any:
        if device == "build2" and request["stage"] == "7" and request["action"] == "run":
            raise Killed()
        sent.append(device)
        return real(device, request)

    monkeypatch.setattr(build.transport, "send", kill_at_join)
    with pytest.raises(Killed):
        build.run()
    monkeypatch.setattr(build.transport, "send", real)
    before = len(build.transport.requests)
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "stage_interrupted")
    assert [r for _, r in build.transport.requests[before:] if r["action"] == "run"] == []


def _kill_at(build: Build, monkeypatch: pytest.MonkeyPatch, device: str, nth_run: int) -> None:
    """Run until the runner sends its ``nth_run``-th stage 7 run request to
    ``device``, and kill the runner there (the request is not sent)."""

    class Killed(BaseException):
        pass

    real = build.transport.send
    seen = {"runs": 0}

    def kill(dev: str, request: Any) -> Any:
        if dev == device and request["stage"] == "7" and request["action"] == "run":
            seen["runs"] += 1
            if seen["runs"] == nth_run:
                raise Killed()
        return real(dev, request)

    monkeypatch.setattr(build.transport, "send", kill)
    with pytest.raises(Killed):
        build.run()
    monkeypatch.setattr(build.transport, "send", real)


def _drop_the_marker() -> None:
    """The agent can write the run state: it deletes stage 7's begun marker."""
    path = approve.build_run_state_path(PLAN_ID)
    state = json.loads(path.read_text())
    state.pop("replica", None)
    path.write_text(json.dumps(state))


@pytest.mark.parametrize(
    "device, nth_run",
    [("build2", 1), ("build1", 2), ("build1", 3)],
    ids=["killed-at-the-join", "killed-at-the-install", "killed-at-the-read"],
)
def test_a_replica_interrupted_mid_way_stops_from_the_journals_without_the_marker(
    monkeypatch: pytest.MonkeyPatch, device: str, nth_run: int
) -> None:
    """IC-1 of the part B triage: the stop rests on the helpers' journals,
    not on the agent-written marker.  Before DC1's provision the runner
    reads stage 7's state on both servers and stops when either holds any
    stage 7 entry."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, device, nth_run)
    _drop_the_marker()
    before = len(build.transport.requests)
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "stage_interrupted"), state
    assert [r for _, r in build.transport.requests[before:] if r["action"] == "run"] == []


def test_the_stage_7_states_are_read_on_both_servers_before_the_provision(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    assert build.run()["state"] == "done"
    steps = [(d, a) for d, s, a in build.transport.actions() if s == "7"]
    provision = steps.index(("build1", "run"))
    assert ("build1", "status") in steps[:provision]
    assert ("build2", "status") in steps[:provision]


@pytest.mark.parametrize("device", ["build1", "build2"])
def test_an_unanswered_stage_7_status_before_the_provision_stops_journal_unreadable(
    monkeypatch: pytest.MonkeyPatch, device: str
) -> None:
    """IC-1: a server that does not answer the status of stage 7 before
    DC1's provision gives no proof that its journal holds no stage 7
    entry.  The run stops ``journal_unreadable`` and sends no run."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    real = build.transport.send

    def silent(dev: str, request: Any) -> Any:
        if dev == device and request["stage"] == "7" and request["action"] == "status":
            raise build_transport.HelperUnavailable("the build helper did not answer")
        return real(dev, request)

    monkeypatch.setattr(build.transport, "send", silent)
    state = build.run()
    assert (state["state"], state["reason"], state["device"], state["stage"]) == (
        "stopped", "journal_unreadable", device, "7"
    ), state
    assert _runs7(build) == []


@pytest.mark.parametrize("device", ["build1", "build2"])
def test_a_refused_stage_7_status_before_the_provision_stops_with_its_code(
    monkeypatch: pytest.MonkeyPatch, device: str
) -> None:
    """IC-1: a refused status of stage 7 before the provision stops the run
    with the helper's code, never ``stage_interrupted`` and never a run."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    real = build.transport.send

    def refuse(dev: str, request: Any) -> Any:
        if dev == device and request["stage"] == "7" and request["action"] == "status":
            build.transport.requests.append((dev, dict(request)))
            return {"ok": False, "status": "refused", "code": "bad_token", "checks": []}
        return real(dev, request)

    monkeypatch.setattr(build.transport, "send", refuse)
    state = build.run()
    assert (state["state"], state["reason"], state["device"], state["stage"]) == (
        "stopped", "bad_token", device, "7"
    ), state
    assert _runs7(build) == []


@pytest.mark.parametrize(
    "device, nth_run, reason, stage",
    [
        # DC2's stage 7 is in flight (``rebooting``, a member): its helper
        # refuses the resume plan's journal read (``out_of_order``).
        ("build1", 2, "journal_unreadable", ""),
        # DC2's stage 7 is done, its next stage is 9: one start_stage cannot
        # name both servers' next stage (open point 26).
        ("build1", 3, "plan_mismatch", ""),
    ],
    ids=["killed-at-the-install", "killed-at-the-read"],
)
def test_a_resume_plan_at_7_after_an_interrupted_replica_stops_for_the_owner(
    monkeypatch: pytest.MonkeyPatch, device: str, nth_run: int, reason: str, stage: str
) -> None:
    """IC-1, DESIGN-1.5 open point 38: Newton never resumes a stage 7 that
    began and did not end, even through a resume plan that starts at 7
    (the blob is gone with the killed runner; the computer object the
    provision made stays).  The resume run stops, sends no stage 7 run,
    and its own stop says that the owner decides, not that a resume plan
    goes on."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, device, nth_run)
    build.resume("7")
    before = len(build.transport.requests)
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", reason, stage), state
    assert [r for _, r in build.transport.requests[before:] if r["stage"] == "7" and r["action"] == "run"] == []
    if reason == "stage_interrupted":
        assert "resume plan goes on" not in state["detail"]
        assert "owner" in state["detail"]


def test_an_interrupted_replica_never_says_a_resume_plan_goes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stop of a stage 7 that began (the run state's marker) names the
    owner, not a resume plan (open point 38)."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, "build2", 1)
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "stage_interrupted"), state
    assert "resume plan goes on" not in state["detail"]
    assert "owner" in state["detail"]


def test_stage_7_waits_for_both_stage_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    state = build.run()
    while not (state["state"] == build_run.STOPPED_FOR_APPROVAL and state["stage"] == "7"):
        assert build.approve_stage(state["stage"]) == 0
        state = build.run()
    record_path = approve.build_stage_approval_path(PLAN_ID, "7")
    assert build.approve_stage("7") == 0
    record = json.loads(record_path.read_text())
    del record["servers"]["build2"]
    record_path.write_text(json.dumps(record))
    state = build.run()
    assert state["state"] == build_run.STOPPED_FOR_APPROVAL and state["stage"] == "7"
    assert _runs7(build) == []


# --------------------------------------------------------------------------
# the contract of the blob
# --------------------------------------------------------------------------

_REQUEST = dict(
    run="ab" * 16, plan_bytes=b"plan", token="cd" * 32, nbf=1794578100, exp=1794579960,
)


def test_only_a_stage_7_run_request_carries_a_blob() -> None:
    request = build_transport.helper_request(stage="7", action="run", odj=FAKE_ODJ, **_REQUEST)
    assert request["odj"] == FAKE_ODJ
    for stage, action in (("6", "run"), ("7", "status"), ("7", "checkpoint"), ("9", "run")):
        with pytest.raises(ValueError):
            build_transport.helper_request(stage=stage, action=action, odj=FAKE_ODJ, **_REQUEST)


@pytest.mark.parametrize(
    "odj",
    ["", "abc", "not base64!", "QUJD" * 9000, "QUJD\nQUJD", 7, None.__class__],
    ids=["empty", "unpadded", "alphabet", "too-long", "newline", "int", "type"],
)
def test_a_blob_outside_its_grammar_is_never_sent(odj: Any) -> None:
    with pytest.raises(ValueError):
        build_transport.helper_request(stage="7", action="run", odj=odj, **_REQUEST)


def _answer(**extra: Any) -> str:
    return json.dumps({"ok": True, "status": "started", "code": "", "checks": [], **extra})


def test_a_run_answer_may_carry_a_blob_and_no_other_answer_may() -> None:
    assert build_transport.parse_answer(_answer(odj=FAKE_ODJ), action="run")["odj"] == FAKE_ODJ
    for action in ("status", "checkpoint", "read"):
        with pytest.raises(build_transport.HelperAnswerInvalid):
            build_transport.parse_answer(_answer(odj=FAKE_ODJ), action=action)


@pytest.mark.parametrize("odj", ["", "abc", "not base64!", "QUJD" * 9000, 7, None])
def test_a_blob_answer_outside_its_grammar_is_invalid(odj: Any) -> None:
    with pytest.raises(build_transport.HelperAnswerInvalid):
        build_transport.parse_answer(_answer(odj=odj), action="run")


def test_a_blob_answer_that_is_not_ok_started_is_invalid() -> None:
    for ok, status in ((True, "done"), (False, "stopped"), (True, "rebooting")):
        text = json.dumps({"ok": ok, "status": status, "code": "", "checks": [], "odj": FAKE_ODJ})
        with pytest.raises(build_transport.HelperAnswerInvalid):
            build_transport.parse_answer(text, action="run")


# -- IC1-resume7 of the part C triage (open point 33): a resume plan at 7 ----


def test_a_resume_plan_at_7_after_a_provision_dc2_never_joined_ends_done(monkeypatch: pytest.MonkeyPatch) -> None:
    """Killed at the join: DC1's journal holds the provision, DC2's nothing.
    A resume plan at 7 sends DC1's run again, its helper provisions again
    with /reuse, and the sequence ends done."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, "build2", 1)
    build.resume("7")
    state = build.drive()
    assert state["state"] == "done", state
    assert build.helpers["build1"].reprovisions == 1
    assert build.helpers["build2"]._state("7") == "done"


def test_without_a_resume_plan_a_provision_dc2_never_joined_stops_stage_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, "build2", 1)
    _drop_the_marker()
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "stage_interrupted"), state
    assert build.helpers["build1"].reprovisions == 0


def test_a_resume_plan_at_7_over_a_dc1_past_its_provision_sends_no_join(monkeypatch: pytest.MonkeyPatch) -> None:
    """DC1's helper refuses a resume run over any phase after the
    provision's: the run stops with its refusal, and DC2 gets no run."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, "build2", 1)
    last = [e for e in build.helpers["build1"].journal if e["stage"] == "7" and e["state"] != "checkpointed"][-1]
    last["phase"] = "s7_install"
    build.resume("7")
    before = len(build.transport.requests)
    state = build.drive()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "out_of_order", "build1"), state
    assert [d for d, r in build.transport.requests[before:] if r["stage"] == "7" and r["action"] == "run"] == ["build1"]
    assert build.helpers["build1"].reprovisions == 0


@pytest.mark.parametrize("dc2_state", ["rebooting", "stopped"])
def test_a_resume_plan_at_7_does_not_provision_again_once_dc2_began(monkeypatch: pytest.MonkeyPatch, dc2_state: str) -> None:
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _kill_at(build, monkeypatch, "build2", 1)
    dc2 = build.helpers["build2"]
    digest = next(e["digest"] for e in build.helpers["build1"].journal if e["stage"] == "7" and e["state"] != "checkpointed")
    dc2._entry7(dc2_state, digest, "s7_join")
    build.resume("7")
    before = len(build.transport.requests)
    state = build.drive()
    assert state["state"] == "stopped", state
    assert [r for _, r in build.transport.requests[before:] if r["stage"] == "7" and r["action"] == "run"] == []


# -- the read-back's bound (K17) ----------------------------------------------


def test_dc1s_read_back_may_take_up_to_35_minutes(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    build.helpers["build1"].read_s = 30 * 60
    state = build.drive()
    assert state["state"] == "done", state
    assert build_run.READBACK_TIMEOUT_S == 35 * 60


def test_a_read_back_past_35_minutes_is_status_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    build.helpers["build1"].read_s = 40 * 60
    state = build.drive()
    assert (state["state"], state["reason"], state["device"], state["stage"]) == ("stopped", "status_timeout", "build1", "7"), state
    assert "35 minutes" in state["detail"]


# -- a held journal lock (the lab run of 2026-11-23) ---------------------------


def _arm_at_the_install(build: Build, monkeypatch: pytest.MonkeyPatch, busy: int) -> None:
    """DC2's helper refuses its next ``busy`` status answers with
    ``journal_busy`` (another request holds the journal of the server) from
    the install of the replica on."""
    real = build.transport.send
    seen = {"runs": 0}

    def arm(device: str, request: Any) -> Any:
        if device == "build1" and request["stage"] == "7" and request["action"] == "run":
            seen["runs"] += 1
            if seen["runs"] == 2:
                build.helpers["build2"].busy_stage = "7"
                build.helpers["build2"].busy_statuses = busy
        return real(device, request)

    monkeypatch.setattr(build.transport, "send", arm)


def test_a_dc2_poll_refused_journal_busy_waits_for_the_stage_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper of DC2 holds the journal of the server while its own
    ``s7-dc`` op runs, and refuses every status with ``journal_busy``.  The
    runner waits for the answer it polls for and stage 7 ends done (the lab
    run of 2026-11-23 measured the refusal)."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _arm_at_the_install(build, monkeypatch, 2)
    before = len(build.transport.requests)
    state = build.run()
    assert state["state"] == "done", state
    polls = [r for d, r in build.transport.requests[before:] if d == "build2" and r["stage"] == "7" and r["action"] == "status"]
    assert len(polls) >= 3, polls


def test_a_dc2_poll_refused_journal_busy_until_the_deadline_stops_reboot_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A status that stays refused ``journal_busy`` never ends the stage:
    the poll waits for the deadline it has and stops as it does for a
    stage that did not end."""
    build = Build(monkeypatch, two=True)
    _to_stage7(build)
    _arm_at_the_install(build, monkeypatch, 10**6)
    state = build.run()
    assert (state["state"], state["reason"], state["device"], state["stage"]) == (
        "stopped", "reboot_timeout", "build2", "7",
    ), state


# -- DC2's own dcdiag wait (the lab run of 2026-11-23) ------------------------


def test_the_dc_diag_bound_of_the_runner_is_the_helpers_own() -> None:
    """The runner waits as long as the helper's own dcdiag waits: the two
    numbers are one number."""
    text = (
        Path(__file__).resolve().parents[3] / "newton_mcp" / "ad" / "build" / "helper" / "build.ps1"
    ).read_text(encoding="utf-8")
    line = next(row for row in text.splitlines() if row.startswith("$script:DiagMaxSeconds = "))
    assert line.split("=", 1)[1].strip().isdigit()
    assert build_run.S7_DC_DIAG_MAX_S == int(line.split("=", 1)[1].strip())


def test_a_dc2_that_answers_done_after_twenty_minutes_completes_stage_7(monkeypatch: pytest.MonkeyPatch) -> None:
    """DC2's own dcdiag may wait for the first replication to settle: the
    runner waits for the promotion's reboot and that wait."""
    build = Build(monkeypatch, two=True)
    build.helpers["build2"].dc_s = 20 * 60
    state = build.drive()
    assert state["state"] == "done", state
    assert build_run.S7_DC_DIAG_MAX_S == 15 * 60


def test_a_dc2_whose_status_answers_in_flight_while_its_task_runs_completes_stage_7(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DC2's own read runs in its SYSTEM task: while it runs, the status of
    DC2's stage 7 answers in flight (``started``), and the runner goes on
    polling until the stage ends done."""
    build = Build(monkeypatch, two=True)
    build.helpers["build2"].dc_in_flight = True
    build.helpers["build2"].dc_s = 20 * 60
    state = build.drive()
    assert state["state"] == "done", state
    polls = [r for d, r in build.transport.requests if d == "build2" and r["stage"] == "7" and r["action"] == "status"]
    assert len(polls) >= 2, polls


def test_the_runner_waits_a_margin_of_one_pass_for_the_last_diag_pass() -> None:
    """The bound of the runner leaves room for the pass that ends after the
    dcdiag wait: the margin is the helper's own margin of one pass."""
    text = (
        Path(__file__).resolve().parents[3] / "newton_mcp" / "ad" / "build" / "helper" / "build.ps1"
    ).read_text(encoding="utf-8")
    line = next(row for row in text.splitlines() if row.startswith("$script:DiagPassMarginSeconds = "))
    assert line.split("=", 1)[1].strip().isdigit()
    assert build_run.S7_DC_PASS_MARGIN_S == int(line.split("=", 1)[1].strip())


def test_a_dc2_that_answers_done_after_the_diag_wait_and_a_margin_completes_stage_7(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DC2's last pass may end just after its dcdiag wait: the runner waits
    the margin of one pass on top of that wait, so the result is read and
    the stage ends done.  The stage token's own window is widened here, so
    that the bound of the runner is what decides."""
    monkeypatch.setattr(approve, "BUILD_STAGE_WINDOW_S", 60 * 60)
    build = Build(monkeypatch, two=True)
    build.helpers["build2"].dc_s = build_run.REBOOT_TIMEOUT_S + 900 + 60
    state = build.drive()
    assert state["state"] == "done", state
    assert build_run.S7_DC_DIAG_MAX_S == 15 * 60
