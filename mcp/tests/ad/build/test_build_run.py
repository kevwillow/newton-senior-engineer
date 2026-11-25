"""The runner of an AD build (PLAN-1.5 task 8, part A; DESIGN-1.5 "Stage
graphs", "Checkpoints", "Deviation and resume").

``run_build(plan_id)`` drives the approved plan through each server's
helper.  These tests drive it through the fake transport
(``fake_build_helper``), whose fake helpers answer the task 3 contract and
record every request, and once through the real ``build.ps1`` under pwsh
with the task 3 fake stage table.  Stage 7 here is only the helper's
request shape with a fake stage table (part B builds option B).

The owner's approvals are the real ``newton-approve`` functions: the plan
approval mints the plan tokens, and each stage approval verifies the
checkpoint through the adapters with ``not_before`` read from the helper's
journal, then mints the stage tokens the runner resumes with.
"""

from __future__ import annotations

import copy
import fcntl
import io
import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from fake_build_helper import Clock, FakeHelper, FakeTransport  # type: ignore[import-not-found]
from newton_mcp import approve
from newton_mcp.ad.build import checkpoint as build_checkpoint
from newton_mcp.ad.build import plan
from newton_mcp.ad.build import run as build_run
from newton_mcp.ad.build import tools as build_tools
from newton_mcp.ad.build import transport as build_transport
from ops_fixture import OPS  # type: ignore[import-not-found]

PASSPHRASE = "correct horse battery staple"
PLAN_ID = "0123456789abcdef0123456789abcdef"
RESUME_ID = "fedcba9876543210fedcba9876543210"

#: The plan approval of the tests is made at 2027-01-01T00:00:00Z.
APPROVED_AT = datetime(2027, 1, 1, tzinfo=timezone.utc)

DC1: dict[str, Any] = {
    "device": "build1",
    "role": "dc1",
    "hostname": "DC1",
    "ip": "192.0.2.11",
    "prefix": 24,
    "gateway": "192.0.2.1",
    "forwarders": ["192.0.2.53"],
    "checkpoint": "proxmox",
    "vmgenid": "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d",
    "agent": 1,
}
DC2: dict[str, Any] = dict(DC1, device="build2", role="dc2", hostname="DC2", ip="192.0.2.12",
                           vmgenid="55387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d")

INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers"],
        "groups": ["IT Admins"],
        "owner_admin": "owner-admin",
    },
    "servers": [DC1],
    "baseline": {"version": "2026.11", "options": {"administrator": "random-password"}},
    "accepted_findings": [{"id": "AD-A-51", "reason": "owner-accepted"}],
    "ops": dict(OPS),
}


def _inputs(two: bool = False) -> dict[str, Any]:
    inputs = copy.deepcopy(INPUTS)
    if two:
        inputs["servers"] = [copy.deepcopy(DC1), copy.deepcopy(DC2)]
    return inputs


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    monkeypatch.setenv("NEWTON_AD_BUILD_CONFIG", str(tmp_path / "no-config.toml"))
    return root


class FakeAdapters:
    """The checkpoint adapters: a checkpoint is taken at the fake clock's
    time and verifies only when it is no older than ``not_before``."""

    def __init__(self, clock: Clock, *, ok: bool = True) -> None:
        self.clock = clock
        self.ok = ok
        self.taken: list[tuple[str, str, str]] = []
        self.created: dict[str, int] = {}
        self.verified: list[tuple[str, str, int]] = []

    def checkpoint(self, server_cfg: Any, kind: str) -> dict[str, str]:
        ident = f"cp-{server_cfg['device']}-{len(self.taken)}"
        self.taken.append((server_cfg["device"], kind, ident))
        self.created[ident] = int(self.clock())
        return {"name": f"newton-{kind}-{len(self.taken)}", "id": ident}

    def verify(self, server_cfg: Any, cp: Any, kind: str, *, stage: str, not_before: int) -> bool:
        self.verified.append((server_cfg["device"], stage, not_before))
        return self.ok and self.created.get(cp["id"], 0) >= not_before


class Build:
    """One build of the tests: the plan on record, its approval, the fake
    helpers and transport, the adapters and the fake clock."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, two: bool = False, transport: Any = None, clock: Clock | None = None) -> None:
        self.monkeypatch = monkeypatch
        self.built = plan.plan_build(_inputs(two))
        path = approve.build_plan_path(PLAN_ID)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.built), encoding="utf-8")
        monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
        monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))
        assert approve.approve_ad_build(PLAN_ID, now=APPROVED_AT) == 0
        self.keys = {s["device"]: approve.derive_k(PASSPHRASE.encode(), s["device"]) for s in self.built["servers"]}
        self.clock = clock or Clock(APPROVED_AT.timestamp() + 60)
        if transport is None:
            helpers = {d: FakeHelper(self.built, d, k, self.clock) for d, k in self.keys.items()}
            transport = FakeTransport(helpers)
        self.transport = transport
        self.adapters = FakeAdapters(self.clock)
        self.acceptance_read: dict[str, Any] = {"build_account": "absent", "findings": ["AD-A-51"], "unknown": []}
        self.accepted = 0
        self.approved: list[str] = []
        self.plan_id = PLAN_ID

    @property
    def helpers(self) -> dict[str, FakeHelper]:
        return self.transport.helpers

    def acceptance(self, built: Any, server: Any) -> dict[str, Any]:
        assert server["role"] == "dc1"
        self.accepted += 1
        return self.acceptance_read

    def run(self) -> dict[str, Any]:
        return build_run.run_build(
            self.plan_id,
            transport=self.transport,
            adapters=self.adapters,
            acceptance=self.acceptance,
            clock=self.clock,
            sleep=self.clock.sleep,
        )

    def approve_stage(self, stage: str) -> int:
        self.monkeypatch.setattr("sys.stdin", io.StringIO(f"approve stage {stage} of {self.plan_id[:8]}\n"))
        code = approve.approve_ad_build_stage(
            self.plan_id,
            stage,
            verifier=self.adapters,
            transport=self.transport,
            now=datetime.fromtimestamp(self.clock(), tz=timezone.utc),
        )
        self.approved.append(stage)
        return code

    def resume(self, start_stage: str, plan_id: str = RESUME_ID) -> dict[str, Any]:
        """Plan, store and approve a resume plan of the run (what
        ``newton_ad_build_plan`` and ``newton-approve ad-build`` do): its
        ``resume_from`` is the digest of the plan on record, its run the
        same run.  The runner then drives the resume plan."""
        inputs = _inputs(len(self.built["servers"]) == 2)
        inputs["resume_from"] = plan.digest(self.built)
        inputs["secrets_from"] = plan.digest(self.built)
        inputs["start_stage"] = start_stage
        resumed = plan.plan_build(inputs)
        approve._atomic_write(approve.build_plan_path(plan_id), resumed)
        approve._atomic_write(
            approve.build_run_state_path(plan_id),
            {"plan_id": plan_id, "plan_digest": plan.digest(resumed), "run": PLAN_ID, "state": "planned", "servers": {}},
        )
        self.monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {plan_id[:8]}\n"))
        assert approve.approve_ad_build(plan_id, now=datetime.fromtimestamp(self.clock(), tz=timezone.utc)) == 0
        if isinstance(self.transport, FakeTransport):
            for helper in self.helpers.values():
                helper.know(resumed)
        self.plan_id = plan_id
        return resumed

    def drive(self, limit: int = 12) -> dict[str, Any]:
        state = self.run()
        for _ in range(limit):
            if state["state"] != build_run.STOPPED_FOR_APPROVAL:
                return state
            assert self.approve_stage(state["stage"]) == 0
            state = self.run()
        raise AssertionError("the run did not end")


def _state_file() -> dict[str, Any]:
    return json.loads(approve.build_run_state_path(PLAN_ID).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# whole runs
# --------------------------------------------------------------------------


def test_a_one_dc_run_ends_at_stage_10_done(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    state = build.drive()
    assert state["state"] == "done", state
    assert state["stage"] == "10"
    assert build.approved == ["2", "3", "4", "6"]
    assert state["finished"]["build1"] == list(plan.DC1_GRAPH_ALONE)
    runs = [stage for _, stage, action in build.transport.actions() if action == "run"]
    assert runs == [s for s in plan.DC1_GRAPH_ALONE if s != "10"]
    assert sorted(build.helpers["build1"].completed()) == sorted(s for s in plan.DC1_GRAPH_ALONE if s != "10")
    assert _state_file()["state"] == "done"


def test_a_two_dc_run_ends_at_stage_10_done(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    state = build.drive()
    assert state["state"] == "done", state
    assert build.approved == ["2", "3", "4", "6", "7"]
    assert state["finished"]["build1"] == list(plan.DC1_GRAPH)
    assert state["finished"]["build2"] == list(plan.DC2_GRAPH)
    runs = [(d, s) for d, s, a in build.transport.actions() if a == "run"]
    assert runs == [
        ("build1", "0"), ("build2", "0"), ("build1", "1"), ("build2", "1"),
        ("build1", "2"), ("build1", "3"), ("build1", "4"), ("build1", "5"), ("build1", "6"),
        # stage 7, option B: DC1 provisions, DC2 joins, DC1 installs, DC1 reads
        ("build1", "7"), ("build2", "7"), ("build1", "7"), ("build1", "7"),
        ("build1", "8"), ("build2", "9"), ("build1", "9"),
    ]


@pytest.mark.parametrize("two", [False, True], ids=["one-dc", "two-dc"])
def test_stage_8_runs_for_real_in_a_whole_run(monkeypatch: pytest.MonkeyPatch, two: bool) -> None:
    """Stage 8 as the helper runs it (the maintainer's decisions on open points 34 and
    37, 2026-11-16): the helper answers started while sshd restarts, and a
    status ends it done; the run then goes on to 9 and ends at 10 done.
    No request carries the write helper: the bootstrap installed it on DC1
    (the maintainer's decision of 2026-11-19 on the stage 8 transport), and every
    request stays under the 64 KB that PowerShell 5.1 under OpenSSH reads
    from stdin (measured on BUILD1, 2026-11-18: it hangs past 70 001 to
    80 001 bytes)."""
    build = Build(monkeypatch, two=two)
    build.helpers["build1"].ops_s = 45.0
    state = build.drive()
    assert (state["state"], state["stage"]) == ("done", "10"), state
    eight = [(d, r) for d, r in build.transport.requests if r["stage"] == "8"]
    runs = [r for d, r in eight if r["action"] == "run"]
    assert [d for d, r in eight if r["action"] == "run"] == ["build1"]
    assert len(runs) == 1
    assert [r["action"] for _, r in eight].count("status") >= 1
    assert all("write_helper" not in r for _, r in build.transport.requests)
    assert max(len(json.dumps(r).encode("ascii")) for _, r in build.transport.requests) < 65536
    # the run state and its receipts never hold the helper's bytes
    assert "write_helper" not in approve.build_run_state_path(PLAN_ID).read_text(encoding="utf-8")


def test_a_stage_8_that_stops_in_the_helper_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].ops_read_stop = "readback_failed"
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "readback_failed", "8"), state
    assert all(r["stage"] != "9" for _, r in build.transport.requests)


def test_no_request_can_carry_the_write_helper() -> None:
    """The transport has no write helper field any more: the bootstrap
    installs the helper on DC1 (the maintainer's decision of 2026-11-19)."""
    with pytest.raises(TypeError):
        build_transport.helper_request(stage="8", action="run", write_helper=b"abc", **_REQUEST)  # type: ignore[call-arg]
    assert not hasattr(build_transport, "WRITE_HELPER_MAX_BYTES")


_REQUEST = dict(run="ab" * 16, plan_bytes=b"plan", token="cd" * 32, nbf=1794578100, exp=1794579960)


@pytest.mark.parametrize("two", [False, True], ids=["one-dc", "two-dc"])
def test_each_irreversible_stage_stops_for_approval_with_its_checkpoint(monkeypatch: pytest.MonkeyPatch, two: bool) -> None:
    build = Build(monkeypatch, two=two)
    seen: list[str] = []
    state = build.run()
    while state["state"] == build_run.STOPPED_FOR_APPROVAL:
        stage = state["stage"]
        seen.append(stage)
        assert plan.STAGE_KINDS[stage] == "irreversible"
        waiting = {d: e for d, e in state["servers"].items() if e["stage"] == stage}
        expected_devices = {s["device"] for s in build.built["servers"] if stage in plan.stage_graph(build.built, s)}
        assert set(waiting) == expected_devices
        for device, entry in waiting.items():
            assert entry["state"] == "stopped_for_approval"
            role = next(s["role"] for s in build.built["servers"] if s["device"] == device)
            assert entry["checkpoint_kind"] == build_checkpoint.KIND_OF_STAGE[(role, stage)]
            assert entry["checkpoint"]["id"] in build.helpers[device].checkpoints_seen
            # no run of the stage was sent before the owner's approval
            assert (device, stage, "run") not in build.transport.actions()
        # a second call before the approval sends no run and takes no new checkpoint
        taken = len(build.adapters.taken)
        again = build.run()
        assert again["state"] == build_run.STOPPED_FOR_APPROVAL and again["stage"] == stage
        assert len(build.adapters.taken) == taken
        assert build.approve_stage(stage) == 0
        state = build.run()
    assert state["state"] == "done", state
    assert seen == (["2", "3", "4", "6", "7"] if two else ["2", "3", "4", "6"])


def test_the_checkpoint_bound_is_the_journal_completion_of_the_previous_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    state = build.drive()
    assert state["state"] == "done"
    helper1, helper2 = build.helpers["build1"], build.helpers["build2"]
    graph1 = plan.stage_graph(build.built, build.built["servers"][0])
    graph2 = plan.stage_graph(build.built, build.built["servers"][1])
    nbf = json.loads((approve.build_plan_dir() / f"{PLAN_ID}.approval.json").read_text())["nbf"]
    for device, stage, bound in build.adapters.verified:
        helper, graph = (helper1, graph1) if device == "build1" else (helper2, graph2)
        before = graph[graph.index(stage) - 1]
        assert bound == max(nbf, helper.completed()[before]), (device, stage)


def test_the_run_state_file_never_feeds_not_before(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    state = build.run()
    assert state["state"] == build_run.STOPPED_FOR_APPROVAL and state["stage"] == "2"
    path = approve.build_run_state_path(PLAN_ID)
    record = json.loads(path.read_text())
    record["not_before"] = 1000000001
    record["completed"] = {"1": 1000000001}
    record["servers"]["build1"]["not_before"] = 1000000001
    path.write_text(json.dumps(record))
    build.adapters.verified.clear()
    assert build.approve_stage("2") == 0
    state = build.run()  # stage 2 runs, stops at 3: verify of stage 3's checkpoint
    assert state["stage"] == "3"
    completed = build.helpers["build1"].completed()
    assert [b for _, _, b in build.adapters.verified] == [completed["1"], completed["2"]]
    assert 1000000001 not in [b for _, _, b in build.adapters.verified]


def _real_proxmox(build: Build, stamp: Any, calls: list[tuple[str, str]]) -> Any:
    """The real Proxmox adapter with a fake API answering the measured
    shapes; ``stamp()`` is the time the host reports for the snapshot."""
    target = build_checkpoint.ProxmoxTarget(
        api="https://pve.example.test:8006/api2/json", node="pve", vmid="8301",
        token_id="newton@pve!build", token_file=Path("/nonexistent"), ca_file=Path("/nonexistent"),
    )
    made: dict[str, Any] = {}

    def request(t: Any, method: str, path: str, params: Any) -> Any:
        calls.append((method, path))
        if method == "POST":
            made["name"] = params["snapname"]
            made["at"] = stamp()
            made["upid"] = f"UPID:pve:0001A2B3:0C4D5E6F:{made['at']:08X}:qmsnapshot:8301:newton@pve!build:"
            return {"data": made["upid"]}
        if path.endswith("/status"):
            return {"data": {"status": "stopped", "exitstatus": "OK", "upid": made["upid"], "type": "qmsnapshot", "id": "8301"}}
        if path.endswith("/log"):
            lines = [
                "freeze guest filesystem",
                "snapshotting 'drive-sata0' (vmdata:vm-8301-disk-0)",
                f'  Logical volume "snap_vm-8301-disk-0_{made["name"]}" created.',
                "thaw guest filesystem",
                "TASK OK",
            ]
            return {"data": [{"n": i, "t": t} for i, t in enumerate(lines, start=1)], "total": len(lines)}
        return {"data": [{"name": made["name"], "snaptime": made["at"], "vmstate": 0}]}

    adapter = build_checkpoint.ProxmoxAdapter(
        {"build1": target},
        read_genid=lambda s: "",
        request=request,
        clock=lambda: datetime.fromtimestamp(build.clock(), tz=timezone.utc),
        sleep=build.clock.sleep,
    )
    return build_checkpoint.CheckpointAdapters({"proxmox": adapter})


@pytest.mark.parametrize("stale", [False, True], ids=["fresh-verifies", "older-refused"])
def test_an_older_checkpoint_is_refused_through_the_real_adapters(monkeypatch: pytest.MonkeyPatch, stale: bool) -> None:
    """The real Proxmox adapter with a fake API: a snapshot the host dates
    after stage 1's recorded completion verifies and the run stops for the
    approval; one dated before it (still after the plan's NBF) stops the
    run ``checkpoint_unverified``."""
    build = Build(monkeypatch)
    old = int(APPROVED_AT.timestamp()) + 30
    calls: list[tuple[str, str]] = []
    build.adapters = _real_proxmox(build, (lambda: old) if stale else (lambda: int(build.clock())), calls)  # type: ignore[assignment]
    state = build.run()
    assert ("POST", "/nodes/pve/qemu/8301/snapshot") in calls
    assert state["stage"] == "2"
    completed = build.helpers["build1"].completed()
    assert old < completed["1"]
    if stale:
        assert (state["state"], state["reason"]) == ("stopped", "checkpoint_unverified")
    else:
        assert state["state"] == build_run.STOPPED_FOR_APPROVAL
        assert state["servers"]["build1"]["checkpoint"]["id"].startswith("UPID:pve:")


# --------------------------------------------------------------------------
# deviations
# --------------------------------------------------------------------------


def test_a_dropped_session_that_does_not_end_in_rebooting_is_connection_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].drop_no_reboot = {"5"}
    state = build.drive()
    assert state["state"] == "stopped"
    assert (state["reason"], state["stage"], state["device"]) == ("connection_lost", "5", "build1")
    sent = len(build.transport.requests)
    assert build.run()["state"] == "stopped"
    assert len(build.transport.requests) == sent  # a stopped run sends nothing more


def test_a_dropped_answer_of_a_stage_that_did_not_reboot_is_connection_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].drop_run = {"5"}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "connection_lost", "5")


def test_a_dropped_session_of_a_rebooting_stage_goes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].drop_run = {"1"}
    state = build.drive()
    assert state["state"] == "done", state


def test_a_server_that_never_answers_after_a_drop_is_connection_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].drop_run = {"1"}
    build.helpers["build1"].never_boots = {"1"}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "connection_lost", "1")


def test_a_reboot_that_does_not_end_in_15_minutes_is_reboot_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].never_boots = {"1"}
    state = build.run()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "reboot_timeout", "1")
    run_at = next(r["at"] for r in state["receipts"] if r["stage"] == "1" and r["action"] == "run")
    assert build_run.REBOOT_TIMEOUT_S == 15 * 60
    assert run_at + 15 * 60 <= build.clock() <= run_at + 15 * 60 + build_run.POLL_S


def test_a_reboot_that_ends_inside_15_minutes_goes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].boot_s = 14 * 60
    state = build.drive()
    assert state["state"] == "done", state


def test_a_stopped_stage_stops_the_run_with_its_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].stop_stage = {"5": "readback_failed"}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "readback_failed", "5")
    assert state["detail"] == "op"


def test_an_unverified_checkpoint_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.adapters.ok = False
    state = build.run()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "checkpoint_unverified", "2")
    assert ("build1", "2", "run") not in build.transport.actions()


# --------------------------------------------------------------------------
# a held journal lock (the lab run of 2026-11-23): another request holds
# the journal of the server, and the helper refuses with journal_busy
# --------------------------------------------------------------------------


def test_a_journal_read_refused_journal_busy_stops_the_run_with_that_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read of the journal of the server is a status: a refusal of
    that kind stops the run, and nothing is sent again."""
    build = Build(monkeypatch)
    build.helpers["build1"].busy_stage = "0"
    build.helpers["build1"].busy_statuses = 1
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "journal_busy", "build1"), state
    assert ("build1", "0", "run") not in build.transport.actions()


def test_a_read_refused_journal_busy_stops_the_run_with_that_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """The read of the DC (through the helper) is not a status: it stops
    the run with the code of the helper, and no request is sent again."""
    build = Build(monkeypatch)

    def busy(*args: Any, **kwargs: Any) -> bool:
        raise build_checkpoint.JournalBusy("another request holds the journal of the server")

    monkeypatch.setattr(build.adapters, "verify", busy)
    state = build.run()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "journal_busy", "2"), state
    assert ("build1", "2", "run") not in build.transport.actions()


def test_a_plan_changed_after_its_approval_runs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    changed = copy.deepcopy(build.built)
    changed["domain"]["site"] = "Other-Site"
    approve.build_plan_path(PLAN_ID).write_text(json.dumps(changed), encoding="utf-8")
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "plan_mismatch")
    assert build.transport.requests == []


# --------------------------------------------------------------------------
# stage 9 and stage 10
# --------------------------------------------------------------------------


def test_the_cleanup_runs_dc2_first_then_dc1_under_the_plan_token(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    assert build.drive()["state"] == "done"
    nines = [(i, d) for i, (d, r) in enumerate(build.transport.requests) if r["stage"] == "9" and r["action"] == "run"]
    assert [d for _, d in nines] == ["build2", "build1"]
    digest = plan.digest(build.built)
    for _, (device, request) in [(i, build.transport.requests[i]) for i, _ in nines]:
        assert request["token"] == plan.plan_token(build.keys[device], digest, request["nbf"], request["exp"])
    # nothing is sent to DC2 once its cleanup ran (its helper is gone)
    first_dc2_nine = nines[0][0]
    assert all(d != "build2" for d, _ in build.transport.requests[first_dc2_nine + 1:])
    # the final stage never gets a stage token
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve stage 9 of {PLAN_ID[:8]}\n"))
    assert approve.approve_ad_build_stage(PLAN_ID, "9", verifier=build.adapters, transport=build.transport) == 1


def test_stage_10_stops_on_a_finding_outside_the_accepted_list(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.acceptance_read = {"build_account": "absent", "findings": ["AD-A-51", "AD-B-07"], "unknown": []}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "finding_outside_accepted", "10")
    assert state["detail"] == "AD-B-07"


def test_stage_10_stops_while_the_build_account_remains(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.acceptance_read = {"build_account": "present", "findings": [], "unknown": []}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "build_account_remains", "10")


@pytest.mark.parametrize(
    "read",
    [None, {"build_account": "gone", "findings": []}, {"build_account": "absent", "findings": ["x; y"]}, {"build_account": "absent"}, {"build_account": "absent", "findings": []}, {"build_account": "absent", "findings": [], "unknown": "AD-A-51"}],
)
def test_stage_10_stops_when_the_acceptance_cannot_answer(monkeypatch: pytest.MonkeyPatch, read: Any) -> None:
    build = Build(monkeypatch)
    build.acceptance_read = read  # type: ignore[assignment]
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "acceptance_unavailable", "10")


def test_stage_10_is_the_acceptance_read_and_sends_no_helper_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stage 10 is the acceptance callable (the newton-audit read of the maintainer's
    decision R2; ``acceptance.audit_acceptance``), made once, for DC1, when
    the first read finds the build account gone; no helper request names
    stage 10."""
    build = Build(monkeypatch)
    assert build.drive()["state"] == "done"
    assert build.accepted == 1
    assert all(r["stage"] != "10" for _, r in build.transport.requests)


def test_stage_10_without_an_acceptance_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    state = build.run()
    for _ in range(6):
        if state["state"] != build_run.STOPPED_FOR_APPROVAL:
            break
        assert build.approve_stage(state["stage"]) == 0
        state = build_run.run_build(PLAN_ID, transport=build.transport, adapters=build.adapters, clock=build.clock, sleep=build.clock.sleep)
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "acceptance_unavailable", "10")


# --------------------------------------------------------------------------
# no credential
# --------------------------------------------------------------------------


def test_no_domain_credential_is_in_any_request_or_under_the_state_directory(monkeypatch: pytest.MonkeyPatch, state_dir: Path) -> None:
    build = Build(monkeypatch, two=True)
    assert build.drive()["state"] == "done"
    digest = plan.digest(build.built)
    secrets = {
        **{f"dsrm {d}": plan.derive_secret(k, digest, plan.DSRM_INFO) for d, k in build.keys.items()},
        **{f"admin {d}": plan.derive_secret(k, digest, plan.ADMIN_INFO) for d, k in build.keys.items()},
        **{f"K {d}": k for d, k in build.keys.items()},
        "passphrase": PASSPHRASE,
    }
    sent = b"\n".join(json.dumps(r, sort_keys=True).encode() for _, r in build.transport.requests)
    sent_plans = b"\n".join(__import__("base64").b64decode(r["plan"]) for _, r in build.transport.requests)
    files = [p for p in state_dir.rglob("*") if p.is_file()]
    assert files
    stored = b"\n".join(p.read_bytes() for p in files)
    for name, secret in secrets.items():
        for blob in (sent, sent_plans, stored):
            assert secret.encode() not in blob, name
            assert secret.lower().encode() not in blob.lower(), name
    for _, request in build.transport.requests:
        assert set(request) <= {"run", "plan", "stage", "action", "token", "nbf", "exp", "checkpoint", "checkpoint_name", "odj"}
        # a checkpoint's name rides only with its id, on a checkpoint request
        if "checkpoint_name" in request:
            assert request["action"] == "checkpoint" and "checkpoint" in request
        # the djoin blob is a machine secret, carried to DC2's stage 7 run only
        if "odj" in request:
            assert (request["stage"], request["action"]) == ("7", "run")


# --------------------------------------------------------------------------
# the real helper under pwsh, with the task 3 fake stage table
# --------------------------------------------------------------------------


class PwshTransport:
    """The real ``build.ps1`` under pwsh, one install root per server, the
    fake clock as ``-Now`` and a boot time that advances after each
    ``rebooting`` answer (the server restarts)."""

    def __init__(self, roots: dict[str, Path], table: Path, clock: Clock) -> None:
        self.roots = roots
        self.table = table
        self.clock = clock
        self.boot = {device: 0 for device in roots}
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def send(self, device: str, request: Any) -> dict[str, Any]:
        from pwsh_path import PWSH  # type: ignore[import-not-found]
        from test_build_helper import HELPER  # type: ignore[import-not-found]

        self.requests.append((device, dict(request)))
        boot = datetime.fromtimestamp(1790000000 + 600 * self.boot[device], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        done = subprocess.run(
            [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(HELPER), "-InstallRoot", str(self.roots[device]),
             "-Now", str(int(self.clock())), "-BootTime", boot, "-StageTablePath", str(self.table)],
            input=json.dumps(dict(request)), capture_output=True, text=True, timeout=300, check=False,
        )
        answer = build_transport.parse_answer(done.stdout, action=request["action"])
        if answer["status"] == "rebooting" and request["action"] == "run":
            self.boot[device] += 1
        return answer


def test_a_one_dc_run_through_the_real_helper_ends_done(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from test_build_helper import STAGE_TABLE, Server  # type: ignore[import-not-found]

    clock = Clock(APPROVED_AT.timestamp() + 60)
    keys = {"build1": approve.derive_k(PASSPHRASE.encode(), "build1")}
    server = Server(tmp_path / "build1", key_hex=keys["build1"], device="build1")
    table = server.write_table(STAGE_TABLE)
    transport = PwshTransport({"build1": server.root}, table, clock)
    build = Build(monkeypatch, transport=transport, clock=clock)
    state = build.drive()
    assert state["state"] == "done", state
    assert build.approved == ["2", "3", "4", "6"]
    done = {e["stage"] for e in server.journal(PLAN_ID) if e["state"] == "done"}
    assert done == set(plan.DC1_GRAPH_ALONE) - {"10"}
    named = [e["checkpoint"] for e in server.journal(PLAN_ID) if e["state"] == "checkpointed"]
    assert named == [ident for _, _, ident in build.adapters.taken]


def test_an_expired_stage_approval_sends_no_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stage token past its EXP is not used: the run stays stopped for
    the approval of the stage and sends no run of it."""
    build = Build(monkeypatch)
    assert build.run()["stage"] == "2"
    assert build.approve_stage("2") == 0
    build.clock.now += approve.BUILD_STAGE_WINDOW_S + 1
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2")
    assert ("build1", "2", "run") not in build.transport.actions()


# --------------------------------------------------------------------------
# the run state is the agent's: it never says what is done (X2 of the
# task 8 review)
# --------------------------------------------------------------------------


def _forge(build: Build, **fields: Any) -> None:
    """Write the run state an agent could write: over this plan's digest."""
    path = approve.build_run_state_path(build.plan_id)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        record = {"plan_id": build.plan_id, "run": PLAN_ID, "servers": {}, "receipts": []}
    record["plan_digest"] = plan.digest(build.built)
    record.update(fields)
    approve._atomic_write(path, record)


def _runs(build: Build) -> list[tuple[str, str]]:
    return [(d, s) for d, s, a in build.transport.actions() if a == "run"]


def test_a_finished_list_in_the_run_state_skips_no_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    _forge(build, state="running", finished={"build1": list(plan.DC1_GRAPH_ALONE)})
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2")
    assert _runs(build) == [("build1", "0"), ("build1", "1")]
    assert build.accepted == 0
    state = build.drive()
    assert state["state"] == "done", state
    assert [s for _, s in _runs(build)] == [s for s in plan.DC1_GRAPH_ALONE if s != "10"]


def test_a_finished_list_naming_dc2s_cleanup_does_not_skip_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """With DC2's stage 9 listed, DC1's cleanup (which deletes the domain
    account) must still come after DC2's own cleanup."""
    build = Build(monkeypatch, two=True)
    state = build.run()
    while state["stage"] != "7":
        assert state["state"] == build_run.STOPPED_FOR_APPROVAL, state
        assert build.approve_stage(state["stage"]) == 0
        state = build.run()
    assert build.approve_stage("7") == 0
    _forge(build, finished={"build1": list(plan.DC1_GRAPH), "build2": list(plan.DC2_GRAPH)})
    state = build.run()
    assert state["state"] == "done", state
    runs = _runs(build)
    assert runs.index(("build2", "9")) < runs.index(("build1", "9"))
    assert build.helpers["build2"].gone and build.helpers["build1"].gone


@pytest.mark.parametrize(
    "read, expected",
    [
        ({"build_account": "present", "findings": [], "unknown": []}, ("stopped", "build_account_remains")),
        ({"build_account": "absent", "findings": ["AD-B-07"], "unknown": []}, ("stopped", "finding_outside_accepted")),
        (None, ("stopped", "acceptance_unavailable")),
        ({"build_account": "absent", "findings": ["AD-A-51"], "unknown": []}, ("done", "")),
    ],
    ids=["account-remains", "finding-outside", "no-answer", "accepted"],
)
def test_a_done_run_state_is_done_only_through_the_acceptance(
    monkeypatch: pytest.MonkeyPatch, read: Any, expected: tuple[str, str]
) -> None:
    """A run state that says done (the agent can write it) sends no helper
    request and is answered done only when stage 10's acceptance passes
    again."""
    build = Build(monkeypatch)
    _forge(build, state="done", stage="10", finished={"build1": list(plan.DC1_GRAPH_ALONE)})
    build.acceptance_read = read  # type: ignore[assignment]
    state = build.run()
    assert (state["state"], state["reason"]) == expected
    # A read that finds the build account still there is made again for
    # run.ACCEPTANCE_WAIT_S (F4: the cleanup task deletes it after its wait).
    if read is not None and read["build_account"] == "present":
        assert build.accepted > 1
    else:
        assert build.accepted == 1
    assert build.transport.requests == []


def test_a_done_run_state_without_an_acceptance_is_not_done(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    _forge(build, state="done", stage="10")
    state = build_run.run_build(PLAN_ID, transport=build.transport, adapters=build.adapters, clock=build.clock, sleep=build.clock.sleep)
    assert (state["state"], state["reason"]) == ("stopped", "acceptance_unavailable")


# --------------------------------------------------------------------------
# a runner killed during a rebooting stage resumes from the journal (X3 of
# the task 8 review; PLAN-1.5 review focus 2)
# --------------------------------------------------------------------------


class Killed(BaseException):
    """The runner's process killed (not an exception the runner catches)."""


def _kill_after_run_of(build: Build, stage: str) -> None:
    """Kill the runner at its first wait after the run of ``stage``."""
    real = build.clock.sleep

    def sleep(seconds: float) -> None:
        if ("build1", stage, "run") in build.transport.actions():
            raise Killed()
        real(seconds)

    build.clock.sleep = sleep  # type: ignore[method-assign]


def _revive(build: Build) -> None:
    del build.clock.sleep  # the class's own sleep again


@pytest.mark.parametrize("stage", ["1", "2", "4"])
def test_a_runner_killed_during_a_rebooting_stage_resumes_from_the_journal(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    build = Build(monkeypatch)
    _kill_after_run_of(build, stage)
    with pytest.raises(Killed):
        build.drive()
    _revive(build)
    assert _state_file()["state"] == "running" and _state_file()["stage"] == stage
    state = build.drive()
    assert state["state"] == "done", state
    # the stage ran once: the restart read its status and never sent a
    # second run (the helper refuses a stage in flight out_of_order)
    assert _runs(build).count(("build1", stage)) == 1
    assert [e["state"] for e in build.helpers["build1"].journal if e["stage"] == stage and e["state"] != "checkpointed"] == [
        "started", "rebooting", "done"
    ]


def test_a_runner_restarted_inside_a_tokens_post_boot_grace_waits_for_a_new_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    """DESIGN-1.5 open point 68 of task 8: the helper completes a stage 2
    or 4 in flight until EXP plus 15 minutes, but a runner started again
    after EXP drops the stage token and sends nothing of the stage, not
    even its status.  It stops for a new approval of the stage; that token then
    completes the stage from the journal without a second run."""
    build = Build(monkeypatch)
    _kill_after_run_of(build, "2")
    with pytest.raises(Killed):
        build.drive()
    _revive(build)
    record = json.loads(approve.build_stage_approval_path(PLAN_ID, "2").read_text(encoding="utf-8"))
    build.clock.now = record["exp"] + 60
    assert [e["state"] for e in build.helpers["build1"].journal if e["stage"] == "2"][-1] == "rebooting"
    sent = len(build.transport.actions())
    taken = list(build.adapters.taken)
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2"), state
    # the restart reads the journal under the plan token, and sends nothing
    # of stage 2 under its expired token
    assert [a for a in build.transport.actions()[sent:] if a[1] == "2"] == []
    # the held checkpoint is reused, not retaken
    assert build.adapters.taken == taken
    assert build.approve_stage("2") == 0
    assert build.adapters.taken == taken
    state = build.drive()
    assert state["state"] == "done", state
    assert _runs(build).count(("build1", "2")) == 1


def test_a_runner_killed_while_its_server_is_still_down_waits_for_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The restart's first journal read finds the server still booting:
    the runner asks again, inside the 15 minutes, instead of stopping."""
    build = Build(monkeypatch)
    build.helpers["build1"].boot_s = 5 * 60
    _kill_after_run_of(build, "1")
    with pytest.raises(Killed):
        build.drive()
    _revive(build)
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2"), state
    assert _runs(build).count(("build1", "1")) == 1


def test_a_runner_restarted_after_a_server_never_came_back_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].never_boots = {"1"}
    _kill_after_run_of(build, "1")
    with pytest.raises(Killed):
        build.drive()
    _revive(build)
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "journal_unreadable"), state
    assert _runs(build).count(("build1", "1")) == 1


def test_a_runner_killed_during_a_rebooting_stage_resumes_through_the_real_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from test_build_helper import STAGE_TABLE, Server  # type: ignore[import-not-found]

    clock = Clock(APPROVED_AT.timestamp() + 60)
    keys = {"build1": approve.derive_k(PASSPHRASE.encode(), "build1")}
    server = Server(tmp_path / "build1", key_hex=keys["build1"], device="build1")
    table = server.write_table(STAGE_TABLE)
    transport = PwshTransport({"build1": server.root}, table, clock)
    build = Build(monkeypatch, transport=transport, clock=clock)
    real = clock.sleep

    def sleep(seconds: float) -> None:
        if any(d == "build1" and r["stage"] == "1" and r["action"] == "run" for d, r in transport.requests):
            raise Killed()
        real(seconds)

    clock.sleep = sleep  # type: ignore[method-assign]
    with pytest.raises(Killed):
        build.run()
    del clock.sleep
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2"), state
    assert sum(1 for d, r in transport.requests if r["stage"] == "1" and r["action"] == "run") == 1
    assert [e["state"] for e in server.journal(PLAN_ID) if e["stage"] == "1"] == ["started", "rebooting", "done"]


# --------------------------------------------------------------------------
# a two-DC resume (X4 of the task 8 review; DESIGN-1.5 open point 26 of
# task 8: one start_stage for both servers)
# --------------------------------------------------------------------------


def test_a_two_dc_resume_whose_start_stage_is_both_servers_next_ends_done(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch, two=True)
    build.helpers["build1"].stop_stage = {"0": "ip_mismatch"}
    state = build.drive()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "ip_mismatch", "build1")
    build.helpers["build1"].stop_stage = {}
    build.resume("0")
    state = build.drive()
    assert state["state"] == "done", state
    assert _runs(build).count(("build1", "0")) == 2
    assert all(stage in build.helpers["build2"].completed() for stage in plan.DC2_GRAPH)


def test_a_two_dc_resume_whose_start_stage_is_not_each_servers_next_stops_plan_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """DC2's stage 1 stopped: DC1's next stage is 2 and DC2's is 1.  One
    start_stage cannot name both, the helper of the other server refuses
    the plan, and the run stops ``plan_mismatch`` with no run sent."""
    build = Build(monkeypatch, two=True)
    build.helpers["build2"].stop_stage = {"1": "op_failed"}
    state = build.drive()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "op_failed", "build2")
    build.helpers["build2"].stop_stage = {}
    sent = len(_runs(build))
    build.resume("1")
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "plan_mismatch", "build1"), state
    assert "start_stage" in state["detail"]
    assert len(_runs(build)) == sent


@pytest.mark.parametrize("start", ["3", "8"])
def test_a_two_dc_resume_at_a_stage_dc2_has_not_sends_nothing(monkeypatch: pytest.MonkeyPatch, start: str) -> None:
    """A start_stage outside DC2's graph (0 1 7 9) is never DC2's next
    stage: the runner stops ``plan_mismatch`` before any request."""
    build = Build(monkeypatch, two=True)
    build.resume(start)
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "plan_mismatch"), state
    assert "start_stage" in state["detail"]
    assert build.transport.requests == []


# --------------------------------------------------------------------------
# stage 8 refuses write helper bytes that are not the plan's (the maintainer's decision
# R1, 2026-11-15)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("helper", ["other-bytes", "missing"])
def test_stage_8_stops_when_the_installed_write_helper_is_not_the_plans(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, helper: str
) -> None:
    from newton_mcp.ad import setupgen_write

    build = Build(monkeypatch)
    path = tmp_path / "write.ps1"
    if helper == "other-bytes":
        path.write_bytes(setupgen_write.WRITE_HELPER_PATH.read_bytes() + b"\n# changed\n")
    monkeypatch.setattr(setupgen_write, "WRITE_HELPER_PATH", path)
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "write_helper_mismatch", "8")
    assert all(r["stage"] != "8" for _, r in build.transport.requests)


@pytest.mark.parametrize(
    "installed, code",
    [("missing", "write_helper_missing"), ("other-bytes", "write_helper_mismatch")],
)
def test_stage_8_stops_with_the_next_step_when_the_dcs_installed_write_helper_is_not_the_plans(
    monkeypatch: pytest.MonkeyPatch, installed: str, code: str
) -> None:
    """DC1's helper checks the write helper the bootstrap installed before
    anything of stage 8 runs (the maintainer's decision of 2026-11-19).  A missing or
    changed file stops the run with the helper's code and Newton's own next
    step, the bootstrap again; the run is sent once and never re-sent."""
    build = Build(monkeypatch)
    build.helpers["build1"].installed_write_helper = None if installed == "missing" else b"# another helper\n"
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"], state["device"]) == ("stopped", code, "8", "build1"), state
    assert "run the bootstrap of build1 again" in state["detail"], state
    assert len([r for _, r in build.transport.requests if (r["stage"], r["action"]) == ("8", "run")]) == 1
    assert all(r["stage"] != "9" for _, r in build.transport.requests)
    rendered = build_tools.render_state(PLAN_ID, state)
    assert "run the bootstrap of build1 again" in json.dumps(rendered)


# --------------------------------------------------------------------------
# stage 0's DNS check stays strict; the next step names the prep (open point
# 79, the maintainer, 2026-11-21)
# --------------------------------------------------------------------------


def test_stage_0_dns_unchecked_stops_with_the_dns_client_next_step(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].stop_stage = {"0": "dns_unchecked"}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"], state["device"]) == ("stopped", "dns_unchecked", "0", "build1"), state
    assert "set the server's DNS client to a resolver that answers before stage 0" in state["detail"], state
    assert "build1" in state["detail"]
    assert "set the server's DNS client to a resolver that answers before stage 0" in json.dumps(build_tools.render_state(PLAN_ID, state))


def test_another_stage_0_stop_does_not_get_the_dns_client_next_step(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].stop_stage = {"0": "ip_mismatch"}
    state = build.drive()
    assert state["reason"] == "ip_mismatch"
    assert "DNS client" not in state["detail"]


# --------------------------------------------------------------------------
# an expired plan approval is reported as expired (F6 of the part B
# review): the journal read keeps the fixed word, not the device text
# --------------------------------------------------------------------------


class _RefusingTransport:
    def __init__(self, code: str) -> None:
        self.code = code

    def send(self, device: str, request: Any) -> dict[str, Any]:
        return {"ok": False, "status": "refused", "code": self.code, "checks": []}


@pytest.mark.parametrize("code, expected", [("expired", "expired"), ("plan_mismatch", "plan_mismatch"), ("bad_token", "refused"), ("Exp1red\nx", "refused")])
def test_a_refused_journal_read_keeps_only_the_fixed_words(code: str, expected: str) -> None:
    with pytest.raises(build_transport.JournalUnreadable) as caught:
        build_transport.read_completions(
            _RefusingTransport(code), "build1", run="ab" * 16, plan_bytes=b"plan", token="cd" * 32, nbf=1797000000, exp=1797003600
        )
    assert caught.value.code == expected


def test_a_journal_read_refused_as_expired_stops_the_run_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper refuses the plan token as expired: the run stops
    ``expired`` (the owner approves the plan again), not
    ``journal_unreadable``, and sends no run."""
    build = Build(monkeypatch)
    real = build.transport.send

    def expired(device: str, request: Any) -> Any:
        if request["stage"] == "0" and request["action"] == "status":
            build.transport.requests.append((device, dict(request)))
            return {"ok": False, "status": "refused", "code": "expired", "checks": []}
        return real(device, request)

    monkeypatch.setattr(build.transport, "send", expired)
    state = build.run()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "expired", "build1"), state
    assert _runs(build) == []


def _stop_expired_once(build: Build, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The helper refuses build1's first stage 0 status as expired, then
    answers as usual: the run stops ``expired``."""
    real = build.transport.send
    seen = {"refused": False}

    def expired(device: str, request: Any) -> Any:
        if not seen["refused"] and request["stage"] == "0" and request["action"] == "status":
            seen["refused"] = True
            build.transport.requests.append((device, dict(request)))
            return {"ok": False, "status": "refused", "code": "expired", "checks": []}
        return real(device, request)

    monkeypatch.setattr(build.transport, "send", expired)
    state = build.run()
    assert (state["state"], state["reason"]) == ("stopped", "expired"), state
    return state


def test_an_expired_stop_names_the_resume_plan_not_a_second_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    """X6 of the review: the stop's detail tells the owner the way out that
    works, a resume plan (point 13), and never a second approval of the
    same plan."""
    state = _stop_expired_once(Build(monkeypatch), monkeypatch)
    assert "resume plan" in state["detail"], state["detail"]
    assert "approves the plan again" not in state["detail"]


def test_a_second_approval_of_the_same_plan_does_not_restart_an_expired_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    """X6: after the expired stop the owner approves the same plan again,
    which now succeeds and gives a fresh token the helper takes.  The run
    stays stopped ``expired`` and sends nothing: a stopped run goes on only
    through a resume plan (point 13)."""
    build = Build(monkeypatch)
    _stop_expired_once(build, monkeypatch)
    before = len(build.transport.requests)
    build.clock.sleep(120)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))
    assert approve.approve_ad_build(PLAN_ID, now=datetime.fromtimestamp(build.clock(), tz=timezone.utc)) == 0
    state = build.drive()
    assert (state["state"], state["reason"], state["device"]) == ("stopped", "expired", "build1"), state
    assert build.transport.requests[before:] == []
    assert _runs(build) == []
    assert _state_file()["state"] == "stopped"


def test_a_resume_plan_at_stage_0_goes_on_after_an_expired_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    """X6: the way out the stop names works: a resume plan at the stage the
    run stopped at ends done."""
    build = Build(monkeypatch)
    _stop_expired_once(build, monkeypatch)
    build.resume("0")
    state = build.drive()
    assert state["state"] == "done", state


# --------------------------------------------------------------------------
# a checkpoint the helper holds and the run state does not (F1 of the part C
# triage of 24b81a2)
# --------------------------------------------------------------------------


def _kill_at_first_verify(build: Build, monkeypatch: pytest.MonkeyPatch) -> None:
    """Kill the runner inside its first checkpoint verify: after the helper
    recorded the checkpoint, before the run state saved it."""
    real = build.adapters.verify
    seen = {"n": 0}

    def verify(*args: Any, **kwargs: Any) -> bool:
        seen["n"] += 1
        if seen["n"] == 1:
            raise Killed()
        return real(*args, **kwargs)

    monkeypatch.setattr(build.adapters, "verify", verify)


def test_a_runner_killed_after_the_helper_recorded_a_checkpoint_reuses_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """F1: the restart reads the helper's journal before it takes a
    checkpoint.  The checkpoint the helper already holds for the stage under
    this plan is verified again (``require_verified`` with the journal's
    ``not_before``) and no second snapshot is taken."""
    build = Build(monkeypatch)
    _kill_at_first_verify(build, monkeypatch)
    with pytest.raises(Killed):
        build.run()
    assert _state_file()["servers"] == {}
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2"), state
    assert [ident for _, _, ident in build.adapters.taken] == ["cp-build1-0"]
    assert build.helpers["build1"].checkpoints_seen == ["cp-build1-0"]
    entry = state["servers"]["build1"]
    assert entry["checkpoint"] == {"name": "newton-workgroup-1", "id": "cp-build1-0"}
    assert entry["checkpoint_kind"] == "workgroup"
    # verified again on the restart, with the journal's bound
    assert [v for v in build.adapters.verified if v[1] == "2"] == [("build1", "2", int(build.helpers["build1"].completed()["1"]))]
    assert sum(1 for _, r in build.transport.requests if r["action"] == "checkpoint") == 1
    assert build.drive()["state"] == "done"


def test_a_held_checkpoint_that_does_not_verify_again_stops_and_takes_no_new_one(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    _kill_at_first_verify(build, monkeypatch)
    with pytest.raises(Killed):
        build.run()
    build.adapters.ok = False
    state = build.run()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "checkpoint_unverified", "2"), state
    assert len(build.adapters.taken) == 1
    assert sum(1 for _, r in build.transport.requests if r["action"] == "checkpoint") == 1


def test_a_checkpoint_request_names_the_checkpoint_and_its_name(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    assert build.run()["state"] == build_run.STOPPED_FOR_APPROVAL
    sent = [r for _, r in build.transport.requests if r["action"] == "checkpoint"]
    assert [(r["checkpoint"], r["checkpoint_name"]) for r in sent] == [("cp-build1-0", "newton-workgroup-1")]


def test_a_killed_checkpoint_is_reused_through_the_real_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from test_build_helper import STAGE_TABLE, Server  # type: ignore[import-not-found]

    clock = Clock(APPROVED_AT.timestamp() + 60)
    keys = {"build1": approve.derive_k(PASSPHRASE.encode(), "build1")}
    server = Server(tmp_path / "build1", key_hex=keys["build1"], device="build1")
    table = server.write_table(STAGE_TABLE)
    transport = PwshTransport({"build1": server.root}, table, clock)
    build = Build(monkeypatch, transport=transport, clock=clock)
    _kill_at_first_verify(build, monkeypatch)
    with pytest.raises(Killed):
        build.run()
    state = build.run()
    assert (state["state"], state["stage"]) == (build_run.STOPPED_FOR_APPROVAL, "2"), state
    named = [(e["checkpoint"], e.get("checkpoint_name")) for e in server.journal(PLAN_ID) if e["state"] == "checkpointed"]
    assert named == [("cp-build1-0", "newton-workgroup-1")]
    assert len(build.adapters.taken) == 1
    assert state["servers"]["build1"]["checkpoint"] == {"name": "newton-workgroup-1", "id": "cp-build1-0"}


def test_a_status_answer_holds_this_plans_checkpoints(tmp_path: Path) -> None:
    """The helper's status answer names each stage's checkpoint of the
    request's plan, id and name, and none of another plan."""
    answer = {"ok": True, "status": "pending", "code": "", "checks": [], "completed": {"0": 1797000000},
              "checkpoints": {"2": {"id": "cp-1", "name": "newton-workgroup-1"}}}
    journal = build_transport.journal_of(answer)
    assert journal.completed == {"0": 1797000000}
    assert journal.checkpoints == {"2": {"id": "cp-1", "name": "newton-workgroup-1"}}
    for bad in ({"2": {"id": "cp 1", "name": "n"}}, {"2": {"id": "cp-1"}}, {"11": {"id": "a", "name": "b"}}, [], None):
        with pytest.raises(build_transport.JournalUnreadable):
            build_transport.journal_of(dict(answer, checkpoints=bad))
    with pytest.raises(build_transport.JournalUnreadable):
        build_transport.journal_of({k: v for k, v in answer.items() if k != "checkpoints"})


# -- F2 and F4 of the part C triage (tri-c2) -----------------------------------


def test_a_started_stage_that_does_not_end_in_15_minutes_is_status_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.helpers["build1"].hang_stages = {"5"}
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "status_timeout", "5")
    run_at = next(r["at"] for r in state["receipts"] if r["stage"] == "5" and r["action"] == "run")
    assert run_at + 15 * 60 <= build.clock() <= run_at + 15 * 60 + build_run.POLL_S
    assert ("build1", "6", "run") not in build.transport.actions()


def test_the_token_of_each_stage_is_the_kind_stage_token_names(monkeypatch: pytest.MonkeyPatch) -> None:
    # The runner takes the kind of a stage's token from stage_token.token_kind
    # (F4: it was never called), and what it answers decides the token.
    from newton_mcp.ad.build import stage_token

    asked: list[str] = []
    real = stage_token.token_kind

    def spy(stage: str) -> str:
        asked.append(stage)
        return real(stage)

    monkeypatch.setattr(stage_token, "token_kind", spy)
    build = Build(monkeypatch)
    assert build.drive()["state"] == "done"
    ran = [stage for _, stage, action in build.transport.actions() if action == "run"]
    assert set(asked) >= set(ran) and "9" in asked and "2" in asked


@pytest.mark.parametrize("flip", ["3", "5"])
def test_the_answer_of_token_kind_decides_each_stages_token(monkeypatch: pytest.MonkeyPatch, flip: str) -> None:
    # F7 of a review: a spy that answers another kind than the
    # real one changes what the runner does.  Stage 3 (irreversible)
    # answered "plan" is asked for under the plan token, with no checkpoint
    # and no approval of its own; stage 5 (reversible) answered "stage" is
    # never run under the plan token: the runner goes for a checkpoint
    # first, which stage 5 does not have, and stops.
    from newton_mcp.ad.build import stage_token

    real = stage_token.token_kind
    kind = {"3": "plan", "5": "stage"}[flip]
    monkeypatch.setattr(stage_token, "token_kind", lambda stage: kind if stage == flip else real(stage))
    build = Build(monkeypatch)
    state = build.drive(limit=5)
    sent = [(r["stage"], r["action"], r["token"]) for d, r in build.transport.requests if d == "build1"]
    plan_token = next(token for stage, action, token in sent if (stage, action) == ("0", "run"))
    assert flip not in build.approved, build.approved
    assert (flip, "run") not in [(s, a) for s, a, _ in sent], sent
    assert (state["state"], state["stage"], state["reason"]) == ("stopped", flip, "schema"), state
    if flip == "3":
        assert [(a, tok) for s, a, tok in sent if s == "3"] == [("status", plan_token)], sent
        assert ("3", "checkpoint") not in [(s, a) for s, a, _ in sent], sent
    else:
        assert [a for s, a, _ in sent if s == "5"] == [], sent
        assert "checkpoint" in state["detail"], state


# -- IC-M2 of a review: the F1 checkpoint_name guards -------------


def _helper_at_stage_two(tmp_path: Path) -> tuple[Any, Any, dict[str, Any]]:
    """The real helper with stages 0 and 1 done, stage 2 next."""
    import test_build_helper as th  # type: ignore[import-not-found]

    server = th.Server(tmp_path / "install")
    server.write_table(th.STAGE_TABLE)
    the_plan = th._plan()
    assert th._complete(server, the_plan, "0")["status"] == "done"
    assert th._complete(server, the_plan, "1")["status"] == "done"
    return th, server, the_plan


def _checkpoint_request(th: Any, the_plan: dict[str, Any], **fields: Any) -> dict[str, Any]:
    request = th._request(the_plan, stage="2", action="checkpoint")
    request.update(fields)
    return request


def test_the_helper_journals_a_checkpoint_name_in_its_grammar(tmp_path: Path) -> None:
    th, server, the_plan = _helper_at_stage_two(tmp_path)
    _, answer = server.call(_checkpoint_request(th, the_plan, checkpoint="cp-1", checkpoint_name="newton-workgroup-1"),
                            now=th.BASE, boot=th.BOOT_BEFORE)
    assert answer is not None and answer["status"] == "checkpointed", answer
    named = [(e["checkpoint"], e.get("checkpoint_name")) for e in server.journal() if e["state"] == "checkpointed"]
    assert named == [("cp-1", "newton-workgroup-1")]


@pytest.mark.parametrize(
    "fields",
    [
        {"checkpoint_name": "newton-workgroup-1"},
        {"checkpoint": "cp-1", "checkpoint_name": "newton workgroup"},
        {"checkpoint": "cp-1", "checkpoint_name": "x; Remove-Item C:\\x"},
        {"checkpoint": "cp-1", "checkpoint_name": ""},
        {"checkpoint": "cp-1", "checkpoint_name": "n" * 129},
        {"checkpoint": "cp-1", "checkpoint_name": "newton-\u00e9"},
        {"checkpoint": "cp-1", "checkpoint_name": 7},
    ],
)
def test_the_helper_refuses_a_checkpoint_name_without_a_checkpoint_or_outside_its_grammar(
    tmp_path: Path, fields: dict[str, Any]
) -> None:
    th, server, the_plan = _helper_at_stage_two(tmp_path)
    before = server.journal()
    _, answer = server.call(_checkpoint_request(th, the_plan, **fields), now=th.BASE, boot=th.BOOT_BEFORE)
    assert answer is not None and (answer["status"], answer["code"]) == ("refused", "schema"), answer
    assert server.journal() == before


def test_a_helpers_status_skips_a_checkpoint_recorded_without_a_name(tmp_path: Path) -> None:
    th, server, the_plan = _helper_at_stage_two(tmp_path)
    _, answer = server.call(_checkpoint_request(th, the_plan, checkpoint="cp-1"), now=th.BASE, boot=th.BOOT_BEFORE)
    assert answer is not None and answer["status"] == "checkpointed", answer
    _, status = server.call(th._request(the_plan, stage="0", action="status"), now=th.BASE, boot=th.BOOT_BEFORE)
    assert status is not None and status["checkpoints"] == {}, status


def test_a_helpers_status_answers_a_named_checkpoint(tmp_path: Path) -> None:
    th, server, the_plan = _helper_at_stage_two(tmp_path)
    server.call(_checkpoint_request(th, the_plan, checkpoint="cp-1", checkpoint_name="newton-workgroup-1"),
                now=th.BASE, boot=th.BOOT_BEFORE)
    _, status = server.call(th._request(the_plan, stage="0", action="status"), now=th.BASE, boot=th.BOOT_BEFORE)
    assert status is not None and status["checkpoints"] == {"2": {"id": "cp-1", "name": "newton-workgroup-1"}}, status


def _request_fields(**extra: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"run": "a" * 32, "plan_bytes": b"{}", "stage": "2", "action": "checkpoint",
                              "token": "b" * 64, "nbf": 1790000000, "exp": 1790001800}
    fields.update(extra)
    return fields


def test_the_transport_sends_a_checkpoint_name_only_with_a_checkpoint_and_in_its_grammar() -> None:
    sent = build_transport.helper_request(**_request_fields(checkpoint="cp-1", checkpoint_name="newton-workgroup-1"))
    assert (sent["checkpoint"], sent["checkpoint_name"]) == ("cp-1", "newton-workgroup-1")
    with pytest.raises(ValueError, match="names a checkpoint names its name"):
        build_transport.helper_request(**_request_fields(checkpoint_name="newton-workgroup-1"))
    for bad in ["newton workgroup", "", "n" * 129, "newton-\u00e9", 7]:
        with pytest.raises(ValueError, match="checkpoint name is outside its grammar"):
            build_transport.helper_request(**_request_fields(checkpoint="cp-1", checkpoint_name=bad))


@pytest.mark.parametrize("bad", ["newton workgroup", "", "n" * 129, "newton-\u00e9", 7, None])
def test_a_status_whose_checkpoint_name_is_outside_its_grammar_is_unreadable(bad: Any) -> None:
    answer = {"ok": True, "status": "pending", "code": "", "checks": [], "completed": {},
              "checkpoints": {"2": {"id": "cp-1", "name": bad}}}
    with pytest.raises(build_transport.JournalUnreadable, match="checkpoint name is outside its grammar"):
        build_transport.journal_of(answer)


@pytest.mark.parametrize("bad", [[], "cp-1", 7, None])
def test_an_answer_whose_checkpoints_are_not_an_object_is_invalid(bad: Any) -> None:
    answer = {"ok": True, "status": "pending", "code": "", "checks": [], "completed": {}, "checkpoints": bad}
    with pytest.raises(build_transport.HelperAnswerInvalid, match="checkpoints are not an object"):
        build_transport.parse_answer(json.dumps(answer), action="status")
    good = dict(answer, checkpoints={})
    assert build_transport.parse_answer(json.dumps(good), action="status")["checkpoints"] == {}


# -- one build at a time per state directory (the run lock) --------------------
#
# Every MCP tool runs in a worker thread, so two build runs may overlap.
# The lock is of the whole state directory, not of one plan: a resume plan
# is another plan id for the same servers.


#: The lock file of the state directory.
LOCK_NAME = ".run.lock"


def _lock_path() -> Path:
    return approve.build_plan_dir() / LOCK_NAME


def _take_lock() -> int:
    """Take the run lock, as another run (or another process) holds it."""
    directory = approve.build_plan_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(directory / LOCK_NAME), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _lock_is_free() -> bool:
    """True when the run lock of the state directory can be taken."""
    directory = approve.build_plan_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(directory / LOCK_NAME), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


def test_a_run_while_the_lock_is_held_stops_run_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    fd = _take_lock()
    try:
        state = build.run()
    finally:
        os.close(fd)
    assert state["state"] == "stopped", state
    assert state["reason"] == "run_in_progress", state
    assert state["plan_id"] == PLAN_ID, state
    detail = state["detail"]
    assert "another build run is active" in detail, detail
    assert "nothing was sent" in detail, detail
    assert "newton_ad_build_status" in detail, detail
    # nothing was sent, and no adapter was asked for anything
    assert build.transport.requests == []
    assert build.adapters.taken == []
    assert build.adapters.verified == []
    # the run state was not written at all
    assert not approve.build_run_state_path(PLAN_ID).exists()


def test_a_run_while_the_lock_is_held_leaves_the_run_state_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    assert build.run()["state"] == "stopped_for_approval"
    path = approve.build_run_state_path(PLAN_ID)
    before = path.read_bytes()
    fd = _take_lock()
    try:
        state = build.run()
    finally:
        os.close(fd)
    assert state["reason"] == "run_in_progress", state
    assert path.read_bytes() == before


def test_a_run_of_another_plan_while_the_lock_is_held_stops_run_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    """The lock is of the state directory, not of one plan: a resume plan
    is another plan id for the same servers."""
    build = Build(monkeypatch)
    build.resume("2")
    fd = _take_lock()
    try:
        state = build.run()
    finally:
        os.close(fd)
    assert state["state"] == "stopped", state
    assert state["reason"] == "run_in_progress", state
    assert state["plan_id"] == RESUME_ID, state
    assert build.transport.requests == []
    assert build.adapters.taken == []


class _BlockingTransport:
    """A transport whose send waits until the test lets the run go on."""

    def __init__(self, inner: Any, entered: threading.Event, release: threading.Event) -> None:
        self.inner = inner
        self.entered = entered
        self.release = release
        self.sent = 0

    def send(self, device: str, request: Any) -> dict[str, Any]:
        self.sent += 1
        self.entered.set()
        assert self.release.wait(60), "the test did not release the first run"
        return self.inner.send(device, request)


class _NoCallTransport:
    """A transport that must not be called at all."""

    def __init__(self) -> None:
        self.calls = 0

    def send(self, device: str, request: Any) -> dict[str, Any]:
        self.calls += 1
        raise AssertionError("the second run sent a request")


def test_two_overlapping_runs_the_second_stops_run_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    transport = _BlockingTransport(build.transport, entered, release)
    second_transport = _NoCallTransport()
    first: dict[str, Any] = {}

    def run_first() -> None:
        first["state"] = build_run.run_build(
            PLAN_ID,
            transport=transport,
            adapters=build.adapters,
            acceptance=build.acceptance,
            clock=build.clock,
            sleep=build.clock.sleep,
        )

    thread = threading.Thread(target=run_first)
    thread.start()
    try:
        assert entered.wait(60), "the first run did not reach the transport"
        second = build_run.run_build(
            PLAN_ID,
            transport=second_transport,
            adapters=build.adapters,
            acceptance=build.acceptance,
            clock=build.clock,
            sleep=build.clock.sleep,
        )
    finally:
        release.set()
        thread.join(60)
    assert not thread.is_alive()
    assert second["state"] == "stopped", second
    assert second["reason"] == "run_in_progress", second
    assert second_transport.calls == 0
    assert transport.sent >= 1
    assert first["state"]["state"] == "stopped_for_approval", first


def test_the_lock_is_free_again_after_a_run_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    build.run()
    assert _lock_is_free()
    state = build.run()
    assert state["reason"] != "run_in_progress", state


def test_the_lock_is_free_again_after_a_plan_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    state = build_run.run_build(
        "a" * 32,
        transport=build.transport,
        adapters=build.adapters,
        acceptance=build.acceptance,
        clock=build.clock,
        sleep=build.clock.sleep,
    )
    assert state["state"] == "stopped", state
    assert state["reason"] == "plan_mismatch", state
    assert _lock_is_free()


class _Boom(Exception):
    """The transport's own failure, which the runner does not catch."""


class _BoomTransport:
    def send(self, device: str, request: Any) -> dict[str, Any]:
        raise _Boom("the transport failed")


def test_the_lock_is_free_again_after_an_exception_in_the_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    with pytest.raises(_Boom):
        build_run.run_build(
            PLAN_ID,
            transport=_BoomTransport(),
            adapters=build.adapters,
            acceptance=build.acceptance,
            clock=build.clock,
            sleep=build.clock.sleep,
        )
    assert _lock_is_free()


@pytest.mark.parametrize("kind", ["directory", "symlink"])
def test_a_lock_file_that_cannot_be_opened_stops_run_lock_unavailable(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    build = Build(monkeypatch)
    path = _lock_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if kind == "directory":
        path.mkdir()
    else:
        path.symlink_to(path.parent / "somewhere-else")
    state = build.run()
    assert state["state"] == "stopped", state
    assert state["reason"] == "run_lock_unavailable", state
    assert state["plan_id"] == PLAN_ID, state
    assert build.transport.requests == []
    assert build.adapters.taken == []
    assert build.adapters.verified == []
    assert not approve.build_run_state_path(PLAN_ID).exists()


def test_a_state_directory_that_cannot_be_written_stops_run_lock_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lock file of a state directory that cannot be written opens and
    locks all the same: the run state could not be saved, so nothing goes
    out."""
    if os.geteuid() == 0:
        pytest.skip("root writes in a directory of any mode")
    build = Build(monkeypatch)
    path = _lock_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.touch()
    path.parent.chmod(0o500)
    try:
        state = build.run()
    finally:
        path.parent.chmod(0o700)
    assert state["state"] == "stopped", state
    assert state["reason"] == "run_lock_unavailable", state
    assert state["plan_id"] == PLAN_ID, state
    assert build.transport.requests == []
    assert build.adapters.taken == []
    assert build.adapters.verified == []
    assert not approve.build_run_state_path(PLAN_ID).exists()


def _full_disk_after(monkeypatch: pytest.MonkeyPatch, saves: int) -> list[int]:
    """The run state's first ``saves`` writes succeed, every later one
    fails as a full disk does (ENOSPC); the list counts the attempts."""
    import errno

    real = approve._atomic_write
    tries: list[int] = []

    def write(path, value):
        if path == approve.build_run_state_path(PLAN_ID):
            tries.append(1)
            if len(tries) > saves:
                raise OSError(errno.ENOSPC, "No space left on device")
        return real(path, value)

    monkeypatch.setattr(approve, "_atomic_write", write)
    return tries


def test_a_state_directory_with_no_room_stops_before_anything_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review of the merge (2026-11-23): os.access passes on a full disk,
    so the first save is tried before anything goes out; when it fails
    the run stops state_unwritable and sends nothing."""
    build = Build(monkeypatch)
    _full_disk_after(monkeypatch, 0)
    state = build.run()
    assert state["state"] == "stopped", state
    assert state["reason"] == "state_unwritable", state
    assert "nothing was sent" in state["detail"], state
    assert build.transport.requests == []
    assert build.adapters.taken == []
    assert _lock_is_free()


@pytest.mark.parametrize("saves", [1, 2, 3, 5, 8])
def test_a_save_that_fails_after_a_send_stops_and_says_what_went_out(
    monkeypatch: pytest.MonkeyPatch, saves: int
) -> None:
    """A disk that fills up mid-run: the save after a stage fails.  The
    run stops state_write_failed with the stage and device instead of a
    traceback, frees the lock, and says the helper's journal on the
    server holds what ran."""
    build = Build(monkeypatch)
    _full_disk_after(monkeypatch, saves)
    state = build.run()
    assert state["state"] == "stopped", state
    assert state["reason"] == "state_write_failed", state
    assert "journal" in state["detail"], state
    assert state["plan_id"] == PLAN_ID, state
    assert _lock_is_free()


@pytest.mark.parametrize("stage", ["0", "3", "5", "6"])
def test_a_call_after_a_failed_save_does_not_run_a_finished_stage_again(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    """Codex review of 1.5.1: the disk fills up right after a stage ran on
    the server, so its done never reaches the run state.  Once space is
    freed the next call reads the journal: every stage runs exactly once
    and the build ends done."""
    import errno

    build = Build(monkeypatch)
    real = approve._atomic_write
    full = {"on": True}

    def write(path, value):
        if (
            full["on"]
            and path == approve.build_run_state_path(PLAN_ID)
            and ("build1", stage, "run") in build.transport.actions()
        ):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(path, value)

    monkeypatch.setattr(approve, "_atomic_write", write)
    state = build.drive()
    assert (state["state"], state["reason"]) == ("stopped", "state_write_failed"), state
    assert _runs(build).count(("build1", stage)) == 1
    full["on"] = False
    state = build.drive()
    assert state["state"] == "done", state
    runs = _runs(build)
    assert all(runs.count(run) == 1 for run in runs), runs
    assert _lock_is_free()


def test_the_status_answers_while_the_lock_is_held(monkeypatch: pytest.MonkeyPatch) -> None:
    build = Build(monkeypatch)
    assert build.run()["state"] == "stopped_for_approval"
    fd = _take_lock()
    try:
        state = build_run.run_status(PLAN_ID)
    finally:
        os.close(fd)
    assert state["state"] == "stopped_for_approval", state
    assert state["plan_id"] == PLAN_ID, state
