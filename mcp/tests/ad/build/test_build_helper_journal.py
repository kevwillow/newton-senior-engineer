"""The helper's journal as the runner and the stage approval read it
(PLAN-1.5 task 8; DESIGN-1.5 "Checkpoints", ``not_before``, and the open
points of task 7, points 3 and 9).

Two additions to the helper of task 3:

- A status answer carries ``completed``: each stage's recorded
  completion, the ``time`` of its ``done`` entry in the helper's own
  journal (the helper's clock, a UTC second).  The stage approval and the
  runner take ``not_before`` from it, never from the runner's state file.
- A ``checkpoint`` request may name the id of a checkpoint Newton took
  through a hypervisor adapter (Hyper-V, Proxmox): the helper records that
  id in its journal, so the stage token the owner signs over the verified
  id is the one the helper checks.  Only a ``checkpoint`` request may name
  one, only for a server whose plan method is a hypervisor, and only in
  the id grammar of the plan.

The harness and the fake stage table are the ones of the task 3 tests.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import plan
from test_build_helper import (  # type: ignore[import-not-found]
    BASE,
    BOOT_AFTER,
    BOOT_BEFORE,
    EXP,
    NBF,
    PLAN_INPUTS,
    STAGE_TABLE,
    Server,
    _plan,
    _request,
    _token,
)

#: A Proxmox task id of the shape the adapter answers (MEASURED-1.5
#: "The scoped token").
UPID = "UPID:apollo:000A1B2C:0F1E2D3C:6734A2B1:qmsnapshot:8301:newton@pve!build:"


@pytest.fixture
def server(tmp_path: Path) -> Server:
    one = Server(tmp_path / "install")
    one.write_table(STAGE_TABLE)
    return one


def _status(server: Server, the_plan: dict[str, Any], stage: str = "0", *, now: int, boot: str = BOOT_AFTER) -> dict[str, Any]:
    _, answer = server.call(_request(the_plan, stage=stage, action="status"), now=now, boot=boot)
    assert answer is not None
    return answer


def test_a_status_answer_carries_each_done_stage_completion(server: Server) -> None:
    """``completed`` holds the journal time of each stage's done entry."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan, stage="0"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None and answer["status"] == "done"
    _, answer = server.call(_request(the_plan, stage="1"), now=BASE + 10, boot=BOOT_BEFORE)
    assert answer is not None and answer["status"] == "rebooting"
    answer = _status(server, the_plan, "1", now=BASE + 100)
    assert answer["status"] == "done"
    assert answer["completed"] == {"0": BASE, "1": BASE + 100}

    answer = _status(server, the_plan, "0", now=BASE + 200)
    assert answer["status"] == "done"
    assert answer["completed"] == {"0": BASE, "1": BASE + 100}
    done = {e["stage"]: e["time"] for e in server.journal() if e["state"] == "done"}
    assert answer["completed"] == done


def test_a_status_answer_of_an_empty_journal_has_no_completion(server: Server) -> None:
    answer = _status(server, _plan(), "0", now=BASE)
    assert answer["status"] == "pending"
    assert answer["completed"] == {}


def test_a_stage_that_waits_for_its_reboot_has_no_completion(server: Server) -> None:
    the_plan = _plan()
    server.call(_request(the_plan, stage="0"), now=BASE, boot=BOOT_BEFORE)
    server.call(_request(the_plan, stage="1"), now=BASE + 10, boot=BOOT_BEFORE)
    answer = _status(server, the_plan, "1", now=BASE + 20, boot=BOOT_BEFORE)
    assert answer["status"] == "rebooting"
    assert answer["completed"] == {"0": BASE}


def test_a_run_answer_is_still_the_four_fields(server: Server) -> None:
    """Only a status answer carries the completions."""
    _, answer = server.call(_request(_plan(), stage="0"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert set(answer) == {"ok", "status", "code", "checks"}


def test_a_refused_status_carries_no_completion(server: Server) -> None:
    the_plan = _plan()
    server.call(_request(the_plan, stage="0"), now=BASE, boot=BOOT_BEFORE)
    request = _request(the_plan, stage="0", action="status", token="0" * 64)
    _, answer = server.call(request, now=BASE + 5, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "bad_token"
    assert "completed" not in answer


# ---------------------------------------------------------------------------
# the checkpoint id of a hypervisor adapter
# ---------------------------------------------------------------------------


def _hyperv_plan() -> dict[str, Any]:
    """The task 3 plan: build1 (dc1) takes Hyper-V checkpoints."""
    the_plan = _plan()
    assert the_plan["servers"][0]["checkpoint"] == "hyperv"
    return the_plan


def _to_stage_two(server: Server, the_plan: dict[str, Any]) -> None:
    server.call(_request(the_plan, stage="0"), now=BASE, boot=BOOT_BEFORE)
    server.call(_request(the_plan, stage="1"), now=BASE + 10, boot=BOOT_BEFORE)
    answer = _status(server, the_plan, "1", now=BASE + 20)
    assert answer["status"] == "done"


def _checkpoint_request(the_plan: dict[str, Any], stage: str, ident: str | None) -> dict[str, Any]:
    request = _request(the_plan, stage=stage, action="checkpoint")
    if ident is not None:
        request["checkpoint"] = ident
    return request


def test_the_helper_records_the_checkpoint_id_newton_took(server: Server) -> None:
    """The id of a hypervisor checkpoint reaches the journal, and the
    stage token over that id opens the stage."""
    the_plan = _hyperv_plan()
    _to_stage_two(server, the_plan)
    _, answer = server.call(_checkpoint_request(the_plan, "2", UPID), now=BASE + 30, boot=BOOT_AFTER)
    assert answer is not None
    assert answer["status"] == "checkpointed", answer
    assert answer["checks"] == [{"name": "checkpoint", "ok": True, "detail": UPID}]
    entry = server.journal()[-1]
    assert entry["state"] == "checkpointed" and entry["checkpoint"] == UPID

    digest = plan.digest(the_plan)
    stage_token = _token(plan.stage_digest(digest, "2", UPID))
    _, answer = server.call(_request(the_plan, stage="2", token=stage_token), now=BASE + 40, boot=BOOT_AFTER)
    assert answer is not None and answer["status"] == "rebooting", answer


def test_the_helper_records_a_named_checkpoint_without_a_stage_table(tmp_path: Path) -> None:
    """The real path (no fake table): a hypervisor id is recorded, and no
    fake id is ever made."""
    server = Server(tmp_path / "real")
    server.write_table(STAGE_TABLE)
    the_plan = _hyperv_plan()
    _to_stage_two(server, the_plan)
    _, answer = server.call(_checkpoint_request(the_plan, "2", UPID), now=BASE + 30, boot=BOOT_AFTER, table=None)
    assert answer is not None and answer["status"] == "checkpointed", answer
    assert server.journal()[-1]["checkpoint"] == UPID


def test_a_checkpoint_without_an_id_and_without_a_table_is_still_refused(tmp_path: Path) -> None:
    server = Server(tmp_path / "real")
    server.write_table(STAGE_TABLE)
    the_plan = _hyperv_plan()
    _to_stage_two(server, the_plan)
    before = server.names()
    _, answer = server.call(_checkpoint_request(the_plan, "2", None), now=BASE + 30, boot=BOOT_AFTER, table=None)
    assert answer is not None and answer["code"] == "schema"
    assert server.names() == before


@pytest.mark.parametrize("ident", ["", "x" * 129, "has space", "tab\there", "é"])
def test_a_checkpoint_id_outside_the_grammar_is_refused(server: Server, ident: str) -> None:
    the_plan = _hyperv_plan()
    _to_stage_two(server, the_plan)
    before = server.names()
    _, answer = server.call(_checkpoint_request(the_plan, "2", ident), now=BASE + 30, boot=BOOT_AFTER)
    assert answer is not None and answer["code"] == "schema", answer
    assert server.names() == before


@pytest.mark.parametrize("action", ["run", "status"])
def test_only_a_checkpoint_request_names_a_checkpoint(server: Server, action: str) -> None:
    the_plan = _hyperv_plan()
    request = _request(the_plan, stage="0", action=action)
    request["checkpoint"] = UPID
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None and answer["code"] == "schema"
    assert server.names() == []


def test_a_wbadmin_server_names_no_checkpoint(tmp_path: Path) -> None:
    """A server without a hypervisor takes its own backup (open point 2 of
    task 7): Newton cannot name its checkpoint."""
    server = Server(tmp_path / "dc2", device="build2")
    server.write_table(STAGE_TABLE)
    the_plan = _plan()
    assert the_plan["servers"][1]["checkpoint"] == "wbadmin"
    server.call(_request(the_plan, stage="0"), now=BASE, boot=BOOT_BEFORE)
    server.call(_request(the_plan, stage="1"), now=BASE + 10, boot=BOOT_BEFORE)
    assert _status(server, the_plan, "1", now=BASE + 20)["status"] == "done"
    before = server.names()
    _, answer = server.call(_checkpoint_request(the_plan, "7", UPID), now=BASE + 30, boot=BOOT_AFTER)
    assert answer is not None and answer["code"] == "schema", answer
    assert server.names() == before


def test_a_named_checkpoint_needs_the_plan_token(server: Server) -> None:
    the_plan = _hyperv_plan()
    _to_stage_two(server, the_plan)
    request = _checkpoint_request(the_plan, "2", UPID)
    request["token"] = _token(plan.digest(the_plan), key="b3" * 32)
    before = server.names()
    _, answer = server.call(request, now=BASE + 30, boot=BOOT_AFTER)
    assert answer is not None and answer["code"] == "bad_token"
    assert server.names() == before


def test_the_plan_inputs_are_the_ones_of_task_3() -> None:
    """The constants this file imports are the task 3 harness's."""
    assert PLAN_INPUTS["servers"][0]["device"] == "build1"
    assert NBF < BASE < EXP
    assert base64.b64decode(_request(_plan())["plan"]) == plan.canonical_bytes(_plan())
