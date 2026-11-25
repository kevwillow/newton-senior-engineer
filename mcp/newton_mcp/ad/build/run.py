"""The runner of an AD build (PLAN-1.5 task 8; DESIGN-1.5 "Stage graphs",
"Checkpoints", "Deviation and resume").

``run_build(plan_id)`` drives the stages of one approved plan, server by
server, through each helper (``transport``), and stops:

- before each irreversible stage, once its checkpoint is taken through the
  adapters and verified (``checkpoint.require_verified``, with
  ``not_before`` from the helper's journal): the run state says
  ``stopped_for_approval`` with the checkpoint, and the owner runs
  ``newton-approve ad-build-stage <plan> <stage>``; the next call resumes
  with the stage token that approval wrote;
- on any deviation: a refusal or a stopped stage of a helper, a failed
  checkpoint, a lost session that does not end in ``rebooting``
  (``connection_lost``), a reboot that does not end within 15 minutes
  (``reboot_timeout``), or a stage 10 acceptance that fails.  The run state
  records the reason, and nothing more is sent: a stopped run goes on only
  through a resume plan the owner approves.

What the stages did comes from the helpers' journals (the status answer's
``completed``), never from the run state: the run state only says where the
runner stopped, and holds the receipts.  The agent can write the run state,
so nothing in it makes the runner skip a stage (its ``finished`` lists are
what one call saw done in the journals, rebuilt by every call), and a run
state that says ``done`` is answered ``done`` only when stage 10's
acceptance passes again.  Before a run of a stage the runner reads the
stage's own status, so a runner killed during a rebooting stage and started
again goes on from the journal instead of sending a second run.  No request holds a domain
credential: the runner never has the DSRM, admin or newton-build password,
nor any key K.

The order (PLAN-1.5 Constraints): DC1 ``0 1 2 3 4 5 6 7 8 9 10``, DC2
``0 1 7 9``; DC2's stages 0 and 1 beside DC1's; stage 7 DC1's part, then
DC2's; stage 9 DC2 first, then DC1; stage 10 last, from DC1, through the
read-only newton-audit login of the 1.3 collector (the maintainer's decision R2), not
newton-ops and not the build helper (stage 9 removed it).
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from ... import approve as _approve
from . import bootstrap as _bootstrap
from . import checkpoint as _checkpoint
from . import plan as _plan
from . import stage_token as _token_rule
from .transport import (
    HelperAnswerInvalid,
    HelperTransport,
    HelperUnavailable,
    Journal,
    JournalUnreadable,
    helper_request,
    journal_not_before,
    read_journal,
)

#: The run states.
RUNNING = "running"
STOPPED_FOR_APPROVAL = "stopped_for_approval"
STOPPED = "stopped"
DONE = "done"

#: How long a rebooting stage, or a session that dropped, may take to come
#: back to an answer: 15 minutes (the helper's post-boot grace is the same).
REBOOT_TIMEOUT_S = 15 * 60

#: DC1's stage 7 read-back polls up to 30 minutes on the DC (the maintainer's decision
#: K17), and its status records it once its password task ends: the
#: runner waits that long plus five minutes for the record.
READBACK_TIMEOUT_S = 35 * 60

#: How often the runner asks a rebooting stage for its status.
POLL_S = 20.0

#: The code a helper answers with when another request holds the journal
#: of the server (the helper's lock).  A status that is refused this way
#: is not yet: the runner keeps polling until the deadline of its loop.
#: Any other request refused this way stops the run with this code, and
#: nothing is sent again (the lab run of 2026-11-23).
JOURNAL_BUSY = "journal_busy"

#: How long DC2's own dcdiag may wait for the first replication to
#: settle: 15 minutes (the helper's ``$script:DiagMaxSeconds``).  The
#: runner waits the promotion's reboot and that wait before DC2's stage 7
#: may end.
S7_DC_DIAG_MAX_S = 15 * 60

#: The margin of one pass (a repadmin and a dcdiag) the runner waits on
#: top of that: the helper's wait is a hard limit, but the pass that
#: starts before it may end after it (the helper's
#: ``$script:DiagPassMarginSeconds``).
S7_DC_PASS_MARGIN_S = 180

#: The stages that reboot their server (DESIGN-1.5 "The helper"; stage 7's
#: reboots are part B's, and the fake tables of the tests reboot it).
REBOOT_STAGES = frozenset({"1", "2", "4", "7"})

#: The acceptance stage: run from DC1 through the read-only newton-audit
#: login of the 1.3 collector (the maintainer's decision R2, 2026-11-15).
ACCEPTANCE_STAGE = "10"

#: How long stage 10 reads again while the build account is still in the
#: directory (F4 of the part B triage): DC1's stage 9 answers done once its
#: SYSTEM cleanup task runs, and the task waits 15 s
#: (``acceptance.CLEANUP_DELAY_S``) before its deletions, the account last.
ACCEPTANCE_WAIT_S = 300

#: The cleanup stage, under the plan token only.
CLEANUP_STAGE = "9"

#: The replica stage (option B, MEASURED-1.5 "Stage 7 on BUILD1 and
#: BUILD2, 2026-11-15"): DC1 provisions DC2 and answers the offline domain
#: join blob (``s7_provision``); DC2 joins with it and reboots, and its
#: status after that boot says it is a member (``s7_member``); DC1 installs
#: the replica over WinRM and restarts DC2 (``s7_install``); DC2's status
#: after the promotion's boot is done; DC1 reads the replication back.
REPLICA_STAGE = "7"

#: The newton-ops stage: it installs the 1.4 write helper whose sha256 the
#: plan names (the maintainer's decision R1, 2026-11-15).  DC1's bootstrap installed the
#: helper's bytes and DC1's helper checks them before anything of the stage
#: runs (the maintainer's decision of 2026-11-19 on the stage 8 transport); a file that
#: is missing or changed stops the run with the next step below, and the
#: run is never sent again on its own.
OPS_STAGE = "8"
WRITE_HELPER_REFUSALS = ("write_helper_missing", "write_helper_mismatch")


def _write_helper_next_step(device: str) -> str:
    """Newton's own next step for a stage 8 whose installed write helper is
    missing or not the plan's: fixed text and the plan's device name, never
    device text."""
    return (
        f"the write helper installed on {device} is missing or is not the plan's: run the bootstrap of {device} "
        f"again on the server (it installs the write helper at {_bootstrap.WRITE_HELPER_FILE}), then run the build again"
    )


def _dns_next_step(device: str) -> str:
    """Newton's own next step for a stage 0 whose DNS check could not be
    made (open point 79, ruled 2026-11-21): the check stays strict and the
    owner prepares the server.  Fixed text and the plan's device name."""
    return (
        f"stage 0 could not check the domain name in DNS on {device}: set the server's DNS client to a resolver "
        "that answers before stage 0 (an NXDOMAIN for the new domain is the right answer), then run the build again"
    )


S7_PROVISION = "s7_provision"
S7_MEMBER = "s7_member"
S7_INSTALL = "s7_install"

#: What stage 10 reads through newton-audit (``acceptance.audit_acceptance``):
#: whether the build account is still in the directory, the ids of the 1.3
#: audit's findings and of the checks it could not prove.
Acceptance = Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]


class _Stop(Exception):
    def __init__(self, reason: str, device: str, stage: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.device = device
        self.stage = stage
        self.detail = detail


class _Wait(Exception):
    """The run stops for the owner's approval of a stage."""

    def __init__(self, stage: str) -> None:
        super().__init__(stage)
        self.stage = stage


def build_order(built: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The (device, stage) steps of the run, in order."""
    servers = {server["role"]: server for server in built["servers"]}
    dc1 = servers["dc1"]["device"]
    if "dc2" not in servers:
        return [(dc1, stage) for stage in _plan.DC1_GRAPH_ALONE]
    dc2 = servers["dc2"]["device"]
    order = [(dc1, "0"), (dc2, "0"), (dc1, "1"), (dc2, "1")]
    order += [(dc1, stage) for stage in ("2", "3", "4", "5", "6")]
    order += [(dc1, "7"), (dc2, "7"), (dc1, "8"), (dc2, "9"), (dc1, "9"), (dc1, "10")]
    for server in built["servers"]:
        mine = tuple(stage for device, stage in order if device == server["device"])
        if mine != _plan.stage_graph(built, server):
            raise ValueError("the order of the run is not the graph of a server")
    return order


def _now_utc() -> float:
    return datetime.now(timezone.utc).timestamp()


def _journal_busy(answer: Mapping[str, Any]) -> bool:
    """True when the answer is the refusal of a helper whose journal of the
    server another request holds: the status is not yet."""
    return answer.get("status") == "refused" and answer.get("code") == JOURNAL_BUSY


class _Runner:
    def __init__(
        self,
        plan_id: str,
        *,
        transport: HelperTransport,
        adapters: Any,
        acceptance: Acceptance | None,
        clock: Callable[[], float],
        sleep: Callable[[float], None],
        poll_s: float,
    ) -> None:
        self.plan_id = plan_id
        self.transport = transport
        self.adapters = adapters
        self.acceptance = acceptance
        self.clock = clock
        self.sleep = sleep
        self.poll_s = poll_s
        self.built, self.digest = _approve._load_build_plan(plan_id)
        self.plan_bytes = _plan.canonical_bytes(self.built)
        self.servers = {server["device"]: server for server in self.built["servers"]}
        self.approval = _approve._load_build_plan_approval(plan_id)
        if self.approval.get("kind") != "plan" or self.approval.get("plan_digest") != self.digest:
            raise _approve.ApprovalRefused("the plan on record is not the plan that was approved")
        self.state = self._load_state()
        # The completions of each server's journal, as this call read them,
        # with the stages this call saw its helpers answer done.
        self._journals: dict[str, dict[str, int]] = {}

    # -- the run state ------------------------------------------------------

    def _load_state(self) -> dict[str, Any]:
        try:
            state = _approve._load_build_run_state(self.plan_id)
        except _approve.ApprovalRefused:
            state = {}
        run = state.get("run", self.plan_id)
        if not isinstance(run, str) or _approve.PLAN_ID_RE.fullmatch(run) is None:
            run = self.plan_id
        fresh: dict[str, Any] = {
            "plan_id": self.plan_id,
            "plan_digest": self.digest,
            "run": run,
            "state": RUNNING,
            "stage": "",
            "device": "",
            "reason": "",
            "detail": "",
            "servers": {},
            "finished": {},
            "receipts": [],
        }
        if state.get("plan_digest") == self.digest:
            for key in ("state", "stage", "device", "reason", "detail"):
                if isinstance(state.get(key), str):
                    fresh[key] = state[key]
            for key in ("servers", "finished"):
                if isinstance(state.get(key), dict):
                    fresh[key] = state[key]
            if isinstance(state.get("receipts"), list):
                fresh["receipts"] = state["receipts"]
            # stage 7 began and did not end (``_replica``)
            if isinstance(state.get("replica"), str):
                fresh["replica"] = state["replica"]
            # stage 9's cleanups, registered or confirmed (a report)
            if isinstance(state.get("cleanup"), dict):
                fresh["cleanup"] = state["cleanup"]
        return fresh

    def _save(self) -> None:
        _approve._atomic_write(_approve.build_run_state_path(self.plan_id), self.state)

    def _receipt(self, device: str, stage: str, action: str, answer: Mapping[str, Any] | None, note: str = "") -> None:
        entry: dict[str, Any] = {
            "at": int(self.clock()),
            "device": device,
            "stage": stage,
            "action": action,
            "note": note,
        }
        if answer is not None:
            entry["ok"] = answer.get("ok")
            entry["status"] = answer.get("status")
            entry["code"] = answer.get("code")
            entry["checks"] = [
                {"name": c.get("name"), "ok": c.get("ok"), "detail": c.get("detail")}
                for c in answer.get("checks", [])
                if isinstance(c, dict)
            ]
        self.state["receipts"].append(entry)
        self._save()

    def _finished(self, device: str) -> list[str]:
        """What this call saw done on the server (a report; never read to
        skip a stage)."""
        done = self.state["finished"].setdefault(device, [])
        if not isinstance(done, list):
            done = []
            self.state["finished"][device] = done
        return done

    def _saw_done(self, device: str, stage: str) -> None:
        done = self._finished(device)
        if stage not in done:
            done.append(stage)

    # -- the tokens ---------------------------------------------------------

    def _plan_token(self, device: str) -> tuple[str, int, int]:
        tokens = self.approval.get("tokens")
        token = tokens.get(device) if isinstance(tokens, dict) else None
        nbf, exp = self.approval.get("nbf"), self.approval.get("exp")
        if not isinstance(token, str) or not isinstance(nbf, int) or not isinstance(exp, int):
            raise _Stop("plan_mismatch", device, "", "the plan approval holds no token for the server")
        return token, nbf, exp

    def _stage_token(self, device: str, stage: str) -> tuple[str, int, int] | None:
        """The owner's stage token for this server, when the approval of the
        stage is on record, over this plan, and still open."""
        try:
            path = _approve.build_stage_approval_path(self.plan_id, stage)
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(record, dict) or record.get("kind") != "stage":
            return None
        if record.get("plan_digest") != self.digest or record.get("stage") != stage:
            return None
        servers = record.get("servers")
        entry = servers.get(device) if isinstance(servers, dict) else None
        if not isinstance(entry, dict) or not isinstance(entry.get("token"), str):
            return None
        nbf, exp = record.get("nbf"), record.get("exp")
        if not isinstance(nbf, int) or not isinstance(exp, int):
            return None
        if self.clock() >= exp:
            return None
        return entry["token"], nbf, exp

    # -- the helper ---------------------------------------------------------

    def _request(
        self,
        device: str,
        stage: str,
        action: str,
        token: tuple[str, int, int],
        checkpoint: str | None = None,
        odj: str | None = None,
    ) -> dict[str, Any]:
        return helper_request(
            run=self.state["run"],
            plan_bytes=self.plan_bytes,
            stage=stage,
            action=action,
            token=token[0],
            nbf=token[1],
            exp=token[2],
            checkpoint=checkpoint,
            odj=odj,
        )

    def _completions(self, device: str) -> dict[str, int]:
        """The completions of the server's journal, read now."""
        return self._journal(device).completed

    def _journal(self, device: str) -> Journal:
        """The server's journal, read now: its completions and the
        checkpoints it holds for this plan.  A server that does not answer
        may be rebooting (a runner started again during a rebooting stage):
        it is asked again until it answers, at most 15 minutes."""
        token = self._plan_token(device)
        deadline = self.clock() + REBOOT_TIMEOUT_S
        while True:
            try:
                return read_journal(
                    self.transport,
                    device,
                    run=self.state["run"],
                    plan_bytes=self.plan_bytes,
                    token=token[0],
                    nbf=token[1],
                    exp=token[2],
                )
            except JournalUnreadable as exc:
                if exc.code == "expired":
                    raise _Stop(
                        "expired",
                        device,
                        "",
                        "the helper refused the plan token as expired: the run goes on only through a resume plan the "
                        "owner approves (a second approval of this plan does not restart a stopped run)",
                    ) from None
                if exc.code == "plan_mismatch":
                    raise _Stop(
                        "plan_mismatch",
                        device,
                        "",
                        "the helper refused this plan for its journal: a resume plan goes on only when its "
                        "start_stage is the next stage of every server, and its run is the journal's",
                    ) from None
                if exc.code == JOURNAL_BUSY:
                    # Another request holds the journal of the server: the
                    # read is not sent again.
                    raise _Stop(
                        JOURNAL_BUSY,
                        device,
                        "",
                        "another request holds the journal of the server: the run goes on only when the "
                        "request that holds it is through",
                    ) from None
                if exc.code != "unavailable" or self.clock() >= deadline:
                    raise _Stop("journal_unreadable", device, "", str(exc)) from None
            self.sleep(self.poll_s)

    def _journal_done(self, device: str, stage: str) -> bool:
        """True when the server's journal records ``stage`` done.  The
        journal is read once per call; a stage this call saw its helper
        answer done is added (``_answered_done``)."""
        if device not in self._journals:
            self._journals[device] = self._completions(device)
        return stage in self._journals[device]

    def _answered_done(self, device: str, stage: str) -> None:
        self._journals.setdefault(device, {})[stage] = int(self.clock())

    def _send(self, device: str, stage: str, request: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.transport.send(device, request)
        except HelperAnswerInvalid as exc:
            raise _Stop("answer_invalid", device, stage, str(exc)) from None

    # -- the stages ---------------------------------------------------------

    def run(self) -> dict[str, Any]:
        if self.state["state"] == STOPPED:
            # A stopped run goes on only through a resume plan the owner
            # approves (DESIGN-1.5 "Deviation and resume").
            return self.state
        order = build_order(self.built)
        if self.state["state"] == DONE:
            # The run state is the agent's to write: done is answered only
            # when the acceptance passes again.  After stage 9 no helper
            # answers, so nothing is sent to one.
            order = [step for step in order if step[1] == ACCEPTANCE_STAGE]
        else:
            self.state["finished"] = {}
        try:
            self._resume_shared()
            for device, stage in order:
                if stage == ACCEPTANCE_STAGE:
                    self._begin(device, stage)
                    self._accept(device)
                elif stage == REPLICA_STAGE and self.servers[device]["role"] != "dc1":
                    # DC2's part of stage 7 ran inside DC1's step.
                    if not self._journal_done(device, stage):
                        raise _Stop("stage_interrupted", device, stage, "stage 7 is not done in DC2's journal")
                elif stage == REPLICA_STAGE:
                    dc2 = self._dc2()
                    if not (self._journal_done(device, stage) and self._journal_done(dc2, stage)):
                        self._begin(device, stage)
                        self._replica(device)
                        self._answered_done(dc2, stage)
                    self._saw_done(dc2, stage)
                elif not self._journal_done(device, stage):
                    self._begin(device, stage)
                    self._stage(device, stage)
                if stage != ACCEPTANCE_STAGE:
                    self._answered_done(device, stage)
                if stage == CLEANUP_STAGE:
                    # The helper's done of stage 9 says its SYSTEM cleanup
                    # task runs, not that it ran: stage 9 is reported
                    # done only once stage 10 read the account gone.
                    self.state.setdefault("cleanup", {})[device] = "registered"
                else:
                    self._saw_done(device, stage)
                self._save()
        except _Wait as wait:
            self.state.update({"state": STOPPED_FOR_APPROVAL, "stage": wait.stage, "reason": "", "detail": ""})
            self._save()
            return self.state
        except _Stop as stop:
            self.state.update(
                {
                    "state": STOPPED,
                    "stage": stop.stage or self.state["stage"],
                    "device": stop.device or self.state["device"],
                    "reason": stop.reason,
                    "detail": stop.detail,
                }
            )
            self._save()
            return self.state
        self.state.update({"state": DONE, "stage": ACCEPTANCE_STAGE, "reason": "", "detail": ""})
        self._save()
        return self.state

    def _begin(self, device: str, stage: str) -> None:
        self.state.update({"state": RUNNING, "stage": stage, "device": device, "reason": "", "detail": ""})
        self._save()

    def _dc2(self) -> str:
        return next(d for d, server in self.servers.items() if server["role"] == "dc2")

    def _resume_shared(self) -> None:
        """A resume plan has one ``start_stage``, and each server's helper
        takes the plan only when it is that server's next stage (DESIGN-1.5
        "Tokens").  A stage outside a server's graph is never its next
        stage, so such a plan stops here, before any request (open point
        26 of task 8)."""
        start = self.built.get("start_stage")
        if not isinstance(start, str):
            return
        for server in self.built["servers"]:
            if start not in _plan.stage_graph(self.built, server):
                raise _Stop(
                    "plan_mismatch",
                    server["device"],
                    start,
                    "the resume plan's start_stage is not a stage of every server, so it is not every "
                    "server's next stage",
                )

    def _write_helper_is_the_plans(self, device: str) -> None:
        """The installed Newton's write helper is the plan's: one whose
        sha256 is not stops the stage before anything is sent (the maintainer's decision
        R1).  No request carries the bytes: DC1's helper checks the copy its
        bootstrap installed against the plan too (the maintainer's decision of
        2026-11-19)."""
        import hashlib

        from .. import setupgen_write as _setupgen_write

        try:
            helper = _setupgen_write.WRITE_HELPER_PATH.read_bytes()
        except OSError:
            raise _Stop("write_helper_mismatch", device, OPS_STAGE, "the installed Newton holds no write helper") from None
        if hashlib.sha256(helper).hexdigest() != self.built["ops"]["write_helper_sha256"]:
            raise _Stop("write_helper_mismatch", device, OPS_STAGE, "the installed write helper is not the plan's")

    def _stage(self, device: str, stage: str) -> None:
        kind = _token_rule.token_kind(stage)
        if stage == OPS_STAGE:
            self._write_helper_is_the_plans(device)
        if kind == "stage":
            token = self._stage_token(device, stage)
            if token is None:
                self._checkpoints(stage)
                raise _Wait(stage)
        else:
            token = self._plan_token(device)
        if self._settled_before_run(device, stage, token):
            return
        self._execute(device, stage, token)
        entry = self.state["servers"].get(device)
        if kind == "stage" and isinstance(entry, dict) and entry.get("stage") == stage:
            entry["state"] = "done"
            self._save()

    # -- stage 7, option B ---------------------------------------------------

    def _replica(self, device: str) -> None:
        """Stage 7 of both servers, reached at DC1's step of the order.

        The blob DC1 answers is the one secret the runner carries: it is
        held in this frame only, sent in DC2's run request and dropped; it
        never reaches the run state, a receipt or a log.  A runner that
        stops inside the sequence (killed, or a lost session) does not
        pick it up again, and neither does a resume plan that starts at 7:
        the run stops ``stage_interrupted`` and a stage 7 that began needs
        the owner (DESIGN-1.5, open point 38 of task 8).
        """
        if self.servers[device]["role"] != "dc1":
            raise _Stop("schema", device, REPLICA_STAGE, "stage 7 starts from DC1")
        dc1 = device
        dc2 = self._dc2()
        if REPLICA_STAGE in self._completions(dc1) and REPLICA_STAGE in self._completions(dc2):
            self._receipt(dc1, REPLICA_STAGE, "status", None, "done in both helpers' journals")
            return
        if self.state.get("replica"):
            raise _Stop("stage_interrupted", dc1, REPLICA_STAGE, _INTERRUPTED_7)
        if REPLICA_STAGE in self._completions(dc1) or REPLICA_STAGE in self._completions(dc2):
            raise _Stop("stage_interrupted", dc1, REPLICA_STAGE, "stage 7 is done on one server only")
        token1 = self._stage_token(dc1, REPLICA_STAGE)
        token2 = self._stage_token(dc2, REPLICA_STAGE)
        if token1 is None or token2 is None:
            self._checkpoints(REPLICA_STAGE)
            raise _Wait(REPLICA_STAGE)
        # The helpers' journals, not the run state, say whether the sequence
        # began (IC-1 of the part B triage): before the provision, stage 7
        # must hold no entry but its checkpoint on either server.  A runner
        # killed inside the sequence lost the blob, so it never picks the
        # sequence up again; the marker below is an extra check only.
        statuses: dict[str, Any] = {}
        for one, token in ((dc1, token1), (dc2, token2)):
            answer = self._status(one, REPLICA_STAGE, token)
            if answer is None:
                raise _Stop("journal_unreadable", one, REPLICA_STAGE, "the server did not answer the status of stage 7")
            if answer.get("ok") is not True:
                raise _Stop(str(answer.get("code") or "stopped"), one, REPLICA_STAGE, _failed_check(answer))
            statuses[one] = answer.get("status")
        # A resume plan at 7 goes on with a stage 7 that DC1 began and DC2
        # never joined (IC1-resume7 of the part C triage; open point 33):
        # DC1's helper provisions again with /reuse only when its own
        # journal's last phase is the provision's, and refuses any later
        # one.  DC2 must be pending: its own turn of the loop stops the run
        # otherwise.  Without a resume plan, any stage 7 entry stops the run.
        resume7 = self.built.get("resume_from") is not None and str(self.built.get("start_stage")) == REPLICA_STAGE
        for one in (dc1, dc2):
            if statuses[one] == "pending":
                continue
            if resume7 and one == dc1 and statuses[dc1] in ("started", "stopped"):
                self._receipt(dc1, REPLICA_STAGE, "status", None, "a resume plan at 7: DC1's helper decides whether the provision runs again")
                continue
            raise _Stop("stage_interrupted", one, REPLICA_STAGE, "the server's journal holds a stage 7 entry: " + _INTERRUPTED_7)
        self.state["replica"] = "begun"
        self._save()
        started = self.clock()

        # DC1 provisions DC2: the answer holds the blob.
        answer = self._replica_run(dc1, token1)
        odj = answer.pop("odj", None)
        if answer.get("ok") is not True or answer.get("status") != "started" or not _passed(answer, S7_PROVISION):
            odj = None
            self._settle_stop(dc1, answer)
        if odj is None:
            raise _Stop("answer_invalid", dc1, REPLICA_STAGE, "the provision answered no offline domain join blob")
        try:
            request = self._request(dc2, REPLICA_STAGE, "run", token2, odj=odj)
        except ValueError:
            raise _Stop("answer_invalid", dc1, REPLICA_STAGE, "the offline domain join blob is outside its grammar") from None
        finally:
            odj = None
        try:
            answer = self._send(dc2, REPLICA_STAGE, request)
        except HelperUnavailable:
            self._receipt(dc2, REPLICA_STAGE, "run", None, "the session dropped")
            raise _Stop("connection_lost", dc2, REPLICA_STAGE, "the join's session dropped") from None
        finally:
            del request
        self._receipt(dc2, REPLICA_STAGE, "run", answer)
        if answer.get("ok") is not True or answer.get("status") != "rebooting":
            self._settle_stop(dc2, answer)

        # DC2 rebooted into the domain: its status says it is a member.
        self._poll_until(dc2, token2, started, lambda a: a.get("status") == "rebooting" and _passed(a, S7_MEMBER))

        # DC1 installs the replica over WinRM and restarts DC2.
        answer = self._replica_run(dc1, token1)
        if answer.get("ok") is not True or answer.get("status") != "started" or not _passed(answer, S7_INSTALL):
            self._settle_stop(dc1, answer)

        # DC2 is a DC after the promotion's boot, and its read-backs passed.
        # Its own dcdiag waits for the first replication to settle (the
        # helper's DiagMaxSeconds), so the poll waits the promotion's
        # reboot, that wait and the margin of one pass: the last pass may
        # end after the wait it had.
        self._poll_until(
            dc2,
            token2,
            self.clock(),
            lambda a: a.get("status") == "done",
            bound=REBOOT_TIMEOUT_S + S7_DC_DIAG_MAX_S + S7_DC_PASS_MARGIN_S,
        )

        # DC1 reads the replication back.
        answer = self._replica_run(dc1, token1)
        self._settle(dc1, REPLICA_STAGE, token1, answer, self.clock(), bound=READBACK_TIMEOUT_S)
        for one in (dc1, dc2):
            entry = self.state["servers"].get(one)
            if isinstance(entry, dict) and entry.get("stage") == REPLICA_STAGE:
                entry["state"] = "done"
        self.state.pop("replica", None)
        self._save()

    def _replica_run(self, device: str, token: tuple[str, int, int]) -> dict[str, Any]:
        try:
            answer = self._send(device, REPLICA_STAGE, self._request(device, REPLICA_STAGE, "run", token))
        except HelperUnavailable:
            self._receipt(device, REPLICA_STAGE, "run", None, "the session dropped")
            raise _Stop("connection_lost", device, REPLICA_STAGE, "the session of a stage 7 run dropped") from None
        self._receipt(device, REPLICA_STAGE, "run", answer)
        return answer

    def _settle_stop(self, device: str, answer: Mapping[str, Any]) -> None:
        if answer.get("ok") is not True or answer.get("status") in ("stopped", "refused"):
            raise _Stop(str(answer.get("code") or "stopped"), device, REPLICA_STAGE, _failed_check(answer))
        raise _Stop("unexpected_status", device, REPLICA_STAGE, "the helper answered a status the stage 7 sequence does not expect")

    def _poll_until(
        self,
        device: str,
        token: tuple[str, int, int],
        started: float,
        reached: Callable[[Mapping[str, Any]], bool],
        *,
        bound: float = REBOOT_TIMEOUT_S,
    ) -> None:
        """Ask DC2 for its stage 7 status until ``reached``; a server that
        is down is rebooting; a status refused because another request
        holds the journal of the server is not yet; past the bound the run
        stops."""
        deadline = started + bound
        while True:
            if self.clock() >= deadline:
                raise _Stop(
                    "reboot_timeout",
                    device,
                    REPLICA_STAGE,
                    f"the stage did not end within {int(bound // 60)} minutes",
                )
            self.sleep(self.poll_s)
            answer = self._status(device, REPLICA_STAGE, token)
            if answer is None:
                continue
            if _journal_busy(answer):
                # Another request holds the journal of the server: the
                # status is not yet, and the poll goes on.
                continue
            if answer.get("ok") is not True or answer.get("status") in ("stopped", "refused"):
                raise _Stop(str(answer.get("code") or "stopped"), device, REPLICA_STAGE, _failed_check(answer))
            if reached(answer):
                return
            if answer.get("status") in ("rebooting", "started"):
                continue
            raise _Stop("unexpected_status", device, REPLICA_STAGE, "the helper answered a status the stage 7 sequence does not expect")

    def _checkpoints(self, stage: str) -> None:
        """Take, record and verify the checkpoint of ``stage`` on every
        server whose graph holds it and whose journal has not done it."""
        for device, step in build_order(self.built):
            if step != stage:
                continue
            server = self.servers[device]
            journal = self._journal(device)
            if stage in journal.completed:
                continue
            entry = self.state["servers"].get(device)
            if (
                isinstance(entry, dict)
                and entry.get("stage") == stage
                and entry.get("state") == STOPPED_FOR_APPROVAL
                and isinstance(entry.get("checkpoint"), dict)
            ):
                # Taken and verified already: the helper holds one
                # checkpoint per stage per plan, and the owner may be
                # approving this one.
                continue
            kind = _checkpoint.KIND_OF_STAGE.get((server["role"], stage))
            if kind is None:
                raise _Stop("schema", device, stage, "the stage takes no checkpoint on this server")
            held = journal.checkpoints.get(stage)
            if held is not None:
                # The helper already holds this stage's checkpoint under this
                # plan (a runner killed after the helper recorded it and
                # before the run state saved it; F1 of the part C triage):
                # that one is verified again below, and no second one is
                # taken (the helper holds one per stage per plan).
                cp: Any = dict(held)
                self._receipt(device, stage, "checkpoint", None, "the helper's journal holds the stage's checkpoint: verified again, not taken again")
            else:
                cp = self._take_checkpoint(device, stage, server, kind)
            try:
                not_before = journal_not_before(
                    self._completions(device),
                    graph=_plan.stage_graph(self.built, server),
                    stage=stage,
                    plan_nbf=self.approval.get("nbf"),  # type: ignore[arg-type]
                )
            except JournalUnreadable as exc:
                raise _Stop("journal_unreadable", device, stage, str(exc)) from None
            # The DC reads of the real adapters go through this server's
            # helper under its plan token, for this stage (task 8 part B0).
            open_reads = getattr(self.adapters, "open_reads", None)
            close_reads = getattr(self.adapters, "close_reads", None)
            token, nbf, exp = self._plan_token(device)
            try:
                if callable(open_reads):
                    open_reads(
                        device, run=self.state["run"], plan_bytes=self.plan_bytes, token=token, nbf=nbf, exp=exp, stage=stage
                    )
                _checkpoint.require_verified(
                    self.adapters, server, cp, kind, stage=stage, not_before=not_before
                )
            except _checkpoint.CheckpointUnverified as exc:
                raise _Stop(exc.code, device, stage, str(exc)) from None
            finally:
                if callable(close_reads):
                    close_reads(device)
            self.state["servers"][device] = {
                "stage": stage,
                "state": STOPPED_FOR_APPROVAL,
                "checkpoint": {"name": cp["name"], "id": cp["id"]},
                "checkpoint_kind": kind,
            }
            self._save()

    def _take_checkpoint(self, device: str, stage: str, server: Mapping[str, Any], kind: str) -> dict[str, str]:
        """A new checkpoint through the adapter, recorded in the helper's
        journal with its id and name."""
        try:
            cp = self.adapters.checkpoint(server, kind)
        except _checkpoint.CheckpointUnverified as exc:
            raise _Stop(_checkpoint.CHECKPOINT_UNVERIFIED, device, stage, str(exc)) from None
        if not isinstance(cp, dict) or not isinstance(cp.get("id"), str) or not isinstance(cp.get("name"), str):
            raise _Stop(_checkpoint.CHECKPOINT_UNVERIFIED, device, stage, "the adapter answered no checkpoint")
        try:
            request = helper_request(
                run=self.state["run"],
                plan_bytes=self.plan_bytes,
                stage=stage,
                action="checkpoint",
                token=self._plan_token(device)[0],
                nbf=self._plan_token(device)[1],
                exp=self._plan_token(device)[2],
                checkpoint=cp["id"],
                checkpoint_name=cp["name"],
            )
        except ValueError:
            raise _Stop(_checkpoint.CHECKPOINT_UNVERIFIED, device, stage, "the checkpoint id or name is outside its grammar") from None
        try:
            answer = self._send(device, stage, request)
        except HelperUnavailable:
            raise _Stop("connection_lost", device, stage, "the helper did not answer the checkpoint") from None
        self._receipt(device, stage, "checkpoint", answer)
        if answer.get("ok") is not True or answer.get("status") != "checkpointed":
            raise _Stop(str(answer.get("code") or "schema"), device, stage, "the helper did not record the checkpoint")
        return {"name": cp["name"], "id": cp["id"]}

    def _settled_before_run(self, device: str, stage: str, token: tuple[str, int, int]) -> bool:
        """The stage's own status, read before any run of it (PLAN-1.5
        review focus 2).  A runner killed during a stage and started again
        finds it in the journal: ``rebooting`` or ``started`` is polled to
        its end (the helper refuses a second run of a stage in flight),
        ``done`` needs no run, ``pending`` runs.  A resume plan's start
        stage left ``started`` or ``stopped`` by the plan it resumes (or
        whose status the helper leaves to the resume's own run,
        ``plan_mismatch``) runs: the helper decides.  Anything else stops.
        True when the stage needs no run."""
        started = self.clock()
        while True:
            try:
                answer = self._send(device, stage, self._request(device, stage, "status", token))
                break
            except HelperUnavailable:
                if self.clock() >= started + REBOOT_TIMEOUT_S:
                    raise _Stop("connection_lost", device, stage, "the server did not answer the status before the run") from None
                self.sleep(self.poll_s)
        self._receipt(device, stage, "status", answer, "before the run")
        ok = answer.get("ok") is True
        status = answer.get("status")
        if ok and status == "pending":
            return False
        if ok and status == "done":
            return True
        if self.built.get("start_stage") == stage and (
            (ok and status in ("started", "stopped"))
            or (status == "refused" and answer.get("code") == "plan_mismatch")
        ):
            return False
        if ok and status in ("rebooting", "started"):
            self._poll(device, stage, token, started, rebooting=status == "rebooting")
            return True
        if not ok or status in ("stopped", "refused"):
            raise _Stop(str(answer.get("code") or "stopped"), device, stage, _failed_check(answer))
        raise _Stop("unexpected_status", device, stage, "the helper answered a status the run does not expect")

    def _execute(self, device: str, stage: str, token: tuple[str, int, int]) -> None:
        request = self._request(device, stage, "run", token)
        started = self.clock()
        try:
            answer = self._send(device, stage, request)
        except HelperUnavailable:
            self._receipt(device, stage, "run", None, "the session dropped")
            self._after_drop(device, stage, token, started)
            return
        self._receipt(device, stage, "run", answer)
        self._settle(device, stage, token, answer, started)

    def _settle(
        self,
        device: str,
        stage: str,
        token: tuple[str, int, int],
        answer: Mapping[str, Any],
        started: float,
        *,
        bound: float = REBOOT_TIMEOUT_S,
    ) -> None:
        status = answer.get("status")
        if stage == OPS_STAGE and status == "refused" and answer.get("code") in WRITE_HELPER_REFUSALS:
            raise _Stop(str(answer["code"]), device, stage, _write_helper_next_step(device))
        if stage == "0" and answer.get("code") == "dns_unchecked":
            raise _Stop("dns_unchecked", device, stage, _dns_next_step(device))
        if answer.get("ok") is not True or status in ("stopped", "refused"):
            raise _Stop(str(answer.get("code") or "stopped"), device, stage, _failed_check(answer))
        if status == "done":
            return
        if status in ("rebooting", "started"):
            self._poll(device, stage, token, started, rebooting=status == "rebooting", bound=bound)
            return
        raise _Stop("unexpected_status", device, stage, "the helper answered a status the run does not expect")

    def _status(self, device: str, stage: str, token: tuple[str, int, int]) -> dict[str, Any] | None:
        try:
            answer = self._send(device, stage, self._request(device, stage, "status", token))
        except HelperUnavailable:
            return None
        self._receipt(device, stage, "status", answer)
        return answer

    def _poll(
        self,
        device: str,
        stage: str,
        token: tuple[str, int, int],
        started: float,
        *,
        rebooting: bool,
        bound: float = REBOOT_TIMEOUT_S,
    ) -> None:
        deadline = started + bound
        while True:
            if self.clock() >= deadline:
                raise _Stop(
                    "reboot_timeout" if rebooting else "status_timeout",
                    device,
                    stage,
                    f"the stage did not end within {int(bound // 60)} minutes",
                )
            self.sleep(self.poll_s)
            answer = self._status(device, stage, token)
            if answer is None:
                continue
            status = answer.get("status")
            if _journal_busy(answer):
                # Another request holds the journal of the server: the
                # status is not yet, and the poll goes on.
                continue
            if answer.get("ok") is not True or status in ("stopped", "refused"):
                raise _Stop(str(answer.get("code") or "stopped"), device, stage, _failed_check(answer))
            if status == "done":
                return
            if status == "rebooting":
                rebooting = True
                continue
            if status == "started":
                continue
            raise _Stop("unexpected_status", device, stage, "the helper answered a status the run does not expect")

    def _after_drop(self, device: str, stage: str, token: tuple[str, int, int], started: float) -> None:
        """A run request whose session dropped: it may be the stage's own
        reboot.  The status says: a stage that waits for its reboot, or a
        rebooting stage already done after its boot, goes on; anything else
        is ``connection_lost`` (DESIGN-1.5 "Deviation and resume")."""
        deadline = started + REBOOT_TIMEOUT_S
        while True:
            if self.clock() >= deadline:
                raise _Stop("connection_lost", device, stage, "the server did not answer after the session dropped")
            self.sleep(self.poll_s)
            answer = self._status(device, stage, token)
            if answer is None:
                continue
            status = answer.get("status")
            if _journal_busy(answer):
                # Another request holds the journal of the server: the
                # status is not yet, and the poll goes on.
                continue
            if answer.get("ok") is True and status == "rebooting":
                self._poll(device, stage, token, started, rebooting=True)
                return
            if answer.get("ok") is True and status == "done" and stage in REBOOT_STAGES:
                return
            raise _Stop("connection_lost", device, stage, "the session dropped and the stage did not end in rebooting")

    def _acceptance_read(self, device: str) -> tuple[str, list[str], list[str]]:
        """One read of the acceptance, checked: the build account's
        presence, the finding ids and the ids of the checks the audit could
        not prove."""
        if self.acceptance is None:
            raise _Stop("acceptance_unavailable", device, ACCEPTANCE_STAGE, "no newton-audit acceptance is configured")
        try:
            read = self.acceptance(self.built, self.servers[device])
        except Exception as exc:
            raise _Stop("acceptance_unavailable", device, ACCEPTANCE_STAGE, type(exc).__name__) from None
        if not isinstance(read, Mapping):
            raise _Stop("acceptance_unavailable", device, ACCEPTANCE_STAGE, "the acceptance answered nothing")
        account = read.get("build_account")
        findings = read.get("findings")
        unknown = read.get("unknown")
        if account not in ("absent", "present") or not isinstance(findings, list) or not isinstance(unknown, list):
            raise _Stop("acceptance_unavailable", device, ACCEPTANCE_STAGE, "the acceptance answer is not one")
        lists: list[list[str]] = []
        for values in (findings, unknown):
            ids: list[str] = []
            for finding in values:
                if not isinstance(finding, str) or _plan.FINDING_ID_RE.fullmatch(finding) is None:
                    raise _Stop("acceptance_unavailable", device, ACCEPTANCE_STAGE, "a finding id is outside its grammar")
                ids.append(finding)
            lists.append(sorted(set(ids)))
        self._receipt(
            device,
            ACCEPTANCE_STAGE,
            "acceptance",
            None,
            f"build account {account}; findings {','.join(lists[0])}; unknown {','.join(lists[1])}",
        )
        return str(account), lists[0], lists[1]

    def _accept(self, device: str) -> None:
        """Stage 10: through the read-only newton-audit login (the maintainer's decision
        R2), the build account is gone and the 1.3 audit has no finding, and
        no check it could not prove, outside the plan's accepted list.

        While the account is still there the read is made again, every poll,
        for ``ACCEPTANCE_WAIT_S``: DC1's cleanup task deletes it after its
        own wait.  The read that finds it gone is the evidence that
        stage 9's cleanups ran to their last step, and only then is stage 9
        reported done."""
        deadline = self.clock() + ACCEPTANCE_WAIT_S
        while True:
            account, findings, unknown = self._acceptance_read(device)
            if account == "absent":
                break
            if self.clock() >= deadline:
                raise _Stop("build_account_remains", device, ACCEPTANCE_STAGE, "newton-build is still in the directory")
            self.sleep(self.poll_s)
        cleanup = self.state.setdefault("cleanup", {})
        for server in self.built["servers"]:
            one = server["device"]
            if CLEANUP_STAGE in _plan.stage_graph(self.built, server):
                cleanup[one] = "confirmed"
                self._saw_done(one, CLEANUP_STAGE)
        self._save()
        accepted = {finding["id"] for finding in self.built["accepted_findings"]}
        outside = sorted(set(findings) - accepted)
        if outside:
            raise _Stop("finding_outside_accepted", device, ACCEPTANCE_STAGE, ",".join(outside))
        unproved = sorted(set(unknown) - accepted)
        if unproved:
            raise _Stop("unknown_outside_accepted", device, ACCEPTANCE_STAGE, ",".join(unproved))


def _passed(answer: Mapping[str, Any], name: str) -> bool:
    """True when the answer holds the check ``name`` and it passed."""
    return any(
        isinstance(check, dict) and check.get("name") == name and check.get("ok") is True
        for check in answer.get("checks", []) or []
    )


#: The stop of a stage 7 that began and did not end (DESIGN-1.5, open
#: point 38 of task 8): Newton never resumes it, a resume plan included.
_INTERRUPTED_7 = (
    "stage 7 began and did not end, past a provision DC2 never joined (the one a resume plan at 7 may "
    "provision again); Newton does not go on with it: the owner decides (roll both servers back to their "
    "stage 7 checkpoints, or finish by hand)"
)


def _failed_check(answer: Mapping[str, Any]) -> str:
    for check in answer.get("checks", []) or []:
        if isinstance(check, dict) and check.get("ok") is False:
            return str(check.get("name", ""))
    return ""


def run_build(
    plan_id: str,
    *,
    transport: HelperTransport | None = None,
    adapters: Any = None,
    acceptance: Acceptance | None = None,
    clock: Callable[[], float] = _now_utc,
    sleep: Callable[[float], None] = time.sleep,
    poll_s: float = POLL_S,
) -> dict[str, Any]:
    """Drive the build of one approved plan until it is done, stops for
    an approval or stops on a deviation; return the run state.

    Without a transport or adapters the owner's build config gives them
    (``config.load_config``), and the stage 10 acceptance of its
    newton-audit login when the caller passes none (the MCP tool passes
    none); a config that cannot be read stops nothing because nothing is
    sent: the answer says why.

    One build at a time per state directory: the lock of the state
    directory is taken before the runner is built and held until the run
    ends, so two runs of the same servers never overlap (a resume plan is
    another plan id for the same servers).  A run that finds the lock held
    stops ``run_in_progress`` and sends nothing.  A state directory that
    cannot be written stops ``run_lock_unavailable`` and sends nothing:
    the run state could not be saved there.
    """
    if not isinstance(plan_id, str) or _approve.PLAN_ID_RE.fullmatch(plan_id) is None:
        return {"state": STOPPED, "reason": "schema", "detail": "the plan id is not 32 lowercase hexadecimal characters"}
    if transport is None or adapters is None:
        from . import config as _config

        try:
            loaded = _config.load_config()
        except _config.BuildConfigError as exc:
            return {"plan_id": plan_id, "state": STOPPED, "reason": "no_build_config", "detail": str(exc)}
        transport = transport or _config.build_transport(loaded)
        adapters = adapters or _config.build_adapters(loaded, transport=transport)
        if acceptance is None:
            acceptance = _config.build_acceptance(loaded)
    # kiss: one build at a time per state directory; a lock per server set if parallel builds matter
    try:
        directory = _approve.build_plan_dir()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not os.access(str(directory), os.W_OK | os.X_OK):
            # the lock file of a directory that cannot be written opens and
            # locks all the same, but the run state could not be saved
            # there: refuse before anything goes out
            raise OSError("the state directory is not writable and searchable")
        lock = os.open(
            str(directory / ".run.lock"),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except OSError:
        return {
            "plan_id": plan_id,
            "state": STOPPED,
            "reason": "run_lock_unavailable",
            "detail": "the run lock of the state directory could not be opened or locked, so nothing was sent",
        }
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        return {
            "plan_id": plan_id,
            "state": STOPPED,
            "reason": "run_in_progress",
            "detail": "another build run is active: nothing was sent, read newton_ad_build_status and call again",
        }
    except OSError:
        os.close(lock)
        return {
            "plan_id": plan_id,
            "state": STOPPED,
            "reason": "run_lock_unavailable",
            "detail": "the run lock of the state directory could not be opened or locked, so nothing was sent",
        }
    try:
        try:
            runner = _Runner(
                plan_id,
                transport=transport,
                adapters=adapters,
                acceptance=acceptance,
                clock=clock,
                sleep=sleep,
                poll_s=poll_s,
            )
        except _approve.ApprovalRefused as exc:
            return {"plan_id": plan_id, "state": STOPPED, "reason": "plan_mismatch", "detail": str(exc)}
        return runner.run()
    finally:
        os.close(lock)


def run_status(plan_id: str) -> dict[str, Any]:
    """The run state on record, as the runner last wrote it."""
    if not isinstance(plan_id, str) or _approve.PLAN_ID_RE.fullmatch(plan_id) is None:
        return {"state": STOPPED, "reason": "schema", "detail": "the plan id is not 32 lowercase hexadecimal characters"}
    try:
        return _approve._load_build_run_state(plan_id)
    except _approve.ApprovalRefused:
        return {"plan_id": plan_id, "state": "not_started", "reason": "", "detail": ""}


__all__: Sequence[str] = ("run_build", "run_status", "build_order", "REBOOT_TIMEOUT_S")
