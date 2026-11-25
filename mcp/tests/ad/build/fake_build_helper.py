"""A fake of the build helper and its transport (PLAN-1.5 task 8 tests).

The fake answers the way ``build.ps1`` answers with a fake stage table
(the task 3 contract): the exact request fields, the token over the plan
digest or over the stage digest of the journal's checkpoint, the graph
order, ``already_done``, the reboot stages that answer ``rebooting`` and
finish on a status after the boot, the status answer's ``completed``, and
the ``checkpoint`` action that records the id the request names.  One
test in ``test_build_run.py`` drives the same run through the real helper
under pwsh, so the fake cannot drift from it unseen.

Every request is recorded, as sent, so a test can grep every byte the
runner sent.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from newton_mcp.ad import setupgen_write
from newton_mcp.ad.build import plan
from newton_mcp.ad.build.transport import HelperUnavailable

_FIELDS = {"run", "plan", "stage", "action", "token", "nbf", "exp"}

#: The offline domain join blob DC1's provision answers in the fake: the
#: measured file is UTF-16LE with a byte order mark, 6532 bytes
#: (MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2").
FAKE_ODJ = base64.b64encode(b"\xff\xfe" + "ODJ-FAKE-MACHINE-SECRET-0123456789".encode("utf-16-le") * 40).decode("ascii")


class Clock:
    """A fake clock: ``sleep`` moves it on."""

    def __init__(self, now: float) -> None:
        self.now = float(now)
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _answer(ok: bool, status: str, code: str = "", checks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"ok": ok, "status": status, "code": code, "checks": list(checks or [])}


class FakeHelper:
    """The helper of one server."""

    def __init__(
        self,
        built: Mapping[str, Any],
        device: str,
        key_hex: str,
        clock: Clock,
        *,
        reboot_stages: tuple[str, ...] = ("1", "2", "4", "7"),
        boot_s: float = 120.0,
    ) -> None:
        self.built = built
        self.device = device
        self.key_hex = key_hex
        self.clock = clock
        self.reboot_stages = set(reboot_stages)
        self.boot_s = boot_s
        server = next(s for s in built["servers"] if s["device"] == device)
        self.graph = list(plan.stage_graph(built, server))
        self.journal: list[dict[str, Any]] = []
        # the plans this helper is shown (a resume plan is a new plan of
        # the same run): by digest
        self.plans: dict[str, Mapping[str, Any]] = {plan.digest(built): built}
        self.down_until = 0.0
        self.gone = False
        # what a test makes go wrong
        self.drop_run: set[str] = set()       # the session drops after the run's entries
        self.drop_no_reboot: set[str] = set()  # ... and the stage did not reboot (left started)
        self.never_boots: set[str] = set()
        self.hang_stages: set[str] = set()  # a run answered started that never ends
        self.read_s = 0.0  # DC1's stage 7 read-back answers started and ends this long after
        self.read_until = 0.0
        self.reprovisions = 0  # a resume plan's provisions with /reuse
        self.stop_stage: dict[str, str] = {}
        self.checkpoints_seen: list[str] = []
        # stage 7, option B: DC1's helper names DC2's (``peer``)
        self.peer: FakeHelper | None = None
        self.odj = FAKE_ODJ
        self.expect_odj = ""
        self.member = False
        self.promoted = False
        self.never_member = False
        self.replica_stop: dict[str, str] = {}  # phase -> code
        self.odj_missing = False
        self.no_check: set[str] = set()  # phases whose answer holds no check
        self.join_answer = ""  # a join answered with this status, no reboot
        # the next status answers of this helper are refused
        # ``journal_busy``: another request holds the journal of the server
        # (the helper's lock, the lab run of 2026-11-23)
        self.busy_statuses = 0
        self.busy_stage = ""  # the stage those answers are of (any: "")
        # DC2's own read (s7-dc) answers done this long after the promotion
        self.dc_s = 0.0
        self.dc_until = 0.0
        # DC2's own read runs in its SYSTEM task: while it runs the status
        # answers in flight (started), not rebooting
        self.dc_in_flight = False
        # stage 8: the run answers started while sshd restarts; a status
        # this long after the run reads stage 8 back and ends it
        self.ops_s = 0.0
        self.ops_until = 0.0
        self.ops_read_stop = ""  # the read-back of stage 8 stops with this code
        # the write helper DC1's bootstrap installed (None: no file)
        self.installed_write_helper: bytes | None = setupgen_write.WRITE_HELPER_PATH.read_bytes()

    # -- the journal -------------------------------------------------------

    def _entry(self, stage: str, state: str, digest: str, checkpoint: str = "") -> None:
        self.journal.append(
            {"stage": stage, "state": state, "digest": digest, "checkpoint": checkpoint, "time": int(self.clock())}
        )

    def _state(self, stage: str) -> str:
        state = ""
        for entry in self.journal:
            if entry["stage"] == stage and entry["state"] != "checkpointed":
                state = entry["state"]
        return state

    def _checkpoint_id(self, stage: str, digest: str) -> str:
        ident = ""
        for entry in self.journal:
            if entry["state"] == "checkpointed" and entry["stage"] == stage and entry["digest"] == digest:
                ident = entry["checkpoint"]
        return ident

    def _next(self) -> str:
        for stage in self.graph:
            if self._state(stage) != "done":
                return stage
        return ""

    def know(self, built: Mapping[str, Any]) -> None:
        """Show the helper another plan (a resume plan of the run)."""
        self.plans[plan.digest(built)] = built

    def _journal_digest(self) -> str:
        digest = ""
        for entry in self.journal:
            if entry["state"] != "checkpointed" and entry["digest"]:
                digest = entry["digest"]
        return digest

    def _plan_of_run(self, built: Mapping[str, Any], digest: str) -> dict[str, Any] | None:
        """``Assert-NewtonPlanOfRun``: the plan of the request against the
        plan of the run, unless it resumes the run (its ``resume_from`` the
        journal's digest, its ``start_stage`` the next stage, not in
        flight)."""
        journal = self._journal_digest()
        if not journal or journal == digest:
            return None
        if built.get("resume_from") != journal or built.get("start_stage") != self._next():
            return _answer(False, "refused", "plan_mismatch")
        if self._state(str(built["start_stage"])) not in ("", "stopped", "started"):
            return _answer(False, "refused", "out_of_order")
        return None

    def held(self, digest: str) -> dict[str, dict[str, str]]:
        """Each stage's checkpoint of the plan of this digest (the newest),
        as the status answer names it."""
        out: dict[str, dict[str, str]] = {}
        for entry in self.journal:
            if entry["state"] == "checkpointed" and entry["digest"] == digest:
                out[entry["stage"]] = {"id": entry["checkpoint"], "name": entry.get("checkpoint_name", "")}
        return out

    def completed(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for stage in self.graph:
            for entry in self.journal:
                if entry["stage"] == stage and entry["state"] == "done":
                    out[stage] = entry["time"]
        return out

    # -- one request -------------------------------------------------------

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if self.gone or self.clock() < self.down_until:
            raise HelperUnavailable("the build helper did not answer")
        fields = set(request)
        # build.ps1: no request carries the write helper (the bootstrap
        # installed it; the maintainer's decision of 2026-11-19)
        if fields not in (_FIELDS, _FIELDS | {"checkpoint"}, _FIELDS | {"checkpoint", "checkpoint_name"}, _FIELDS | {"odj"}):
            return _answer(False, "refused", "schema")
        action = request["action"]
        stage = request["stage"]
        if (
            action == "status"
            and self.busy_statuses > 0
            and (not self.busy_stage or stage == self.busy_stage)
        ):
            # Another request holds the journal of the server: the status is
            # refused, and nothing is written.
            self.busy_statuses -= 1
            return _answer(False, "refused", "journal_busy")
        if "checkpoint" in request and action != "checkpoint":
            return _answer(False, "refused", "schema")
        if "odj" in request and (action != "run" or request["stage"] != "7" or not self._replica_dc2()):
            return _answer(False, "refused", "schema")
        plan_bytes = base64.b64decode(request["plan"])
        built = next((b for b in self.plans.values() if plan.canonical_bytes(b) == plan_bytes), None)
        if built is None:
            return _answer(False, "refused", "plan_mismatch")
        digest = plan.digest(built)
        if stage not in self.graph:
            return _answer(False, "refused", "out_of_order")
        kind = plan.STAGE_KINDS[stage]
        token_digest = digest
        if action != "checkpoint" and kind == "irreversible":
            ident = self._checkpoint_id(stage, digest)
            if not ident:
                return self._plan_of_run(built, digest) or _answer(False, "refused", "schema")
            token_digest = plan.stage_digest(digest, stage, ident)
        expected = plan.plan_token(self.key_hex, token_digest, request["nbf"], request["exp"])
        if not hmac.compare_digest(expected, request["token"]):
            return _answer(False, "refused", "bad_token")
        refused = self._plan_of_run(built, digest)
        if refused is not None:
            return refused
        now = self.clock()
        limit = request["exp"]
        if action == "status" and self._state(stage) == "rebooting":
            limit += 900
        recording = (action == "status" and stage == "7" and self._state(stage) == "started"
                     and (self._last7() or {}).get("phase") in ("s7_read", "s7_dc"))
        if recording:
            # build.ps1: a status that records a stage left started has the
            # grace, and past it still records (-PastBound).
            limit = float("inf")
        if now > limit or now < request["nbf"]:
            return _answer(False, "refused", "expired")
        if action == "checkpoint":
            return self._checkpoint(request, stage, digest)
        if action == "status":
            answer = self._status(stage, digest)
            answer["completed"] = self.completed()
            answer["checkpoints"] = self.held(digest)
            return answer
        if stage == "7" and self._replica_dc2():
            return self._run7_dc2(request, digest)
        if stage == "7" and self.peer is not None:
            return self._run7_dc1(digest)
        if stage == "8":
            return self._run8(request, built, digest)
        return self._run(stage, digest)

    # -- stage 8 -------------------------------------------------------------

    def _run8(self, request: Mapping[str, Any], built: Mapping[str, Any], digest: str) -> dict[str, Any]:
        """build.ps1 Invoke-NewtonOpsRun: the installed write helper must be
        there and hash to the plan's, then both setups run and the sshd
        restart is registered; the stage stays started until a status reads
        it back."""
        helper = self.installed_write_helper
        if helper is None:
            return _answer(False, "refused", "write_helper_missing")
        if hashlib.sha256(helper).hexdigest() != built["ops"]["write_helper_sha256"]:
            return _answer(False, "refused", "write_helper_mismatch")
        state = self._state("8")
        if state == "done":
            return _answer(False, "refused", "already_done")
        if state in ("started", "stopped") and self._journal_digest() == digest:
            return _answer(False, "refused", "out_of_order")
        if self._next() != "8":
            return _answer(False, "refused", "out_of_order")
        self._entry("8", "started", digest)
        self.ops_until = self.clock() + self.ops_s
        if "8" in self.drop_run:
            raise HelperUnavailable("the build helper did not answer")
        return _answer(True, "started", "", [{"name": "s8-restart", "ok": True, "detail": "registered"}])

    def _status8(self, digest: str) -> dict[str, Any]:
        if self.clock() < self.ops_until:
            return _answer(True, "started")
        if self.ops_read_stop:
            self._entry("8", "stopped", digest)
            return _answer(False, "stopped", self.ops_read_stop, [{"name": "ops_delegation", "ok": False, "detail": "x"}])
        self._entry("8", "done", digest)
        return _answer(True, "done", "", [{"name": "ops_delegation", "ok": True, "detail": "2 objects"}])

    # -- stage 7, option B -------------------------------------------------

    def _replica_dc2(self) -> bool:
        server = next(s for s in self.built["servers"] if s["device"] == self.device)
        return server["role"] == "dc2"

    def _last7(self) -> dict[str, Any] | None:
        last = None
        for entry in self.journal:
            if entry["stage"] == "7" and entry["state"] != "checkpointed":
                last = entry
        return last

    def _entry7(self, state: str, digest: str, phase: str) -> None:
        self._entry("7", state, digest, self._checkpoint_id("7", digest))
        self.journal[-1]["phase"] = phase

    def _run7_dc1(self, digest: str) -> dict[str, Any]:
        """DC1's three runs: the provision (the blob in the answer), the
        install over WinRM (DC2 restarts), the read-backs."""
        assert self.peer is not None
        last = self._last7()
        if self._next() != "7":
            return _answer(False, "refused", "out_of_order")
        phase = "" if last is None else f"{last['state']}:{last.get('phase', '')}"
        if last is not None and last["digest"] != digest:
            # A resume plan (build.ps1 Invoke-NewtonReplicaRun): a provision
            # again with /reuse over a stage 7 whose last phase is the
            # provision's; any later phase is refused.
            if phase not in ("started:s7_provision", "stopped:s7_provision"):
                return _answer(False, "refused", "out_of_order")
            self.reprovisions += 1
            phase = ""
        if phase == "":
            self._entry7("started", digest, "s7_provision")
            if "provision" in self.replica_stop:
                self._entry7("stopped", digest, "s7_provision")
                return _answer(False, "stopped", self.replica_stop["provision"], [{"name": "s7_provision", "ok": False, "detail": "x"}])
            self.peer.expect_odj = self.odj
            answer = _answer(True, "started", "", [] if "provision" in self.no_check else [{"name": "s7_provision", "ok": True, "detail": "BDC2"}])
            if not self.odj_missing:
                answer["odj"] = self.odj
            return answer
        if phase == "started:s7_provision":
            if not self.peer.member or "install" in self.replica_stop:
                self._entry7("stopped", digest, "s7_install")
                return _answer(False, "stopped", self.replica_stop.get("install", "readback_failed"), [{"name": "s7_install", "ok": False, "detail": "x"}])
            self._entry7("started", digest, "s7_install")
            self.peer.promoted = True
            self.peer.dc_until = self.clock() + self.peer.dc_s
            self.peer.down_until = self.clock() + self.peer.boot_s
            return _answer(True, "started", "", [] if "install" in self.no_check else [{"name": "s7_install", "ok": True, "detail": "Success"}])
        if phase == "started:s7_install":
            if self.peer._state("7") != "done" or "read" in self.replica_stop:
                self._entry7("stopped", digest, "s7_read")
                return _answer(False, "stopped", self.replica_stop.get("read", "readback_failed"), [{"name": "s7_read", "ok": False, "detail": "x"}])
            if self.read_s:
                self._entry7("started", digest, "s7_read")
                self.read_until = self.clock() + self.read_s
                return _answer(True, "started", "", [{"name": "s7-read", "ok": True, "detail": "the password task of the stage still runs"}])
            self._entry7("done", digest, "s7_read")
            return _answer(True, "done", "", [{"name": "s7_read", "ok": True, "detail": "0 failures"}])
        return _answer(False, "refused", "out_of_order")

    def _run7_dc2(self, request: Mapping[str, Any], digest: str) -> dict[str, Any]:
        """DC2's run: the join with the blob, then the reboot."""
        if self._state("7"):
            return _answer(False, "refused", "out_of_order")
        if self._next() != "7":
            return _answer(False, "refused", "out_of_order")
        if "odj" not in request:
            return _answer(False, "refused", "schema")
        self._entry7("started", digest, "s7_join")
        if request["odj"] != self.expect_odj or "join" in self.replica_stop:
            self._entry7("stopped", digest, "s7_join")
            return _answer(False, "stopped", self.replica_stop.get("join", "op_failed"), [{"name": "s7_join", "ok": False, "detail": "x"}])
        self.expect_odj = ""
        if self.join_answer:
            return _answer(True, self.join_answer, "", [{"name": "s7_join", "ok": True, "detail": "joined"}])
        self._entry7("rebooting", digest, "s7_join")
        self.down_until = self.clock() + self.boot_s
        if "7" in self.drop_run:
            raise HelperUnavailable("the build helper did not answer")
        return _answer(True, "rebooting", "", [{"name": "s7_join", "ok": True, "detail": "joined"}])

    def _status7_dc2(self, digest: str) -> dict[str, Any]:
        last = self._last7()
        assert last is not None
        if last.get("phase") == "s7_join":
            if self.never_member:
                return _answer(True, "rebooting")
            self.member = True
            self._entry7("rebooting", digest, "s7_member")
            return _answer(True, "rebooting", "", [{"name": "s7_member", "ok": True, "detail": "member"}])
        if not self.promoted:
            return _answer(True, "rebooting", "", [{"name": "s7_member", "ok": True, "detail": "member"}])
        if "promoted" in self.replica_stop:
            self._entry7("stopped", digest, "s7_dc")
            return _answer(False, "stopped", self.replica_stop["promoted"], [{"name": "s7_dc", "ok": False, "detail": "x"}])
        if self.dc_until and self.clock() < self.dc_until:
            # DC2's own dcdiag still waits for the first replication to settle.
            # The op runs in its SYSTEM task: while it runs the helper answers
            # the stage in flight (started), not rebooting.
            return _answer(True, "started" if self.dc_in_flight else "rebooting")
        self._entry7("done", digest, "s7_dc")
        return _answer(True, "done", "", [{"name": "s7_dc", "ok": True, "detail": "dc"}])

    def _checkpoint(self, request: Mapping[str, Any], stage: str, digest: str) -> dict[str, Any]:
        if plan.STAGE_KINDS[stage] != "irreversible" or self._next() != stage:
            return _answer(False, "refused", "out_of_order")
        if self._checkpoint_id(stage, digest):
            return _answer(False, "refused", "out_of_order")
        ident = request.get("checkpoint") or f"fake-cp-{stage}-{len(self.journal)}"
        self.checkpoints_seen.append(ident)
        self._entry(stage, "checkpointed", digest, ident)
        self.journal[-1]["checkpoint_name"] = request.get("checkpoint_name") or f"fake-{stage}"
        return _answer(True, "checkpointed", "", [{"name": "checkpoint", "ok": True, "detail": ident}])

    def _run(self, stage: str, digest: str) -> dict[str, Any]:
        state = self._state(stage)
        if state == "done":
            return _answer(False, "refused", "already_done")
        if state in ("started", "rebooting", "stopped") and self._journal_digest() == digest:
            return _answer(False, "refused", "out_of_order")
        if self._next() != stage:
            return _answer(False, "refused", "out_of_order")
        ident = self._checkpoint_id(stage, digest)
        self._entry(stage, "started", digest, ident)
        if stage in self.stop_stage:
            self._entry(stage, "stopped", digest, ident)
            return _answer(False, "stopped", self.stop_stage[stage], [{"name": "op", "ok": False, "detail": "x"}])
        if stage in self.drop_no_reboot:
            raise HelperUnavailable("the build helper did not answer")
        if stage in self.hang_stages:
            return _answer(True, "started")
        if stage in self.reboot_stages:
            self._entry(stage, "rebooting", digest, ident)
            self.down_until = self.clock() + (10**9 if stage in self.never_boots else self.boot_s)
            if stage in self.drop_run:
                raise HelperUnavailable("the build helper did not answer")
            return _answer(True, "rebooting")
        self._entry(stage, "done", digest, ident)
        if stage == "9":
            self.gone = True
        if stage in self.drop_run:
            raise HelperUnavailable("the build helper did not answer")
        return _answer(True, "done")

    def _status(self, stage: str, digest: str) -> dict[str, Any]:
        state = self._state(stage)
        if state == "started" and stage == "8":
            return self._status8(digest)
        if state == "rebooting" and stage == "7" and self._replica_dc2():
            return self._status7_dc2(digest)
        if state == "started" and stage == "7" and self.read_until and (self._last7() or {}).get("phase") == "s7_read":
            if self.clock() < self.read_until:
                return _answer(True, "started")
            self._entry7("done", digest, "s7_read")
            return _answer(True, "done", "", [{"name": "s7_read", "ok": True, "detail": "0 failures"}])
        if state == "rebooting":
            self._entry(stage, "done", digest, self._checkpoint_id(stage, digest))
            return _answer(True, "done")
        return _answer(True, {"": "pending", "started": "started", "done": "done", "stopped": "stopped"}[state])


class FakeTransport:
    """The transport of a run: every request recorded as sent."""

    def __init__(self, helpers: Mapping[str, FakeHelper]) -> None:
        self.helpers = dict(helpers)
        self.requests: list[tuple[str, dict[str, Any]]] = []
        roles = {
            next(s["role"] for s in h.built["servers"] if s["device"] == d): h for d, h in self.helpers.items()
        }
        if "dc1" in roles and "dc2" in roles:
            roles["dc1"].peer = roles["dc2"]

    def send(self, device: str, request: Mapping[str, Any]) -> dict[str, Any]:
        self.requests.append((device, copy.deepcopy(dict(request))))
        return self.helpers[device].handle(request)

    def actions(self, device: str | None = None) -> list[tuple[str, str, str]]:
        return [
            (d, r["stage"], r["action"])
            for d, r in self.requests
            if device is None or d == device
        ]
