"""The transport to the build helper (PLAN-1.5 task 8; DESIGN-1.5 "The
helper", "Checkpoints").

One ssh session per request, as for the 1.4 write helper
(``newton_mcp.ad.write.transport``): the request is one JSON object on
stdin, the session carries no remote command (the forced command of the
bootstrap's ``newton-build`` login is the helper), and the answer is one
JSON object ``{ok, status, code, checks}``; a status answer also carries
``completed``, each stage's recorded completion from the helper's own
journal.

The session is the locked runner of the repository (``SshSessionRunner``):
argv lists only, ``BatchMode=yes``, ``StrictHostKeyChecking=yes`` against
the owner's pinned ``known_hosts`` file, no agent, no forwarding.  Nothing
here builds a shell string, and no request holds a domain credential: the
plan bytes, the stage, the action, a token and its window, and for a
checkpoint request the id of a hypervisor checkpoint.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ...adapters.vendor_ssh import SshSessionRunner
from ...adapters.vendor_write import SessionSpec
from ...vendor_change import RunOut
from . import plan as _plan
from .checkpoint import CheckpointUnverified, JournalBusy, ShowbackupRead, WbadminRead

#: The local account of the bootstrap that runs the helper
#: (``bootstrap.BUILD_USER``).
BUILD_USER = "newton-build"

#: The platform whose sshd runs a forced command that reads its request on
#: stdin (``adapters.vendor_ssh.FORCED_COMMAND_STDIN_PLATFORMS``).
HELPER_PLATFORM = "ad-windows-write"

#: The biggest answer the transport reads.
STDOUT_CAP = 256 * 1024

#: How long one session may take: the helper waits at most 10 minutes for
#: a password task (DESIGN-1.5 "The build account after promotion"), plus
#: room for the session itself.
TIMEOUT_S = 720

#: The biggest request the helper reads (``build.ps1`` MaxRequestBytes).
MAX_REQUEST_BYTES = 1048576

#: The actions of a request.
ACTIONS: tuple[str, ...] = ("run", "status", "checkpoint", "read")

#: The DC reads of a checkpoint verify (PLAN-1.5 task 8 part B0):
#: ``msDS-GenerationId`` (the ``s2-genid`` line), ``repadmin /showbackup``
#: and ``wbadmin get versions``.
READS: tuple[str, ...] = ("genid", "showbackup", "versions")

#: A computer name a read may answer: the plan's hostname grammar.
COMPUTER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?")

#: The statuses the helper answers with.
STATUSES: tuple[str, ...] = (
    "pending",
    "started",
    "rebooting",
    "done",
    "stopped",
    "checkpointed",
    "refused",
)

#: The range of a UTC second the helper takes (``build.ps1`` EpochMin and
#: EpochMax).
EPOCH_MIN = 1000000000
EPOCH_MAX = 9999999999

#: A run id: 32 lowercase hexadecimal characters (``build.ps1`` RunPattern).
RUN_RE = re.compile(r"[0-9a-f]{32}")

_ANSWER_FIELDS = frozenset({"ok", "status", "code", "checks"})
_STATUS_FIELDS = _ANSWER_FIELDS | {"completed", "checkpoints"}
_READ_FIELDS = _ANSWER_FIELDS | {"read"}
_READ_ANSWER_FIELDS = frozenset({"name", "computer", "utc_offset_minutes", "text"})
_RUN_FIELDS = _ANSWER_FIELDS | {"odj"}

#: The offline domain join blob of stage 7 (option B): DC1's helper
#: answers it from ``djoin /provision`` and the runner carries it to DC2's
#: stage 7 run, in memory only.  It is the base64 of the blob file's bytes
#: (measured: 6532 bytes, UTF-16LE, 8712 base64 characters; MEASURED-1.5
#: "Stage 7 on BUILD1 and BUILD2, 2026-11-15"); the bound leaves it room.
ODJ_MAX_CHARS = 32768
ODJ_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)")

#: The stage whose run requests and answers carry the blob.
ODJ_STAGE = "7"


#: No request carries the 1.4 write helper: DC1's bootstrap installs it
#: and DC1's helper checks its sha256 against the plan at stage 8 (the maintainer's
#: decision of 2026-11-19 on the stage 8 transport; DESIGN-1.5 open point
#: 78).  Measured on BUILD1, 2026-11-18: Windows PowerShell 5.1 under the
#: server's OpenSSH hangs reading stdin past 70 001 to 80 001 bytes.


def valid_odj(value: Any) -> bool:
    """True for a blob in its grammar: padded base64, at most the bound."""
    return isinstance(value, str) and 0 < len(value) <= ODJ_MAX_CHARS and ODJ_RE.fullmatch(value) is not None
_CHECK_FIELDS = frozenset({"name", "ok", "detail"})


class HelperUnavailable(Exception):
    """The session ended without one answer of the helper: the server was
    unreachable, it dropped the session (a reboot, a lost link) or the
    session timed out.  The message is fixed and holds no device text."""


class HelperAnswerInvalid(Exception):
    """The helper answered something that is not an answer of the contract.
    The message is fixed and holds no device text."""


class JournalUnreadable(Exception):
    """The helper's journal could not give the bound a checkpoint needs:
    the read failed, it was refused, the previous stage has no recorded
    completion, or its time is not a UTC second.  The message is fixed per
    reason and holds no device text.

    ``code`` says why a read of the journal failed, in fixed words:
    ``unavailable`` (the server did not answer: it may be rebooting),
    ``plan_mismatch`` (the helper refused the plan of the request: another
    plan's journal, or a resume plan whose ``start_stage`` is not this
    server's next stage), ``expired`` (the token's window is over),
    ``refused`` (any other refusal), or empty."""

    def __init__(self, message: str, *, code: str = "") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class HelperTarget:
    """The ``newton-build`` login of one server, as the owner's build
    config names it.  It has the fields ``SshSessionRunner`` reads.

    The key and the pinned host key are files; nothing here is a secret.
    """

    name: str
    host: str
    port: int
    key_file: Path
    known_hosts: Path
    user: str = BUILD_USER
    platform: str = HELPER_PLATFORM
    auth: str = "key"
    password_file: Path | None = None
    proxy_command: str | None = None


class HelperTransport(Protocol):
    """What sends one request to the helper of one server."""

    def send(self, device: str, request: Mapping[str, Any]) -> dict[str, Any]: ...


def helper_request(
    *,
    run: str,
    plan_bytes: bytes,
    stage: str,
    action: str,
    token: str,
    nbf: int,
    exp: int,
    checkpoint: str | None = None,
    read: str | None = None,
    odj: str | None = None,
    checkpoint_name: str | None = None,
) -> dict[str, Any]:
    """One request of the contract (PLAN-1.5 task 3), checked here so a
    request the helper would refuse ``schema`` is never sent.

    A checkpoint request that names a hypervisor checkpoint's id also names
    its name (``checkpoint_name``), so the helper's journal holds what a
    restarted runner needs to verify that checkpoint again instead of
    taking a second one (F1 of the part C triage)."""
    if not isinstance(run, str) or RUN_RE.fullmatch(run) is None:
        raise ValueError("the run id is not 32 lowercase hexadecimal characters")
    if not isinstance(plan_bytes, bytes) or not plan_bytes:
        raise ValueError("the plan bytes are not bytes")
    if stage not in _plan.STAGE_IDS:
        raise ValueError("the stage is not a stage of the design")
    if action not in ACTIONS:
        raise ValueError("the action is not one of the actions")
    if not isinstance(token, str) or _plan.DIGEST_RE.fullmatch(token) is None:
        raise ValueError("the token is not 64 lowercase hexadecimal characters")
    for value in (nbf, exp):
        if isinstance(value, bool) or not isinstance(value, int) or not EPOCH_MIN <= value <= EPOCH_MAX:
            raise ValueError("the window of the token is not a UTC second")
    if exp <= nbf:
        raise ValueError("the window of the token does not move forward")
    request: dict[str, Any] = {
        "run": run,
        "plan": base64.b64encode(plan_bytes).decode("ascii"),
        "stage": stage,
        "action": action,
        "token": token,
        "nbf": nbf,
        "exp": exp,
    }
    if checkpoint is not None:
        if action != "checkpoint":
            raise ValueError("only a checkpoint request names a checkpoint")
        if not isinstance(checkpoint, str) or _plan.CHECKPOINT_ID_RE.fullmatch(checkpoint) is None:
            raise ValueError("the checkpoint id is outside its grammar")
        request["checkpoint"] = checkpoint
    if checkpoint_name is not None:
        if checkpoint is None:
            raise ValueError("only a request that names a checkpoint names its name")
        if not isinstance(checkpoint_name, str) or _plan.CHECKPOINT_ID_RE.fullmatch(checkpoint_name) is None:
            raise ValueError("the checkpoint name is outside its grammar")
        request["checkpoint_name"] = checkpoint_name
    if (read is not None or action == "read") and (read not in READS or action != "read" or checkpoint is not None):
        raise ValueError("only a read request names a read, one of the reads, and no checkpoint")
    if read is not None:
        request["read"] = read
    if odj is not None:
        if action != "run" or stage != ODJ_STAGE:
            raise ValueError("only a stage 7 run request carries the offline domain join blob")
        if not valid_odj(odj):
            raise ValueError("the offline domain join blob is outside its grammar")
        request["odj"] = odj
    return request


def parse_answer(text: str, *, action: str) -> dict[str, Any]:
    """The one answer of the helper, checked against the contract.

    A check's ``detail`` is device text: it is kept as text, and the
    caller wraps it before it reaches a model.
    """
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        raise HelperAnswerInvalid("the helper did not answer with one JSON object") from None
    if not isinstance(value, dict):
        raise HelperAnswerInvalid("the helper did not answer with one JSON object")
    fields = set(value)
    allowed = {"status": _STATUS_FIELDS, "read": _READ_FIELDS, "run": _RUN_FIELDS}.get(action, _ANSWER_FIELDS)
    if not _ANSWER_FIELDS <= fields or not fields <= allowed:
        raise HelperAnswerInvalid("the helper's answer does not hold the fields of the contract")
    if not isinstance(value["ok"], bool):
        raise HelperAnswerInvalid("the helper's answer holds no ok")
    if value["status"] not in STATUSES:
        raise HelperAnswerInvalid("the helper's answer holds no status of the contract")
    if not isinstance(value["code"], str) or len(value["code"]) > 64:
        raise HelperAnswerInvalid("the helper's answer holds no code")
    checks = value["checks"]
    if not isinstance(checks, list):
        raise HelperAnswerInvalid("the helper's checks are not a list")
    for check in checks:
        if (
            not isinstance(check, dict)
            or set(check) != _CHECK_FIELDS
            or not isinstance(check["name"], str)
            or not isinstance(check["ok"], bool)
            or not isinstance(check["detail"], str)
        ):
            raise HelperAnswerInvalid("a check of the helper's answer is not a check")
    if "completed" in value and not isinstance(value["completed"], dict):
        raise HelperAnswerInvalid("the helper's completions are not an object")
    if "checkpoints" in value and not isinstance(value["checkpoints"], dict):
        raise HelperAnswerInvalid("the helper's checkpoints are not an object")
    if "odj" in value and (value["ok"] is not True or value["status"] != "started" or not valid_odj(value["odj"])):
        raise HelperAnswerInvalid("the helper's offline domain join blob is not one of the contract")
    if action == "read" and value["ok"] is True and "read" not in value:
        raise HelperAnswerInvalid("the helper's read answer holds no read")
    if "read" in value:
        read = value["read"]
        if (
            not isinstance(read, dict)
            or set(read) != _READ_ANSWER_FIELDS
            or read["name"] not in READS
            or not isinstance(read["computer"], str)
            or not isinstance(read["text"], str)
            or isinstance(read["utc_offset_minutes"], bool)
            or not isinstance(read["utc_offset_minutes"], int)
        ):
            raise HelperAnswerInvalid("the helper's read is not a read of the contract")
    return value


class SshHelperTransport:
    """The helper of each server, over its ``newton-build`` login."""

    def __init__(
        self,
        targets: Mapping[str, HelperTarget],
        *,
        runner_for: Callable[[HelperTarget], Callable[[SessionSpec], RunOut]] | None = None,
    ) -> None:
        self._targets = dict(targets)
        self._runner_for = runner_for

    def send(self, device: str, request: Mapping[str, Any]) -> dict[str, Any]:
        target = self._targets.get(device)
        if target is None:
            raise HelperUnavailable("the build config names no login for the server")
        payload = json.dumps(dict(request), separators=(",", ":"), ensure_ascii=True)
        if len(payload.encode("ascii")) > MAX_REQUEST_BYTES:
            raise ValueError("the request is bigger than the helper reads")
        if self._runner_for is None:
            runner: Callable[[SessionSpec], RunOut] = SshSessionRunner(
                target, stdout_cap=STDOUT_CAP, timeout_s=TIMEOUT_S
            )
        else:
            runner = self._runner_for(target)
        out = runner(SessionSpec(remote="", stdin=payload))
        if out.status != "ok" or out.exit_code != 0 or not out.stdout.strip():
            raise HelperUnavailable("the build helper did not answer")
        return parse_answer(out.stdout, action=str(request.get("action")))


@dataclass(frozen=True)
class ReadContext:
    """What a DC read of one server is sent under: the run, the plan
    bytes, the server's plan token and its window, and the stage whose
    checkpoint is being verified."""

    run: str
    plan_bytes: bytes
    token: str
    nbf: int
    exp: int
    stage: str


class HelperDcReads:
    """The DC reads of the build config's real checkpoint adapters,
    through the helper of each server (PLAN-1.5 task 8 part B0; DESIGN-1.5
    open point 3 of task 8, 7 of task 7).

    The approval and the runner open a server's context before they verify
    its checkpoint, and close it after.  A read with no open context, a
    read the helper did not answer, refused, or answered for another read,
    another computer than the plan's hostname or an offset that is not
    whole minutes in range is ``CheckpointUnverified``: the checkpoint does
    not verify.
    """

    def __init__(self, transport: HelperTransport) -> None:
        self.transport = transport
        self._open: dict[str, ReadContext] = {}

    def open(
        self, device: str, *, run: str, plan_bytes: bytes, token: str, nbf: int, exp: int, stage: str
    ) -> None:
        self._open[device] = ReadContext(run=run, plan_bytes=plan_bytes, token=token, nbf=nbf, exp=exp, stage=stage)

    def close(self, device: str) -> None:
        self._open.pop(device, None)

    def _read(self, server_cfg: Mapping[str, Any], name: str) -> Mapping[str, Any]:
        device = server_cfg.get("device")
        context = self._open.get(device) if isinstance(device, str) else None
        if context is None:
            raise CheckpointUnverified("no read of the server is open")
        try:
            request = helper_request(
                run=context.run,
                plan_bytes=context.plan_bytes,
                stage=context.stage,
                action="read",
                token=context.token,
                nbf=context.nbf,
                exp=context.exp,
                read=name,
            )
            answer = self.transport.send(device, request)
        except (ValueError, HelperUnavailable, HelperAnswerInvalid):
            raise CheckpointUnverified("the helper did not answer the read") from None
        if answer.get("ok") is not True and answer.get("status") == "refused" and answer.get("code") == "journal_busy":
            # Another request holds the journal of the server: the read is
            # not sent again, the run stops with the helper's own code.
            raise JournalBusy("another request holds the journal of the server") from None
        read = answer.get("read") if answer.get("ok") is True and answer.get("status") == "done" else None
        if not isinstance(read, Mapping) or read.get("name") != name:
            raise CheckpointUnverified("the helper did not answer the read")
        computer, offset, text = read.get("computer"), read.get("utc_offset_minutes"), read.get("text")
        hostname = server_cfg.get("hostname")
        if (
            not isinstance(computer, str)
            or COMPUTER_RE.fullmatch(computer) is None
            or not isinstance(hostname, str)
            or computer.casefold() != hostname.casefold()
        ):
            raise CheckpointUnverified("the read ran on another computer")
        if isinstance(offset, bool) or not isinstance(offset, int) or not -1440 < offset < 1440:
            raise CheckpointUnverified("the read holds no UTC offset in range")
        if not isinstance(text, str):
            raise CheckpointUnverified("the read holds no text")
        return read

    def read_genid(self, server_cfg: Mapping[str, Any]) -> str:
        return str(self._read(server_cfg, "genid")["text"])

    def read_showbackup(self, server_cfg: Mapping[str, Any]) -> ShowbackupRead:
        read = self._read(server_cfg, "showbackup")
        return ShowbackupRead(str(read["text"]), int(read["utc_offset_minutes"]))

    def read_versions(self, server_cfg: Mapping[str, Any]) -> WbadminRead:
        read = self._read(server_cfg, "versions")
        return WbadminRead(str(read["computer"]), str(read["text"]), int(read["utc_offset_minutes"]))


def completions(answer: Mapping[str, Any]) -> dict[str, int]:
    """The recorded completions of a status answer, each checked.

    A key that is not a stage of the design, or a time that is not a UTC
    second in the helper's range, makes the whole map unreadable: a bound
    is never taken from a journal the transport cannot read whole.
    """
    raw = answer.get("completed")
    if not isinstance(raw, dict):
        raise JournalUnreadable("the helper's status holds no completions")
    out: dict[str, int] = {}
    for stage, when in raw.items():
        if stage not in _plan.STAGE_IDS:
            raise JournalUnreadable("the helper's completions hold a stage outside the design")
        if isinstance(when, bool) or not isinstance(when, int) or not EPOCH_MIN <= when <= EPOCH_MAX:
            raise JournalUnreadable("the helper's completion of a stage is not a UTC second")
        out[stage] = when
    return out


@dataclass(frozen=True)
class Journal:
    """What a status answer says of the helper's journal: each stage's
    recorded completion, and each stage's checkpoint of the request's plan
    (its id and name, as the checkpoint request named them)."""

    completed: dict[str, int]
    checkpoints: dict[str, dict[str, str]]


def journal_of(answer: Mapping[str, Any]) -> Journal:
    """The completions and the checkpoints of a status answer, each
    checked: a stage outside the design, or an id or a name outside the
    checkpoint grammar, makes the whole journal unreadable."""
    raw = answer.get("checkpoints")
    if not isinstance(raw, dict):
        raise JournalUnreadable("the helper's status holds no checkpoints")
    held: dict[str, dict[str, str]] = {}
    for stage, one in raw.items():
        if stage not in _plan.STAGE_IDS or not isinstance(one, dict) or set(one) != {"id", "name"}:
            raise JournalUnreadable("the helper's checkpoints are not checkpoints of the design")
        ident, name = one["id"], one["name"]
        if not isinstance(ident, str) or _plan.CHECKPOINT_ID_RE.fullmatch(ident) is None:
            raise JournalUnreadable("the helper's checkpoint id is outside its grammar")
        if not isinstance(name, str) or _plan.CHECKPOINT_ID_RE.fullmatch(name) is None:
            raise JournalUnreadable("the helper's checkpoint name is outside its grammar")
        held[stage] = {"id": ident, "name": name}
    return Journal(completed=completions(answer), checkpoints=held)


def read_journal(
    transport: HelperTransport,
    device: str,
    *,
    run: str,
    plan_bytes: bytes,
    token: str,
    nbf: int,
    exp: int,
) -> Journal:
    """The helper's journal on one server (``read_completions``), with the
    checkpoints it holds for the request's plan."""
    return journal_of(_journal_status(transport, device, run=run, plan_bytes=plan_bytes, token=token, nbf=nbf, exp=exp))


def _journal_status(
    transport: HelperTransport,
    device: str,
    *,
    run: str,
    plan_bytes: bytes,
    token: str,
    nbf: int,
    exp: int,
) -> Mapping[str, Any]:
    request = helper_request(
        run=run, plan_bytes=plan_bytes, stage="0", action="status", token=token, nbf=nbf, exp=exp
    )
    try:
        answer = transport.send(device, request)
    except HelperUnavailable:
        raise JournalUnreadable("the helper's journal could not be read", code="unavailable") from None
    except HelperAnswerInvalid:
        raise JournalUnreadable("the helper's journal could not be read") from None
    if answer.get("ok") is not True:
        # The helper's code is device text: it is compared, never kept.
        code = answer.get("code") if answer.get("code") in ("plan_mismatch", "expired", "journal_busy") else "refused"
        raise JournalUnreadable("the helper refused the read of its journal", code=code)
    return answer


def read_completions(
    transport: HelperTransport,
    device: str,
    *,
    run: str,
    plan_bytes: bytes,
    token: str,
    nbf: int,
    exp: int,
) -> dict[str, int]:
    """Each stage's recorded completion on one server, read from its
    helper's journal through a status of stage 0 under the plan token.

    Stage 0 is a read stage in every graph: its status is covered by the
    plan token, waits for no reboot and records nothing, and the answer
    carries the completions of every stage of the server.
    """
    return completions(_journal_status(transport, device, run=run, plan_bytes=plan_bytes, token=token, nbf=nbf, exp=exp))


def previous_stage(graph: Sequence[str], stage: str) -> str:
    """The stage before ``stage`` in a server's graph."""
    stages = list(graph)
    if stage not in stages or stages.index(stage) == 0:
        raise JournalUnreadable("the stage has no stage before it in the graph of the server")
    return stages[stages.index(stage) - 1]


def journal_not_before(
    completed: Mapping[str, int],
    *,
    graph: Sequence[str],
    stage: str,
    plan_nbf: int,
) -> int:
    """``not_before`` for a checkpoint of ``stage`` (DESIGN-1.5
    "Checkpoints"): the later of the plan approval's NBF and the recorded
    completion of the stage before on that server, from its journal.

    A previous stage with no recorded completion is a refusal, never a
    bound of the NBF alone.
    """
    if isinstance(plan_nbf, bool) or not isinstance(plan_nbf, int):
        raise JournalUnreadable("the plan approval holds no NBF")
    before = previous_stage(graph, stage)
    when = completed.get(before)
    if isinstance(when, bool) or not isinstance(when, int):
        raise JournalUnreadable("the helper's journal records no completion of the stage before")
    return max(plan_nbf, when)
