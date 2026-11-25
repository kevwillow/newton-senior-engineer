"""The checkpoint adapters of the build (PLAN-1.5 task 7, DESIGN-1.5
"Checkpoints").

Every adapter answers ``checkpoint(server_cfg, kind) -> {"name", "id"}``
and ``verify(server_cfg, cp, kind, *, stage, not_before) -> bool``: is
this checkpoint of this server good enough to undo this stage?  The stage
is passed by keyword (the maintainer, 2026-11-13), because the kind alone does not
say which backup a server without a hypervisor must hold: DC1's stage-7
checkpoint is of kind ``dc``, like the ones of the stages 3, 4 and 6,
yet only an all-critical backup can undo a promotion.

``not_before`` is the earliest UTC second the checkpoint may have been
taken at, passed on every call, with no default (the task 7 triage, B1
and M1).  The caller (the runner and the stage approval, PLAN-1.5 task
8, from the helper's journal) passes the later of the plan approval's
NBF and the recorded completion of the stage before.  A checkpoint taken
before it is unverified, whatever else it holds: stage 2's pre-promotion
snapshot or backup, valid freeze lines and all, is never the DC
checkpoint of stage 3 or later, and a checkpoint of an earlier run never
verifies.  Each adapter compares the time the hypervisor or wbadmin
reports, as it reports it: there is no skew allowance (DESIGN-1.5, open
points of task 7).

The adapters read what the design names, pinned to the bytes measured
on the apollo lab (MEASURED-1.5 "The scoped token", "wbadmin on BUILD1",
"Checkpoints on BUILD1, 2026-11-14") and to the forced command of the
Hyper-V host (``helper/hv-checkpoint.ps1``, MEASURED-1.5 section 4):

- Proxmox: the snapshot is listed with ``vmstate`` 0, its task stopped
  with ``exitstatus OK``, and its whole log is ``freeze guest
  filesystem``, the measured snapshot and LVM lines, ``thaw guest
  filesystem``, ``TASK OK``; anything else is unverified.
- Hyper-V: the checkpoint is listed once, the VM's checkpoint type is
  ``ProductionOnly``, and on a DC every partition's ``dSASignature`` is
  no older than the checkpoint.
- wbadmin: the version the checkpoint names is listed, it is not older
  than ``not_before`` and was read on the server itself, and its "Can
  recover" holds what the stage needs.

A DC checkpoint also needs ``msDS-GenerationId`` on the DC's computer
object, read the way stage 2 reads it (the ``s2-genid`` op).

The adapters take their transports as arguments: the run of an argv
list, the Proxmox API (``pve_request``, the token read from its file at
each call), and the reads of the DC through the helper.  The reads of
the DC through the helper belong to the runner (PLAN-1.5 task 8); here
they are callables.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple, Protocol

#: The "Can recover" item of an all-critical (bare-metal) backup.
BARE_METAL = "Bare Metal Recovery"

#: The "Can recover" item of a system-state backup (MEASURED-1.5).
SYSTEM_STATE = "System State"

#: The item a wbadmin backup must list in "Can recover" before each stage
#: that takes a checkpoint (DESIGN-1.5 "Checkpoints", "No hypervisor";
#: the maintainer, 2026-11-13): the bare-metal one before the promotions (2 and 7),
#: system state before the stages 3, 4 and 6.  A system-state backup
#: cannot undo a promotion, so it never verifies stage 2 or 7.
WBADMIN_RECOVERY_OF_STAGE: dict[str, str] = {
    "2": BARE_METAL,
    "3": SYSTEM_STATE,
    "4": SYSTEM_STATE,
    "6": SYSTEM_STATE,
    "7": BARE_METAL,
}

#: The kinds of checkpoint of the design.
CHECKPOINT_KINDS: tuple[str, ...] = ("workgroup", "dc")

def wbadmin_version_verifies(can_recover: object, *, stage: str) -> bool:
    """True when a wbadmin version may be relied on to undo ``stage``.

    ``can_recover`` is the list of the items wbadmin prints after
    "Can recover", each one exactly as wbadmin spells it.  Anything
    that is not such a list, and any stage that takes no checkpoint,
    never verifies.
    """
    need = WBADMIN_RECOVERY_OF_STAGE.get(stage) if isinstance(stage, str) else None
    if need is None:
        return False
    if not isinstance(can_recover, (list, tuple)):
        return False
    items: list[str] = []
    for item in can_recover:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(item, str):
            return False
        items.append(item)
    return need in items


# ---------------------------------------------------------------------------
# What every adapter shares
# ---------------------------------------------------------------------------

#: The code a run stops with when a checkpoint does not verify
#: (PLAN-1.5 task 7); the approval refuses with the same code.
CHECKPOINT_UNVERIFIED = "checkpoint_unverified"


class CheckpointUnverified(Exception):
    """A checkpoint that could not be taken or did not verify.

    The run stops with ``checkpoint_unverified``.  The message never
    holds a secret: it names the server and the check, nothing else.
    """

    code = CHECKPOINT_UNVERIFIED


class JournalBusy(CheckpointUnverified):
    """The helper refused the read: another request holds the journal of
    the server (the helper's own code ``journal_busy``).

    The run stops with ``journal_busy``: the read is not re-sent.
    """

    code = "journal_busy"


#: The kind of the checkpoint of every stage that takes one, per role
#: (DESIGN-1.5 "Checkpoints"): the workgroup checkpoint before stage 2
#: on DC1 and before stage 7 on DC2, the DC checkpoint before the stages
#: 3, 4 and 6 and of DC1 before 7.  The approval holds the same table.
KIND_OF_STAGE: dict[tuple[str, str], str] = {
    ("dc1", "2"): "workgroup",
    ("dc1", "3"): "dc",
    ("dc1", "4"): "dc",
    ("dc1", "6"): "dc",
    ("dc1", "7"): "dc",
    ("dc2", "7"): "workgroup",
}

#: What reads the s2-genid op's output on a server (through the helper).
GenIdReader = Callable[[Mapping[str, Any]], str]

#: What runs one argv list and answers its exit code and its stdout.
Runner = Callable[[list[str]], tuple[int, str]]


def _bound(not_before: object) -> datetime:
    """The ``not_before`` of a verify call as a UTC time.

    It is a UTC second (an ``int``, never a ``bool``), passed on every
    call: a missing one is a ``TypeError`` of the call itself, and
    anything else raises here, so a caller cannot verify a checkpoint
    without saying how old it may be.
    """
    if isinstance(not_before, bool) or not isinstance(not_before, int):
        raise TypeError("not_before is a UTC second")
    return datetime.fromtimestamp(not_before, timezone.utc)


def _kind_fits(server_cfg: Mapping[str, Any], kind: str, stage: object) -> bool:
    """True when ``kind`` is the kind of checkpoint ``stage`` takes on
    this server's role."""
    if not isinstance(stage, str) or kind not in CHECKPOINT_KINDS:
        return False
    return KIND_OF_STAGE.get((str(server_cfg.get("role")), stage)) == kind


#: The line of the s2-genid op that says msDS-GenerationId is stored
#: on the DC's computer object (MEASURED-1.5 "Stage 2"; the helper's own
#: rule): present, 8 bytes, the bytes in hexadecimal.
_GENID_LINE_RE = re.compile(
    r"msDS-GenerationId on CN=(?P<host>[A-Za-z0-9-]{1,15}),OU=Domain Controllers,"
    r"(?:DC=[A-Za-z0-9-]{1,63},)*DC=[A-Za-z0-9-]{1,63}: "
    r"(?P<value>present, 8 bytes, [0-9a-f]{16}|absent)"
)


def genid_present(text: object, *, hostname: str) -> bool:
    """True when the s2-genid read shows msDS-GenerationId on this DC.

    The read holds exactly one ``msDS-GenerationId on`` line, of the
    computer object of ``hostname`` under the Domain Controllers OU,
    and that line says ``present, 8 bytes``.  Anything else -- absent,
    another DC, two lines, a short value, no read -- is not present.
    """
    if not isinstance(text, str) or not isinstance(hostname, str) or not hostname:
        return False
    lines = [line.rstrip("\r") for line in text.split("\n")]
    hits = [line for line in lines if line.startswith("msDS-GenerationId on ")]
    if len(hits) != 1:
        return False
    match = _GENID_LINE_RE.fullmatch(hits[0])
    if match is None:
        return False
    if match.group("host").casefold() != hostname.casefold():
        return False
    return match.group("value") != "absent"


def _dc_read_ok(
    read_genid: GenIdReader, server_cfg: Mapping[str, Any], kind: str
) -> bool:
    """The msDS-GenerationId part of a DC checkpoint; a workgroup
    checkpoint has no directory and reads nothing."""
    if kind != "dc":
        return True
    return genid_present(read_genid(server_cfg), hostname=str(server_cfg.get("hostname", "")))


class CheckpointAdapter(Protocol):
    """An adapter of one method."""

    def checkpoint(self, server_cfg: Mapping[str, Any], kind: str) -> dict[str, str]: ...

    def verify(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool: ...


class CheckpointAdapters:
    """The adapter of a build: each server goes to the adapter of its
    plan's checkpoint method.  A method with no adapter takes no
    checkpoint and verifies none.  It is the ``verifier`` the stage
    approval takes (``newton_mcp.approve.approve_ad_build_stage``)."""

    def __init__(self, by_method: Mapping[str, CheckpointAdapter], *, reads: Any = None) -> None:
        self._by_method = dict(by_method)
        #: The DC reads the adapters read through (``transport.HelperDcReads``),
        #: or None when they read through no helper.
        self.reads = reads

    def open_reads(
        self, device: str, *, run: str, plan_bytes: bytes, token: str, nbf: int, exp: int, stage: str
    ) -> None:
        """Open the DC reads of one server for the verify of ``stage``
        (the approval and the runner call it before they verify)."""
        if self.reads is not None:
            self.reads.open(device, run=run, plan_bytes=plan_bytes, token=token, nbf=nbf, exp=exp, stage=stage)

    def close_reads(self, device: str) -> None:
        if self.reads is not None:
            self.reads.close(device)

    def _adapter(self, server_cfg: Mapping[str, Any]) -> CheckpointAdapter | None:
        method = server_cfg.get("checkpoint")
        if not isinstance(method, str):
            return None
        return self._by_method.get(method)

    def checkpoint(self, server_cfg: Mapping[str, Any], kind: str) -> dict[str, str]:
        """Take the checkpoint; an adapter that raises stops the run with
        ``checkpoint_unverified``, as ``require_verified`` does."""
        adapter = self._adapter(server_cfg)
        if adapter is None:
            raise CheckpointUnverified("the server's checkpoint method has no adapter")
        try:
            return adapter.checkpoint(server_cfg, kind)
        except CheckpointUnverified:
            raise
        except Exception as exc:
            raise CheckpointUnverified(
                f"the checkpoint could not be taken ({type(exc).__name__})"
            ) from None

    def verify(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        adapter = self._adapter(server_cfg)
        if adapter is None:
            return False
        return adapter.verify(server_cfg, cp, kind, stage=stage, not_before=not_before) is True


def require_verified(
    adapter: Any,
    server_cfg: Mapping[str, Any],
    cp: Mapping[str, Any],
    kind: str,
    *,
    stage: str,
    not_before: int,
) -> None:
    """Stop the run unless the adapter verifies the checkpoint.

    Only ``True`` verifies; an adapter that answers anything else, or
    raises, stops the run with ``checkpoint_unverified``.  This is the
    seam the runner (PLAN-1.5 task 8) calls before it asks the owner
    for a stage approval; it passes ``not_before`` from the journal (the
    later of the plan approval's NBF and the previous stage's recorded
    completion).
    """
    try:
        verified = adapter.verify(server_cfg, cp, kind, stage=stage, not_before=not_before)
    except CheckpointUnverified:
        # The adapter's own refusal keeps its code (the journal of the
        # server was busy, the run stops with that code).
        raise
    except Exception as exc:
        raise CheckpointUnverified(
            f"the checkpoint could not be verified ({type(exc).__name__})"
        ) from None
    if verified is not True:
        raise CheckpointUnverified("the checkpoint did not verify")


# ---------------------------------------------------------------------------
# Proxmox
# ---------------------------------------------------------------------------

#: A snapshot name of Newton: Proxmox allows a letter then up to 39
#: letters, digits, '_' and '-'.
PROXMOX_SNAPNAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,39}")

_PVE_NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}")
_PVE_VMID_RE = re.compile(r"[1-9][0-9]{2,8}")
_PVE_TOKEN_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,64}![A-Za-z0-9._-]{1,64}")
_PVE_API_RE = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?/api2/json")
_PVE_SECRET_RE = re.compile(r"[A-Za-z0-9-]{1,128}")
_PVE_UPID_RE = re.compile(
    r"UPID:(?P<node>[A-Za-z0-9-]{1,63}):[0-9A-F]{8}:[0-9A-F]{8}:(?P<start>[0-9A-F]{8}):"
    r"(?P<type>[a-z]+):(?P<vmid>[0-9]{1,9}):(?P<user>[A-Za-z0-9._@!-]{1,200}):"
)

#: How long a snapshot task may run before the checkpoint gives up:
#: the measured freezes took 35 s (MEASURED-1.5 section 7).
PROXMOX_TASK_WAIT_S = 900.0

#: The log lines of a measured snapshot that may stand between the
#: freeze and the thaw (MEASURED-1.5 "The scoped token", "Checkpoints on
#: BUILD1, 2026-11-14"): the disk lines of Proxmox and the LVM thin-pool
#: lines of apollo's vmdata.  ``{vmid}`` and ``{snap}`` are the VM's and
#: the snapshot's, so a line of another VM or snapshot is not one of
#: them.  A thin-pool line matches exactly; anything else is unverified.
_LVM_LINES: tuple[str, ...] = (
    r"  WARNING: You have not turned on protection against thin pools running out of space\.",
    r"  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic "
    r"extension of thin pools before they get full\.",
    r"  Consider pruning [A-Za-z0-9_.+-]{1,64} VG archive with more than [0-9]{1,9} MiB in "
    r"[0-9]{1,9} files \(see archiving settings in lvm\.conf\)\.",
    r"  WARNING: Sum of all thin volume sizes \(<?[0-9]{1,6}(?:\.[0-9]{1,2})? [KMGTPE]iB\) exceeds "
    r"the size of thin pool [A-Za-z0-9_.+-]{1,64}/[A-Za-z0-9_.+-]{1,64} and the size of whole "
    r"volume group \(<?[0-9]{1,6}(?:\.[0-9]{1,2})? [KMGTPE]iB\)\.",
)
_LVM_LINE_RES = tuple(re.compile(line) for line in _LVM_LINES)


def _disk_line_re(vmid: str) -> re.Pattern[str]:
    return re.compile(
        r"snapshotting 'drive-sata[0-9]{1,2}' \([A-Za-z0-9][A-Za-z0-9_.-]{0,63}:"
        rf"vm-{re.escape(vmid)}-disk-(?P<disk>[0-9]{{1,3}})\)"
    )


def _created_line_re(vmid: str, snapname: str) -> re.Pattern[str]:
    return re.compile(
        rf'  Logical volume "snap_vm-{re.escape(vmid)}-disk-(?P<disk>[0-9]{{1,3}})_'
        rf'{re.escape(snapname)}" created\.'
    )


def proxmox_log_verifies(lines: Sequence[str], *, vmid: str, snapname: str) -> bool:
    """True when a snapshot task's whole log is the measured shape of a
    snapshot taken inside a guest filesystem freeze.

    The first line is ``freeze guest filesystem``; then, for each disk,
    its ``snapshotting`` line and the LVM lines, ending with the line
    that creates that disk's snapshot volume of this snapshot; then
    ``thaw guest filesystem`` and ``TASK OK``, the last line.  A log
    that skipped the freeze, has no disk, or holds any other line
    anywhere (a warning of the freeze, a second freeze, a line of
    another VM or snapshot) does not verify.
    """
    if not isinstance(lines, (list, tuple)) or not all(isinstance(line, str) for line in lines):
        return False
    if not isinstance(vmid, str) or _PVE_VMID_RE.fullmatch(vmid) is None:
        return False
    if not isinstance(snapname, str) or PROXMOX_SNAPNAME_RE.fullmatch(snapname) is None:
        return False
    if len(lines) < 5:
        return False
    if lines[0] != "freeze guest filesystem":
        return False
    if lines[-2] != "thaw guest filesystem" or lines[-1] != "TASK OK":
        return False
    disk_re = _disk_line_re(vmid)
    created_re = _created_line_re(vmid, snapname)
    open_disk: str | None = None
    disks = 0
    seen: set[str] = set()
    for line in lines[1:-2]:
        disk = disk_re.fullmatch(line)
        if disk is not None:
            if open_disk is not None or disk.group("disk") in seen:
                return False
            open_disk = disk.group("disk")
            seen.add(open_disk)
            continue
        created = created_re.fullmatch(line)
        if created is not None:
            if open_disk is None or created.group("disk") != open_disk:
                return False
            open_disk = None
            disks += 1
            continue
        if open_disk is None:
            # A thin-pool line comes only while a disk is snapshotted.
            if not any(r.fullmatch(line) for r in _LVM_LINE_RES) or disks == 0:
                return False
            continue
        if not any(r.fullmatch(line) for r in _LVM_LINE_RES):
            return False
    return open_disk is None and disks >= 1


@dataclass(frozen=True)
class ProxmoxTarget:
    """Where one server's VM is, and the token Newton reaches it with.

    The token's secret is never held here: ``token_file`` names the file
    it is in (one line), and ``pve_request`` reads it at each call.
    """

    api: str
    node: str
    vmid: str
    token_id: str
    token_file: Path
    ca_file: Path

    def __post_init__(self) -> None:
        if not isinstance(self.api, str) or _PVE_API_RE.fullmatch(self.api) is None:
            raise ValueError("the Proxmox API is not an https URL ending in /api2/json")
        if not isinstance(self.node, str) or _PVE_NODE_RE.fullmatch(self.node) is None:
            raise ValueError("the Proxmox node is outside its grammar")
        if not isinstance(self.vmid, str) or _PVE_VMID_RE.fullmatch(self.vmid) is None:
            raise ValueError("the Proxmox VM id is outside its grammar")
        if not isinstance(self.token_id, str) or _PVE_TOKEN_ID_RE.fullmatch(self.token_id) is None:
            raise ValueError("the Proxmox token id is not user@realm!name")
        object.__setattr__(self, "token_file", Path(self.token_file))
        object.__setattr__(self, "ca_file", Path(self.ca_file))


def _read_token_secret(path: Path) -> str:
    """The secret of the token: the one line of its file."""
    raw = path.read_text(encoding="ascii")
    lines = raw.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if len(lines) != 1 or _PVE_SECRET_RE.fullmatch(lines[0]) is None:
        raise ValueError("the token file does not hold one token secret")
    return lines[0]


#: What makes one call of the Proxmox API: the target, the method, the
#: path under ``/api2/json`` and the parameters (the query of a GET, the
#: form of a POST).  It answers the decoded JSON body.
PveRequest = Callable[[ProxmoxTarget, str, str, Mapping[str, str] | None], Any]


def pve_request(
    target: ProxmoxTarget,
    method: str,
    path: str,
    params: Mapping[str, str] | None = None,
    *,
    opener: Any = None,
    timeout: float = 60.0,
) -> Any:
    """One call of the Proxmox API with the scoped token.

    TLS is checked against the target's CA file.  The token secret is
    read from its file here and goes only into the ``Authorization``
    header of this request: never into a URL, a form, an argv, an
    environment or a message.
    """
    if method not in ("GET", "POST", "DELETE"):
        raise ValueError("the method is not one Newton uses")
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("the path is not a path of the API")
    url = target.api + path
    data: bytes | None = None
    if params:
        encoded = urllib.parse.urlencode(sorted(params.items()))
        if method == "POST":
            data = encoded.encode("ascii")
        else:
            url = url + "?" + encoded
    secret = _read_token_secret(target.token_file)
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"PVEAPIToken={target.token_id}={secret}")
    del secret
    if data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    if opener is None:
        context = ssl.create_default_context(cafile=str(target.ca_file))
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=timeout) as answer:
        body = answer.read()
    return json.loads(body.decode("utf-8"))


def _task_path(target: ProxmoxTarget, upid: str) -> str:
    return f"/nodes/{target.node}/tasks/" + urllib.parse.quote(upid, safe="")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProxmoxAdapter:
    """The Proxmox method: a ``vmstate=0`` snapshot through the scoped
    token (VM.Snapshot and VM.Audit on the build VMs only)."""

    def __init__(
        self,
        targets: Mapping[str, ProxmoxTarget],
        *,
        read_genid: GenIdReader,
        request: PveRequest = pve_request,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], None] = time.sleep,
        wait_s: float = PROXMOX_TASK_WAIT_S,
    ) -> None:
        self._targets = dict(targets)
        self._read_genid = read_genid
        self._request = request
        self._clock = clock
        self._sleep = sleep
        self._wait_s = wait_s

    def _target(self, server_cfg: Mapping[str, Any]) -> ProxmoxTarget | None:
        if server_cfg.get("checkpoint") != "proxmox":
            return None
        return self._targets.get(str(server_cfg.get("device")))

    def checkpoint(self, server_cfg: Mapping[str, Any], kind: str) -> dict[str, str]:
        """Take the snapshot and wait for its task to stop.  Whether it
        is good enough is ``verify``'s answer, not this one's."""
        target = self._target(server_cfg)
        if target is None or kind not in CHECKPOINT_KINDS:
            raise CheckpointUnverified("the server has no Proxmox target")
        name = f"newton-{kind}-{self._clock().astimezone(timezone.utc):%Y%m%d-%H%M%S}"
        answer = self._request(
            target,
            "POST",
            f"/nodes/{target.node}/qemu/{target.vmid}/snapshot",
            {"snapname": name, "vmstate": "0", "description": "newton-ad-build"},
        )
        upid = answer.get("data") if isinstance(answer, dict) else None
        if not isinstance(upid, str) or _PVE_UPID_RE.fullmatch(upid) is None:
            raise CheckpointUnverified("the snapshot answered no task")
        waited = 0.0
        while True:
            status = self._request(target, "GET", _task_path(target, upid) + "/status", None)
            data = status.get("data") if isinstance(status, dict) else None
            if isinstance(data, dict) and data.get("status") == "stopped":
                break
            if waited >= self._wait_s:
                raise CheckpointUnverified("the snapshot task did not stop in time")
            self._sleep(3.0)
            waited += 3.0
        return {"name": name, "id": upid}

    def verify(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        bound = int(_bound(not_before).timestamp())
        target = self._target(server_cfg)
        if target is None or not _kind_fits(server_cfg, kind, stage):
            return False
        name, upid = cp.get("name"), cp.get("id")
        if not isinstance(name, str) or PROXMOX_SNAPNAME_RE.fullmatch(name) is None:
            return False
        if not isinstance(upid, str):
            return False
        parts = _PVE_UPID_RE.fullmatch(upid)
        if parts is None or parts.group("type") != "qmsnapshot":
            return False
        if parts.group("node") != target.node or parts.group("vmid") != target.vmid:
            return False
        # The task started no earlier than the bound (the UPID's starttime,
        # the host's clock, seconds).
        if int(parts.group("start"), 16) < bound:
            return False

        listed = self._request(
            target, "GET", f"/nodes/{target.node}/qemu/{target.vmid}/snapshot", None
        )
        snaps = listed.get("data") if isinstance(listed, dict) else None
        if not isinstance(snaps, list):
            return False
        mine = [s for s in snaps if isinstance(s, dict) and s.get("name") == name]
        if len(mine) != 1 or mine[0].get("vmstate") != 0 or isinstance(mine[0].get("vmstate"), bool):
            return False
        # The snapshot was taken no earlier than the bound (its snaptime,
        # the host's clock, seconds); a missing or other-typed one is
        # unverified.
        snaptime = mine[0].get("snaptime")
        if isinstance(snaptime, bool) or not isinstance(snaptime, int) or snaptime < bound:
            return False

        status = self._request(target, "GET", _task_path(target, upid) + "/status", None)
        data = status.get("data") if isinstance(status, dict) else None
        if not isinstance(data, dict):
            return False
        if (
            data.get("upid") != upid
            or data.get("type") != "qmsnapshot"
            or data.get("id") != target.vmid
            or data.get("status") != "stopped"
            or data.get("exitstatus") != "OK"
        ):
            return False

        log = self._request(
            target, "GET", _task_path(target, upid) + "/log", {"start": "0", "limit": "1000"}
        )
        if not isinstance(log, dict):
            return False
        entries = log.get("data")
        total = log.get("total")
        if not isinstance(entries, list) or isinstance(total, bool) or total != len(entries):
            return False
        lines: list[str] = []
        for index, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict) or entry.get("n") != index:
                return False
            text = entry.get("t")
            if not isinstance(text, str):
                return False
            lines.append(text)
        if not proxmox_log_verifies(lines, vmid=target.vmid, snapname=name):
            return False
        return _dc_read_ok(self._read_genid, server_cfg, kind)


# ---------------------------------------------------------------------------
# wbadmin
# ---------------------------------------------------------------------------


class WbadminVersion(NamedTuple):
    """One version of ``wbadmin get versions``."""

    #: The version identifier's minute, read as UTC.
    time: datetime
    identifier: str
    can_recover: tuple[str, ...]
    #: The "Backup time" line: the server's local time, to the minute,
    #: naive (wbadmin names no zone).
    backup_time: datetime


class WbadminRead(NamedTuple):
    """A read of ``wbadmin get versions`` on a server: the computer name
    it ran on, its output, exactly as wbadmin printed it, and the
    server's offset from UTC in minutes at the read (local minus UTC),
    since the "Backup time" line is the server's local time."""

    computer: str
    text: str
    utc_offset_minutes: int


_WB_HEADER = (
    "wbadmin 1.0 - Backup command-line tool",
    "(C) Copyright Microsoft Corporation. All rights reserved.",
    "",
)
#: The measured "Backup time" line: ``M/D/YYYY H:MM AM`` unpadded, on the
#: 12-hour clock, ending in a space.
_WB_TIME_RE = re.compile(
    r"Backup time: (?P<month>1[0-2]|[1-9])/(?P<day>3[01]|[12][0-9]|[1-9])/(?P<year>[0-9]{4}) "
    r"(?P<hour>1[0-2]|[1-9]):(?P<minute>[0-5][0-9]) (?P<half>AM|PM) "
)
_WB_TARGET_RE = re.compile(r"Backup target: [ -~]{1,200}")
_WB_ID_RE = re.compile(r"Version identifier: (?P<id>([0-9]{2})/([0-9]{2})/([0-9]{4})-([0-9]{2}):([0-9]{2}))")
_WB_CAN_RE = re.compile(r"Can recover: (?P<items>[A-Za-z()]+(?: [A-Za-z()]+)*(?:, [A-Za-z()]+(?: [A-Za-z()]+)*)*)")
_WB_SNAP_RE = re.compile(r"Snapshot ID: \{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}")


def _wb_backup_time(match: re.Match[str]) -> datetime:
    """The naive local minute of a "Backup time" line: 12 AM is
    midnight, 12 PM noon.  A day that does not exist raises
    ``ValueError``."""
    hour = int(match.group("hour")) % 12 + (12 if match.group("half") == "PM" else 0)
    return datetime(
        int(match.group("year")), int(match.group("month")), int(match.group("day")),
        hour, int(match.group("minute")),
    )


def parse_wbadmin_versions(text: str) -> list[WbadminVersion]:
    """The versions of ``wbadmin get versions``, oldest first.

    The answer is the measured one: the two header lines and a blank
    line, then per version ``Backup time``, ``Backup target``, ``Version
    identifier``, ``Can recover``, ``Snapshot ID`` and a blank line.  The
    version identifier is read as wbadmin's UTC minute
    (``MM/DD/YYYY-HH:MM``), the Backup time as the server's local
    minute; whether they agree is the adapter's check, which knows the
    server's offset.  Anything else raises ``ValueError`` (a Backup time
    of no real day included); so do two versions of one identifier.
    """
    if not isinstance(text, str):
        raise ValueError("the answer is not text")
    lines = text.replace("\r\n", "\n").split("\n")
    if tuple(lines[:3]) != _WB_HEADER:
        raise ValueError("the answer does not start with the wbadmin header")
    body = lines[3:]
    if body and body[-1] == "":
        body = body[:-1]
    if not body or len(body) % 6 != 0:
        raise ValueError("the versions are not blocks of the measured shape")
    versions: list[WbadminVersion] = []
    for start in range(0, len(body), 6):
        block = body[start : start + 6]
        backup_time = _WB_TIME_RE.fullmatch(block[0])
        target = _WB_TARGET_RE.fullmatch(block[1])
        ident = _WB_ID_RE.fullmatch(block[2])
        can = _WB_CAN_RE.fullmatch(block[3])
        snap = _WB_SNAP_RE.fullmatch(block[4])
        if not (backup_time and target and ident and can and snap) or block[5] != "":
            raise ValueError("a version is not of the measured shape")
        identifier = ident.group("id")
        when = datetime.strptime(identifier, "%m/%d/%Y-%H:%M").replace(tzinfo=timezone.utc)
        local = _wb_backup_time(backup_time)
        items = tuple(can.group("items").split(", "))
        versions.append(
            WbadminVersion(time=when, identifier=identifier, can_recover=items, backup_time=local)
        )
    identifiers = [v.identifier for v in versions]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("two versions share one identifier")
    return versions


#: The backup every wbadmin checkpoint takes.  The design takes the
#: all-critical backup before the stages 2 and 7 and a system-state one
#: before 3, 4 and 6, but ``checkpoint(server_cfg, kind)`` is not told
#: the stage, and a ``dc`` checkpoint may be the one of DC1's stage 7.
#: The all-critical backup lists System State too, so it serves every
#: stage: the conservative choice (DESIGN-1.5, open points of task 7).
WBADMIN_CHECKPOINT_BACKUP = "allCritical"

#: What takes a wbadmin backup on a server through the helper and
#: answers the version identifier it made.
WbadminTaker = Callable[[Mapping[str, Any], str], str]

#: What reads ``wbadmin get versions`` on a server through the helper:
#: the computer name, the text and the server's current UTC offset in
#: minutes (task 8's transport supplies all three from one read).
WbadminReader = Callable[[Mapping[str, Any]], WbadminRead]


class WbadminAdapter:
    """The method of a server without a hypervisor: a wbadmin backup.

    A version older than the ``not_before`` of the verify call is
    refused, so neither a backup of an earlier run nor stage 2's
    pre-promotion backup is relied on for a later stage.  A version
    whose identifier is not its local Backup time minus the server's
    UTC offset is refused too (W1 of the ccdd15e review).
    """

    def __init__(
        self,
        *,
        read_versions: WbadminReader,
        read_genid: GenIdReader,
        take: WbadminTaker,
    ) -> None:
        self._read_versions = read_versions
        self._read_genid = read_genid
        self._take = take

    def checkpoint(self, server_cfg: Mapping[str, Any], kind: str) -> dict[str, str]:
        if server_cfg.get("checkpoint") != "wbadmin" or kind not in CHECKPOINT_KINDS:
            raise CheckpointUnverified("the server does not take wbadmin checkpoints")
        identifier = self._take(server_cfg, WBADMIN_CHECKPOINT_BACKUP)
        if not isinstance(identifier, str) or _WB_ID_RE.fullmatch("Version identifier: " + identifier) is None:
            raise CheckpointUnverified("the backup answered no version identifier")
        return {"name": f"wbadmin-{server_cfg.get('device')}-{kind}", "id": identifier}

    def verify(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        # wbadmin's version identifier holds the minute the backup started
        # (MEASURED-1.5), so the bound is floored to its minute, the same
        # grid, and no further.  So a version that started in the bound's
        # own minute but before it is accepted: that needs the backup and
        # the whole previous stage, its approval included, inside one
        # minute (the shortest measured backup, the workgroup all-critical
        # one, ran 06:58:23 to under 83 s).  DESIGN-1.5 open point 3 says
        # so.
        bound = _bound(not_before).replace(second=0)
        if server_cfg.get("checkpoint") != "wbadmin" or not _kind_fits(server_cfg, kind, stage):
            return False
        identifier = cp.get("id")
        if not isinstance(identifier, str):
            return False
        read = self._read_versions(server_cfg)
        if not isinstance(read, WbadminRead) or not isinstance(read.computer, str):
            return False
        hostname = server_cfg.get("hostname")
        if not isinstance(hostname, str) or read.computer.casefold() != hostname.casefold():
            return False
        offset = read.utc_offset_minutes
        if isinstance(offset, bool) or not isinstance(offset, int) or not -1440 < offset < 1440:
            return False
        try:
            versions = parse_wbadmin_versions(read.text)
        except ValueError:
            return False
        mine = [v for v in versions if v.identifier == identifier]
        if len(mine) != 1:
            return False
        # Nothing pins the server's clock to UTC (BUILD1's guest ran UTC,
        # so its identifier and its local Backup time agreed).  Microsoft
        # documents the identifier as UTC; if it were local, on a server
        # east of UTC an older backup would read later by the offset and
        # meet the bound.  So the identifier must be the Backup time minus
        # the server's offset at the read, to the minute (both lines hold
        # minutes, the offset whole minutes): an identifier in local time
        # on a server off UTC never matches, whichever clock wbadmin used.
        # A DST change between the backup and the read changes the offset:
        # with a UTC identifier and a Backup time shown in the backup's
        # own offset the two no longer match and the version is unverified
        # (fail closed).  The one case it does not catch needs both
        # unmeasured shapes at once: an identifier in local time, and a
        # Backup time shown in the backup's own offset, taken at a nonzero
        # offset and read at offset 0 (a UTC+0 zone back from summer
        # time); that version reads later by the summer offset.
        # DESIGN-1.5 open point 3 says so.
        if mine[0].time.replace(tzinfo=None) != mine[0].backup_time - timedelta(minutes=offset):
            return False
        # the bound is compared against the identifier's UTC minute
        if mine[0].time < bound:
            return False
        if not wbadmin_version_verifies(list(mine[0].can_recover), stage=stage):
            return False
        return _dc_read_ok(self._read_genid, server_cfg, kind)


# ---------------------------------------------------------------------------
# Hyper-V
# ---------------------------------------------------------------------------

_HV_VM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_HV_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_HV_GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HV_CREATED_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HV_FIELDS = frozenset({"name", "id", "created", "vm", "checkpoint_type"})


@dataclass(frozen=True)
class HyperVTarget:
    """The forced-command login of the Hyper-V host and the server's VM.

    ``ssh`` is the argv that reaches the ``hv-checkpoint`` login (its
    key, its options and its ``user@host``); the words of a request are
    appended to it, and the host's ``hv-checkpoint.ps1`` reads them.
    """

    ssh: tuple[str, ...]
    vm: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.ssh, tuple)
            or not self.ssh
            or not all(isinstance(a, str) and a and "\0" not in a for a in self.ssh)
        ):
            raise ValueError("the ssh argv is not a tuple of words")
        if not isinstance(self.vm, str) or _HV_VM_RE.fullmatch(self.vm) is None:
            raise ValueError("the VM name is outside the grammar of hv-checkpoint.ps1")


class ShowbackupRead(NamedTuple):
    """A read of ``repadmin /showbackup`` on a DC (through the helper):
    its output and the DC's offset from UTC in minutes, since repadmin
    prints the DC's local time."""

    text: str
    utc_offset_minutes: int


#: What reads ``repadmin /showbackup`` on a DC.
ShowbackupReader = Callable[[Mapping[str, Any]], ShowbackupRead]


def _hv_checkpoint(raw: object) -> dict[str, str] | None:
    """One checkpoint of hv-checkpoint.ps1's answer, or None."""
    if not isinstance(raw, dict) or set(raw) != _HV_FIELDS:
        return None
    if not all(isinstance(v, str) for v in raw.values()):
        return None
    if _HV_NAME_RE.fullmatch(raw["name"]) is None or _HV_GUID_RE.fullmatch(raw["id"]) is None:
        return None
    if _HV_CREATED_RE.fullmatch(raw["created"]) is None:
        return None
    return dict(raw)


_SB_HEADER = "Repadmin: running command /showbackup against full DC localhost"
_SB_COLUMNS = "Loc.USN                           Originating DSA  Org.USN  Org.Time/Date        Ver Attribute"
_SB_RULE = "=======                           =============== ========= =============        === ========="
_SB_PARTITION_RE = re.compile(r"(?:(?:CN|DC)=[A-Za-z0-9-]{1,63},)*DC=[A-Za-z0-9-]{1,63}")
_SB_ROW_RE = re.compile(
    r"  +[0-9]{1,20} +[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} +[0-9]{1,20} "
    r"(?P<when>[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) +[0-9]{1,10} dSASignature"
)


def parse_showbackup(text: str) -> dict[str, datetime | None]:
    """Every partition of ``repadmin /showbackup`` and the DC-local time
    of its ``dSASignature``, or None when it has never been backed up.

    The answer is the measured one (MEASURED-1.5 "Checkpoints on BUILD1,
    2026-11-14"): the header, the column line and its rule, then each
    partition's name, followed by one ``dSASignature`` row once it has
    been backed up.  Blank lines are ignored.  Anything else raises
    ``ValueError``.
    """
    if not isinstance(text, str):
        raise ValueError("the answer is not text")
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip() != ""]
    if lines[:3] != [_SB_HEADER, _SB_COLUMNS, _SB_RULE]:
        raise ValueError("the answer does not start with the measured header")
    found: dict[str, datetime | None] = {}
    current: str | None = None
    for line in lines[3:]:
        if _SB_PARTITION_RE.fullmatch(line):
            if line in found:
                raise ValueError("a partition is listed twice")
            found[line] = None
            current = line
            continue
        row = _SB_ROW_RE.fullmatch(line)
        if row is None or current is None or found[current] is not None:
            raise ValueError("a line is not of the measured shape")
        found[current] = datetime.strptime(row.group("when"), "%Y-%m-%d %H:%M:%S")
    if not found:
        raise ValueError("no partition is listed")
    return found


def dsa_signatures_no_older(read: object, created: datetime) -> bool:
    """True when every partition of the DC was backed up no earlier than
    the checkpoint (DESIGN-1.5 "Checkpoints", Hyper-V; MEASURED-1.5
    section 4).

    The partitions must be exactly the five of a forest root (measured):
    the domain, its Configuration, its Schema and the two DNS application
    partitions; a missing one or another one is unverified.  Each must hold a
    ``dSASignature`` whose time, turned from the DC's local time to UTC,
    is at or after ``created``.
    """
    if not isinstance(read, ShowbackupRead):
        return False
    offset = read.utc_offset_minutes
    if isinstance(offset, bool) or not isinstance(offset, int) or not -1440 < offset < 1440:
        return False
    try:
        found = parse_showbackup(read.text)
    except ValueError:
        return False
    roots = [name for name in found if name.startswith("DC=") and f"CN=Configuration,{name}" in found]
    if len(roots) != 1:
        return False
    root = roots[0]
    expected = {
        root,
        f"CN=Configuration,{root}",
        f"CN=Schema,CN=Configuration,{root}",
        f"DC=DomainDnsZones,{root}",
        f"DC=ForestDnsZones,{root}",
    }
    if set(found) != expected:
        return False
    for local in found.values():
        if local is None:
            return False
        utc = (local - timedelta(minutes=offset)).replace(tzinfo=timezone.utc)
        if utc < created:
            return False
    return True


class HyperVAdapter:
    """The Hyper-V method: a production checkpoint through the
    ``hv-checkpoint`` forced command of the Hyper-V host."""

    def __init__(
        self,
        targets: Mapping[str, HyperVTarget],
        *,
        run: Runner,
        read_genid: GenIdReader,
        read_showbackup: ShowbackupReader,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._targets = dict(targets)
        self._run = run
        self._read_genid = read_genid
        self._read_showbackup = read_showbackup
        self._clock = clock

    def _target(self, server_cfg: Mapping[str, Any]) -> HyperVTarget | None:
        if server_cfg.get("checkpoint") != "hyperv":
            return None
        return self._targets.get(str(server_cfg.get("device")))

    def checkpoint(self, server_cfg: Mapping[str, Any], kind: str) -> dict[str, str]:
        target = self._target(server_cfg)
        if target is None or kind not in CHECKPOINT_KINDS:
            raise CheckpointUnverified("the server has no Hyper-V target")
        name = f"newton-{kind}-{self._clock().astimezone(timezone.utc):%Y%m%d-%H%M%S}"
        rc, out = self._run([*target.ssh, "create", target.vm, name])
        if rc != 0:
            raise CheckpointUnverified("the Hyper-V host did not take the checkpoint")
        try:
            made = _hv_checkpoint(json.loads(out))
        except ValueError:
            made = None
        if made is None or made["name"] != name or made["vm"] != target.vm:
            raise CheckpointUnverified("the Hyper-V host answered no checkpoint of the design")
        return {"name": name, "id": made["id"]}

    def verify(
        self,
        server_cfg: Mapping[str, Any],
        cp: Mapping[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        bound = _bound(not_before)
        target = self._target(server_cfg)
        if target is None or not _kind_fits(server_cfg, kind, stage):
            return False
        name, ident = cp.get("name"), cp.get("id")
        if not isinstance(name, str) or not isinstance(ident, str):
            return False
        rc, out = self._run([*target.ssh, "list", target.vm])
        if rc != 0:
            return False
        try:
            listed = json.loads(out)
        except ValueError:
            return False
        # The forced command answers a list as an array, even of one.
        if not isinstance(listed, list):
            return False
        mine = [c for c in (_hv_checkpoint(raw) for raw in listed) if c is not None and c["id"] == ident]
        if len(mine) != 1:
            return False
        one = mine[0]
        if one["name"] != name or one["vm"] != target.vm or one["checkpoint_type"] != "ProductionOnly":
            return False
        # The checkpoint was created no earlier than the bound (the time
        # hv-checkpoint.ps1 reports, UTC to the second, the host's clock).
        try:
            created = datetime.strptime(one["created"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        if created < bound:
            return False
        if kind != "dc":
            return True
        if not dsa_signatures_no_older(self._read_showbackup(server_cfg), created):
            return False
        return _dc_read_ok(self._read_genid, server_cfg, kind)
