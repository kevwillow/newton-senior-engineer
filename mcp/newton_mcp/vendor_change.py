"""Generic vendor change driver over an injected session runner.

The driver owns the safety order: preflight, apply with the device-side
revert armed, fresh-session verification, then confirm.  It never confirms
unless verification passed, and it never reports a rollback without reading
the base configuration hash back from the device.

A confirmed change is saved after the confirm, in its own fresh session:
the saved configuration is what survives the next reboot, so a change that
was confirmed but not saved is reported as such in the outcome log and in
the ``saved`` field of the outcome.

The commit-confirm timer is read after the confirm as well.  A read that
fails, or that does not say "idle", is retried with the same bounded wait
loop the recovery uses; a change whose confirm succeeded stays confirmed
whatever the timer says, and the problem is noted in the log.

The CS-06 proof -- that the device reverts by itself when the confirm is
withheld -- is a LAB test and not a unit test: a fake runner cannot model
the device-side commit-confirm timer, so the tests here can pin the order
of the sessions only, never the revert itself.

The ops that stage a candidate say what the candidate was (Junos, which
stages a candidate configuration and reads it back): the configuration
that comes back after the commit has to be that candidate.  A commit that
is not the candidate is a partial commit or a concurrent change, and the
driver takes the revert.  The ops without a candidate do not have the
attribute, so the check is skipped for them.

The same candidate is the proof after the confirm.  The armed revert can
fire between the verify and the confirm, and the device then holds the
base configuration again while the confirm still says that the commit
went through.  The driver reads a fresh snapshot after the confirm and
compares it with the candidate: a device that differs from the verified
change is ``unknown`` and never ``confirmed``.

A session that died while it held the exclusive lock of a device leaves
the configuration database of that device locked, and every session after
it is refused with "configuration database locked".  The abort is retried
with the bounded wait of the recovery (a step of five seconds and the
same bound) until the device lets go of the lock.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from .adapters.vendor_write import (
    LintError,
    SessionSpec,
    StageResult,
    minutes_for,
    parse_lines,
    render_line,
)


RunStatus = Literal["ok", "timed_out", "unreachable", "auth_failed"]
ApplyResult = Literal["confirmed", "rolled_back", "unknown", "stale", "refused"]


@dataclass(frozen=True)
class RunOut:
    """The result of one fresh remote session."""

    status: RunStatus
    stdout: str
    stderr: str
    exit_code: int | None


Run = Callable[[SessionSpec], RunOut]


class VendorRefusal(Exception):
    """A preflight refusal whose message is safe to show the client."""


@dataclass(frozen=True)
class Snapshot:
    """One device configuration snapshot and its safety facts."""

    text: str
    base_hash: str
    reload_ok: bool
    saved_clean: bool
    pending: str


class VendorOps(Protocol):
    """The vendor-specific operations used by the generic driver."""

    platform: str

    def snapshot(self, run: Run) -> Snapshot: ...

    def stage(self, run: Run, stmts: list[list[str]]) -> StageResult: ...

    def apply(self, run: Run, stmts: list[list[str]], timeout_s: int) -> str: ...

    def confirm(self, run: Run) -> bool: ...

    def save(self, run: Run) -> bool: ...

    def abort(self, run: Run) -> bool: ...

    def pending(self, run: Run) -> str: ...

    def probe_ping(self, run: Run, host: str) -> bool: ...

    def has_line(self, snapshot_text: str, rendered_line: str) -> bool: ...


@dataclass(frozen=True)
class ApplyOutcome:
    """The terminal result of applying a stored vendor plan.

    ``saved`` says what happened to the saved configuration: True when the
    change was saved, False when the save was attempted and failed, and
    None when no save was attempted (nothing was committed, or the change
    was rolled back).
    """

    result: ApplyResult
    log: str
    failed_probe: list[str] | None
    lost_out_of_band: bool
    saved: bool | None


@dataclass(frozen=True)
class PlanData:
    """The vendor-neutral data produced while staging a plan."""

    lines: list[str]
    diff: str
    base_hash: str
    probes: list[list[str]]


class _Recorder:
    """A runner wrapper that remembers the status of every session."""

    def __init__(self, run: Run) -> None:
        self._run = run
        self.outputs: list[RunOut] = []

    def __call__(self, spec: SessionSpec) -> RunOut:
        output = self._run(spec)
        self.outputs.append(output)
        return output

    @property
    def ok(self) -> bool:
        return all(output.status == "ok" for output in self.outputs)


_RELOAD_REFUSAL = (
    "set system config-management commit-confirm action reload must be set; "
    "then commit and save"
)
_SAVED_REFUSAL = "running config differs from saved; save or discard first"
_PENDING_REFUSAL = "a commit-confirm is already pending on this device"
_NO_CHANGES_REFUSAL = (
    "the candidate configuration is the same as the running one; nothing to change"
)
_LINE_ERROR_RE = re.compile(r"NEWTON-LINE-ERROR (\d+)")
_SAVED_LOG = "the change was verified, confirmed and saved"
_NOT_SAVED_LOG = (
    "the change was verified and confirmed, but it was not saved: lost on reboot"
)
_PENDING_NOT_IDLE = "the device did not report an idle commit-confirm timer"
_NOT_SAVED_TEXT = "not saved: lost on reboot"
_DIFFERS_AFTER_CONFIRM = "the device differs from the verified change after the confirm"

# The messages a device prints when it refuses a session because its
# configuration database is locked.  A session that died while it held
# the lock leaves the device locked, and every session after it is
# refused until the device lets go of the lock.
_LOCK_MESSAGES = (
    "configuration database locked",
    "exclusive lock",
    "locked by",
)

# The refusal of the device is a line of its own that starts with
# "error:" and carries one of the messages above.  The check is on the
# refusal and never on the data the session carried: a configuration
# value that holds the phrase ("locked by") is not a lock.
_LOCK_REFUSAL_RE = re.compile(
    r"^error:.*(?:" + "|".join(_LOCK_MESSAGES) + r")",
    re.IGNORECASE,
)


def _preflight_refusal(snapshot: Snapshot) -> str | None:
    if not snapshot.reload_ok:
        return _RELOAD_REFUSAL
    if not snapshot.saved_clean:
        return _SAVED_REFUSAL
    if snapshot.pending != "idle":
        return _PENDING_REFUSAL
    return None


def _refused(log: str) -> ApplyOutcome:
    return ApplyOutcome(
        result="refused",
        log=log,
        failed_probe=None,
        lost_out_of_band=False,
        saved=None,
    )


def _unknown(log: str, failed_probe: list[str] | None) -> ApplyOutcome:
    return ApplyOutcome(
        result="unknown",
        log=log,
        failed_probe=failed_probe,
        lost_out_of_band=False,
        saved=None,
    )


def stage_plan(
    ops: VendorOps,
    run: Run,
    text: str,
    timeout_s: int,
) -> PlanData:
    """Parse, preflight and stage a change without committing it."""
    statements = parse_lines(ops.platform, text)
    minutes_for(timeout_s)

    snapshot_run = _Recorder(run)
    snapshot = ops.snapshot(snapshot_run)
    if not snapshot_run.ok:
        raise VendorRefusal("the device is unreachable")
    refusal = _preflight_refusal(snapshot)
    if refusal is not None:
        raise VendorRefusal(refusal)

    stage_run = _Recorder(run)
    staged = ops.stage(stage_run, statements)
    if not stage_run.ok:
        raise VendorRefusal("the candidate stage did not complete")
    if staged.bad_line is not None:
        raise VendorRefusal(f"statement {staged.bad_line} was rejected by the device")
    if staged.no_changes:
        raise VendorRefusal(_NO_CHANGES_REFUSAL)
    if not staged.ok:
        raise VendorRefusal("the device rejected the candidate configuration")

    lines = [render_line(ops.platform, statement) for statement in statements]
    return PlanData(
        lines=lines,
        diff=staged.diff,
        base_hash=snapshot.base_hash,
        probes=[],
    )


def _effective_probes(
    plan: Mapping[str, Any],
    claims: list[list[str]],
) -> list[list[str]]:
    stored = plan.get("probes", [])
    if not isinstance(stored, list):
        raise VendorRefusal("the stored probe list is invalid")
    probes = [list(probe) for probe in stored]
    probes.extend(list(claim) for claim in claims)
    for probe in probes:
        if not isinstance(probe, list) or len(probe) != 2:
            raise VendorRefusal("a probe is invalid")
        kind, value = probe
        if not isinstance(kind, str) or not isinstance(value, str) or not value:
            raise VendorRefusal("a probe is invalid")
        if kind not in ("ping", "config_has"):
            raise VendorRefusal("a probe is invalid")
    return probes


def _line_error(outputs: list[RunOut]) -> int | None:
    for output in outputs:
        for line in output.stdout.splitlines():
            match = _LINE_ERROR_RE.fullmatch(line.rstrip())
            if match:
                return int(match.group(1))
    return None


def _is_locked(outputs: Sequence[RunOut]) -> bool:
    """True when a session was refused because the database was locked.

    The check is on the refusal of the device and not on the data the
    session carried: a line that starts with "error:" and carries one
    of the three things the device says when its configuration database
    is locked.  A configuration value that holds the phrase ("locked
    by") is never a lock.
    """
    for output in outputs:
        text = f"{output.stdout}\n{output.stderr}"
        for line in text.splitlines():
            if _LOCK_REFUSAL_RE.match(line.strip()):
                return True
    return False


def _read_pending(ops: VendorOps, run: Run) -> str | None:
    """Read the pending state; None when the read failed.

    A read that fails and a read that says something other than "idle"
    are both a state the driver cannot use, so they are told apart from
    an idle timer only.
    """
    pending_run = _Recorder(run)
    try:
        pending = ops.pending(pending_run)
    except Exception:
        return None
    if not pending_run.ok:
        return None
    return pending


def _abort_with_retry(
    ops: VendorOps,
    run: Run,
    wait: Callable[[float], None],
    recover_wait_s: int,
) -> bool:
    """Run the abort and retry it while the database of the device is locked.

    A session that died while it held the exclusive lock of a device
    leaves the configuration database of that device locked, and the
    abort is refused with "configuration database locked" until the
    device lets go of the lock.  The retry is the bounded wait of the
    recovery: a step of five seconds and the same bound.

    The revert may be gone while the device is locked: the device may
    have rolled the change back by itself.  The pending read says so,
    and then the abort is not run again: a second rollback would roll
    back the commit of somebody else.
    """
    elapsed = 0
    while True:
        abort_run = _Recorder(run)
        aborted = ops.abort(abort_run)
        if aborted or not _is_locked(abort_run.outputs):
            return aborted
        if _read_pending(ops, run) == "idle":
            # the revert is not armed any more: the device rolled the
            # change back by itself and the abort must not run again.
            return False
        if elapsed >= recover_wait_s:
            return False
        wait(5)
        elapsed += 5


def _recover(
    ops: VendorOps,
    run: Run,
    base_hash: str,
    failed_probe: list[str] | None,
    wait: Callable[[float], None],
    recover_wait_s: int,
) -> ApplyOutcome:
    try:
        aborted = _abort_with_retry(ops, run, wait, recover_wait_s)
    except Exception:
        return _unknown("the rollback state is unknown", failed_probe)
    # The ops know whether the revert worked.  A CHR reboots into the
    # backup, so the session of the load may drop: the sessions of the
    # abort are not all "ok" even when the revert did work, so the verdict
    # of the ops is what counts and the hash below is the proof.
    abort_ok = aborted

    elapsed = 0
    snapshot_run: _Recorder | None = None
    snapshot: Snapshot | None = None
    while True:
        try:
            snapshot_run = _Recorder(run)
            snapshot = ops.snapshot(snapshot_run)
        except Exception:
            snapshot_run = None
            snapshot = None
        if snapshot_run is not None and snapshot_run.ok:
            break
        if elapsed >= recover_wait_s:
            return _unknown("the rollback state is unknown", failed_probe)
        wait(5)
        elapsed += 5

    restored = (
        abort_ok
        and snapshot is not None
        and snapshot.base_hash == base_hash
        and snapshot.pending == "idle"
    )
    if not restored:
        return _unknown("the rollback state is unknown", failed_probe)
    return ApplyOutcome(
        result="rolled_back",
        log="the device restored the base configuration",
        failed_probe=failed_probe,
        lost_out_of_band=False,
        saved=None,
    )


def _config_is_base(
    ops: VendorOps,
    run: Run,
    base_hash: str,
    wait: Callable[[float], None],
    recover_wait_s: int,
) -> bool:
    """Read the configuration hash back; True when it is the base hash.

    A rollback is never claimed from text alone.  The device's own
    configuration is read back in a fresh session, and only a hash that
    matches the base hash says that nothing was committed.

    A read that fails is not an answer.  A CHR abort loads the backup and
    the device reboots, so the first read after a line error can fail
    while the device is still down.  The read is therefore retried with
    the same bounded wait loop the recovery uses (a step of five seconds
    and the same bound).  A read that succeeds ends the wait: a hash that
    is not the base hash is an answer and not a failure.
    """
    elapsed = 0
    while True:
        try:
            snapshot_run = _Recorder(run)
            snapshot = ops.snapshot(snapshot_run)
        except Exception:
            snapshot_run = None
            snapshot = None
        if snapshot_run is not None and snapshot_run.ok:
            return snapshot.base_hash == base_hash
        if elapsed >= recover_wait_s:
            return False
        wait(5)
        elapsed += 5


def _pending_after_confirm(
    ops: VendorOps,
    run: Run,
    wait: Callable[[float], None],
    recover_wait_s: int,
) -> str | None:
    """Wait for the commit-confirm timer to say idle; None when it does.

    The confirm already succeeded, so this is a read of the device's own
    state and not a safety gate: the same bounded wait loop the recovery
    uses (a step of five seconds and the same bound) is enough.  When the
    bound runs out, the note is returned and the change stays confirmed.
    """
    elapsed = 0
    while True:
        pending = _read_pending(ops, run)
        if pending == "idle":
            return None
        if elapsed >= recover_wait_s:
            return _PENDING_NOT_IDLE
        wait(5)
        elapsed += 5


def apply_plan(
    ops: VendorOps,
    run: Run,
    plan: Mapping[str, Any],
    claims: list[list[str]],
    *,
    wait: Callable[[float], None] = time.sleep,
    recover_wait_s: int = 150,
) -> ApplyOutcome:
    """Apply a stored plan with preflight, fresh verify and safe recovery."""
    try:
        text = plan["uci_batch"]
        base_hash = plan["base_hash"]
        timeout_s = plan["timeout_s"]
        if not isinstance(text, str) or not isinstance(base_hash, str):
            raise TypeError("invalid plan")
        statements = parse_lines(ops.platform, text)
        minutes_for(timeout_s)
        probes = _effective_probes(plan, claims)
    except LintError:
        return _refused("the change text was refused")
    except (KeyError, TypeError, ValueError, VendorRefusal):
        return _refused("the stored plan is invalid")

    preflight_run = _Recorder(run)
    snapshot = ops.snapshot(preflight_run)
    if not preflight_run.ok:
        return _refused("the device is unreachable")
    refusal = _preflight_refusal(snapshot)
    if refusal is not None:
        return _refused(refusal)
    if snapshot.base_hash != base_hash:
        return ApplyOutcome(
            result="stale",
            log="the device configuration changed after the plan was staged",
            failed_probe=None,
            lost_out_of_band=False,
            saved=None,
        )

    apply_run = _Recorder(run)
    applied = ops.apply(apply_run, statements, timeout_s)
    if applied == "armed_failed":
        # No change line ran: the revert could not be armed, so there is
        # nothing to undo.  The ops removed the backup it had made, so the
        # driver must not load it: the hash is read back instead, and the
        # base hash says that nothing was committed.
        if not _config_is_base(ops, run, base_hash, wait, recover_wait_s):
            return _unknown("the rollback state is unknown", None)
        return ApplyOutcome(
            result="rolled_back",
            log="the revert could not be armed; nothing was changed",
            failed_probe=None,
            lost_out_of_band=False,
            saved=None,
        )
    if applied == "line_error":
        # The ops loaded the backup before they answered, so the device is
        # rebooting and the session of the load may have dropped: that is
        # the load and not a failure.  The hash is read back and it
        # decides, so a dropped session never forces a second load.
        line = _line_error(apply_run.outputs)
        if line is None:
            log = "a statement was rejected by the device; nothing was committed"
        else:
            log = f"statement {line} was rejected by the device; nothing was committed"
        if not _config_is_base(ops, run, base_hash, wait, recover_wait_s):
            return _unknown("the rollback state is unknown", None)
        return ApplyOutcome(
            result="rolled_back",
            log=log,
            failed_probe=None,
            lost_out_of_band=False,
            saved=None,
        )
    if applied != "committed" or not apply_run.ok:
        return _recover(
            ops,
            run,
            base_hash,
            None,
            wait,
            recover_wait_s,
        )

    verify_run = _Recorder(run)
    verify_snapshot = ops.snapshot(verify_run)
    if not verify_run.ok:
        return _recover(
            ops,
            run,
            base_hash,
            ["snapshot"],
            wait,
            recover_wait_s,
        )

    # The ops that stage a candidate tell the driver what the candidate
    # was (Junos): the configuration that comes back has to be that
    # candidate.  A commit that is not the candidate is a partial commit
    # or a concurrent change, and the revert is taken now.  The ops
    # without a candidate (VyOS, RouterOS) do not have the attribute, so
    # the check is skipped for them.
    expected_hash = getattr(ops, "expected_hash", None)
    if expected_hash is not None and verify_snapshot.base_hash != expected_hash:
        return _recover(
            ops,
            run,
            base_hash,
            None,
            wait,
            recover_wait_s,
        )

    for probe in probes:
        kind, value = probe
        if kind == "ping":
            probe_run = _Recorder(run)
            passed = ops.probe_ping(probe_run, value)
            if not passed or not probe_run.ok:
                return _recover(
                    ops,
                    run,
                    base_hash,
                    list(probe),
                    wait,
                    recover_wait_s,
                )
        elif not ops.has_line(verify_snapshot.text, value):
            return _recover(
                ops,
                run,
                base_hash,
                list(probe),
                wait,
                recover_wait_s,
            )

    confirm_run = _Recorder(run)
    confirmed = ops.confirm(confirm_run)
    if not confirmed or not confirm_run.ok:
        return _recover(
            ops,
            run,
            base_hash,
            None,
            wait,
            recover_wait_s,
        )

    # The confirm does not prove that the change is still on the device:
    # the armed revert can fire between the verify and the confirm, and
    # the device then holds the base configuration again while the
    # confirm still says that the commit went through.  The ops that
    # stage a candidate know the hash of that candidate, so the
    # configuration that comes back after the confirm is read in a
    # fresh session and compared with it.
    if expected_hash is not None:
        after_run = _Recorder(run)
        try:
            after = ops.snapshot(after_run)
        except Exception:
            after = None
        if (
            after is None
            or not after_run.ok
            or after.base_hash != expected_hash
            or after.pending != "idle"
        ):
            return _unknown(_DIFFERS_AFTER_CONFIRM, None)

    pending_note = _pending_after_confirm(ops, run, wait, recover_wait_s)

    save_run = _Recorder(run)
    try:
        saved = ops.save(save_run)
    except Exception:
        saved = False
    if not saved or not save_run.ok:
        log = _NOT_SAVED_LOG
        saved_state: bool | None = False
    else:
        log = _SAVED_LOG
        saved_state = True
    if pending_note is not None:
        log = f"{log}; {pending_note}"
    return ApplyOutcome(
        result="confirmed",
        log=log,
        failed_probe=None,
        lost_out_of_band=False,
        saved=saved_state,
    )


def change_status(
    ops: VendorOps,
    run: Run,
    base_hash: str | None = None,
) -> dict[str, Any]:
    """Read the device's pending and saved state without confirming it.

    The state says whether a commit-confirm is pending, whether the
    running configuration is the base configuration (when the caller
    knows the base hash) and whether the running configuration is saved.
    A configuration that is not saved is lost on the next reboot.
    """
    pending_run = _Recorder(run)
    try:
        pending = ops.pending(pending_run)
    except Exception:
        pending = "unknown"
    else:
        if not pending_run.ok:
            pending = "unknown"

    saved: bool | None = None
    matches: bool | None = None
    try:
        snapshot_run = _Recorder(run)
        snapshot = ops.snapshot(snapshot_run)
    except Exception:
        pass
    else:
        if snapshot_run.ok:
            saved = snapshot.saved_clean
            if base_hash is not None:
                matches = snapshot.base_hash == base_hash

    return {
        "pending": pending,
        "config_matches_base": matches,
        "saved": saved,
    }


def plan_status_text(state: Mapping[str, Any]) -> str:
    """The plan's status as one line of owner-facing text.

    A running configuration that is not saved is spelled out: the change
    is on the device now and gone after the next reboot.
    """
    pending = state.get("pending")
    pending_text = pending if isinstance(pending, str) and pending else "unknown"
    saved = state.get("saved")
    if saved is False:
        saved_text = _NOT_SAVED_TEXT
    elif saved is True:
        saved_text = "saved"
    else:
        saved_text = "the saved state is unknown"
    return f"pending: {pending_text}; {saved_text}"


def abort_change(
    ops: VendorOps,
    run: Run,
    base_hash: str | None,
    *,
    wait: Callable[[float], None] = time.sleep,
    recover_wait_s: int = 150,
) -> dict[str, Any]:
    """Abort an armed change, then read back whether the base hash returned.

    The abort waits for the lock of the device the way the recovery
    does: a session that died while it held the exclusive lock leaves
    the configuration database of the device locked, and the abort is
    refused until the device lets go of the lock.
    """
    try:
        aborted = _abort_with_retry(ops, run, wait, recover_wait_s)
    except Exception:
        return {"aborted": False, "restored": None}
    # The ops know whether the revert worked; a CHR reboots into the
    # backup and the session of the load may drop, so the sessions of the
    # abort are not all "ok" even when it did.
    abort_ok = aborted

    restored: bool | None = None
    try:
        snapshot_run = _Recorder(run)
        snapshot = ops.snapshot(snapshot_run)
    except Exception:
        snapshot_run = None
        snapshot = None
    if (
        snapshot_run is not None
        and snapshot_run.ok
        and snapshot is not None
        and base_hash is not None
    ):
        restored = snapshot.base_hash == base_hash

    return {"aborted": abort_ok, "restored": restored}
