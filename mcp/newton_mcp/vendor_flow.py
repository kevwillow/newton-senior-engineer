"""The MCP dispatch glue for vendor write devices.

The functions here keep the generic driver in ``vendor_change`` separate from
the OpenWrt protocol in ``server``.  A vendor approval is enforced by this
host; the device does not re-check the approval token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, cast
from uuid import uuid4

from . import approval_gate as _gate
from . import envelope as _envelope
from . import explanation as _explanation
from . import receipts as _receipts
from .adapters import platform_redact as _platform_redact
from .adapters.junos_write import JunosOps
from .adapters.routeros_write import MIN_WINDOW_S as ROUTEROS_MIN_WINDOW_S
from .adapters.routeros_write import RouterosOps
from .adapters.vendor_ssh import SshSessionRunner
from .adapters.vendor_write import LintError, StageResult, VyosOps, minutes_for
from .plan import compute_plan_hash
from .vendor_change import (
    ApplyOutcome,
    Run,
    Snapshot,
    VendorOps,
    VendorRefusal,
    abort_change,
    apply_plan,
    change_status,
    stage_plan,
)

if TYPE_CHECKING:
    from .server import Device, NewtonService


# The operations of every vendor platform that may write.  The device
# says which platform it speaks; the flow picks the operations of that
# platform and refuses a platform it has none for.
OPS_BY_PLATFORM: dict[str, Any] = {
    "vyos": VyosOps,
    "routeros": RouterosOps,
    "junos": JunosOps,
}


def _raise(message: str) -> NoReturn:
    from .server import NewtonError

    raise NewtonError(message)


def _ops_for(platform: str) -> Any:
    """The operations of one vendor platform."""
    factory = OPS_BY_PLATFORM.get(platform)
    if factory is None:
        _raise(f"platform {platform} has no vendor write operations")
    return factory()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _runner(device: Device) -> Run:
    return SshSessionRunner(device)


def _write_plan(svc: NewtonService, record: dict[str, Any]) -> str | None:
    plans = svc.state / "plans"
    refusal = _receipts.check_state_write_path(plans, svc.state)
    if refusal is not None:
        return refusal
    plans.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = plans / f"{record['session_id']}.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)
    return None


def plan(
    svc: NewtonService,
    device: Device,
    name: str,
    text: str,
    timeout_s: int,
    explanation: Any,
    owner_confirmed: Any,
) -> dict[str, Any]:
    """Stage one vendor change and persist its plan record."""
    from .server import check_explanation_inputs

    if not isinstance(text, str):
        _raise("uci_batch must be a string")
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, int)
        or not 60 <= timeout_s <= 600
    ):
        _raise("timeout_s must be an integer 60..600")

    stored_explanation = check_explanation_inputs(
        explanation,
        owner_confirmed,
        _explanation.change_lines(text),
        platform=device.platform,
    )
    staged_at = _now()
    ops = _ops_for(device.platform)
    try:
        staged = stage_plan(
            ops,
            _runner(device),
            text,
            timeout_s,
        )
    except VendorRefusal as exc:
        _raise(str(exc))
    except LintError as exc:
        _raise(str(exc))

    probes = list(staged.probes) + _explanation.claim_probes(
        stored_explanation, device.platform
    )
    if not _explanation.claims_match_probes(
        probes, stored_explanation, device.platform
    ):
        _raise("the plan's claims are not its last probes")

    session_id = uuid4().hex
    created_at = _now()
    requires_approval = _gate.plan_requires_approval(
        device,
        router_requires=True,
        policy_requires=True,
    )
    router_digest = hashlib.sha256(
        (staged.diff + staged.base_hash).encode("utf-8")
    ).hexdigest()
    record: dict[str, Any] = {
        "device": name,
        "host": device.host,
        "session_id": session_id,
        "uci_batch": "\n".join(staged.lines),
        "diff": staged.diff,
        "probes": probes,
        "timeout_s": timeout_s,
        "base_hash": staged.base_hash,
        "requires_approval": requires_approval,
        "router_digest": router_digest,
        "explanation": stored_explanation,
        "owner_confirmed_in_chat": True,
        "reasons": [f"vendor change on {device.platform}"],
        "created_at": created_at,
        "staged_at": staged_at,
        "platform": device.platform,
        "router_leash": "vendor",
        "router_profile": device.profile,
        "router_requires_approval": True,
        "router_sections": [],
        # Sealed into the plan hash; vendors have no fw4 check.
        "staged_check": {"fw4": "not-checked", "reason": "vendor-platform", "not_checked": []},
    }
    record["plan_hash"] = compute_plan_hash(record)
    refusal = _write_plan(svc, record)
    if refusal is not None:
        return {"error": refusal}

    from .server import write_audit

    intent = stored_explanation["intent"]
    write_audit(
        "newton_explanation",
        name,
        f"session={session_id} intent_len={len(intent)} "
        f"intent_sha256={hashlib.sha256(intent.encode('utf-8')).hexdigest()[:12]}",
    )
    reply: dict[str, Any] = {
        "session_id": session_id,
        "plan_hash": record["plan_hash"],
        "base_hash": record["base_hash"],
        "touched_configs": [],
        "requires_approval": requires_approval,
        "approval_required": requires_approval,
        "risk": "medium",
        "diff": _envelope.envelope(f"{name}:plan", staged.diff),
        "backup_path": "",
    }
    if device.platform == "routeros":
        # A CHR has no soft revert: the undo loads the backup and reboots.
        # The window of the revert is the timeout of the plan, and never
        # less than two minutes, so the reply says which window is armed.
        reply["undo"] = "reboot into the backup"
        reply["revert_window_s"] = max(timeout_s, ROUTEROS_MIN_WINDOW_S)
    if device.platform == "junos":
        # A Junos holds the revert itself: the apply commits with "commit
        # confirmed N" and the device rolls the commit back when nobody
        # confirms it.  There is no undo to describe, so the reply says
        # how long the revert is armed: the window is the timeout of the
        # plan, rounded up to the minute the device is told.
        reply["revert_window_minutes"] = minutes_for(timeout_s)
    return reply


def _validated_record(
    svc: NewtonService,
    device: Device,
    name: str,
    session_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from .server import require_session

    require_session(session_id)
    record_path = svc.state / "plans" / f"{session_id}.json"
    try:
        value = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _raise("no plan record for this device and session")
    if not isinstance(value, dict):
        _raise("plan record was modified or is invalid; plan again")
    record = value
    if record.get("device") != name:
        _raise("no plan record for this device and session")
    if record.get("host") != device.host or record.get("session_id") != session_id:
        _raise("plan device or host changed since planning; plan again")
    try:
        actual_plan_hash = compute_plan_hash(record)
    except (TypeError, ValueError):
        _raise("plan record was modified or is invalid; plan again")
    stored_plan_hash = record.get("plan_hash")
    if not isinstance(stored_plan_hash, str) or not hmac.compare_digest(
        stored_plan_hash, actual_plan_hash
    ):
        _raise("plan record was modified or is invalid; plan again")

    timeout_s = record.get("timeout_s")
    probes = record.get("probes")
    base_hash = record.get("base_hash")
    router_digest = record.get("router_digest")
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, int)
        or not 60 <= timeout_s <= 600
        or not isinstance(probes, list)
        or not all(
            isinstance(probe, list)
            and all(isinstance(field, str) for field in probe)
            for probe in probes
        )
        or not isinstance(base_hash, str)
        or len(base_hash) != 64
        or any(char not in "0123456789abcdef" for char in base_hash)
        or not isinstance(router_digest, str)
        or len(router_digest) != 64
        or any(char not in "0123456789abcdef" for char in router_digest)
        or not isinstance(record.get("requires_approval"), bool)
    ):
        _raise("plan record was modified or is invalid; plan again")

    # These checks duplicate the OpenWrt apply checks so that path stays
    # byte-for-byte unchanged while the vendor path reparses platform claims.
    if record.get("owner_confirmed_in_chat") is not True:
        _raise(
            "plan record has no owner_confirmed_in_chat; plan again after "
            "explaining to the owner and asking them"
        )
    try:
        checked = _explanation.parse_explanation(
            record.get("explanation"),
            change_lines=_explanation.change_lines(str(record.get("uci_batch", ""))),
            platform=device.platform,
        )
    except _explanation.ExplanationError as exc:
        _raise(f"plan record has an invalid explanation ({exc}); plan again")
    if not _explanation.claims_match_probes(probes, checked, device.platform):
        _raise(
            "plan record does not carry the explanation's expect claims as its "
            "last probes; plan again"
        )
    if record["requires_approval"] is not True and not _gate.lab_carve_out_applies(
        device
    ):
        _raise(
            "this device requires approval for every change but the plan record "
            "says none is needed; plan again"
        )
    return record, checked


class _TrackingOps:
    """Delegate vendor operations and remember when apply was called."""

    def __init__(self, ops: VendorOps, reached: list[bool]) -> None:
        self._ops = ops
        self._reached = reached

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ops, name)

    def apply(self, run: Run, statements: list[list[str]], timeout_s: int) -> str:
        self._reached[0] = True
        return self._ops.apply(run, statements, timeout_s)


def _failed_claim(
    outcome: ApplyOutcome,
    explanation: dict[str, Any],
    platform: str,
) -> dict[str, Any] | None:
    if outcome.failed_probe is None:
        return None
    wanted = _explanation.claim_probes(explanation, platform)
    for index, probe in enumerate(wanted, start=1):
        if probe != outcome.failed_probe:
            continue
        claim = explanation["expect"][index - 1]
        reason = _explanation.describe_failed_claim(claim, "absent")
        return {"claim": index, "text": f"expect claim {index} failed: {reason}"}
    return None


def apply(
    svc: NewtonService,
    device: Device,
    name: str,
    session_id: str,
) -> dict[str, Any]:
    """Apply one vendor plan with host-only approval and device rollback.

    On a vendor device the MCP host validates and consumes the approval, but
    the token is not sent to or checked by the device.
    """
    record, explanation = _validated_record(svc, device, name, session_id)
    requires_approval = record["requires_approval"] is True
    if requires_approval:
        svc.consume_approval(name, session_id, record)

    reached = [False]
    try:
        outcome = apply_plan(
            cast(VendorOps, _TrackingOps(_ops_for(device.platform), reached)),
            _runner(device),
            record,
            [],
        )
    finally:
        if requires_approval:
            svc.settle_approval(session_id, reached_router=reached[0])

    if outcome.result in ("stale", "refused"):
        _raise(outcome.log)
    result: dict[str, Any] = {
        "result": outcome.result,
        "log": _envelope.envelope(f"{name}:apply", outcome.log),
        "lost_out_of_band": outcome.lost_out_of_band,
    }
    failed = _failed_claim(outcome, explanation, device.platform)
    if failed is not None:
        result["failed_claim"] = failed
    return result


def status(
    svc: NewtonService,
    device: Device,
    name: str,
    session_id: str,
) -> dict[str, Any]:
    """Read the vendor device's pending state without confirming it."""
    from .server import require_session

    require_session(session_id)
    state = change_status(_ops_for(device.platform), _runner(device))
    exit_code = 0 if state["pending"] != "unknown" else 1
    text = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return {
        "exit_code": exit_code,
        "log": _envelope.envelope(f"{name}:status", text),
    }


def _base_hash(svc: NewtonService, session_id: str) -> str | None:
    try:
        value = json.loads(
            (svc.state / "plans" / f"{session_id}.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    base_hash = value.get("base_hash")
    return base_hash if isinstance(base_hash, str) else None


def abort(
    svc: NewtonService,
    device: Device,
    name: str,
    session_id: str,
) -> dict[str, Any]:
    """Abort a vendor change and report whether the base hash returned."""
    from .server import require_session

    require_session(session_id)
    state = abort_change(
        _ops_for(device.platform),
        _runner(device),
        _base_hash(svc, session_id),
    )
    exit_code = 0 if state["aborted"] else 1
    text = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return {
        "exit_code": exit_code,
        "log": _envelope.envelope(f"{name}:abort", text),
    }


def backup(
    svc: NewtonService,
    device: Device,
    name: str,
) -> dict[str, Any]:
    """Save a redacted vendor running configuration locally."""
    snapshot = _ops_for(device.platform).snapshot(_runner(device))
    text = _platform_redact.redact(device.platform, snapshot.text)
    backups = svc.state / "backups"
    refusal = _receipts.check_state_write_path(backups, svc.state)
    if refusal is not None:
        _raise(refusal)
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = backups / f"{device.name}-{timestamp}.txt"
    temporary = target.with_suffix(".txt.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)
    return {
        "backup_path": _envelope.envelope(f"{name}:backup", str(target)),
        "config_files": ["running-config"],
    }
