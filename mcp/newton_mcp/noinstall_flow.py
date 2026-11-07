"""The plan of a no-install device.

The allowlist of :mod:`newton_mcp.noinstall_checks` decides what Newton
may do by itself: a change of an allowlisted class becomes an auto plan
(mode ``auto``), and every other change becomes an owner script (the
owner flow, :mod:`newton_mcp.owner_flow`).

The auto plan is planned from ONE fresh limited session: the settings
the change touches are copied to the Newton computer, the change is
resolved against that copy (an ``@type[k]`` address names the section
the router holds at that index, counted from 0), the diff is rendered
from it and the policy judges the change.  The record carries the
fields the installed record has, so the approval machinery works on it
unchanged, plus the no-install ones: the mode, the ops, the checks and
the list of what Newton cannot verify.

Nothing is written to the router here: the plan is a plan.  The apply
of an auto plan comes later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import change_classes
from . import consequences
from . import envelope
from . import explanation as _explanation
from . import grants as _grants
from . import noinstall_checks
from . import noinstall_read
from . import owner_backup
from . import owner_flow
from . import owner_ops
from . import owner_records
from . import owner_verify
from . import plan as _plan
from . import rpcd_txn
from . import owner_script
from . import policy
from . import server as _server
from .adapters import openwrt_rpcd as rpcd
from .server import NewtonError


#: The leash code of an auto plan: the rpcd user of the no-install mode.
AUTO_LEASH = "rpcd"

#: The mode of an auto plan.
AUTO_MODE = "auto"

#: The profile every no-install record carries.
PROFILE = "no-install"

#: The states the apply of an auto plan ends in.  These are the words
#: the callers of the installed apply know.
CONFIRMED = "confirmed"
ROLLED_BACK = "rolled_back"
NOT_APPLIED = "not_applied"
UNKNOWN = "unknown"

#: The verdict words of an owner-script run, as the status answers them.
#: The run of an owner script carries its verdict, not an outcome.
VERDICT_RESULTS = {
    "CONFIRMED": CONFIRMED,
    "ROLLED BACK": ROLLED_BACK,
    "NOT APPLIED": NOT_APPLIED,
    "KEPT": UNKNOWN,
    "UNKNOWN": UNKNOWN,
}

#: The receipt word of every state that has one.  A change that was
#: never applied leaves no receipt, exactly as on an installed device.
RECEIPT_OUTCOMES = {
    CONFIRMED: "confirmed",
    ROLLED_BACK: "rolled_back",
    UNKNOWN: "unknown",
}

#: The line the receipt carries for every state, in the words the
#: installed apply uses.
RECEIPT_LINES = {
    CONFIRMED: "CONFIRMED session={0}",
    ROLLED_BACK: "ROLLBACK WINDOW PASSED session={0}",
    UNKNOWN: "OUTCOME UNKNOWN session={0}",
}

#: How often the pending detector is polled while the window closes.
SETTLE_POLL_S = 5.0

#: The timeout of the session the checks run in.
LOGIN_TIMEOUT_S = 30

#: The timeout of the session the checks run in.  The internet check
#: waits out the settle and its retries, and the class checks run
#: after it, so the session has to outlive that whole budget: a
#: session that is gone would answer every later probe with "could
#: not run".
CHECK_TIMEOUT_S = (
    LOGIN_TIMEOUT_S
    + noinstall_checks.INTERNET_SETTLE_S
    + noinstall_checks.INTERNET_WAIT_MAX_S
)

#: The result of a plan that is being applied right now.
IN_PROGRESS = "in_progress"

#: What the owner is told while the change is being applied.
IN_PROGRESS_NOTE = (
    "the change is being applied; the router undoes it unless Newton "
    "confirms"
)


# ---- the helpers -----------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    """The one byte form of a JSON document."""
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _types_of(backup: Any) -> dict[tuple[str, str], str]:
    """The type of every section the router holds now.

    The type of a section the batch creates is the batch's own, so this
    map only fills in what the router knows.
    """
    types: dict[tuple[str, str], str] = {}
    for config, sections in getattr(backup, "configs", {}).items():
        if not isinstance(sections, Mapping):
            continue
        for name, entry in sections.items():
            if not isinstance(entry, Mapping):
                continue
            section_type = entry.get(".type")
            if isinstance(section_type, str) and section_type:
                types[(config, name)] = section_type
    return types


def _check_names(class_checks: Any) -> list[str]:
    """The names of the mandatory and the optional checks, in order."""
    names: list[str] = []
    for check in class_checks:
        for one in list(check.mandatory) + list(check.optional):
            if one.kind not in names:
                names.append(one.kind)
    return names


def _probe_specs(class_checks: Any) -> list[list[str]]:
    """The probes the mandatory checks run, as the approval shows them.

    A probe is the probe and its arguments, the same shape the
    installed records use: the display joins the fields with spaces.
    """
    probes: list[list[str]] = []
    for check in class_checks:
        for one in check.mandatory:
            if one.probe is None:
                continue
            probes.append([one.probe, *one.args])
    return probes


def _take_backup(factory: Any, device: Any, uci_batch: str) -> Any:
    """The backup of the configs the batch touches, or a refusal.

    The configs are the ones the BATCH names: the record is what is
    being checked, so it never decides what is read.
    """
    try:
        configs = sorted(owner_flow.configs_of(uci_batch))
        creates = owner_flow.creates_of(uci_batch)
    except owner_flow.OwnerFlowError as exc:
        raise NewtonError(str(exc)) from None
    try:
        return owner_backup.take(factory, device, configs, creates=creates)
    except owner_backup.BackupError as exc:
        raise NewtonError(str(exc)) from None


def _grant_could_cover(device_name: str, uci_batch: str) -> bool:
    """Could a live grant cover this batch?

    The answer is decided HERE, before the router is read: the router
    may be read before the owner's yes ONLY when a live grant could
    cover the change.  A grant covers the changes Newton applies
    itself, so the batch must be one of them: no list verb (the
    transaction engine has no list verb), no other verb, and not HIGH.

    On a no-install router Newton applies only the allowlisted classes
    (:data:`noinstall_checks.AUTO_APPLY`), so a grant of any other
    class covers nothing here: those classes are ignored, and a change
    of a class outside the allowlist is never covered.

    The class of a change of a section the router already holds needs
    the type the router holds, and the router is not read yet, so the
    batch is classified with an OPTIMISTIC type map: every section the
    batch touches gets the type that would make it grantable within
    the grant's classes.  The grant has to cover that class.
    """
    try:
        record = _grants.load_live_grant(device_name)
    except (OSError, RuntimeError, ValueError):
        return False
    if record is None:
        return False
    granted = record.get("classes")
    if not isinstance(granted, list) or not granted:
        return False
    classes = [
        name for name in granted if name in noinstall_checks.AUTO_APPLY
    ]
    if not classes:
        # the grant allows no class Newton applies itself here
        return False
    if change_classes.uses_a_list_verb(uci_batch):
        # a list verb is an owner script: a grant never covers one
        return False
    types = change_classes.optimistic_types(uci_batch, classes)
    classification = change_classes.classify(uci_batch, types=types)
    if not classification.grantable or classification.high:
        return False
    if not set(classification.classes) <= set(noinstall_checks.AUTO_APPLY):
        # the change touches a class Newton never applies itself
        return False
    try:
        return _grants.covers(device_name, classification) is not None
    except (OSError, RuntimeError, ValueError):
        return False


# ---- the plan --------------------------------------------------------------


def plan(
    svc: Any,
    device_name: str,
    uci_batch: str,
    window_s: int = 180,
    *,
    explanation: Any,
    owner_confirmed_in_chat: Any,
    client_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Plan a change on a no-install router.

    The allowlist decides: a change Newton may apply itself becomes an
    auto plan, and every other change becomes an owner script.  The
    owner's yes in the chat (or a live grant) and the agent's
    explanation come before the router is read, exactly as on an
    installed device.
    """
    if not isinstance(device_name, str) or not device_name:
        raise NewtonError("the device name must be text")
    device = svc.device(device_name, allow_noinstall=True)
    if device.access != "no-install":
        raise NewtonError(
            "this device does not use no-install access; the no-install "
            "plan is for a router Newton cannot manage"
        )
    if device.platform != "openwrt":
        raise NewtonError("a no-install plan is only for OpenWrt routers")
    if not isinstance(uci_batch, str):
        raise NewtonError("uci_batch must be a string")
    if isinstance(window_s, bool) or not isinstance(window_s, int):
        raise NewtonError("the window must be an integer number of seconds")
    if not owner_script.WINDOW_MIN_S <= window_s <= owner_script.WINDOW_MAX_S:
        raise NewtonError(
            "the window must be {0}..{1} seconds".format(
                owner_script.WINDOW_MIN_S, owner_script.WINDOW_MAX_S
            )
        )
    factory = client_factory or noinstall_read.default_client_factory

    # the owner's yes in the chat and the agent's explanation come
    # before any device contact.  A live grant is the owner's consent
    # for a change Newton applies itself, so it waives the chat
    # yes -- but never for an owner script, which is checked below.
    #
    # The class of a change of a section the router ALREADY holds needs
    # the type the router holds, so such a grant is answered after the
    # router was read.  The router is read for that only when a grant
    # is on disk: a request with no grant and no chat yes is still
    # refused before any device contact.
    change_lines = _explanation.change_lines(uci_batch)
    waived = _server._grant_waives_chat(
        device_name, uci_batch, owner_confirmed_in_chat
    )
    backup = None
    if owner_confirmed_in_chat is not True:
        # The router may be read before the owner's yes ONLY when a
        # live grant could cover the change.  The gate does not depend
        # on what the grant waives: a grant covers the changes Newton
        # applies itself, and nothing else.  So the change is weighed
        # HERE, before any device contact, whatever the grant says
        # about it.
        if not _server._grant_can_waive_chat(device_name):
            raise NewtonError(_server.OWNER_CONFIRMATION_HELP)
        # A grant is on disk.  It may cover this change: the router may
        # be read before the owner's yes ONLY then.  That is decided
        # HERE, before any device contact: the batch is classified with
        # an optimistic type map and the grant has to cover it.
        if not _grant_could_cover(device_name, uci_batch):
            raise NewtonError(_server.OWNER_CONFIRMATION_HELP)
        # the explanation is checked first (a grant
        # waives the owner's yes, never the explanation), then the
        # router is read for the types the class of the change needs
        _server.check_explanation_inputs(
            explanation, True, change_lines, waived=True
        )
        backup = _take_backup(factory, device, uci_batch)
        waived = _server._grant_waives_chat(
            device_name,
            uci_batch,
            owner_confirmed_in_chat,
            types=_types_of(backup),
        )
    stored_explanation = _server.check_explanation_inputs(
        explanation,
        owner_confirmed_in_chat,
        change_lines,
        waived=waived,
    )

    try:
        configs = sorted(owner_flow.configs_of(uci_batch))
        creates = owner_flow.creates_of(uci_batch)
    except owner_flow.OwnerFlowError as exc:
        raise NewtonError(str(exc)) from None
    if backup is None:
        backup = _take_backup(factory, device, uci_batch)

    try:
        ops = owner_ops.parse_batch(uci_batch, backup, device)
    except owner_ops.OwnerScriptError as exc:
        raise NewtonError(str(exc)) from None
    diff = owner_ops.render_diff(ops, backup)
    facts = owner_flow.section_facts(backup)
    try:
        decision = policy.classify(device, uci_batch, diff, facts)
    except ValueError as exc:
        raise NewtonError(f"the change cannot be judged: {exc}") from None
    reasons = list(decision.get("reasons", []))
    risk = str(decision.get("risk", "low"))

    types = _types_of(backup)
    auto, reason = noinstall_checks.auto_apply_decision(
        uci_batch, types, risk=risk
    )
    if auto:
        # The transaction engine is what talks to the router, so a
        # change it cannot carry is not a change Newton applies itself:
        # the plan says so here, instead of promising an apply that
        # cannot happen.
        carried, why_not = txn_ops(ops, _sections_of(backup), types)
        if not carried:
            auto = False
            reason = noinstall_checks.OWNER_SCRIPT_REASON + why_not
    if not auto:
        if waived and owner_confirmed_in_chat is not True:
            # a grant covers the changes Newton applies itself.  An
            # owner script is the owner's own bytes, so it always needs
            # the owner's yes in the chat.
            raise NewtonError(_server.OWNER_CONFIRMATION_HELP)
        try:
            result = owner_flow.plan(
                svc,
                device_name,
                uci_batch,
                window_s,
                explanation=explanation,
                owner_confirmed_in_chat=owner_confirmed_in_chat,
                client_factory=factory,
            )
        except owner_flow.OwnerFlowError as exc:
            raise NewtonError(str(exc)) from None
        result["auto_apply_reason"] = reason
        return result

    # The checks are built from the RESOLVED batch, the same one the
    # apply runs its checks on: an address like "@dnsmasq[0]" is a
    # section the router holds, and a check on the unresolved batch
    # would look at a section that does not exist.
    resolved_batch = "\n".join(owner_ops.batch_lines(ops))
    class_checks = noinstall_checks.checks_for(resolved_batch, types)
    checks = _check_names(class_checks)
    not_verified = owner_flow.not_verified(stored_explanation)
    for check in class_checks:
        for one in check.optional:
            if not one.runnable:
                not_verified.append(
                    f"the {one.kind} check cannot run in no-install access"
                )
    ops_out = [list(op) for op in owner_ops.to_script_ops(ops)]
    base_hash = _sha256(_canonical(backup.configs))
    sid = owner_flow.new_id()
    record = {
        "device": device_name,
        "host": device.host,
        "session_id": sid,
        "uci_batch": uci_batch,
        "diff": diff,
        "probes": _probe_specs(class_checks)
        + _explanation.claim_probes(stored_explanation, "openwrt"),
        "timeout_s": window_s,
        "reboot_line": owner_flow.REBOOT_LINE.format(window_s),
        "base_hash": base_hash,
        "requires_approval": True,
        "explanation": stored_explanation,
        "owner_confirmed_in_chat": not waived,
        "reasons": reasons,
        "risk": risk,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "staged_at": None,
        "manifest_checks": [],
        "router_leash": AUTO_LEASH,
        "router_profile": PROFILE,
        "router_requires_approval": True,
        "router_sections": sorted(
            {f"{op.config}.{op.section}" for op in ops}
        ),
        "staged_check": {
            "fw4": "not-checked",
            "reason": "no-install",
            "not_checked": [],
        },
        "platform": "openwrt",
        # the no-install bookkeeping, which is not hash-bound
        "mode": AUTO_MODE,
        "ops": ops_out,
        "checks": checks,
        "not_verified": not_verified,
        # the type of every section of the router the change touches:
        # the class of a change of a section the router already holds
        # needs it, and the grant that covers the change is decided
        # from it
        "section_types": {
            f"{config}.{section}": section_type
            for (config, section), section_type in types.items()
            if (config, section) in {(op.config, op.section) for op in ops}
        },
    }
    if waived:
        record["consent_basis"] = "grant"
    # The digest binds the router facts of the record: the ops, the
    # type of every section the change touches and the risk the policy
    # gave the change.  It is computed over the record itself, so the
    # types and the risk are in it.
    record["router_digest"] = _router_digest(record)
    record["plan_hash"] = _server.compute_plan_hash(record)
    owner_flow.write_record(Path(svc.state), record)

    return {
        "mode": AUTO_MODE,
        "device": device_name,
        "session_id": sid,
        "plan_hash": record["plan_hash"],
        "base_hash": base_hash,
        "timeout_s": window_s,
        "touched_configs": list(configs),
        "requires_approval": True,
        "approval_required": True,
        "router_requires_approval": True,
        "approval_reasons": _server.returned_approval_reasons(
            reasons, uci_batch, diff
        ),
        "risk": risk,
        "consent_basis": "grant" if waived else "chat",
        "what_this_does": consequences.describe(uci_batch),
        "smaller_alternatives": consequences.alternatives(uci_batch),
        "diff": envelope.envelope(f"{device_name}:plan", diff),
        "checks": checks,
        "reboot_line": owner_flow.REBOOT_LINE.format(window_s),
        "not_verified": not_verified,
        "auto_apply_reason": reason,
    }


# ---- the ops of the transaction --------------------------------------------


def _sections_of(backup: Any) -> set[tuple[str, str]]:
    """The sections the router holds now."""
    sections: set[tuple[str, str]] = set()
    for config, entries in getattr(backup, "configs", {}).items():
        if not isinstance(entries, Mapping):
            continue
        for name in entries:
            sections.add((str(config), str(name)))
    return sections


def txn_ops(
    ops: Sequence[owner_ops.OwnerOp],
    existing: set[tuple[str, str]],
    types: Mapping[tuple[str, str], str] | None = None,
) -> tuple[list[rpcd_txn.Op], str]:
    """The ops of a change as the transaction engine's ops.

    The engine is what talks to the router, so a change it cannot
    carry is never applied by Newton:

    * a set of an option is a set;
    * a set of a section is an add: rpcd creates the section and its
      options in one call, so the options of a created section travel
      with it;
    * a delete is a delete;
    * a list verb (add_list, del_list) and a reorder have no shape in
      the engine -- rpcd's uci API has no list verb -- so such a change
      is an owner script.

    The second value is the reason when the change cannot be carried,
    and the empty string when it can.  ``types`` is the type of every
    section the router holds: a line that says another type for one of
    them is refused, never dropped.
    """
    creates: dict[tuple[str, str], str] = {}
    for op in ops:
        key = (op.config, op.section)
        if op.verb == "set" and op.option is None and key not in existing:
            section_type = str(op.type or "")
            known = creates.get(key)
            if known is not None and known != section_type:
                # the batch says two types for one new section: the
                # engine creates the section with one type, so this is
                # a change Newton does not apply by itself
                return [], (
                    f"the batch creates {op.config}.{op.section} as {known} "
                    f"and as {section_type}; Newton does not do that"
                )
            creates[key] = section_type
    values_of: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for op in ops:
        key = (op.config, op.section)
        if op.verb != "set" or op.option is None or key not in creates:
            continue
        values_of.setdefault(key, []).append((op.option, str(op.value)))

    result: list[rpcd_txn.Op] = []
    added: set[tuple[str, str]] = set()
    for op in ops:
        key = (op.config, op.section)
        if op.verb == "set" and op.option is None:
            if key in existing:
                # the section is already there: the change of the
                # section itself is nothing, unless the batch says
                # another type than the router holds
                known = (types or {}).get(key)
                if known is not None and known != str(op.type or ""):
                    return [], (
                        f"the batch changes the type of {op.config}.{op.section}"
                        f" from {known} to {op.type}; Newton does not do that"
                    )
                continue
            values = dict(values_of.get(key, []))
            if not values:
                return [], (
                    "the change creates a section with no settings of its own"
                )
            if key in added:
                # the same section line twice: the engine creates the
                # section once, with the settings that travel with it
                continue
            added.add(key)
            try:
                result.append(
                    rpcd_txn.add(op.config, creates[key], op.section, values)
                )
            except rpcd_txn.RpcdTxnError as exc:
                return [], str(exc)
            continue
        if op.verb == "set":
            if key in creates:
                # the option travels with the section it belongs to
                continue
            try:
                result.append(
                    rpcd_txn.set(op.config, op.section, {op.option: str(op.value)})
                )
            except rpcd_txn.RpcdTxnError as exc:
                return [], str(exc)
            continue
        if op.verb == "delete":
            try:
                result.append(
                    rpcd_txn.delete(op.config, op.section, op.option)
                )
            except rpcd_txn.RpcdTxnError as exc:
                return [], str(exc)
            continue
        return [], (
            f"the change uses {op.verb}, which Newton does not apply itself"
        )
    if not result:
        return [], "the change stages nothing at all"
    return result, ""


# ---- the record ------------------------------------------------------------


def _load_record(
    svc: Any, device_name: str, session_id: str, device: Any
) -> dict[str, Any]:
    """The plan record of a no-install plan."""
    path = Path(svc.state) / "plans" / f"{session_id}.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NewtonError("no plan record for this device and session") from exc
    if not isinstance(record, dict):
        raise NewtonError("no plan record for this device and session")
    if record.get("device") != device_name:
        raise NewtonError("no plan record for this device and session")
    if (
        record.get("host") != device.host
        or record.get("session_id") != session_id
    ):
        raise NewtonError("plan device or host changed since planning; plan again")
    return record


def _router_digest(record: Mapping[str, Any]) -> str:
    """The digest the record's own ops must carry.

    The plan hash does not cover the ops, so this is what binds them:
    the digest is over the leash, the base hash and the ops together,
    and over the type of every section the change touches and the risk
    the policy gave the change.  The apply recomputes it before the
    router is contacted.
    """
    return _plan.router_digest(record)


def _check_record(record: Mapping[str, Any]) -> None:
    """The front half: the record must be the one the owner approved."""
    try:
        actual = _server.compute_plan_hash(record)
    except (TypeError, ValueError) as exc:
        raise NewtonError(
            "plan record was modified or is invalid; plan again"
        ) from exc
    stored = record.get("plan_hash")
    if not isinstance(stored, str) or not hmac.compare_digest(stored, actual):
        raise NewtonError("plan record was modified or is invalid; plan again")
    digest = record.get("router_digest")
    if not isinstance(digest, str) or not hmac.compare_digest(
        digest, _router_digest(record)
    ):
        raise NewtonError(
            "the plan record's router digest does not match its own ops: "
            "the record was modified; plan again"
        )
    if (
        record.get("owner_confirmed_in_chat") is not True
        and record.get("consent_basis") != "grant"
    ):
        raise NewtonError(
            "plan record has no owner_confirmed_in_chat; plan again after "
            "explaining to the owner and asking them"
        )
    if record.get("router_leash") != AUTO_LEASH:
        raise NewtonError(
            "the plan record's router leash is not the no-install leash: "
            "the record was modified; plan again"
        )
    if record.get("router_profile") != PROFILE:
        raise NewtonError(
            "the plan record's router profile is not the no-install profile: "
            "the record was modified; plan again"
        )
    if record.get("requires_approval") is not True:
        raise NewtonError(
            "the plan record does not need an approval: a change Newton "
            "applies itself always needs one; plan again"
        )
    _check_explanation(record)
    timeout_s = record.get("timeout_s")
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, int)
        or not owner_script.WINDOW_MIN_S <= timeout_s <= owner_script.WINDOW_MAX_S
    ):
        raise NewtonError("plan record was modified or is invalid; plan again")


def _check_explanation(record: Mapping[str, Any]) -> None:
    """The explanation of a record must be one Newton can read.

    A malformed explanation is refused here.  It used to be swallowed
    into an empty list of claims, which made an apply look verified
    when nothing had been checked.
    """
    uci_batch = record.get("uci_batch")
    if not isinstance(uci_batch, str):
        raise NewtonError(
            "the plan record carries no change: the record was modified; "
            "plan again"
        )
    platform = record.get("platform")
    if not isinstance(platform, str) or not platform:
        platform = "openwrt"
    try:
        _explanation.parse_explanation(
            record.get("explanation"),
            change_lines=_explanation.change_lines(uci_batch),
            platform=platform,
            allow_targets=True,
        )
    except _explanation.ExplanationError as exc:
        raise NewtonError(
            f"the plan record's explanation is not one Newton can read "
            f"({exc}); plan again"
        ) from None


def _expected_ops(
    record: Mapping[str, Any], backup: Any, device: Any
) -> list[owner_ops.OwnerOp]:
    """The ops the record's own batch has, against the router as it is.

    The record's ops, its diff and the policy's verdict must all be the
    ones its own batch produces.  A record that does not agree with
    itself is refused here, before anything is written.
    """
    uci_batch = record.get("uci_batch")
    if not isinstance(uci_batch, str):
        raise NewtonError(
            "the plan record carries no change: the record was modified; "
            "plan again"
        )
    try:
        ops = owner_ops.parse_batch(uci_batch, backup, device)
    except owner_ops.OwnerScriptError as exc:
        raise NewtonError(
            f"the plan record's change cannot be read ({exc}); plan again"
        ) from None
    expected = [list(op) for op in owner_ops.to_script_ops(ops)]
    stored = record.get("ops")
    normalised: list[list[Any]] | None = []
    if isinstance(stored, list):
        for entry in stored:
            if not isinstance(entry, (list, tuple)):
                normalised = None
                break
            normalised.append(list(entry))
    if normalised != expected:
        raise NewtonError(
            "the plan record's ops are not the ops of its own change: "
            "the record was modified; plan again"
        )
    diff = owner_ops.render_diff(ops, backup)
    if diff != record.get("diff"):
        raise NewtonError(
            "the plan record's diff is not the diff of its own change: "
            "the record was modified; plan again"
        )
    types = _types_of(backup)
    # The types the record carries must be the types the router holds:
    # they decide the class of the change, and the class decides what
    # the grant covers.  EVERY touched section must be in them: a key
    # that was stripped from the record is a mismatch as well.
    stored_types = change_classes.types_of_record(record)
    expected_types = {
        (op.config, op.section): types[(op.config, op.section)]
        for op in ops
        if (op.config, op.section) in types
    }
    if stored_types != expected_types:
        raise NewtonError(
            "the plan record's section types are not the types the "
            "router holds: the record was modified; plan again"
        )
    # The risk the policy gives the change must be the risk the record
    # carries: a record may not claim a risk its own change does not
    # have.
    try:
        decision = policy.classify(
            device, uci_batch, diff, owner_flow.section_facts(backup)
        )
    except ValueError as exc:
        raise NewtonError(f"the change cannot be judged: {exc}") from None
    risk = str(decision.get("risk", ""))
    if risk != str(record.get("risk", "")):
        raise NewtonError(
            "the plan record's risk is not the risk of its own change: "
            "the record was modified; plan again"
        )
    auto, _reason = noinstall_checks.auto_apply_decision(
        uci_batch, types, risk=risk
    )
    if not auto:
        raise NewtonError(
            "the plan record's change is not one Newton may apply itself: "
            "the record was modified; plan again"
        )
    return ops


# ---- the session -----------------------------------------------------------


class _ReadSession:
    """A session that may make the read calls the checks need."""

    def __init__(self, client: Any, session: Any) -> None:
        self._client = client
        self._session = session

    def call(
        self, obj: str, fn: str, args: Mapping[str, Any] | None = None
    ) -> Any:
        return self._client.call(self._session, obj, fn, dict(args or {}))


def _claim_probes(record: Mapping[str, Any]) -> list[list[str]]:
    """The probes of the plan's own claims."""
    explanation = record.get("explanation")
    if not isinstance(explanation, dict):
        return []
    platform = record.get("platform")
    if not isinstance(platform, str) or not platform:
        platform = "openwrt"
    # The explanation was checked when the record was loaded, so a
    # malformed one never reaches here: it is refused, never dropped.
    return _explanation.claim_probes(explanation, platform)


def _could_not_run(failure: str) -> bool:
    """True when the failure says the check could not run.

    A check that could not run is not a verified check: it is listed
    for the owner, and it never counts as a pass.
    """
    return "could not run" in failure


def _run_checks(
    client: Any,
    password: str,
    record: Mapping[str, Any],
    ops: Sequence[owner_ops.OwnerOp],
    backup: Any,
    applied_at: float,
    deadline: float,
    now: Callable[[], float],
    sleep: Callable[[float], None],
) -> tuple[str | None, list[str]]:
    """The internet check, then the classes, then the plan's claims.

    The internet check comes first: it is the check the installed
    router program runs before every confirm, and a router without the
    internet confirms nothing here either.  It waits for the router's
    own reload (the apply returns before netifd has taken the uplinks
    down) and retries until the router has the internet again.

    The reason is None when every check passed.  Otherwise it names the
    check that failed or could not run, and the list carries the ones
    that could not run: a check Newton could not make is not a verified
    check, and the owner is told which one it was.
    """
    batch = "\n".join(owner_ops.batch_lines(ops))
    types = _types_of(backup)
    try:
        session = client.login(rpcd.RPCD_USER, password, CHECK_TIMEOUT_S)
    except rpcd.RpcdError as exc:
        # The router cannot be reached: no check ran at all.  A check
        # that could not run is not a verified check, and it blocks the
        # confirm.
        failure = f"the checks could not run: {exc}"
        return failure, [failure]
    try:
        probe_session = _ReadSession(client, session)
        failure = noinstall_checks.wait_for_internet(
            probe_session,
            applied_at=applied_at,
            deadline=deadline,
            now=now,
            sleep=sleep,
        )
        if failure is not None:
            unverifiable = [failure] if _could_not_run(failure) else []
            return failure, unverifiable
        failure = noinstall_checks.check_class_checks(
            probe_session, batch, types
        )
        if failure is not None:
            unverifiable = [failure] if _could_not_run(failure) else []
            return failure, unverifiable
        failure = noinstall_checks.check_claims(
            probe_session, _claim_probes(record)
        )
        if failure is not None:
            unverifiable = [failure] if _could_not_run(failure) else []
            return failure, unverifiable
        return None, []
    except rpcd.RpcdError as exc:
        failure = f"the checks could not run: {exc}"
        return failure, [failure]
    finally:
        try:
            session.mark_spent()
        except Exception:
            pass


def _settle(
    transaction: rpcd_txn.RpcdTransaction,
    ops: Sequence[rpcd_txn.Op],
    deadline: float,
    client: Any,
    password: str,
    now: Callable[[], float],
    sleep: Callable[[float], None],
) -> tuple[str, list[str]]:
    """Wait for the window to close, and read back what the router did.

    The state is read from the router, never from the clock: a change
    that was rolled back, a change that stayed and a change Newton
    cannot explain are three different answers.
    """
    limit = deadline + owner_verify.SETTLE_GRACE_S
    polls_left = int(max(0.0, limit - now()) / SETTLE_POLL_S) + 1
    pending = True
    while True:
        polls_left -= 1
        try:
            session = client.login(
                rpcd.RPCD_USER, password, rpcd_txn.READ_TIMEOUT_S
            )
            try:
                pending = transaction.pending(session)
            finally:
                try:
                    session.mark_spent()
                except Exception:
                    pass
        except rpcd.RpcdError:
            # the router cannot be reached: the state of the window is
            # unknown, and unknown is never "not pending"
            pending = True
        if not pending:
            break
        if now() >= limit or polls_left <= 0:
            break
        sleep(SETTLE_POLL_S)
    if pending:
        # The window did not close.  The values are read anyway: a
        # router that forgot the window (its web service restarted,
        # measured a4m-02) leaves the change on the router, and that is
        # worth saying out loud.
        try:
            verdict = transaction.settle(ops)
        except rpcd.RpcdError:
            verdict = rpcd_txn.UNKNOWN
        if verdict == rpcd_txn.KEPT:
            return rpcd_txn.UNKNOWN, (
                "the window did not close on the router: its web service "
                "most likely restarted, so the change stayed (see the "
                "reboot line)",
            )
        return rpcd_txn.UNKNOWN, (
            "the change is still waiting for confirmation on the router",
        )
    verdict = transaction.settle(ops)
    if verdict == rpcd_txn.REVERTED:
        return verdict, ("the router put the change back",)
    if verdict == rpcd_txn.KEPT:
        return verdict, ("the change is on the router and stayed",)
    return verdict, ("Newton cannot tell what the router did with the change",)


# ---- the apply -------------------------------------------------------------


def apply(
    svc: Any,
    device_name: str,
    session_id: str,
    *,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    client_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Apply an auto plan of a no-install router.

    The front half is the installed apply's: the record is loaded and
    verified, the owner's yes (or a live grant) is there, and the
    approval is consumed and settled.  The router is never contacted
    before the record has been verified.

    Then the change is applied in THIS call: the router is read again
    (a router that changed since the plan is refused), the change is
    staged and applied in one session, every mandatory check and every
    claim runs, and the change is confirmed only when every check
    passed and the pending change is provably ours.  Anything else is
    read back from the router after the window closes.

    The transaction object lives from the apply to the settle: the
    values before the change are in it, in memory, and they are what
    the settle compares the router's values with.
    """
    device = svc.device(device_name, allow_noinstall=True)
    if device.access != "no-install":
        raise NewtonError(
            "this device does not use no-install access; the no-install "
            "apply is for a router Newton cannot manage"
        )
    if device.platform != "openwrt":
        raise NewtonError("a no-install apply is only for OpenWrt routers")
    record = _load_record(svc, device_name, session_id, device)
    if record.get("mode") != AUTO_MODE:
        # an owner script is the owner's own bytes: Newton never runs it
        raise NewtonError(
            "this plan is an owner script: Newton does not apply it; "
            + owner_flow.next_step(device_name, session_id)
        )
    _check_record(record)
    try:
        ops = owner_ops.ops_of(record)
    except owner_ops.OwnerScriptError as exc:
        raise NewtonError(
            f"plan record was modified or is invalid ({exc}); plan again"
        ) from None
    timeout_s = int(record["timeout_s"])
    notes: list[str] = []
    not_verified = [
        str(item)
        for item in record.get("not_verified", [])
        if isinstance(item, str)
    ]
    reached_router = False

    # the approval is claimed here and settled in the finally below,
    # whether the change was applied or not
    svc.consume_approval(device_name, session_id, record)
    try:
        factory = client_factory or noinstall_read.default_client_factory
        password = noinstall_read._password(device)
        client = factory(device)

        # 1. the fresh read: the router must still hold what the plan
        #    was made against.  The configs are the ones the BATCH
        #    names, not the ones the record's ops name: the record is
        #    what is being checked.
        uci_batch = record.get("uci_batch")
        if not isinstance(uci_batch, str):
            raise NewtonError(
                "the plan record carries no change: the record was "
                "modified; plan again"
            )
        try:
            configs = sorted(owner_flow.configs_of(uci_batch))
            creates = owner_flow.creates_of(uci_batch)
        except owner_flow.OwnerFlowError as exc:
            raise NewtonError(str(exc)) from None
        try:
            backup = owner_backup.take(
                factory, device, configs, creates=creates
            )
        except owner_backup.BackupError as exc:
            raise NewtonError(str(exc)) from None
        base_hash = _sha256(_canonical(backup.configs))
        if base_hash != record.get("base_hash"):
            raise NewtonError(
                "the router changed since the plan: nothing was applied; "
                "plan again"
            )

        # 2. the ops come from the batch, not from the record: the
        #    record's ops, its diff and the policy's verdict must all
        #    be the ones its own change produces
        ops = _expected_ops(record, backup, device)

        # 3. the ops the transaction engine can carry
        carried, why = txn_ops(ops, _sections_of(backup), _types_of(backup))
        if not carried:
            raise NewtonError(
                "this change cannot be applied by Newton itself: " + why
            )

        transaction = rpcd_txn.RpcdTransaction(
            client,
            rpcd_txn.RpcdCredentials(password=password),
            now=now,
        )
        # The change may reach the router from here on: the approval
        # is consumed from now on, whatever happens next.
        reached_router = True
        outcome = transaction.apply(carried, timeout_s)

        if outcome.state in (rpcd_txn.BUSY, rpcd_txn.REFUSED):
            notes.append(outcome.reason or "the router refused the change")
            return _finish(
                svc, device_name, record, session_id,
                _result(NOT_APPLIED, notes, not_verified),
            )

        deadline = outcome.deadline
        if deadline is None:
            deadline = now() + timeout_s
        # the apply is the moment the change went to the router: the
        # internet check waits for the router's own reload from there
        applied_at = deadline - timeout_s
        mine = outcome.state == rpcd_txn.APPLIED_PENDING or (
            outcome.state == rpcd_txn.LOST and outcome.resolve == rpcd_txn.OWN
        )
        if outcome.state == rpcd_txn.LOST:
            notes.append("the answer to the apply was lost")
            if outcome.resolve == rpcd_txn.NOT_APPLIED:
                notes.append("the change is not on the router")
                return _finish(
                    svc, device_name, record, session_id,
                    _result(NOT_APPLIED, notes, not_verified),
                )
            if outcome.resolve != rpcd_txn.OWN:
                notes.append("Newton cannot prove the pending change is its own")

        confirmed = False
        if mine:
            failure, unverifiable = _run_checks(
                client,
                password,
                record,
                ops,
                backup,
                applied_at,
                deadline,
                now,
                sleep,
            )
            not_verified.extend(unverifiable)
            if failure is None:
                verdict = transaction.confirm(carried, deadline, True)
                if verdict.state == rpcd_txn.CONFIRMED:
                    confirmed = True
                else:
                    notes.append(verdict.reason or "the change was not confirmed")
            else:
                notes.append(failure)

        if confirmed:
            result = _result(CONFIRMED, notes, not_verified)
        else:
            verdict, extra = _settle(
                transaction, carried, deadline, client, password, now, sleep
            )
            notes.extend(extra)
            if verdict == rpcd_txn.REVERTED:
                result = _result(ROLLED_BACK, notes, not_verified)
            elif verdict == rpcd_txn.KEPT:
                result = _result(UNKNOWN, notes, not_verified)
            else:
                result = _result(UNKNOWN, notes, not_verified)
        return _finish(svc, device_name, record, session_id, result)
    except rpcd.RpcdError as exc:
        # Something on the router failed in a way Newton did not
        # expect.  The change may be live, so the run record is written
        # and the owner is told the outcome is unknown.
        notes.append(f"the change could not be finished: {exc}")
        return _finish(
            svc, device_name, record, session_id,
            _result(UNKNOWN, notes, not_verified),
            receipt=reached_router,
        )
    finally:
        svc.settle_approval(session_id, reached_router=reached_router)


def _result(
    state: str, notes: Sequence[str], not_verified: Sequence[str]
) -> dict[str, Any]:
    """The answer of an apply: the state, the notes and what was not checked."""
    return {
        "result": state,
        "notes": list(notes),
        "not_verified": list(not_verified),
    }


def _finish(
    svc: Any,
    device_name: str,
    record: Mapping[str, Any],
    session_id: str,
    result: Mapping[str, Any],
    *,
    receipt: bool = True,
) -> dict[str, Any]:
    """Write the run record and the receipt of a finished apply.

    EVERY outcome leaves a run record: the status answers the owner
    with the notes of the run, and not with a default.  The receipt is
    written when the change may have reached the router.
    """
    _write_run(svc, session_id, result)
    if receipt:
        _write_receipt(svc, device_name, record, session_id, result)
    return dict(result)


def _write_run(svc: Any, session_id: str, result: Mapping[str, Any]) -> None:
    """The run record of an apply: the state the status answers with."""
    try:
        owner_records.write_run(
            Path(svc.state),
            session_id,
            {
                "started_at": time.time(),
                "outcome": result.get("result"),
                "notes": list(result.get("notes", [])),
                "not_verified": list(result.get("not_verified", [])),
            },
        )
    except OSError:
        return


def _write_receipt(
    svc: Any,
    device_name: str,
    record: Mapping[str, Any],
    session_id: str,
    result: Mapping[str, Any],
) -> None:
    """The receipt of a finished apply, as the installed apply writes it."""
    state = str(result.get("result", ""))
    outcome = RECEIPT_OUTCOMES.get(state)
    if outcome is None:
        return
    lines = [RECEIPT_LINES[state].format(session_id)]
    lines.extend(str(note) for note in result.get("notes", []))
    try:
        svc._write_change_receipt(device_name, dict(record), outcome, "\n".join(lines))
    except Exception:
        return


# ---- the status and the abort ----------------------------------------------


def status(svc: Any, device_name: str, session_id: str) -> dict[str, Any]:
    """The state of a no-install plan: what the apply ended in."""
    device = svc.device(device_name, allow_noinstall=True)
    if device.access != "no-install":
        raise NewtonError(
            "this device does not use no-install access; the no-install "
            "status is for a router Newton cannot manage"
        )
    record = _load_record(svc, device_name, session_id, device)
    run = owner_records.read_run(Path(svc.state), session_id)
    outcome = run.get("outcome")
    started_at = run.get("started_at")
    notes = run.get("notes")
    not_verified = run.get("not_verified")
    verdict = run.get("verdict")
    if isinstance(verdict, Mapping):
        # An owner script's run carries its verdict, not an outcome: a
        # run that confirmed is a confirmed change.
        state = VERDICT_RESULTS.get(str(verdict.get("state")))
        if state is not None:
            return {
                "result": state,
                "notes": _texts(verdict.get("notes")),
                "not_verified": _texts(verdict.get("not_verified")),
            }
    if outcome in (CONFIRMED, ROLLED_BACK, NOT_APPLIED, UNKNOWN):
        return {
            "result": outcome,
            "notes": [str(note) for note in notes] if isinstance(notes, list) else [],
            "not_verified": (
                [str(item) for item in not_verified]
                if isinstance(not_verified, list)
                else []
            ),
        }
    # A run that is in flight is not a change that was not applied: the
    # change may be on the router, and the router undoes it unless
    # Newton confirms it.  An approval that is claimed is such a run,
    # and so is a run that started and has not ended yet.
    claimed = (Path(svc.state) / "approvals" / f"{session_id}.claimed").exists()
    started = isinstance(started_at, (int, float)) and not isinstance(
        started_at, bool
    )
    if claimed or started:
        return {
            "result": IN_PROGRESS,
            "notes": [IN_PROGRESS_NOTE],
            "not_verified": [
                str(item)
                for item in record.get("not_verified", [])
                if isinstance(item, str)
            ],
        }
    return {
        "result": NOT_APPLIED,
        "notes": ["the change has not been applied"],
        "not_verified": [
            str(item)
            for item in record.get("not_verified", [])
            if isinstance(item, str)
        ],
    }


def _texts(value: Any) -> list[str]:
    """A list of texts, or an empty one when the value is not a list."""
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def abort(svc: Any, device_name: str, session_id: str) -> dict[str, Any]:
    """Drop a no-install plan that has not been applied.

    During an apply there is nothing to abort: the router undoes the
    change unless Newton confirms it, and that is what the owner is
    told.
    """
    device = svc.device(device_name, allow_noinstall=True)
    if device.access != "no-install":
        raise NewtonError(
            "this device does not use no-install access; the no-install "
            "abort is for a router Newton cannot manage"
        )
    record = _load_record(svc, device_name, session_id, device)
    state = Path(svc.state)
    if (state / "approvals" / f"{session_id}.claimed").exists():
        return {
            "result": "not_aborted",
            "message": (
                "an apply is in flight: there is nothing to abort; the "
                "router undoes it unless Newton confirms"
            ),
        }
    run = owner_records.read_run(state, session_id)
    outcome = run.get("outcome")
    verdict = run.get("verdict")
    verdict_state = (
        str(verdict.get("state")) if isinstance(verdict, Mapping) else ""
    )
    never_applied = (
        outcome == NOT_APPLIED
        or verdict_state == owner_verify.NOT_APPLIED
    )
    started_at = run.get("started_at")
    ran = (
        bool(run.get("outcome"))
        or bool(run.get("verdict"))
        or (
            isinstance(started_at, (int, float))
            and not isinstance(started_at, bool)
        )
    )
    if ran and not never_applied:
        # The plan ran: the change may be on the router, and a plan
        # that says "nothing was applied" would be a lie.  A run that
        # PROVED the change was never applied is the one exception:
        # there is nothing on the router to undo, so the plan may go.
        return {
            "result": "not_aborted",
            "message": (
                "the plan already ran: there is nothing to abort; the "
                "change is on the router unless the router put it back"
            ),
        }
    # The plan is dropped whole: the record, the approval that could
    # still be used, and the artifacts that belong to it.
    _unlink(state / "plans" / f"{session_id}.json")
    _unlink(state / "approvals" / f"{session_id}.json")
    if owner_records.is_owner_record(record):
        _remove_tree(state / owner_records.OWNER_DIR / session_id)
        restore_sid = record.get("restore_sid")
        if isinstance(restore_sid, str) and restore_sid:
            _remove_tree(state / owner_records.OWNER_DIR / restore_sid)
            _unlink(state / "plans" / f"{restore_sid}.json")
    else:
        _unlink(owner_records.run_path(state, session_id))
    return {
        "result": "aborted",
        "message": "the plan was dropped; nothing was applied",
    }


def _unlink(path: Path) -> None:
    """Remove a file, and do not mind when it is not there."""
    try:
        path.unlink()
    except OSError:
        return


def _remove_tree(path: Path) -> None:
    """Remove a directory and everything in it."""
    shutil.rmtree(path, ignore_errors=True)
