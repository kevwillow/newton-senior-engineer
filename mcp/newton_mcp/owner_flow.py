"""the plan of an owner script, and the two records it writes.

ADR-021 point 7 and the design: for a change Newton may not apply
itself, Newton writes a script the owner approves byte for byte and
runs with one command.  This module builds that script, keeps a copy of
the settings it touches on the Newton computer, and writes the two plan
records the rest of the owner flow works with:

  * the apply plan ``SID``, whose script makes the change;
  * the restore plan ``RSID``, whose script puts the old values back.

Both records use the fields the installed mode already uses, so
``compute_plan_hash``, ``validate_plan_for_approval``, ``mint_approval``
and ``consume_approval`` work on them **unchanged**: ``PLAN_HASH_FIELDS``
is not edited.  The owner-script records carry a few extra fields that
are not hash-bound (the script's sha256, the id of the other plan, the
manifest of the backup and the list of claims Newton cannot check).

Nothing in this module reaches a router except through the one backup
read (the host-side copy of the settings the change touches).  It never
writes to the router: the owner does that, with the script.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import consequences
from . import envelope
from . import explanation as _explanation
from . import noinstall_checks
from . import noinstall_read
from . import owner_backup
from . import owner_ops
from . import owner_records
from . import owner_script
from . import policy
from . import receipts as _receipts
from . import server as _server


class OwnerFlowError(Exception):
    """A refusal of the owner-script plan.

    The message names a config, a section or an option.  It never
    echoes a value: a value can hold a secret, and a value that came
    from the router is untrusted text.
    """


#: The leash code of the apply plan.
OWNER_LEASH = "owner-script"

#: The leash code of the restore plan.
RESTORE_LEASH = "owner-script-restore"

#: The profile the no-install records carry.
OWNER_PROFILE = "no-install"

#: What Newton cannot read on a no-install router, in its own words.
BLIND_SPOT = (
    "Newton cannot read the rpcd, uhttpd or dropbear config, files, cron, "
    "keys, passwords or packages"
)

#: What Newton says about a claim it cannot check: a claim about a
#: client needs a vantage on the network, and the no-install path has
#: none.  The kind of the claim is named, so the owner knows which one.
CLIENT_CLAIM_NOTE = (
    "Newton cannot check the {kind} claim: it needs a client on the network"
)

#: The reboot line the owner reads, word for word.
REBOOT_LINE = (
    "If the router reboots or its web service restarts in the next {0} "
    "seconds, this change stays."
)

#: The plan kind of both records.
KIND = "owner-script"


# ---- the ids ---------------------------------------------------------------


def new_id() -> str:
    """A new plan id: 32 lowercase hex characters."""
    return secrets.token_hex(16)


def next_step(device_name: str, sid: str) -> str:
    """What the owner runs next: the command that runs the owner script.

    The same words everywhere: the plan says it, and the refusal of an
    apply of an owner script says it too.
    """
    return (
        "run sudo -u newton /usr/local/bin/newton-router-setup "
        f"{device_name} owner-run {sid}; it asks for your approval passphrase"
    )

_ID_RE = owner_script.PLAN_ID_RE


def _check_id(value: str, what: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise OwnerFlowError(f"the {what} must be 32 lowercase hex characters")
    return value


# ---- the batch -------------------------------------------------------------


def _batch_lines(uci_batch: str) -> list[str]:
    """The change lines of a batch: the ones the explanation counts."""
    return [
        line.strip()
        for line in uci_batch.split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]


def configs_of(uci_batch: str) -> list[str]:
    """The configs a batch touches, in the order they first appear.

    A config Newton may not read is refused here, before the backup:
    the backup would refuse it too, but with the wrong words.
    """
    configs: list[str] = []
    for line in _batch_lines(uci_batch):
        words = line.split(None, 1)
        if len(words) != 2:
            continue
        argument = words[1].split("=", 1)[0].strip()
        config = argument.split(".", 1)[0]
        if policy.CONFIG_NAME_RE.fullmatch(config) is None:
            continue
        if config not in owner_ops.ALLOWED_CONFIGS:
            raise OwnerFlowError(f"{config} is {owner_ops.CONFIG_REFUSAL}")
        if config not in configs:
            configs.append(config)
    if not configs:
        raise OwnerFlowError("the change is empty: there is nothing to put in a script")
    return configs


def creates_of(uci_batch: str) -> list[str]:
    """The configs whose first section the change creates.

    A config the router does not have may only be backed up when the
    change creates that config's first section: otherwise there is
    nothing to back up and nothing to check.
    """
    creates: list[str] = []
    for line in _batch_lines(uci_batch):
        words = line.split(None, 1)
        if len(words) != 2 or words[0] != "set":
            continue
        argument = words[1]
        path, separator, value = argument.partition("=")
        if not separator or not value:
            continue
        parts = path.split(".")
        if len(parts) != 2:
            continue
        config = parts[0]
        if policy.CONFIG_NAME_RE.fullmatch(config) is None:
            continue
        if config not in owner_ops.ALLOWED_CONFIGS:
            continue
        if config not in creates:
            creates.append(config)
    return creates


# ---- the preconditions of the restore script --------------------------------


def preconditions_after(
    ops: Sequence[owner_ops.OwnerOp], before: Any
) -> tuple[tuple[str, str | None], ...]:
    """The checks the restore script makes: the state the change left.

    The restore script runs after the change, so its preconditions are
    what the change must have produced -- the opposite of the apply
    script's, which are what the router held before it.
    """
    expected = owner_ops.expected_after(ops, before)
    checks: list[tuple[str, str | None]] = []
    for unit in sorted(expected, key=lambda item: (item[0], item[1], item[2] or "")):
        config, section, option = unit
        value = expected[unit]
        key = f"{config}.{section}" if option is None else f"{config}.{section}.{option}"
        if value is None:
            checks.append((key, None))
            continue
        if isinstance(value, tuple):
            if any(" " in item for item in value):
                raise OwnerFlowError(
                    owner_ops.UNSAFE_CHECK_REFUSAL.format(unit=key)
                )
            joined = " ".join(value)
        else:
            joined = str(value)
        if not owner_ops.check_value(joined):
            raise OwnerFlowError(owner_ops.UNSAFE_CHECK_REFUSAL.format(unit=key))
        checks.append((key, joined))
    return tuple(checks)


# ---- the hashes ------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    """The one byte form of a JSON document."""
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _base_hash(preconditions: Sequence[tuple[str, str | None]]) -> str:
    """The sha256 of the precondition values, the plan's base hash."""
    payload = {key: value for key, value in preconditions}
    return _sha256(_canonical(payload))


def _router_digest(leash: str, apply_sha: str, restore_sha: str) -> str:
    """The digest that binds the scripts to the plan.

    One implementation, in ``owner_records``: the approval dialogs and
    the setup CLI check the same bytes the same way.
    """
    return owner_records.expected_digest(
        {"router_leash": leash}, apply_sha, restore_sha
    )


# ---- the records -----------------------------------------------------------


def _no_install_literals() -> dict[str, Any]:
    """The fixed no-install literals every owner-script record carries."""
    return {
        "router_profile": OWNER_PROFILE,
        "router_requires_approval": True,
        "staged_at": None,
        "staged_check": {
            "fw4": "not-checked",
            "reason": "no-install",
            "not_checked": [],
        },
        "manifest_checks": [],
        "platform": "openwrt",
    }


def _restore_explanation(
    restore_batch: str, apply_sid: str, risk: str
) -> dict[str, Any]:
    """Newton's own explanation of the restore plan.

    The restore plan is Newton's own change, so its explanation is
    Newton's too: one step per restore line and no agent text at all.
    """
    steps = []
    for line in restore_batch.split("\n"):
        line = line.strip()
        if not line:
            continue
        verb, _, rest = line.partition(" ")
        path = rest.split("=", 1)[0].strip()
        if verb == "set":
            steps.append(f"restore {path}")
        elif verb == "add_list":
            steps.append(f"restore list {path}")
        elif verb == "delete":
            steps.append(f"remove {path}")
        elif verb == "reorder":
            steps.append(f"put {path} back in its place")
        else:
            steps.append(f"apply the {verb} change for {path}")
    intent = (
        f"Restore what plan {apply_sid[:8]} changed on this router, with the "
        "router's own undo timer armed."
    )
    risk_text = (
        f"Newton restores the values the plan {apply_sid[:8]} replaced. "
        "Every change uses OpenWrt's own undo timer: if you do not confirm, "
        "the router puts itself back. {0}".format(risk)
    )
    built = {
        "intent": intent,
        "steps": steps,
        "expect": [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}],
        "risk": risk_text,
    }
    try:
        return _explanation.parse_explanation(
            built, change_lines=len(steps), platform="openwrt"
        )
    except _explanation.ExplanationError as exc:
        raise OwnerFlowError(f"the restore explanation cannot be built: {exc}") from None


def not_verified(stored_explanation: Mapping[str, Any]) -> list[str]:
    """The claims Newton cannot check, and what it cannot read at all.

    The name of the probe is the one the claim was SEALED with (the same
    form ``explanation.claim_probes`` produces), and the probe is one
    the no-install path can run or not: a claim whose probe cannot run
    here is listed, and the read-back skips it.  A claim whose probe can
    run is checked, and it is not listed.
    """
    unverifiable: list[str] = []
    for claim in stored_explanation.get("expect", []):
        if not isinstance(claim, dict):
            continue
        if _explanation.is_client_claim(claim):
            # A client claim is checked from a client vantage, not by a
            # probe of the router.  The no-install path has no vantage,
            # so the claim is listed, never dropped: the owner has to
            # know what Newton did not check.
            unverifiable.append(
                CLIENT_CLAIM_NOTE.format(kind=str(claim.get("kind", "claim")))
            )
            continue
        try:
            probe = _explanation.claim_to_probe(claim)
        except _explanation.ExplanationError:
            unverifiable.append(str(claim.get("kind", "claim")))
            continue
        name = str(probe[0]) if probe else str(claim.get("kind", ""))
        if not noinstall_checks.probe_supported(name):
            unverifiable.append(str(claim.get("kind", "claim")))
    unverifiable.append(BLIND_SPOT)
    return unverifiable


def write_record(state: Path, record: dict[str, Any]) -> Path:
    """Write one plan record the way ``server.plan`` writes it."""
    plans = Path(state) / "plans"
    refusal = _receipts.check_state_write_path(plans, Path(state))
    if refusal is not None:
        raise OwnerFlowError(refusal)
    plans.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(plans, 0o700)
    target = plans / f"{record['session_id']}.json"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=plans)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(record, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return target


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
    """Plan an owner script for a no-install router.

    The steps are the design's: the device must be a no-install OpenWrt
    router, the owner's chat yes and the agent's explanation must be
    there, the settings the change touches are copied to the Newton
    computer, the script and its restore are rendered from one template,
    and the two plan records are written.

    Nothing is sent to the router and nothing is written to it.
    """
    if not isinstance(device_name, str) or not device_name:
        raise OwnerFlowError("the device name must be text")
    device = svc.device(device_name, allow_noinstall=True)
    if device.access != "no-install":
        raise OwnerFlowError(
            "this device does not use no-install access; an owner script is "
            "for a router Newton cannot manage"
        )
    if device.platform != "openwrt":
        raise OwnerFlowError("an owner script is only for OpenWrt routers")
    if not isinstance(uci_batch, str):
        raise OwnerFlowError("the change must be text")
    if isinstance(window_s, bool) or not isinstance(window_s, int):
        raise OwnerFlowError("the window must be an integer number of seconds")
    if not owner_script.WINDOW_MIN_S <= window_s <= owner_script.WINDOW_MAX_S:
        raise OwnerFlowError(
            "the window must be {0}..{1} seconds".format(
                owner_script.WINDOW_MIN_S, owner_script.WINDOW_MAX_S
            )
        )
    # the owner's yes in the chat and the agent's explanation come
    # before any device contact.  There is no grant waiver and no lab
    # carve-out for an owner script: the owner approves the bytes.
    stored_explanation = _server.check_explanation_inputs(
        explanation,
        owner_confirmed_in_chat,
        _explanation.change_lines(uci_batch),
        waived=False,
    )

    configs = configs_of(uci_batch)
    creates = creates_of(uci_batch)
    sid = new_id()
    rsid = new_id()
    factory = client_factory or noinstall_read.default_client_factory
    try:
        backup = owner_backup.take(factory, device, configs, creates=creates)
    except owner_backup.BackupError as exc:
        raise OwnerFlowError(str(exc)) from None
    backup = backup.with_sid(sid)

    try:
        ops = owner_ops.parse_batch(uci_batch, backup, device)
    except owner_ops.OwnerScriptError as exc:
        raise OwnerFlowError(str(exc)) from None
    apply_preconditions = owner_ops.preconditions(ops, backup)
    expected = owner_ops.expected_after(ops, backup)
    if owner_ops.changes_nothing(ops, backup):
        raise OwnerFlowError(
            "this change does nothing: it would stage no change at all"
        )
    restore_ops = owner_ops.inverse_ops(ops, backup)
    # The restore script runs on the CHANGED router, so its preconditions
    # are what the change must have produced -- not what the backup
    # holds.  They are the apply ops' expected values.
    restore_preconditions = preconditions_after(ops, backup)
    restore_batch = "\n".join(owner_ops.batch_lines(restore_ops))

    apply_plan = owner_script.ScriptPlan(
        sid=sid,
        kind=owner_script.KIND_APPLY,
        device=device_name,
        window=window_s,
        restore_sid=rsid,
        preconditions=apply_preconditions,
        ops=owner_ops.to_script_ops(ops),
    )
    restore_plan = owner_script.ScriptPlan(
        sid=rsid,
        kind=owner_script.KIND_RESTORE,
        device=device_name,
        window=window_s,
        restore_of=sid,
        preconditions=restore_preconditions,
        ops=owner_ops.to_script_ops(restore_ops),
    )
    apply_bytes = owner_script.render_script(apply_plan)
    restore_bytes = owner_script.render_script(restore_plan)
    apply_sha = owner_script.script_sha256(apply_bytes)
    restore_sha = owner_script.script_sha256(restore_bytes)

    diff = owner_ops.render_diff(ops, backup)
    restore_diff = owner_ops.render_diff(restore_ops, backup)
    facts = section_facts(backup)
    try:
        decision = policy.classify(device, uci_batch, diff, facts)
    except ValueError as exc:
        raise OwnerFlowError(f"the change cannot be judged: {exc}") from None
    reasons = list(decision.get("reasons", []))
    risk = str(decision.get("risk", "low"))
    claim_probes = _explanation.claim_probes(stored_explanation)

    manifest = owner_backup.write(Path(svc.state), sid, backup)
    manifest_sha = _sha256(_canonical(manifest))
    # The restore plan runs against the state the change made, so it
    # keeps a backup of THAT state: the apply backup with the ops
    # applied, the same running state the restore's own preconditions
    # are built from.  Without it the restore plan cannot be checked,
    # and an undo the owner cannot run is no undo at all.
    restore_configs = owner_ops.after_configs(backup, ops)
    restore_backup = owner_backup.Backup(
        configs=restore_configs,
        board=backup.board,
        sid=rsid,
        missing=tuple(
            config for config in backup.missing if config not in restore_configs
        ),
    )
    restore_manifest = owner_backup.write(Path(svc.state), rsid, restore_backup)
    restore_manifest_sha = _sha256(_canonical(restore_manifest))

    now = datetime.now(timezone.utc).isoformat()
    apply_record = {
        "device": device_name,
        "host": device.host,
        "session_id": sid,
        "uci_batch": uci_batch,
        "diff": diff,
        "probes": claim_probes,
        "timeout_s": window_s,
        "base_hash": _base_hash(apply_preconditions),
        "requires_approval": True,
        "router_digest": _router_digest(OWNER_LEASH, apply_sha, restore_sha),
        "explanation": stored_explanation,
        "owner_confirmed_in_chat": True,
        "reasons": reasons,
        "risk": risk,
        "created_at": now,
        "manifest_checks": [],
        "router_leash": OWNER_LEASH,
        "router_sections": sorted(
            {f"{config}.{section}" for config, section, _option in expected}
        ),
        # the owner-script bookkeeping, which is not hash-bound
        "kind": KIND,
        "platform": "openwrt",
        "script_sha256": apply_sha,
        "restore_sid": rsid,
        "backup_manifest_sha256": manifest_sha,
        "not_verified": not_verified(stored_explanation),
        "ops": [list(op) for op in owner_ops.to_script_ops(ops)],
        **_no_install_literals(),
    }
    apply_record["plan_hash"] = _server.compute_plan_hash(apply_record)

    restore_explanation = _restore_explanation(restore_batch, sid, risk)
    restore_record = {
        "device": device_name,
        "host": device.host,
        "session_id": rsid,
        "uci_batch": restore_batch,
        "diff": restore_diff,
        "probes": [],
        "timeout_s": window_s,
        "base_hash": _base_hash(restore_preconditions),
        "requires_approval": True,
        "router_digest": _router_digest(RESTORE_LEASH, restore_sha, restore_sha),
        "explanation": restore_explanation,
        "owner_confirmed_in_chat": True,
        "reasons": reasons,
        "risk": risk,
        "created_at": now,
        "manifest_checks": [],
        "router_leash": RESTORE_LEASH,
        "router_sections": sorted(
            {f"{config}.{section}" for config, section, _option in expected}
        ),
        "kind": KIND,
        "platform": "openwrt",
        "script_sha256": restore_sha,
        "restore_of": sid,
        "backup_manifest_sha256": restore_manifest_sha,
        "not_verified": not_verified(restore_explanation),
        "ops": [list(op) for op in owner_ops.to_script_ops(restore_ops)],
        **_no_install_literals(),
    }
    restore_record["plan_hash"] = _server.compute_plan_hash(restore_record)

    write_record(Path(svc.state), apply_record)
    write_record(Path(svc.state), restore_record)
    _write_script(Path(svc.state), sid, apply_bytes)
    _write_script(Path(svc.state), rsid, restore_bytes)
    owner_records.write_run(
        Path(svc.state), sid, {"started_at": None, "owner_keep": None}
    )
    _audit(svc, device_name, sid, rsid, apply_sha, restore_sha)

    return {
        "mode": KIND,
        "device": device_name,
        "session_id": sid,
        "restore_session_id": rsid,
        "plan_hash": apply_record["plan_hash"],
        "restore_plan_hash": restore_record["plan_hash"],
        "script_sha256": apply_sha,
        "restore_script_sha256": restore_sha,
        "script": envelope.envelope(f"{device_name}:owner-script", apply_bytes.decode("utf-8")),
        "restore_script": envelope.envelope(
            f"{device_name}:owner-restore-script", restore_bytes.decode("utf-8")
        ),
        "what_this_does": consequences.describe(uci_batch),
        "reasons": reasons,
        "risk": risk,
        "reboot_line": REBOOT_LINE.format(window_s),
        "not_verified": apply_record["not_verified"],
        "next_step": next_step(device_name, sid),
    }


def section_facts(backup: Any) -> dict[tuple[str, str], tuple[str | None, str | None]]:
    """The section facts the policy reads: the type and the name option."""
    facts: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for config, sections in getattr(backup, "configs", {}).items():
        if not isinstance(sections, Mapping):
            continue
        for name, entry in sections.items():
            if not isinstance(entry, Mapping):
                continue
            section_type = entry.get(".type")
            section_name = entry.get("name")
            facts[(config, name)] = (
                section_type if isinstance(section_type, str) else None,
                section_name if isinstance(section_name, str) else None,
            )
    return facts


def _write_script(state: Path, sid: str, data: bytes) -> Path:
    """Write a script next to its backup, mode 0600."""
    directory = Path(state) / owner_backup.OWNER_DIR / sid
    refusal = _receipts.check_state_write_path(directory, Path(state))
    if refusal is not None:
        raise OwnerFlowError(refusal)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(Path(state) / owner_backup.OWNER_DIR, 0o700)
    os.chmod(directory, 0o700)
    target = directory / "script.sh"
    descriptor, temporary = tempfile.mkstemp(prefix=".script.sh.", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return target


def _audit(
    svc: Any,
    device_name: str,
    sid: str,
    rsid: str,
    apply_sha: str,
    restore_sha: str,
) -> None:
    """One audit line per plan: ids and hash prefixes only, never a value."""
    try:
        svc.audit(
            "newton_owner_script",
            device_name,
            f"session={sid} restore={rsid} "
            f"script_sha256={apply_sha[:12]} restore_sha256={restore_sha[:12]}",
        )
    except Exception:
        pass
