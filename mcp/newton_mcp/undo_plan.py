"""Undo after confirm: the planner.

A change that ended CONFIRMED may be undone: the router's config from before
the change (B, the off-device backup copy) and the config now (C, a fresh
backup) are turned into a ``uci batch`` that puts the router back.  The batch
comes from ``undo.inverse_batch``, which proves itself on the way.

This module decides whether the undo may be built at all:

* the change must have a plan record that verifies for this device and host,
  an outcome re-derived from the audit log that says CONFIRMED, one receipt
  that says so too, and a backup copy that matches its receipt;
* the change must not have been undone already;
* the config now must be exactly the config right after the change (the md5
  of every touched package must match the recorded ``after_hash``), and no
  later confirmed change may have touched the same packages;
* the batch must stay inside its limits.

Every refusal is an ``UndoRefused``.  Its message is safe to show an agent:
it may name a package, a section, an option, a session id prefix or a rule,
but never a config value (a value can be a secret) and never a file path.

Nothing here talks to a router: no shell, no subprocess, standard library
only.  The server wires this module up.
"""

from __future__ import annotations

import hmac
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from . import change_receipt as _receipts
from . import explanation as _explanation
from . import plan as _plan
from . import policy as _policy
from .undo import (
    Section,
    UndoError,
    _ADDRESS_RE as _UNDO_ADDRESS_RE,
    inverse_batch,
    md5_hex,
    parse_uci_config,
    config_base_hash,
    read_config_members,
)


class UndoRefused(ValueError):
    """The undo was refused.  The message is safe to show an agent."""


@dataclass(frozen=True)
class UndoDraft:
    """The undo that may be planned, before the owner has seen it.

    ``batch`` is the ``uci batch`` text, one line each, with a trailing
    newline.  ``explanation`` is already valid for
    ``explanation.parse_explanation(.., change_lines=len(lines))``.
    ``not_undone`` is the fixed list of things an undo of a config change
    never undoes.
    """

    change_id: str
    packages: tuple[str, ...]
    batch: str
    explanation: dict[str, Any]
    current_md5: dict[str, str]
    deleted_values: Mapping[tuple[str, str, str], str | tuple[str, ...]]
    not_undone: tuple[str, ...]


NOT_UNDONE = (
    "packages",
    "passwords",
    "reboots",
    "client state such as leases and Wi-Fi associations",
)

CLAIM_VALUE_PACKAGES = frozenset({"firewall", "dhcp", "network"})
# network holds credentials under names no secret filter knows (pppd_options, ...): only these are shown
NETWORK_CLAIM_OPTIONS = frozenset(
    {"proto", "ipaddr", "netmask", "gateway", "device", "ifname", "type", "mtu", "metric", "disabled", "auto"}
)
MAX_BATCH_LINES = 200
MAX_AFTER_HASH_LINES = 200
MAX_CONFLICTS_SHOWN = 20

FIXED_RISK = (
    "Config only: packages, passwords, reboots and client leases are not undone."
)
PARTIAL_CLAIM_RISK = "Not every restored value can be checked after the apply."
NO_CLAIM_RISK = (
    "No config value could be claimed; the only check is that the router still answers."
)
NO_AFTER_HASH = (
    "this change was confirmed before undo records were kept; restore its backup by hand"
)

_SID_RE = re.compile(r"^[0-9a-f]{32}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HASH_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONFIGHASH_RE = re.compile(r"^([0-9a-f]{32}) ([A-Za-z0-9_-]{1,64})$")


def _grammar_body(pattern: re.Pattern[str]) -> str:
    """The body of one anchored grammar pattern, safe to embed in another."""
    body = pattern.pattern
    if body.startswith("^"):
        body = body[1:]
    if body.endswith("$"):
        body = body[:-1]
    return body


_DELETE_OPTION_RE = re.compile(
    "^delete (?P<config>" + _grammar_body(_policy.CONFIG_NAME_RE) + r")\."
    r"(?P<address>" + _grammar_body(_policy.SECTION_NAME_RE) + r"|"
    + _UNDO_ADDRESS_RE.pattern + r")\."
    r"(?P<option>" + _grammar_body(_policy.OPTION_NAME_RE) + r")$"
)

# the placeholders the maskers leave in a diff or a backup: ``<masked>``
# (scripts/owrt-change.sh mask_secrets), ``<masked: ...>``, ``<redacted:...>``
# and a bare ``***``.  The prefix can appear anywhere in the value.
# A placeholder is not a value: the committed value of the option is
# unknown, so a set that carries one poisons the key rather than giving the
# policy a literal it would read as a harmless string.
_MASKED_VALUE_RE = re.compile(r"<(?:masked|redacted)|\*{3}", re.IGNORECASE)


# ------------------------------------------------------------ the records


def _read_record(path: Path) -> dict[str, Any] | None:
    """The plan record at *path*, or None when it is not a readable dict."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _hash_verifies(record: dict[str, Any]) -> bool:
    """True when the stored plan hash is the hash of the record."""
    stored = record.get("plan_hash")
    if not isinstance(stored, str):
        return False
    try:
        computed = _plan.compute_plan_hash(record)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(stored, computed)


def _write_record(path: Path, record: dict[str, Any]) -> None:
    """Write a plan record through a temporary file, owner-only."""
    tmp = path.with_suffix(".json.tmp")
    handle = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


# -------------------------------------------------------------- the receipts


def _receipt_parts(path: Path) -> tuple[str, str, str] | None:
    """(stamp, device, sid) of a receipt file name, None when it is not one."""
    name = path.name
    if not name.endswith(".md"):
        return None
    stem = name[:-3]
    stamp, sep, rest = stem.partition("-")
    if not sep or not stamp:
        return None
    device, sep, sid = rest.rpartition("-")
    if not sep or len(sid) != 32 or _SID_RE.fullmatch(sid) is None:
        return None
    return stamp, device, sid


def _device_receipts(state: Path, device: str) -> list[Path]:
    """Every receipt of one device, oldest name first."""
    directory = state / "receipts"
    try:
        entries = sorted(directory.glob("*.md"))
    except OSError:
        return []
    out: list[Path] = []
    for path in entries:
        parts = _receipt_parts(path)
        if parts is not None and parts[1] == device:
            out.append(path)
    return out


def _outcome(sid: str) -> str | None:
    """The outcome of a session, re-derived from the audit log."""
    lines = _receipts.audit_lines(sid)
    if not lines:
        return None
    return _receipts.outcome_from_lines(lines, sid)


def _receipt_sha256(path: Path) -> str:
    """The sha256 the receipt names for its backup, or an empty string."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    in_backup = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            in_backup = line == "## Backup"
            continue
        if in_backup and line.startswith("- sha256:"):
            value = line.split(":", 1)[1].strip()
            if _SHA256_RE.fullmatch(value):
                return value
    return ""


# ------------------------------------------------------------ the backups


def _read_members(path: Path, wanted: set[str]) -> dict[str, bytes | None]:
    """The config files of a backup tarball, in memory."""
    try:
        return read_config_members(path, wanted)
    except UndoError as exc:
        raise UndoRefused(str(exc)) from None
    except ValueError:
        raise UndoRefused("the backup cannot be read") from None


def _sections(data: bytes | None) -> list[Section]:
    """The sections of one config file, an absent file being empty."""
    if data is None:
        return []
    try:
        return parse_uci_config(data.decode("utf-8", errors="replace"))
    except UndoError as exc:
        raise UndoRefused(str(exc)) from None


# ------------------------------------------------------------- the refusals


def _verified_record(
    state: Path, device: str, host: str, change_id: str
) -> dict[str, Any]:
    """The plan record of the change, when it verifies for this device."""
    record = _read_record(state / "plans" / f"{change_id}.json")
    if record is None:
        raise UndoRefused("no verified plan record for this device and change")
    if record.get("device") != device or record.get("host") != host:
        raise UndoRefused("no verified plan record for this device and change")
    if record.get("session_id") != change_id:
        raise UndoRefused("no verified plan record for this device and change")
    if not _hash_verifies(record):
        raise UndoRefused("no verified plan record for this device and change")
    return record


def _require_confirmed(change_id: str) -> None:
    """The outcome of the change, re-derived from the audit log."""
    lines = _receipts.audit_lines(change_id)
    if not lines:
        raise UndoRefused("no audit lines for this change")
    outcome = _receipts.outcome_from_lines(lines, change_id)
    if outcome == "confirmed":
        return
    word = "ROLLED BACK" if outcome == "rolled_back" else "UNKNOWN"
    raise UndoRefused(
        "only a change that ended CONFIRMED can be undone (this one ended "
        f"{word})"
    )


def _require_receipt(state: Path, device: str, change_id: str) -> Path:
    """The one receipt of the change, when it says the change was confirmed."""
    found = [
        path
        for path in _device_receipts(state, device)
        if (_receipt_parts(path) or ("", "", ""))[2] == change_id
    ]
    if not found:
        raise UndoRefused("no receipt for this change")
    if len(found) > 1:
        raise UndoRefused("more than one receipt for this change")
    path = found[0]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raise UndoRefused("no receipt for this change") from None
    if not any(line.strip() == "Outcome: CONFIRMED" for line in text.splitlines()):
        raise UndoRefused("the receipt of this change does not say it was confirmed")
    return path


def _require_backup_copy(state: Path, change_id: str, receipt: Path) -> Path:
    """The off-device backup copy, when it matches the receipt."""
    copy = state / "receipts" / "backups" / f"{change_id}.tar.gz"
    digest, _reason = _receipts._hash_backup(copy)
    if not digest or digest != _receipt_sha256(receipt):
        raise UndoRefused(
            "the backup copy of this change is missing or does not match its receipt"
        )
    return copy


def _require_planned_base(record: dict[str, Any], backup_copy: Path) -> None:
    """The backup copy must be the config the change was planned on (its sealed base hash)."""
    try:
        actual = config_base_hash(backup_copy)
    except UndoError as exc:
        raise UndoRefused(str(exc)) from None
    stored = record.get("base_hash")
    if not isinstance(stored, str) or not hmac.compare_digest(stored, actual):
        raise UndoRefused(
            "the backup copy is not the config this change was planned on "
            "(the config moved between the backup and the staging)"
        )


def _require_after_hash(record: dict[str, Any]) -> dict[str, str]:
    """The md5 of every config file right after the change."""
    raw = record.get("after_hash")
    if not isinstance(raw, dict) or not raw:
        raise UndoRefused(NO_AFTER_HASH)
    out: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or _HASH_NAME_RE.fullmatch(name) is None:
            raise UndoRefused(NO_AFTER_HASH)
        if not isinstance(value, str) or _MD5_RE.fullmatch(value) is None:
            raise UndoRefused(NO_AFTER_HASH)
        out[name] = value
    return out


def _require_not_undone(state: Path, change_id: str) -> None:
    """Refuse a change that a confirmed change already undid."""
    try:
        entries = sorted((state / "plans").glob("*.json"))
    except OSError:
        return
    for path in entries:
        sid = path.stem
        if _SID_RE.fullmatch(sid) is None:
            continue
        record = _read_record(path)
        if record is None or record.get("undo_of") != change_id:
            continue
        if _outcome(sid) == "confirmed":
            raise UndoRefused(f"already undone by change {sid[:8]}")


def _touched_packages(record: dict[str, Any]) -> list[str]:
    """The packages the change touched, sorted."""
    raw = record.get("diff")
    text = raw if isinstance(raw, str) else ""
    packages: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        change = _policy.parse_diff_line(line)
        if change is None or not change.parsed or not change.config:
            raise UndoRefused(
                "a line of the change cannot be read, so it cannot be undone safely"
            )
        packages.add(change.config)
    if not packages:
        raise UndoRefused("the change touched no package, so there is nothing to undo")
    return sorted(packages)


def _diff_packages(record: dict[str, Any]) -> set[str] | None:
    """The packages a plan record's diff names; None when a line cannot be read."""
    raw = record.get("diff")
    text = raw if isinstance(raw, str) else ""
    packages: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        change = _policy.parse_diff_line(line)
        if change is None or not change.parsed or not change.config:
            return None
        packages.add(change.config)
    return packages


# --------------------------------------------------------------- the conflicts


def _resolve_conflicts(conflicts: list[str]) -> None:
    """Refuse the whole undo when anything conflicts.

    Any conflict refuses the WHOLE undo; nothing is skipped (a design decision).  The decision lives in this one function.
    """
    if not conflicts:
        return
    shown = conflicts[:MAX_CONFLICTS_SHOWN]
    raise UndoRefused(
        f"Undo refused, {len(conflicts)} conflict(s): " + "; ".join(shown)
    )


def _conflicts(
    state: Path,
    device: str,
    change_id: str,
    receipt: Path,
    packages: list[str],
    after_hash: dict[str, str],
    current: dict[str, bytes | None],
) -> list[str]:
    """Every reason the undo may not be built now."""
    out: list[str] = []
    for package in packages:
        data = current.get(package)
        expected = after_hash.get(package)
        if data is None or expected is None or md5_hex(data) != expected:
            out.append(
                f"{package}: changed since this change (its config file is not "
                "the one right after it)"
            )
    out.extend(_later_conflicts(state, device, change_id, receipt, packages))
    return out


def _later_conflicts(
    state: Path,
    device: str,
    change_id: str,
    receipt: Path,
    packages: list[str],
) -> list[str]:
    """The conflicts with changes that were confirmed after this one."""
    own = _receipt_parts(receipt)
    own_stamp = own[0] if own is not None else ""
    receipts = {
        parts[2]: parts[0]
        for path in _device_receipts(state, device)
        if (parts := _receipt_parts(path)) is not None
    }
    out: list[str] = []
    try:
        plan_paths = sorted((state / "plans").glob("*.json"))
    except OSError:
        plan_paths = []
    records: dict[str, dict[str, Any] | None] = {sid: None for sid in receipts}
    for path in plan_paths:
        if _SID_RE.fullmatch(path.stem) is None:
            continue
        record = _read_record(path)
        if record is not None and record.get("device") == device:
            records[path.stem] = record
    for sid, record in sorted(records.items()):
        if sid == change_id:
            continue
        if _outcome(sid) != "confirmed":
            continue
        # a change is skipped only when its receipt proves it came earlier; no receipt
        # (receipts are best effort) or an equal stamp (one-second resolution) counts as later
        stamp = receipts.get(sid)
        if stamp is not None and stamp < own_stamp:
            continue
        later = _diff_packages(record) if record is not None else None
        if later is None:
            # a diff line that cannot be read could name any of them
            later = set(packages)
        for package in packages:
            if package in later:
                out.append(f"{package}: also changed by later change {sid[:8]}")
    return out


# ---------------------------------------------------------------- the batch


def _build_lines(
    packages: list[str],
    backup: dict[str, bytes | None],
    current: dict[str, bytes | None],
) -> list[str]:
    """The batch that turns the config now into the config from before."""
    lines: list[str] = []
    for package in packages:
        before = _sections(backup.get(package))
        after = _sections(current.get(package))
        try:
            lines.extend(inverse_batch(package, after, before))
        except UndoError as exc:
            raise UndoRefused(str(exc)) from None
    if not lines:
        raise UndoRefused(
            "nothing to undo: the touched packages already match their state "
            "before the change"
        )
    if len(lines) > MAX_BATCH_LINES:
        raise UndoRefused("too many changes to undo in one plan")
    return lines


def _set_values_from_diff(record: dict[str, Any]) -> dict[tuple[str, str, str], str]:
    """The unambiguous option values a change set in its recorded diff.

    A record is trusted only after ``_verified_record`` hash-verifies it, but its
    diff still has to be complete and unambiguous before it can identify an
    anonymous section's committed option.  Any operation other than one simple
    set poisons that option, and so does a second set of the same option: the
    option may hold a list rather than one value.

    Two things are not values at all:

    * a masked value.  The recorded diff is the MASKED diff: the masker turns
      the value of a secret-named option into ``<masked>`` (or ``<masked: ...>``
      / ``<redacted:...>``) or a bare ``***``.  A placeholder says nothing about
      the committed value, and giving it to the policy would tell it that the
      option held a harmless string, so a set that carries one poisons the key.
    * a positional section id.  uci's anonymous id (``cfg`` + 2-hex load
      position + 4-hex type hash) depends on the section's place in the file.
      The record's diff names the sections of the file BEFORE the change and
      the undo's diff names them AFTER it, so the two agree only when the
      change added, deleted, renamed or reordered no section of that config.
      A diff that did any of those (a line with no option: a section add or
      delete, or a rename ``@`` / reorder ``^`` line) therefore keeps no
      diff-derived value for ANY key of that config; the other configs are
      unaffected.
    """
    raw = record.get("diff")
    if not isinstance(raw, str):
        return {}
    values: dict[tuple[str, str, str], str] = {}
    poisoned: set[tuple[str, str, str]] = set()
    moved: set[str] = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        change = _policy.parse_diff_line(line)
        if change is None or not change.parsed or change.config is None:
            return {}
        if change.option is None or change.op in ("@", "^"):
            # the config moved a section: its section ids are not the same
            # before and after the change, so no diff-derived value of that
            # config can be trusted
            moved.add(change.config)
            continue
        key = (change.config, change.section, change.option)
        if change.op == "" and change.value is not None:
            if _value_is_unknown(change.value):
                poisoned.add(key)
            elif key in values:
                poisoned.add(key)
            else:
                values[key] = change.value
        else:
            poisoned.add(key)
    return {
        key: value
        for key, value in values.items()
        if key not in poisoned and key[0] not in moved
    }


def _value_is_unknown(value: str | tuple[str, ...]) -> bool:
    """True when a scalar or any list item is a mask placeholder."""
    items = (value,) if isinstance(value, str) else value
    return any(_MASKED_VALUE_RE.search(item) for item in items)


def _deleted_values(
    packages: list[str],
    current: dict[str, bytes | None],
    record: dict[str, Any],
    lines: Sequence[str] | str,
) -> Mapping[tuple[str, str, str], str | tuple[str, ...]]:
    """Committed values for deleted options, keyed the way their diff names them.

    All options from named sections are retained rather than trying to match
    them to the inverse batch. Anonymous sections have no stable cfgXXXXXX id
    in their backup, so their values come only from an unambiguous recorded
    set in the hash-verified change diff.

    When the backup and the change diff disagree about a named section's
    option, the backup wins: it holds the value the router has now.

    Only the options the inverse batch deletes keep a value: the value of an
    option the undo leaves alone says nothing about the undo.
    """
    values: dict[tuple[str, str, str], str | tuple[str, ...]] = {}
    unknown: set[tuple[str, str, str]] = set()
    for package in packages:
        for section in _sections(current.get(package)):
            if section.name is None:
                continue
            for option, value in section.options:
                if _value_is_unknown(value):
                    unknown.add((package, section.name, option))
                    continue
                values[(package, section.name, option)] = value
    allowed = set(packages)
    for key, value in _set_values_from_diff(record).items():
        if key[0] not in allowed or _policy.ANON_SECTION_RE.fullmatch(key[1]):
            continue
        if key in unknown:
            continue
        if key in values:
            # the backup holds the value the router has now; the diff's
            # staged value does not replace it
            continue
        if _value_is_unknown(value):
            continue
        values[key] = value
    deleted = _deleted_options(lines)
    return MappingProxyType(
        {
            key: value
            for key, value in values.items()
            if (key[0], key[2]) in deleted
        }
    )


def _deleted_options(lines: Sequence[str] | str) -> set[tuple[str, str]]:
    """The (config, option) pairs the batch lines delete.

    A batch line that deletes an option names it as
    ``delete <config>.<address>.<option>``.  The address is a section name or
    an anonymous ``@type[N]``, and only the config and the option are kept:
    the diff names an anonymous section by its own id (``cfg01e48a``) while
    the batch names it by its place (``@system[0]``).  A line that deletes a
    whole section (``delete <config>.<address>``) deletes no option.
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    out: set[tuple[str, str]] = set()
    for raw in lines:
        match = _DELETE_OPTION_RE.fullmatch(raw.strip())
        if match is None:
            continue
        out.add((match.group("config"), match.group("option")))
    return out


# ------------------------------------------------------------ the explanation


def _agent_parts(agent_explanation: Any) -> tuple[str, str]:
    """The intent and the risk the agent gave, and nothing else."""
    if not isinstance(agent_explanation, dict):
        raise UndoRefused("the undo explanation must be an object with intent and risk")
    if set(agent_explanation) - {"intent", "risk"}:
        raise UndoRefused("the undo explanation takes only intent and risk")
    if "intent" not in agent_explanation:
        raise UndoRefused("the undo explanation needs an intent")
    if "risk" not in agent_explanation:
        raise UndoRefused("the undo explanation needs a risk")
    intent = agent_explanation["intent"]
    risk = agent_explanation["risk"]
    if not isinstance(intent, str) or not intent.strip():
        raise UndoRefused("the undo explanation intent must be non-empty text")
    if not isinstance(risk, str) or not risk.strip():
        raise UndoRefused("the undo explanation risk must be non-empty text")
    return intent.strip(), risk.strip()


def _risk_text(agent_risk: str, note: str) -> str:
    """The stored risk: the agent's words, the fixed sentence, and a note."""
    first = agent_risk.replace("\n", " ").strip()
    tail = f" {note}" if note else ""
    room = _explanation.MAX_RISK - len(FIXED_RISK) - 1 - len(tail)
    if len(first) > room:
        first = first[:room].rstrip()
    return (first + tail).strip() + "\n" + FIXED_RISK


def _step_for(line: str) -> str:
    """One step for one batch line: the verb and the path, never a value."""
    verb, _, rest = line.partition(" ")
    if verb == "add":
        words = rest.split()
        package = words[0] if words else ""
        stype = words[1] if len(words) > 1 else ""
        return f"re-add a removed {stype} section in {package}"
    path = rest.split("=", 1)[0]
    if verb == "set":
        text = f"restore {path}"
    elif verb in ("add_list", "del_list"):
        text = f"restore list {path}"
    elif verb == "delete":
        text = f"remove {path}"
    elif verb == "reorder":
        text = f"put {path} back in its place"
    else:
        text = f"apply the {verb} change for {path}"
    if len(text) > _explanation.MAX_STEP:
        text = text[: _explanation.MAX_STEP - 3] + "..."
    return text


def _claim_valid(claim: dict[str, Any]) -> bool:
    """True when the explanation validators accept the claim."""
    try:
        if claim["kind"] == "uci_equals":
            _explanation.UciEqualsClaim(
                kind="uci_equals", path=claim["path"], equals=claim["equals"]
            )
        else:
            _explanation.ProbeClaim(kind="probe", probe=claim["probe"])
    except (ValueError, TypeError):
        return False
    return True


def _claim_for(line: str) -> dict[str, Any] | None:
    """The claim one batch line can carry, or None when it cannot."""
    verb, _, rest = line.partition(" ")
    if verb == "set":
        target, sep, value = rest.partition("=")
        if not sep or not (value.startswith("'") and value.endswith("'")):
            return None
        parts = target.split(".")
        if len(parts) != 3 or any(part.startswith("@") for part in parts):
            return None
        # A restored value comes from the backup, not from the agent, so it is shown to the
        # owner only for packages that hold no secrets under names the secret filters miss.
        if parts[0] not in CLAIM_VALUE_PACKAGES:
            return None
        if parts[0] == "network" and parts[2] not in NETWORK_CLAIM_OPTIONS:
            return None
        claim = {"kind": "uci_equals", "path": target, "equals": value[1:-1]}
        return claim if _claim_valid(claim) else None
    if verb == "delete":
        parts = rest.split(".")
        if len(parts) not in (2, 3) or any(part.startswith("@") for part in parts):
            return None
        claim = {"kind": "probe", "probe": ["uci-unset", rest]}
        return claim if _claim_valid(claim) else None
    return None


def _line_path(line: str) -> str | None:
    """The dotted path one batch line writes to, or None for a line with no path."""
    verb, _, rest = line.partition(" ")
    if verb in ("set", "add_list", "del_list", "delete", "reorder"):
        return rest.split("=", 1)[0]
    return None


def _superseded(path: str, later_paths: list[str]) -> bool:
    """True when a later line writes the same path, a section above it or an option below it."""
    return any(
        other == path or path.startswith(other + ".") or other.startswith(path + ".")
        for other in later_paths
    )


def _claims_for(lines: list[str]) -> list[dict[str, Any]]:
    """The claims the batch can carry, about the state after the whole batch, in batch order."""
    claims: list[dict[str, Any]] = []
    paths = [_line_path(line) for line in lines]
    for index, line in enumerate(lines):
        if len(claims) >= _explanation.MAX_CLAIMS:
            break
        path = paths[index]
        later = [p for p in paths[index + 1 :] if p is not None]
        if path is not None and _superseded(path, later):
            continue
        claim = _claim_for(line)
        if claim is not None:
            claims.append(claim)
    return claims


def _build_explanation(
    change_id: str, lines: list[str], agent_explanation: Any
) -> dict[str, Any]:
    """The stored explanation of the undo."""
    intent, risk = _agent_parts(agent_explanation)
    stored_intent = f"Undo change {change_id[:8]}: {intent}"
    if len(stored_intent) > _explanation.MAX_INTENT:
        raise UndoRefused(
            f"intent is too long (at most {_explanation.MAX_INTENT} characters here)"
        )
    steps = [_step_for(line) for line in lines]
    claims = _claims_for(lines)
    note = ""
    if not claims:
        claims = [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}]
        note = NO_CLAIM_RISK
    elif len(claims) < len(lines):
        note = PARTIAL_CLAIM_RISK
    built = {
        "intent": stored_intent,
        "steps": steps,
        "expect": claims,
        "risk": _risk_text(risk, note),
    }
    try:
        return _explanation.parse_explanation(built, change_lines=len(lines))
    except _explanation.ExplanationError as exc:
        raise UndoRefused(str(exc)) from None


# ------------------------------------------------------------------- the API


def draft_undo(
    state: Path,
    device: str,
    host: str,
    change_id: str,
    current_backup: Path,
    agent_explanation: Any,
) -> UndoDraft:
    """The undo of one confirmed change, ready for the owner to see.

    *current_backup* is a backup tarball of the router's /etc/config as it is
    now.  *agent_explanation* is the agent's own object with an ``intent`` and
    a ``risk``; the steps and the claims are Newton's own.

    Raises ``UndoRefused`` when the change may not be undone.
    """
    if _SID_RE.fullmatch(change_id) is None:
        raise UndoRefused("the change id is not a session id")
    if _DEVICE_RE.fullmatch(device) is None:
        raise UndoRefused("the device name is not usable")
    record = _verified_record(state, device, host, change_id)
    _require_confirmed(change_id)
    receipt = _require_receipt(state, device, change_id)
    backup_copy = _require_backup_copy(state, change_id, receipt)
    _require_planned_base(record, backup_copy)
    after_hash = _require_after_hash(record)
    _require_not_undone(state, change_id)
    packages = _touched_packages(record)

    current = _read_members(current_backup, set(packages))
    conflicts = _conflicts(
        state, device, change_id, receipt, packages, after_hash, current
    )
    _resolve_conflicts(conflicts)

    backup = _read_members(backup_copy, set(packages))
    lines = _build_lines(packages, backup, current)
    explanation = _build_explanation(change_id, lines, agent_explanation)
    current_md5 = {
        package: md5_hex(data)
        for package in packages
        if (data := current.get(package)) is not None
    }
    return UndoDraft(
        change_id=change_id,
        packages=tuple(packages),
        batch="".join(f"{line}\n" for line in lines),
        explanation=explanation,
        current_md5=current_md5,
        deleted_values=_deleted_values(packages, current, record, lines),
        not_undone=NOT_UNDONE,
    )


def verify_plan_base(draft: UndoDraft, plan_backup: Path) -> None:
    """Refuse when the router moved between the plan and the undo.

    *plan_backup* is the backup the plan made of the router at stage time.
    Every package the undo touches must have the same md5 in it as it has now.
    """
    members = _read_members(plan_backup, set(draft.packages))
    for package in draft.packages:
        data = members.get(package)
        planned = md5_hex(data) if data is not None else None
        if planned != draft.current_md5.get(package):
            raise UndoRefused(
                "the router config changed while the undo was being planned; "
                "plan the undo again"
            )


def mark_undo(state: Path, new_sid: str, change_id: str) -> bool:
    """Record that the plan *new_sid* undoes the change *change_id*.

    True when the record was marked, False when there is no such record.
    ``undo_of`` is not a hash-bound field, so the plan hash still verifies.
    """
    if _SID_RE.fullmatch(new_sid) is None or _SID_RE.fullmatch(change_id) is None:
        raise UndoRefused("the change id and the new session id must be session ids")
    path = state / "plans" / f"{new_sid}.json"
    record = _read_record(path)
    if record is None:
        return False
    if not _hash_verifies(record):
        raise UndoRefused("the plan record of the undo does not verify")
    record["undo_of"] = change_id
    try:
        _write_record(path, record)
    except OSError:
        return False
    written = _read_record(path)
    if written is None or not _hash_verifies(written):
        raise UndoRefused("the plan record of the undo does not verify")
    return True


def record_after_hash(state: Path, sid: str, confighash_text: str) -> bool:
    """Store the md5 of every config file of a confirmed change.

    *confighash_text* is the router's ``confighash`` output: one
    ``<md5> <name>`` line per file of /etc/config.  False (and nothing
    written) when the text or the record is not usable.
    """
    if _SID_RE.fullmatch(sid) is None:
        return False
    parsed = _parse_confighash(confighash_text)
    if parsed is None:
        return False
    path = state / "plans" / f"{sid}.json"
    record = _read_record(path)
    if record is None or not _hash_verifies(record):
        return False
    record["after_hash"] = parsed
    try:
        _write_record(path, record)
    except OSError:
        return False
    return True


def _parse_confighash(text: Any) -> dict[str, str] | None:
    """The ``<md5> <name>`` lines of the router's output, or None."""
    if not isinstance(text, str):
        return None
    out: dict[str, str] = {}
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        count += 1
        if count > MAX_AFTER_HASH_LINES:
            return None
        match = _CONFIGHASH_RE.fullmatch(line)
        if match is None:
            return None
        digest, name = match.group(1), match.group(2)
        if name in out:
            return None
        out[name] = digest
    return out or None
