"""Scoped grants: the owner allows named kinds of change on a device until a time.

A grant is a small record on disk under
``state_dir()/grants/<device>.json``: the classes it covers, when it
started, when it ends, the plan that opened it and the approval key it
was opened with.  The key is in the record because a plan inside a
grant is approved with the SAME approval token a manual approval would
produce, and the token is computed from that key.

The record holds a secret, so the directory is 0700, the file is 0600
and both are written atomically.  The display summary never carries the
key: it is shown to the owner and to the agent, and neither needs it.

A grant never covers a HIGH change and never covers a change that is
not fully explained by the classes it allows; both of those decisions
are made by :mod:`newton_mcp.change_classes`, from the staged lines.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import approve
from . import approval_proof
from . import change_classes


# The lengths a grant may be opened for, in hours.  A grant is short by
# design: the owner re-opens it when they want it again.
GRANT_HOURS = (1, 4, 8)

# The directory under the state dir the grant records live in.
_GRANTS_DIR = "grants"


def _grant_path(device: str) -> Path:
    """Where the grant record of *device* lives."""
    approval_proof._check_device(device)
    return approve.state_dir() / _GRANTS_DIR / f"{device}.json"


def _write_record(device: str, record: dict[str, Any]) -> None:
    """Write the grant record of *device*: 0600, atomically, in a 0700 dir."""
    directory = approval_proof._state_subdir(_GRANTS_DIR)
    approve._atomic_write(directory / f"{device}.json", record)


def _read_record(device: str) -> dict[str, Any] | None:
    """The grant record of *device* as it is on disk, or ``None``.

    ``None`` means there is nothing usable there: no file, an unreadable
    file or a file that does not hold a record.
    """
    try:
        raw = _grant_path(device).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    return record


def _well_formed(record: dict[str, Any]) -> bool:
    """Does a record hold everything a grant needs to be trusted?"""
    classes = record.get("classes")
    if not isinstance(classes, list) or not classes:
        return False
    if not all(
        isinstance(name, str) and name in change_classes.GRANTABLE_CLASSES
        for name in classes
    ):
        return False
    for key in ("granted_at", "until"):
        number = record.get(key)
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            return False
    plan_id = record.get("granted_by_plan")
    if not isinstance(plan_id, str) or not approve.PLAN_ID_RE.fullmatch(
        plan_id
    ):
        return False
    k_hex = record.get("k")
    if not isinstance(k_hex, str) or not approve.HEX64_RE.fullmatch(k_hex):
        return False
    return True


def _remove(device: str) -> None:
    """Delete the grant record of *device*, if there is one."""
    try:
        _grant_path(device).unlink()
    except OSError:
        pass


def _moment(now: float | None) -> float:
    return time.time() if now is None else float(now)


def _iso(seconds: float) -> str:
    """A UNIX time as a UTC ISO stamp, the form the owner reads."""
    return (
        datetime.fromtimestamp(float(seconds), tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _check_classes(classes: Iterable[str]) -> list[str]:
    """The grantable class names of *classes*, checked and deduped."""
    if isinstance(classes, str) or not isinstance(classes, Iterable):
        raise ValueError("classes must be a list of grantable class names")
    wanted: list[str] = []
    for name in classes:
        if (
            not isinstance(name, str)
            or name not in change_classes.GRANTABLE_CLASSES
        ):
            raise ValueError(f"unknown grantable class: {name!r}")
        if name not in wanted:
            wanted.append(name)
    if not wanted:
        raise ValueError("a grant must cover at least one class")
    return wanted


def open_grant(
    device: str,
    classes: Iterable[str],
    hours: int,
    k_hex: str,
    plan_id: str,
    now: float | None = None,
) -> None:
    """Open a grant on *device* covering *classes* for *hours*.

    The grant replaces any grant the device had.  ``k_hex`` is the
    approval key the grant was opened with: a plan inside the grant is
    approved with it, so it is the same approval the owner would have
    given by hand.  ``plan_id`` is the plan that opened the grant, kept
    so the record says which change the owner was looking at.

    Raises ``ValueError`` for a device name that is not a plain name, a
    class that is not grantable, a length that is not offered, a key
    that is not 64 lowercase hex characters or a plan id that is not 32
    lowercase hex characters.
    """
    approval_proof._check_device(device)
    wanted = _check_classes(classes)
    if isinstance(hours, bool) or hours not in GRANT_HOURS:
        raise ValueError(f"a grant lasts one of {GRANT_HOURS} hours")
    if not isinstance(k_hex, str) or not approve.HEX64_RE.fullmatch(k_hex):
        raise ValueError(
            "approval key must be 64 lowercase hexadecimal characters"
        )
    if not isinstance(plan_id, str) or not approve.PLAN_ID_RE.fullmatch(
        plan_id
    ):
        raise ValueError("plan id must be 32 lowercase hexadecimal characters")
    moment = _moment(now)
    record = {
        "classes": sorted(wanted),
        "granted_at": float(moment),
        "until": float(moment) + hours * 3600,
        "granted_by_plan": plan_id,
        "k": k_hex,
    }
    _write_record(device, record)


def load_live_grant(
    device: str, now: float | None = None
) -> dict[str, Any] | None:
    """The live grant record of *device*, or ``None``.

    A live grant is one whose deadline has not passed.  A record that
    has expired, or that does not hold a well-formed grant, is deleted:
    a grant nobody can read must not be able to cover a change.
    """
    approval_proof._check_device(device)
    record = _read_record(device)
    if record is None:
        _remove(device)
        return None
    if not _well_formed(record):
        _remove(device)
        return None
    if float(record["until"]) <= _moment(now):
        _remove(device)
        return None
    return record


def grant_summary(
    device: str, now: float | None = None
) -> dict[str, Any] | None:
    """What the owner is told about the grant of *device*.

    The summary carries the classes, the deadline as a UTC stamp and the
    time the grant was opened at as the UNIX time the record holds, and
    never the approval key: the summary is shown where the key has no
    business being.  It is ``None`` when there is no live grant.
    """
    record = load_live_grant(device, now=now)
    if record is None:
        return None
    return {
        "classes": list(record["classes"]),
        "until": _iso(record["until"]),
        "granted_at": record["granted_at"],
    }


def covers(
    device: str,
    classification: change_classes.Classification,
    now: float | None = None,
) -> str | None:
    """The approval key a grant covers *classification* with, or ``None``.

    A grant covers a change when the change is live, is not HIGH, is
    grantable and every class it touches is one the grant allows.  The
    key is returned so the caller can approve the plan with it.
    """
    record = load_live_grant(device, now=now)
    if record is None:
        return None
    if not classification.grantable or classification.high:
        return None
    classes = set(classification.classes)
    if not classes:
        return None
    if not classes <= set(record["classes"]):
        return None
    return record["k"]


def revoke_grant(device: str) -> bool:
    """Delete the grant of *device*.

    Returns True when there was a grant to delete and False when there
    was none.
    """
    approval_proof._check_device(device)
    try:
        _grant_path(device).unlink()
    except FileNotFoundError:
        return False
    return True


def narrow_grant(device: str, keep_classes: Iterable[str]) -> bool:
    """Keep only *keep_classes* of the grant of *device*.

    Narrowing never adds a class and never moves the deadline: the
    grant gets smaller or it goes away.  When nothing is left the grant
    is revoked.

    Returns True when a live grant was there to narrow and False when
    there was none.
    """
    approval_proof._check_device(device)
    record = load_live_grant(device)
    if record is None:
        return False
    if isinstance(keep_classes, str):
        keep_classes = [keep_classes]
    keep = {
        name
        for name in (keep_classes or ())
        if isinstance(name, str) and name in change_classes.GRANTABLE_CLASSES
    }
    remaining = sorted(set(record["classes"]) & keep)
    if not remaining:
        revoke_grant(device)
        return True
    if remaining == sorted(record["classes"]):
        return True
    narrowed = dict(record)
    narrowed["classes"] = remaining
    _write_record(device, narrowed)
    return True
