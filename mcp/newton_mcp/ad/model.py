"""The results model (SPEC-1.3 section 6).

The model is plain data: the runner fills it, the renderer reads it.  A
check that cannot prove PASS is UNKNOWN, and the reason says why: an
empty read is "could not read", never "nothing there".

A finding carries the objects it is about.  The SID or the GUID of an
object is formatted by Newton from the binary value, so it is a fact and
not a name; the name and the distinguished name are directory text and
travel through the untrusted envelope (see ``render.py``).

A fix names the objects by SID or GUID only.  The commands are templates
whose only substitutions are those identifiers, so a directory string can
never end up inside a command the owner runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """The status of one check."""

    PASS = "PASS"
    FINDING = "FINDING"
    UNKNOWN = "UNKNOWN"


class UnknownReason(str, Enum):
    """Why a check could not prove anything."""

    ACCESS_DENIED = "access_denied"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    TRUNCATED = "truncated"
    NOT_COLLECTED = "not_collected"
    ERROR = "error"
    # The collector refused a file or skipped a special one: the data
    # the check reads is not the whole of it, so the check cannot prove
    # anything.
    PARSE_REFUSED = "parse_refused"


class Severity(str, Enum):
    """The severity of a check and of a finding.

    The three levels of the specification are low, medium and high
    (SPEC-1.3 section 6).  There is no fourth one: a finding that hands
    a privilege of this domain to an object that should not hold it is a
    high finding like every other.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Affected:
    """One object a finding is about."""

    sid: str | None = None
    guid: str | None = None
    name: str | None = None
    dn: str | None = None
    evidence: str | None = None


@dataclass(frozen=True)
class FixStep:
    """What the owner runs on one platform, and how to put it back."""

    summary: str
    commands: tuple[str, ...] = ()
    changes: str = ""
    revert: str = ""


@dataclass(frozen=True)
class Fix:
    """The fix of a finding: one step per platform."""

    windows: FixStep
    samba: FixStep


@dataclass(frozen=True)
class Finding:
    """One thing the audit found."""

    check_id: str
    severity: Severity
    title: str
    objects: tuple[Affected, ...] = ()
    maps_to: tuple[str, ...] = ()
    fix: Fix | None = None


@dataclass(frozen=True)
class CheckResult:
    """The result of one check."""

    check_id: str
    title: str
    severity: Severity
    status: Status
    reason: UnknownReason | None = None
    note: str = ""
    findings: tuple[Finding, ...] = ()
    maps_to: tuple[str, ...] = ()
    fix: Fix | None = None


@dataclass(frozen=True)
class AuditReport:
    """The report of one audit."""

    domain: str
    collector: str
    counts: dict[str, int] = field(default_factory=dict)
    results: tuple[CheckResult, ...] = ()
    generated: str = ""
    scope_note: str = ""


# The scope note of every report (SPEC-1.3 section 6): what the audit
# looked at, what it did not collect and what an ordinary account cannot
# see.  The deferred list is the one of section 8.
SCOPE_NOTE = (
    "Configured state only: this audit reads configuration and does not "
    "collect event-based evidence. Deferred checks: 15, 28, 29, 39-42, 47, "
    "49, 50, 54 (file half), 56, 58, 59, 61-66, 67 (host half), 68-80, 82, "
    "83, and AD CS. An ordinary account cannot see objects hidden by "
    "list-object mode or by per-object ACLs (AD-A-43)."
)
