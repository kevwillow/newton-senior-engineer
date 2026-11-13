"""The ACL checks.

The checks of this module read the security descriptors of the objects
the spec lists and look for the write rights that turn a read-only
audit into a way into the domain.

Every check is a pure function of the collector document.  The runner
has already proved that the audit was allowed to see the data (the
status of every query and the sentinels), so a check reads the
descriptors and judges them.

Three rules shape the module:

- privilege is computed by SID, never by name: a renamed group is the
  same group;
- a well-known trustee whose right is fine is not a finding, and the
  list of those trustees is data, with the reason of every entry;
- a fix names the object it changes by SID or by GUID, so a
  directory-originated string never ends up inside a command.

The access mask of a directory ACE is compared against the expanded
forms of the generic rights: a stored ACE never carries the GENERIC_*
bits, it carries the rights they expand to, so the constants of
``values.py`` hold both forms and the checks use the stored ones.  An
ACE that names no object type and carries the write-property bit grants
a write on every property of the object, and one that carries the
control-access bit grants every extended right, the replication rights
among them.

A scope that Newton could not read completely is never a PASS.  A GPO
that a gPLink of the domain head or of an organizational unit points at
and that the collector did not read is such a scope: the check says how
many GPOs it could not read and names none of them, because the GUID and
the name of a GPO are directory text.

A write on a property of a GPO is a way into the domain when the
property says where the files of the GPO come from, what the GPO
applies to the computers and to the users, or which revision of the GPO
the computers take.  The GUIDs of those properties are data of this
module, with the name of the property they stand for.

A fix that no documented cmdlet can write is an explanation: the
commands are empty and the summary tells the owner what to change and
where.  The DACL of an object is the one thing no cmdlet of the
ActiveDirectory module changes by SID or by GUID, so every fix of this
module is an explanation.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable

from ..catalogue import Check
from ..members import Directory
from ..model import (
    Affected,
    CheckResult,
    Finding,
    Fix,
    FixStep,
    Severity,
    Status,
    UnknownReason,
)
from ..secdesc import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    DACL_ABSENT,
    DACL_NULL,
    Ace,
    SecurityDescriptor,
    parse,
)
from ..values import (
    ACCESS_MASK_CONTROL_ACCESS,
    ACCESS_MASK_CREATE_CHILD,
    ACCESS_MASK_DELETE,
    ACCESS_MASK_DELETE_CHILD,
    ACCESS_MASK_READ_PROP,
    ACCESS_MASK_SELF,
    ACCESS_MASK_WRITE_DAC,
    ACCESS_MASK_WRITE_OWNER,
    ACCESS_MASK_WRITE_PROP,
    EXTENDED_RIGHT_GET_CHANGES,
    EXTENDED_RIGHT_GET_CHANGES_ALL,
    EXTENDED_RIGHT_GET_CHANGES_IN_FILTERED_SET,
    GENERIC_ALL_STORED,
    GENERIC_READ_STORED,
    GENERIC_WRITE_STORED,
    PROPERTY_GUIDS,
    guid_from_base64,
    is_guid,
    sid_from_base64,
)
from ..wire import Document, Row


# The extended rights that let a principal replicate the directory
# (SPEC-1.3 section 8, AD-A-51).
DCSYNC_GET_CHANGES = EXTENDED_RIGHT_GET_CHANGES
DCSYNC_GET_CHANGES_ALL = EXTENDED_RIGHT_GET_CHANGES_ALL
DCSYNC_GET_CHANGES_IN_FILTERED_SET = EXTENDED_RIGHT_GET_CHANGES_IN_FILTERED_SET
DCSYNC_RIGHTS = frozenset(
    {
        DCSYNC_GET_CHANGES,
        DCSYNC_GET_CHANGES_ALL,
        DCSYNC_GET_CHANGES_IN_FILTERED_SET,
    }
)

# The name the ActiveDirectory module gives the replication right.
DCSYNC_RIGHT_NAME = "Replicating Directory Changes"

# The name of every replication right, so that a finding may name the
# rights a principal holds and not only the fact that it holds one.
# The GUID is in the name: it is the identifier of the right.
DCSYNC_RIGHT_NAMES: dict[str, str] = {
    DCSYNC_GET_CHANGES: (
        f"Replicating Directory Changes (Get-Changes) {DCSYNC_GET_CHANGES}"
    ),
    DCSYNC_GET_CHANGES_ALL: (
        f"Replicating Directory Changes All (Get-Changes-All) "
        f"{DCSYNC_GET_CHANGES_ALL}"
    ),
    DCSYNC_GET_CHANGES_IN_FILTERED_SET: (
        f"Replicating Directory Changes In Filtered Set "
        f"(Get-Changes-In-Filtered-Set) {DCSYNC_GET_CHANGES_IN_FILTERED_SET}"
    ),
}

# The right an ACE that names no object type and carries the
# control-access bit grants: every extended right, the replication
# rights among them.
DCSYNC_ALL_EXTENDED_RIGHTS = (
    "every extended right (the ACE names no object type and carries the "
    "control-access bit)"
)

# The properties a write on them is a way into the domain
# (SPEC-1.3 section 8, AD-A-52).
DANGEROUS_PROPERTIES: dict[str, str] = dict(PROPERTY_GUIDS)

# The properties of a GPO a write on them is a way into the domain
# (MS-GPOL 2.2.1.1.9 and 2.2.1.1.10, AD-A-54).  The path of the
# SYSVOL folder of the GPO says where the files of the GPO come from,
# the two extension names say what the GPO applies to the computers and
# to the users, and the version says which revision of the GPO the
# computers take.
GPO_PROPERTIES: dict[str, str] = {
    "f30e3bc1-9ff0-11d1-b603-0000f80367c1": "gPCFileSysPath",
    "32ff8ecc-783f-11d2-9916-0000f87a57d4": "gPCMachineExtensionNames",
    "42a75fc6-783f-11d2-9916-0000f87a57d4": "gPCUserExtensionNames",
    "bf967a76-0de6-11d0-a285-00aa003049e2": "versionNumber",
}

# The access mask bits that grant a write (MS-DTYP 2.4.6.2): a write on
# a property, the right to change the DACL and the right to change the
# owner.
WRITE_BITS: int = (
    ACCESS_MASK_WRITE_PROP | ACCESS_MASK_WRITE_DAC | ACCESS_MASK_WRITE_OWNER
)

# The access mask bits that grant a write on a GPO.  A GPO that a
# principal outside the privileged set may write is a way into the
# domain: the principal decides what the computers of the domain run.
GPO_WRITE_BITS: int = (
    WRITE_BITS
    | ACCESS_MASK_CREATE_CHILD
    | ACCESS_MASK_DELETE_CHILD
    | ACCESS_MASK_SELF
    | ACCESS_MASK_DELETE
)


# The trustees whose ACEs are not findings, and the reason of every
# entry.  The data is the allow-list: a trustee that is not in it and
# is not privileged is judged on its rights.
@dataclass(frozen=True)
class Allowed:
    """One trustee whose ACEs are not findings."""

    sid: str
    why: str
    read_only: bool = False


ALLOWED_TRUSTEES: tuple[Allowed, ...] = (
    Allowed(
        "S-1-5-10",
        "SELF: the right the object grants to the object itself",
    ),
    Allowed(
        "S-1-3-0",
        "CREATOR OWNER: the inheritable template a new object takes",
    ),
    Allowed(
        "S-1-5-9",
        "Enterprise Domain Controllers: the replication group of the forest",
    ),
    Allowed(
        "S-1-5-18",
        "SYSTEM: the system account of the machine",
    ),
    Allowed(
        "S-1-5-11",
        "Authenticated Users: read access is the default on every object",
        read_only=True,
    ),
)

# The holders of the replication rights that are allowed to hold them
# (SPEC-1.3 section 8, AD-A-51).  The RIDs are the ones of the domain
# of the document: 512 is the domain admins, 516 the domain
# controllers, 519 the enterprise admins, 521 the read-only domain
# controllers and 498 the enterprise read-only domain controller of the
# forest.  Windows grants the domain admins and the enterprise admins
# every extended right on the domain head by default, so a domain that
# grants it is not a domain that misconfigured it.
ALLOWED_DCSYNC_RIDS: tuple[int, ...] = (512, 516, 519, 521, 498)
ALLOWED_DCSYNC_SIDS: tuple[str, ...] = ("S-1-5-32-544", "S-1-5-9", "S-1-5-18")

# A gPLink entry: "[LDAP://cn={GUID},CN=Policies,CN=System,DC=...;0]".
# The number after the semicolon is the link option: 0 is an enabled
# link, 1 a disabled one.
_GPLINK_RE = re.compile(
    r"\[LDAP://cn=\{(?P<guid>[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}"
    r"[^;\]]*;(?P<option>\d+)\]",
    re.IGNORECASE,
)

# The container of a GPO: its name is the GUID of the GPO.
_GPO_NAME_RE = re.compile(
    r"^\{(?P<guid>[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}$"
)


@dataclass(frozen=True)
class Spec:
    """What the catalogue says about one check."""

    id: str
    title: str
    severity: Severity
    maps_to: tuple[str, ...]
    fix: Fix | None = None


def _make(
    spec: Spec,
    evaluate: Callable[[Document, Spec], CheckResult],
    *,
    queries: tuple[str, ...] = (),
    required_attrs: tuple[str, ...] = (),
    sentinels: tuple[str, ...] = (),
) -> Check:
    """The catalogue entry of one check and the function that runs it."""

    def run(document: Document) -> CheckResult:
        return evaluate(document, spec)

    return Check(
        id=spec.id,
        title=spec.title,
        severity=spec.severity,
        evaluate=run,
        queries=queries,
        required_attrs=required_attrs,
        sentinels=sentinels,
        maps_to=spec.maps_to,
        fix=spec.fix,
    )


def _result(
    spec: Spec,
    status: Status,
    *,
    reason: UnknownReason | None = None,
    note: str = "",
    findings: tuple[Finding, ...] = (),
) -> CheckResult:
    """The result of one check."""
    return CheckResult(
        check_id=spec.id,
        title=spec.title,
        severity=spec.severity,
        status=status,
        reason=reason,
        note=note,
        findings=findings,
        maps_to=spec.maps_to,
        fix=spec.fix,
    )


# ---- small readers ---------------------------------------------------------


def _rows(document: Document, query_id: str) -> tuple[Row, ...]:
    """The rows of a query."""
    result = document.queries.get(query_id)
    if result is None:
        return ()
    return result.rows


def _sid_of(row: Row) -> str | None:
    """The SID of a row, when it carries a usable one."""
    for value in row.a.get("objectSid", ()):
        try:
            return sid_from_base64(value)
        except ValueError:
            continue
    return None


def _descriptor(row: Row) -> SecurityDescriptor | None:
    """The security descriptor of a row, when it carries a readable one."""
    for value in row.a.get("nTSecurityDescriptor", ()):
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            continue
        try:
            return parse(raw)
        except Exception:
            continue
    return None


def _guid_of(row: Row) -> str | None:
    """The GUID of a GPO, taken from the name of its container.

    The name of the container of a GPO is the GUID of the GPO, and it
    is the identifier the commands of the owner need.  The objectGUID
    attribute of the container is a GUID of its own.
    """
    for part in row.dn.split(","):
        match = _GPO_NAME_RE.match(part.split("=", 1)[-1].strip())
        if match is None:
            continue
        guid = match.group("guid").lower()
        return guid if is_guid(guid) else None
    return None


def _guid_from_attribute(row: Row) -> str | None:
    """The objectGUID of a row, when it carries a usable one."""
    for value in row.a.get("objectGUID", ()):
        try:
            guid = guid_from_base64(value)
        except ValueError:
            continue
        return guid if is_guid(guid) else None
    return None


def _grants_write(mask: int) -> bool:
    """True when an access mask grants a write.

    The write bits are the property write, the right to change the
    DACL and the right to change the owner.  The generic rights expand
    to bits that hold them, so a generic write is a write.
    """
    return bool(mask & WRITE_BITS)


def _is_allowed(trustee: str, mask: int, write_bits: int = WRITE_BITS) -> bool:
    """True when the trustee of an ACE is one of the allowed ones."""
    for entry in ALLOWED_TRUSTEES:
        if entry.sid != trustee:
            continue
        if not entry.read_only:
            return True
        return not mask & write_bits
    return False


def _dangerous_property(object_type: str | None) -> str | None:
    """The name of the property an ACE names, when it is one of them."""
    if object_type is None:
        return None
    return DANGEROUS_PROPERTIES.get(object_type.lower())


def _gpo_property(object_type: str | None) -> str | None:
    """The name of the GPO property an ACE names, when it names one."""
    if object_type is None:
        return None
    return GPO_PROPERTIES.get(object_type.lower())


def _grants_dcsync(ace: Ace) -> bool:
    """True when an ACE grants a replication right.

    An ACE that names one of the replication rights grants it.  An ACE
    that names no object type and carries the control-access bit
    grants every extended right, and the replication rights are
    extended rights: such an ACE is a replication right as well.
    """
    if ace.object_type is not None:
        return ace.object_type.lower() in DCSYNC_RIGHTS
    return bool(ace.mask & ACCESS_MASK_CONTROL_ACCESS)


def _replication_right(ace: Ace) -> str:
    """The replication right an ACE grants, named.

    An ACE that names no object type and carries the control-access
    bit grants every extended right: it is named as such, because the
    replication rights are a part of them.
    """
    if ace.object_type is None:
        return DCSYNC_ALL_EXTENDED_RIGHTS
    right = ace.object_type.lower()
    return DCSYNC_RIGHT_NAMES.get(right, right)


def _dangerous_right(ace: Ace) -> tuple[str, str] | None:
    """The rights name and the description of a dangerous ACE.

    The dangerous rights are the ones of SPEC-1.3 section 8: full
    control, a generic write, the right to change the DACL or the
    owner, and a write on one of the properties that lead into the
    domain.  A write on all the properties of an object counts: the
    ACE that carries it names no property.
    """
    mask = ace.mask
    if mask & GENERIC_ALL_STORED == GENERIC_ALL_STORED:
        return "GenericAll", "full control on the object"
    if mask & ACCESS_MASK_WRITE_DAC:
        return "WriteDacl", "the right to change the DACL of the object"
    if mask & ACCESS_MASK_WRITE_OWNER:
        return "WriteOwner", "the right to change the owner of the object"
    if mask & GENERIC_WRITE_STORED == GENERIC_WRITE_STORED:
        return "GenericWrite", "a generic write on the object"
    if mask & ACCESS_MASK_WRITE_PROP:
        name = _dangerous_property(ace.object_type)
        if name is not None:
            return "WriteProperty", f"a write on {name}"
        if ace.object_type is None:
            return "WriteProperty", "a write on every property of the object"
    return None


def _explain_fix(
    summary: str,
    *,
    changes: str,
    revert: str,
    samba_summary: str | None = None,
) -> Fix:
    """A fix that explains the change instead of running it.

    The commands are empty: no documented cmdlet changes the DACL of an
    object that is named by its SID or by its GUID, and a command that
    named the object by its distinguished name would put a directory
    string inside a command.  The summary says what to change and
    where, and the owner runs it.
    """
    return Fix(
        windows=FixStep(
            summary=summary,
            commands=(),
            changes=changes,
            revert=revert,
        ),
        samba=FixStep(
            summary=samba_summary if samba_summary is not None else summary,
            commands=(),
            changes=changes,
            revert=revert,
        ),
    )


def _acl_fix(
    rights: str,
    description: str,
    *,
    trustee: str,
    object_sid: str | None,
    object_guid: str | None,
    target: str | None = None,
) -> Fix:
    """The fix of a finding about a right in the DACL of an object.

    The object is named by its identifier, never by its name: the name
    sits in the envelope, beside the fix.  The target says what the
    object is when the identifier alone does not say it, as for a GPO:
    the identifier of a GPO is the GUID of its container.
    """
    if target is not None:
        pass
    elif object_guid is not None:
        target = f"the object {object_guid}"
    elif object_sid is not None:
        target = f"the object {object_sid}"
    else:
        target = "the object of the envelope"
    return _explain_fix(
        (
            f"Take {description} away from the principal {trustee}: the DACL "
            f"of {target} grants it."
        ),
        changes=(
            "the DACL of the object: the ACE that grants the right to the "
            "principal is removed"
        ),
        revert=(
            "add the ACE again with the rights it had before the change"
        ),
    )


def _gpo_evidence(
    trustee: str,
    description: str,
    row: Row,
) -> tuple[str | None, str]:
    """The GUID of a GPO row and the evidence of a finding about it.

    The name of the container of a GPO is the GUID of the GPO, and it
    is the identifier the commands of the owner need.  The objectGUID
    attribute of the row is the GUID of the container object itself.
    Both are named in a finding, so that the GPO is known by the GUID
    of its name and the object by its own.
    """
    object_guid = _guid_from_attribute(row)
    gpo_guid = _guid_of(row)
    target = "the GPO" if gpo_guid is None else f"the GPO {gpo_guid}"
    evidence = f"the trustee {trustee} holds {description} on {target}"
    if object_guid is not None:
        evidence = (
            f"{evidence} (the objectGUID of the container is {object_guid})"
        )
    return object_guid, evidence


# ---- AD-A-51: the replication rights ----------------------------------------

_SPEC_51 = Spec(
    id="AD-A-51",
    title="Replication rights on the domain head",
    severity=Severity.HIGH,
    maps_to=("ATT&CK T1003.006", "MS-ADTS"),
)


def _allowed_dcsync(document: Document) -> set[str]:
    """The principals that are allowed to hold the replication rights.

    The list is the one of SPEC-1.3 section 8 and nothing else: the
    domain controllers and the read-only domain controllers of the
    domain, the enterprise read-only domain controller of the forest,
    the administrators, the enterprise domain controllers and the
    system account.  Every other principal that holds a replication
    right is a finding, the groups that hold it as members included.
    """
    domain_sid = document.domain.domain_sid
    allowed = set(ALLOWED_DCSYNC_SIDS)
    for rid in ALLOWED_DCSYNC_RIDS:
        allowed.add(f"{domain_sid}-{rid}")
    return allowed


def _evaluate_51(document: Document, spec: Spec) -> CheckResult:
    head = _rows(document, "domain_head")[0]
    descriptor = _descriptor(head)
    if descriptor is None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note="the domain head carries no descriptor the audit could read",
        )
    if descriptor.dacl_state == DACL_NULL:
        return _result(
            spec,
            Status.FINDING,
            note="the DACL of the domain head is null, so every principal may "
            "replicate the directory",
            findings=(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="The domain head has no DACL at all",
                    objects=(
                        Affected(
                            sid=_sid_of(head),
                            dn=head.dn,
                            evidence=(
                                "the DACL of the domain head is null, so every "
                                "principal may replicate the directory"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_explain_fix(
                        "Give the domain head a DACL that only the allowed "
                        "holders may write.",
                        changes=(
                            "the DACL of the domain head: a null DACL grants "
                            "every right to every principal"
                        ),
                        revert=(
                            "put the DACL the object had before the change "
                            "back"
                        ),
                    ),
                ),
            ),
        )
    if descriptor.dacl_state == DACL_ABSENT:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=(
                "the domain head carries no DACL at all, so the replication "
                "rights it holds cannot be read"
            ),
        )
    allowed = _allowed_dcsync(document)
    directory = Directory(document)
    # The rights every principal holds, and the principal itself: a
    # principal is reported once, with every replication right it
    # holds on the object.
    rights_by_trustee: dict[str, list[str]] = {}
    for ace in descriptor.dacl:
        if not isinstance(ace, Ace):
            continue
        if ace.type not in (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE):
            continue
        if not _grants_dcsync(ace):
            continue
        trustee = ace.trustee
        if trustee is None or trustee in allowed:
            continue
        rights = rights_by_trustee.setdefault(trustee, [])
        right = _replication_right(ace)
        if right not in rights:
            rights.append(right)
    findings: list[Finding] = []
    notes: list[str] = []
    for trustee, rights in rights_by_trustee.items():
        principal = directory.principal(trustee)
        holders = [
            member
            for member in sorted(directory.members_recursive(trustee))
            if member not in allowed
        ]
        if holders:
            notes.append(
                "a group that is not an allowed holder holds a replication "
                f"right, and {len(holders)} of its members are not allowed "
                "holders either"
            )
        else:
            notes.append(
                "a principal that is not an allowed holder holds a "
                "replication right"
            )
        evidence = (
            "the principal holds the replication rights "
            f"{', '.join(rights)} on the domain head"
        )
        objects = [
            Affected(
                sid=_sid_of(head),
                dn=head.dn,
                evidence="the object whose DACL carries the replication rights",
            ),
            Affected(
                sid=trustee,
                dn=principal.dn if principal is not None else None,
                evidence=evidence,
            ),
        ]
        objects.extend(
            Affected(
                sid=holder,
                evidence=(
                    "the member of the group inherits the replication right "
                    "on the domain head"
                ),
            )
            for holder in holders
        )
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="A principal outside the allowed holders may replicate the directory",
                objects=tuple(objects),
                maps_to=spec.maps_to,
                fix=_acl_fix(
                    DCSYNC_RIGHT_NAME,
                    f"the replication rights on the domain head ({', '.join(rights)})",
                    trustee=trustee,
                    object_sid=_sid_of(head),
                    object_guid=None,
                ),
            )
        )
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note=(
            "; ".join(notes)
            if notes
            else "no principal outside the allowed holders holds a replication right"
        ),
        findings=tuple(findings),
    )


# ---- AD-A-52 and AD-A-53: the dangerous write rights -----------------------

_SPEC_52 = Spec(
    id="AD-A-52",
    title="Dangerous write rights on the objects of the domain",
    severity=Severity.HIGH,
    maps_to=(
        "BloodHound docs",
        "ANSSI control-paths (unverified)",
        "ATT&CK T1098",
        "T1484",
    ),
)

_SPEC_53 = Spec(
    id="AD-A-53",
    title="The AdminSDHolder and the objects it protects",
    severity=Severity.HIGH,
    maps_to=("ATT&CK T1098", "MS best practices"),
)


def _gplink_entries(value: str) -> list[tuple[str, bool]]:
    """The GPOs a gPLink value points at, and whether the link is enabled.

    The link option after the semicolon is 0 for an enabled link and 1
    for a disabled one: a disabled link configures nothing.
    """
    entries: list[tuple[str, bool]] = []
    for match in _GPLINK_RE.finditer(value):
        guid = match.group("guid").lower()
        enabled = match.group("option") == "0"
        entries.append((guid, enabled))
    return entries


def _linked_gpo_guids(document: Document) -> list[str]:
    """The GUIDs of the GPOs linked at the domain head or at the DC OU.

    The domain head carries its own gPLink.  The DC OU carries none:
    the query that reads it asks for the descriptor only, so the link
    is read from the row of the organizational unit itself.  A link
    that is disabled points at a GPO that configures nothing.
    """
    found: list[str] = []

    def add(rows: list[Row]) -> None:
        for row in rows:
            for value in row.a.get("gPLink", ()):
                for guid, enabled in _gplink_entries(value):
                    if not enabled:
                        continue
                    if guid not in found:
                        found.append(guid)

    add(list(_rows(document, "domain_head")))
    dc_ou = _rows(document, "dc_ou")
    if dc_ou:
        keys = {row.dn.strip().lower() for row in dc_ou}
        add([row for row in _rows(document, "ous") if row.dn.strip().lower() in keys])
    return found


def _gpo_rows(document: Document, guids: list[str]) -> list[Row]:
    """The GPO rows of the GUIDs."""
    rows: list[Row] = []
    for row in _rows(document, "gpos"):
        guid = _guid_of(row)
        if guid is not None and guid in guids:
            rows.append(row)
    return rows


def _referenced_gpos(document: Document) -> list[str]:
    """The GUIDs the gPLink values of the document point at.

    The domain head and every organizational unit of the domain carry a
    link.  Every GUID in one of them is a GPO the domain applies, and
    a GPO the collector did not read is a GPO whose DACL cannot be
    judged.
    """
    found: list[str] = []

    def add(rows: tuple[Row, ...]) -> None:
        for row in rows:
            for value in row.a.get("gPLink", ()):
                for guid, _enabled in _gplink_entries(value):
                    if guid not in found:
                        found.append(guid)

    add(_rows(document, "domain_head"))
    add(_rows(document, "ous"))
    return found


def _missing_gpos(document: Document) -> int:
    """The number of the GPOs a link points at that the collector did not read.

    The gpos query returns the GPO containers of the domain.  A link
    points at a GPO that is not in the result: the collector read no
    descriptor of it.  Only the count is reported: the GUID of a GPO
    and its name are directory text, and they never go into a note.
    """
    present: set[str] = set()
    for row in _rows(document, "gpos"):
        guid = _guid_of(row)
        if guid is not None:
            present.add(guid)
    return sum(
        1 for guid in _referenced_gpos(document) if guid not in present
    )


def _missing_gpo_note(count: int) -> str:
    """The note of a check whose scope holds GPOs the collector did not read."""
    return (
        "the GPO objects were not readable: "
        f"{count} GPO(s) that a link points at were not read"
    )


def _unread_gpo_note(document: Document) -> str | None:
    """The note of a scope whose GPOs the collector did not read, if any.

    A link that points at a GPO the collector did not read is one case.
    An empty GPO read is the other, even when nothing is linked: the
    Default Domain Policy and the Default Domain Controllers Policy
    always exist, so an empty read is "could not read".
    """
    missing = _missing_gpos(document)
    if missing:
        return _missing_gpo_note(missing)
    if not _rows(document, "gpos"):
        return "the GPO objects were not readable: the collector read no GPO"
    return None


def _objects_52(document: Document) -> list[tuple[str, Row]]:
    """The objects AD-A-52 reads: the domain, the GPOs and the holders."""
    objects: list[tuple[str, Row]] = []
    for query_id in ("domain_head", "adminsdholder", "dc_ou"):
        for row in _rows(document, query_id):
            objects.append((query_id, row))
    for row in _rows(document, "protected_sds"):
        objects.append(("protected_sds", row))
    for row in _gpo_rows(document, _linked_gpo_guids(document)):
        objects.append(("gpos", row))
    return objects


def _write_findings(
    document: Document,
    spec: Spec,
    objects: list[tuple[str, Row]],
) -> tuple[list[Finding], list[Row], list[Row]]:
    """The findings of the objects that carry a dangerous write right.

    The second element holds the objects whose descriptor the collector
    did not read: the check cannot prove anything about them.  The
    third holds the objects whose descriptor carries no DACL at all.
    """
    privileged = Directory(document).privileged_set()
    findings: list[Finding] = []
    unreadable: list[Row] = []
    absent: list[Row] = []
    for source, row in objects:
        descriptor = _descriptor(row)
        if descriptor is None:
            unreadable.append(row)
            continue
        if descriptor.dacl_state == DACL_NULL:
            gpo_guid = _guid_of(row) if source == "gpos" else None
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="An object of the domain has no DACL at all",
                    objects=(
                        Affected(
                            sid=_sid_of(row),
                            guid=(
                                _guid_from_attribute(row)
                                if source == "gpos"
                                else None
                            ),
                            dn=row.dn,
                            evidence=(
                                "the DACL of the object is null, so every "
                                "principal may do everything with it"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_acl_fix(
                        "GenericAll",
                        "the missing protection of the object",
                        trustee="every principal",
                        object_sid=_sid_of(row),
                        object_guid=gpo_guid,
                        target=(
                            None if gpo_guid is None else f"the GPO {gpo_guid}"
                        ),
                    ),
                )
            )
            continue
        if descriptor.dacl_state == DACL_ABSENT:
            absent.append(row)
            continue
        for ace in descriptor.dacl:
            if not isinstance(ace, Ace):
                continue
            if ace.type not in (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE):
                continue
            trustee = ace.trustee
            if trustee is None:
                continue
            right = _dangerous_right(ace)
            if right is None:
                continue
            rights_name, description = right
            if trustee in privileged:
                continue
            if _is_allowed(trustee, ace.mask):
                continue
            # A GPO is named by its GUID, every other object by its SID.
            if source == "gpos":
                guid, evidence = _gpo_evidence(trustee, description, row)
                target = (
                    None
                    if _guid_of(row) is None
                    else f"the GPO {_guid_of(row)}"
                )
            else:
                guid = None
                evidence = (
                    f"the trustee {trustee} holds {description} on "
                    f"the object of the {source} query"
                )
                target = None
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A principal outside the privileged set holds a write right",
                    objects=(
                        Affected(
                            sid=_sid_of(row),
                            guid=guid,
                            dn=row.dn,
                            evidence=evidence,
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_acl_fix(
                        rights_name,
                        description,
                        trustee=trustee,
                        object_sid=_sid_of(row),
                        object_guid=guid,
                        target=target,
                    ),
                )
            )
    return findings, unreadable, absent


def _write_note(objects: list[tuple[str, Row]], findings: list[Finding]) -> str:
    """The note of a check about the write rights of objects."""
    if findings:
        return (
            f"{len(findings)} object(s) hold a write right for a principal "
            "outside the privileged set"
        )
    return (
        f"{len(objects)} object(s) hold no write right for a principal outside "
        "the privileged set"
    )


def _unreadable_note(rows: list[Row]) -> str:
    """The note of a check that could not read every descriptor."""
    return (
        f"{len(rows)} object(s) of the scope carry no descriptor the audit could "
        "read"
    )


def _absent_note(rows: list[Row]) -> str:
    """The note of a check whose scope holds an object without a DACL."""
    return (
        f"{len(rows)} object(s) of the scope carry no DACL at all, so the rights "
        "they hold cannot be read"
    )


def _scope_result(
    spec: Spec,
    objects: list[tuple[str, Row]],
    findings: list[Finding],
    unreadable: list[Row],
    absent: list[Row],
) -> CheckResult:
    """The result of a check that read a scope of objects.

    A finding is a fact about the domain and is reported as one.  A
    scope Newton could not read completely is never a PASS: the check
    says so in its note.
    """
    if findings:
        note = _write_note(objects, findings)
        if unreadable:
            note = f"{note}; {_unreadable_note(unreadable)}"
        if absent:
            note = f"{note}; {_absent_note(absent)}"
        return _result(
            spec,
            Status.FINDING,
            note=note,
            findings=tuple(findings),
        )
    if unreadable:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=_unreadable_note(unreadable),
        )
    if absent:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=_absent_note(absent),
        )
    return _result(spec, Status.PASS, note=_write_note(objects, findings))


def _evaluate_52(document: Document, spec: Spec) -> CheckResult:
    unread = _unread_gpo_note(document)
    if unread is not None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=unread,
        )
    objects = _objects_52(document)
    findings, unreadable, absent = _write_findings(document, spec, objects)
    return _scope_result(spec, objects, findings, unreadable, absent)


def _evaluate_53(document: Document, spec: Spec) -> CheckResult:
    objects: list[tuple[str, Row]] = []
    for row in _rows(document, "adminsdholder"):
        objects.append(("adminsdholder", row))
    for row in _rows(document, "protected_sds"):
        objects.append(("protected_sds", row))
    findings, unreadable, absent = _write_findings(document, spec, objects)
    return _scope_result(spec, objects, findings, unreadable, absent)


# ---- AD-A-54: the GPO containers --------------------------------------------

_SPEC_54 = Spec(
    id="AD-A-54",
    title="The DACL and the owner of the GPO containers",
    severity=Severity.HIGH,
    maps_to=("ATT&CK T1484.001", "MS-GPOL"),
)


def _gpo_write_right(ace: Ace) -> tuple[str, str] | None:
    """The rights name and the description of a write right on a GPO.

    A write is a bit of the access mask that changes the GPO or what
    it holds: a write on a property, the right to create or to delete
    a child, the right to delete the GPO, the right to change its DACL
    and the right to change its owner.  An ACE that names a property
    that is neither a dangerous property nor a property of a GPO is
    not a write that leads into the domain, and an ACE that names no
    property grants a write on every property of the GPO.
    """
    gpo_property = _gpo_property(ace.object_type)
    if (
        ace.object_type is not None
        and gpo_property is None
        and _dangerous_property(ace.object_type) is None
    ):
        return None
    mask = ace.mask
    if mask & GENERIC_ALL_STORED == GENERIC_ALL_STORED:
        return ("GenericAll", "full control on the GPO")
    if mask & GENERIC_WRITE_STORED == GENERIC_WRITE_STORED:
        return ("GenericWrite", "a generic write on the GPO")
    if mask & ACCESS_MASK_WRITE_PROP:
        if gpo_property is not None:
            return ("WriteProperty", f"a write on {gpo_property}")
        name = _dangerous_property(ace.object_type)
        if name is None:
            return ("WriteProperty", "a write on every property of the GPO")
        return ("WriteProperty", f"a write on {name}")
    if mask & ACCESS_MASK_WRITE_DAC:
        return ("WriteDacl", "the right to change the DACL of the GPO")
    if mask & ACCESS_MASK_WRITE_OWNER:
        return ("WriteOwner", "the right to change the owner of the GPO")
    if mask & ACCESS_MASK_CREATE_CHILD:
        return ("CreateChild", "the right to create a child of the GPO")
    if mask & ACCESS_MASK_DELETE_CHILD:
        return ("DeleteChild", "the right to delete a child of the GPO")
    if mask & ACCESS_MASK_DELETE:
        return ("Delete", "the right to delete the GPO")
    if mask & ACCESS_MASK_SELF:
        return ("WriteSelf", "the right to change the own descriptor of the GPO")
    return None


def _evaluate_54(document: Document, spec: Spec) -> CheckResult:
    unread = _unread_gpo_note(document)
    if unread is not None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=unread,
        )
    privileged = Directory(document).privileged_set()
    findings: list[Finding] = []
    unreadable: list[Row] = []
    absent: list[Row] = []
    checked = 0
    # Every GPO of the query is read: a GPO that is linked at an
    # organizational unit of the domain, or that is linked nowhere, is
    # a GPO of the domain all the same.
    for row in _rows(document, "gpos"):
        checked += 1
        gpo_guid = _guid_of(row)
        descriptor = _descriptor(row)
        if descriptor is None:
            unreadable.append(row)
            continue
        if descriptor.dacl_state == DACL_NULL:
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A GPO has no DACL at all",
                    objects=(
                        Affected(
                            guid=_guid_from_attribute(row),
                            dn=row.dn,
                            evidence=(
                                "the DACL of the GPO is null, so every "
                                "principal may write it"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_acl_fix(
                        "GenericAll",
                        "the missing protection of the GPO",
                        trustee="every principal",
                        object_sid=None,
                        object_guid=gpo_guid,
                        target=(
                            None if gpo_guid is None else f"the GPO {gpo_guid}"
                        ),
                    ),
                )
            )
            continue
        if descriptor.dacl_state == DACL_ABSENT:
            absent.append(row)
            continue
        owner = descriptor.owner
        if owner is not None and owner not in privileged:
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A GPO is owned by a principal outside the privileged set",
                    objects=(
                        Affected(
                            guid=_guid_from_attribute(row),
                            dn=row.dn,
                            evidence=(
                                "the owner of the GPO is not privileged, so it may "
                                "change the DACL of the GPO"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_explain_fix(
                        "Give the GPO to a privileged principal: the owner of "
                        "the GPO may change its DACL.",
                        changes="the owner of the GPO object",
                        revert=(
                            "give the GPO to the owner it had before the change"
                        ),
                    ),
                )
            )
        for ace in descriptor.dacl:
            if not isinstance(ace, Ace):
                continue
            if ace.type not in (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE):
                continue
            trustee = ace.trustee
            if trustee is None or trustee in privileged:
                continue
            right = _gpo_write_right(ace)
            if right is None:
                continue
            rights_name, description = right
            if _is_allowed(trustee, ace.mask, GPO_WRITE_BITS):
                continue
            guid, evidence = _gpo_evidence(trustee, description, row)
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A principal outside the privileged set holds a write right on a GPO",
                    objects=(
                        Affected(
                            guid=guid,
                            dn=row.dn,
                            evidence=evidence,
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_acl_fix(
                        rights_name,
                        description,
                        trustee=trustee,
                        object_sid=None,
                        object_guid=gpo_guid,
                        target=(
                            None if gpo_guid is None else f"the GPO {gpo_guid}"
                        ),
                    ),
                )
            )
    if findings:
        note = f"{len(findings)} GPO finding(s)"
        if unreadable:
            note = f"{note}; {_unreadable_note(unreadable)}"
        if absent:
            note = f"{note}; {_absent_note(absent)}"
        return _result(
            spec,
            Status.FINDING,
            note=note,
            findings=tuple(findings),
        )
    if unreadable:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=(
                f"{len(unreadable)} of the {checked} GPO(s) carry no "
                "descriptor the audit could read"
            ),
        )
    if absent:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=(
                f"{len(absent)} of the {checked} GPO(s) carry no DACL at all, so "
                "the rights they hold cannot be read"
            ),
        )
    return _result(
        spec,
        Status.PASS,
        note=(
            f"{checked} GPO(s) of the domain hold no write right for a principal "
            "outside the privileged set"
        ),
    )


# ---- AD-A-57: the domain backup keys ----------------------------------------

_SPEC_57 = Spec(
    id="AD-A-57",
    title="The domain backup keys",
    severity=Severity.HIGH,
    maps_to=("ATT&CK T1555",),
)


def backup_key_guid(row: Row) -> str | None:
    """The GUID of a backup key, taken from the objectGUID of the row.

    The name of a backup key carries the GUID of the key, but a name is
    directory text: the identifier of an object is the GUID of its
    binary value, and the name is never parsed.
    """
    return _guid_from_attribute(row)


def _evaluate_57(document: Document, spec: Spec) -> CheckResult:
    privileged = Directory(document).privileged_set()
    rows = _rows(document, "dpapi_backup")
    findings: list[Finding] = []
    unreadable: list[Row] = []
    absent: list[Row] = []
    for row in rows:
        descriptor = _descriptor(row)
        if descriptor is None:
            unreadable.append(row)
            continue
        if descriptor.dacl_state == DACL_NULL:
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A backup key has no DACL at all",
                    objects=(
                        Affected(
                            guid=backup_key_guid(row),
                            dn=row.dn,
                            evidence=(
                                "the DACL of the backup key is null, so every "
                                "principal may read the key"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_explain_fix(
                        "Give the backup key a DACL that only the privileged "
                        "set may read.",
                        changes=(
                            "the DACL of the backup key object: a null DACL "
                            "grants every right to every principal"
                        ),
                        revert=(
                            "put the DACL the object had before the change back"
                        ),
                    ),
                )
            )
            continue
        if descriptor.dacl_state == DACL_ABSENT:
            absent.append(row)
            continue
        for ace in descriptor.dacl:
            if not isinstance(ace, Ace):
                continue
            if ace.type not in (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE):
                continue
            trustee = ace.trustee
            if trustee is None or trustee in privileged:
                continue
            if _is_allowed(trustee, ace.mask):
                continue
            mask = ace.mask
            if not mask & (
                GENERIC_READ_STORED | ACCESS_MASK_READ_PROP | ACCESS_MASK_CONTROL_ACCESS
            ):
                continue
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A principal outside the privileged set may read the backup key",
                    objects=(
                        Affected(
                            guid=backup_key_guid(row),
                            dn=row.dn,
                            evidence=(
                                f"the trustee {trustee} may read the object or "
                                "control it"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_acl_fix(
                        "Read",
                        "the read right on the backup key",
                        trustee=trustee,
                        object_sid=None,
                        object_guid=backup_key_guid(row),
                    ),
                )
            )
    if findings:
        note = (
            f"{len(findings)} backup key object(s) may be read by a principal "
            "outside the privileged set"
        )
        if unreadable:
            note = f"{note}; {_unreadable_note(unreadable)}"
        if absent:
            note = f"{note}; {_absent_note(absent)}"
        return _result(
            spec,
            Status.FINDING,
            note=note,
            findings=tuple(findings),
        )
    if unreadable:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=_unreadable_note(unreadable),
        )
    if absent:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ACCESS_DENIED,
            note=_absent_note(absent),
        )
    return _result(
        spec,
        Status.PASS,
        note=(
            f"{len(rows)} backup key object(s) and no read right outside the "
            "privileged set"
        ),
    )


CHECKS: list[Check] = [
    _make(
        _SPEC_51,
        _evaluate_51,
        queries=(
            "domain_head",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
        sentinels=("domain_head", "groups", "users", "computers", "fsps"),
    ),
    _make(
        _SPEC_52,
        _evaluate_52,
        queries=(
            "domain_head",
            "adminsdholder",
            "protected_sds",
            "dc_ou",
            "gpos",
            "ous",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
        sentinels=(
            "domain_head",
            "adminsdholder",
            "protected_sds",
            "dc_ou",
            "ous",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
    ),
    _make(
        _SPEC_53,
        _evaluate_53,
        queries=(
            "adminsdholder",
            "protected_sds",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
        sentinels=(
            "adminsdholder",
            "protected_sds",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
    ),
    _make(
        _SPEC_54,
        _evaluate_54,
        queries=(
            "domain_head",
            "dc_ou",
            "ous",
            "gpos",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
        sentinels=(
            "domain_head",
            "dc_ou",
            "ous",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
    ),
    _make(
        _SPEC_57,
        _evaluate_57,
        queries=(
            "dpapi_backup",
            "groups",
            "users",
            "computers",
            "fsps",
        ),
        sentinels=("groups", "users", "computers", "fsps"),
    ),
]
