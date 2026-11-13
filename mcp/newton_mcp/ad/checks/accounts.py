"""The account and delegation checks, part 1.

Every check here is a pure function of the collector document.  The runner
has already proved that the audit was allowed to see the data (the status
of the queries, the sentinels and the required attributes), so a check
reads the rows it needs and answers.

Privilege is computed by SID and RID (``members.py``), never by name: a
renamed or localized group is still the same group, and a group the audit
cannot read the name of is still privileged.

The privileged set of the checks is the one of SPEC-1.3 section 8.  The
protected set of AD-A-05 is the other one: the groups the directory
protects (the AdminSDHolder set) and the two well-known accounts it
protects with them.

A group that holds a member value that names no object of the document
hides a principal.  A check that reads such a group cannot prove
anything: it is UNKNOWN with the count of the members it cannot see, and
never the names of those members.

The fixes name their object by SID.  A command carries the ``{sid}``
placeholder and nothing else: a distinguished name, an account name, a
service principal name or any other directory text sits beside the
command, in the report, and never inside it.  On Samba the object is
named in the ``<SID=...>`` form ``ldbmodify`` takes, so no distinguished
name ends up in a command either.

Every Windows command is a cmdlet of the ActiveDirectory module, and a
step that claims a change never runs a cmdlet that only reads.

Every command is one line.  The line breaks of the LDIF of Samba are the
two characters ``\\n`` of the format string, and a command that prints on
two lines is not the command the owner read.

This part holds AD-A-01 to AD-A-14 and AD-A-16.  The second part of the
module holds the rest of the group (AD-A-17 to AD-A-27 and AD-A-30 to
AD-A-32): the lifetime of the accounts, the stale accounts, the service
accounts, the hybrid accounts and the read-only domain controllers.

The clock of the age checks is the clock of the document: the moment the
audit started.  The wall clock of the machine Newton runs on is never
read, so the same document always gives the same ages.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from datetime import datetime

from .. import runner, secdesc
from ..catalogue import Check
from ..members import KIND_COMPUTER, KIND_USER, Directory
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
from ..values import (
    filetime_to_datetime,
    parse_gentime,
    rid_in_domain,
    sid_from_base64,
    uac_flag_names,
)
from ..wire import Document, Row


# The userAccountControl bits (MS-ADTS 2.2.6.1.1) these checks read.
UAC_ACCOUNTDISABLE = 0x00000002
UAC_PASSWD_NOTREQD = 0x00000020
UAC_INTERDOMAIN_TRUST = 0x00000800
UAC_WORKSTATION_TRUST = 0x00001000
UAC_SERVER_TRUST = 0x00002000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_NOT_DELEGATED = 0x00100000
UAC_DONT_REQUIRE_PREAUTH = 0x00400000
UAC_PROTOCOL_TRANSITION = 0x01000000

# The encryption types of msDS-SupportedEncryptionTypes (MS-ADTS
# 6.1.4.4): the weak ciphers and the strong ones.
ENC_DES_CBC_CRC = 0x00000001
ENC_DES_CBC_MD5 = 0x00000002
ENC_RC4 = 0x00000004
ENC_AES128 = 0x00000008
ENC_AES256 = 0x00000010
ENC_AES256_SK = 0x00000020
ENC_FAST_SUPPORTED = 0x00010000

# The two DES ciphers, the weak ciphers (DES and RC4) and the strong
# ones (AES).
ENC_DES = ENC_DES_CBC_CRC | ENC_DES_CBC_MD5
ENC_WEAK = ENC_DES | ENC_RC4
ENC_AES = ENC_AES128 | ENC_AES256

# The value of msDS-SupportedEncryptionTypes that offers AES only: AES128
# and AES256, without the armor bit.
ENC_AES_ONLY = ENC_AES

# The relative identifiers the checks name by number.
RID_ADMINISTRATOR = 500
RID_GUEST = 501
RID_KRBTGT = 502
RID_DOMAIN_USERS = 513
RID_DOMAIN_CONTROLLERS = 516
RID_READ_ONLY_DOMAIN_CONTROLLERS = 521
RID_PROTECTED_USERS = 525

# The privileged groups of the domain (SPEC-1.3 section 8).
PRIVILEGED_RIDS = (512, 516, 518, 519, 520, 521, 498, 526, 527)

# The groups of the domain whose members the inventory of AD-A-03 covers:
# the three admin groups of the domain and the builtin administrators one.
ADMIN_GROUP_RIDS = (512, 519, 518)
BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"

# The groups the directory protects (the AdminSDHolder set): the builtin
# administrators, the four operator groups and the replicator, and the
# seven groups of the domain.  Everything nested in one of them is
# protected as well.
PROTECTED_BUILTIN_SIDS = (
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
)
PROTECTED_DOMAIN_RIDS = (512, 516, 518, 519, 521, 526, 527)

# The two well-known accounts the directory protects with the groups
# above: the administrator of the domain and the key distribution
# account of the domain.
PROTECTED_USER_RIDS = (500, 502)

# The userAccountControl bits of the second part (MS-ADTS 2.2.6.1.1).
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x00000080
UAC_DONT_EXPIRE_PASSWORD = 0x00010000
UAC_SMARTCARD_REQUIRED = 0x00040000

# The bit of pwdProperties that says the domain stores the passwords of
# its accounts with reversible encryption (MS-ADTS 6.1.1.3.2.1).
PWD_PROPERTIES_REVERSIBLE_ENCRYPTION = 0x00000010

# The relative identifiers of the two groups of the password replication
# policy of the read-only domain controllers.
RID_ALLOWED_RODC_REPLICATION = 571
RID_DENIED_RODC_REPLICATION = 572

# The well-known SIDs of the built-in principals the second part names.
EVERYONE_SID = "S-1-1-0"
ANONYMOUS_SID = "S-1-5-7"
PRE_WINDOWS_2000_GROUP_SID = "S-1-5-32-554"

# The three built-in accounts of the domain: the administrator, the guest
# and the key distribution account.
BUILTIN_ACCOUNT_RIDS = (RID_ADMINISTRATOR, RID_GUEST, RID_KRBTGT)

# The ages the second part uses, in days.  A stale account is a quarter
# old, the key distribution account half a year and the password of a
# service account a year.
STALE_DAYS = 90
SMARTCARD_PASSWORD_DAYS = 90
KRBtGT_PASSWORD_DAYS = 180
SERVICE_ACCOUNT_PASSWORD_DAYS = 365

# The age of the machine password of the single sign-on account of a
# hybrid tenant, in days.  The account is rolled over on a schedule, and
# a month is the schedule the tenant asks for.
HYBRID_ACCOUNT_PASSWORD_DAYS = 30

# The account of the single sign-on of a hybrid tenant.  It is a computer
# object, so its name ends with the dollar sign of a computer account.
SINGLE_SIGN_ON_ACCOUNT = "AZUREADSSOACC$"

# The names of the accounts of a hybrid tenant that are not the account of
# the single sign-on (SPEC-1.3 section 8): the accounts of the cloud in
# the directory of the on-premises domain are named MSOL_ or AAD_ and the
# name the cloud gives them.  The name is read in any case.
HYBRID_ACCOUNT_PREFIXES = ("MSOL_", "AAD_")

# The line the result of AD-A-17 carries when the audit account of the
# run was skipped.  The account of Newton's own setup is not judged: its
# password is a random one that nobody holds and it signs in by key
# only.
AUDIT_ACCOUNT_NOTE = (
    "the audit account of this run is not judged: Newton's setup gives it "
    "a random password nobody holds, and it signs in by key only"
)

# The relative identifiers whose SID history is the privilege of a
# privileged group of this domain: the groups of the domain and the
# built-in administrator.  A SID of this domain in the history of an
# object is the privilege of this domain, handed to an object that may
# not hold it.
SAME_DOMAIN_PRIVILEGED_RIDS = (512, 516, 518, 519, 498, 521, 500)

# The title of every check of this module.
TITLE: dict[str, str] = {
    "AD-A-01": "the built-in administrator account of the domain is enabled",
    "AD-A-02": "the built-in guest account of the domain is enabled",
    "AD-A-03": "a privileged group holds a principal that is not one of "
    "its default members",
    "AD-A-04": "an account is privileged through its primary group",
    "AD-A-05": "an account holds adminCount without a membership in a "
    "protected group",
    "AD-A-06": "a privileged account is not a member of the protected "
    "users group",
    "AD-A-07": "an account carries a service principal name and its "
    "ticket can be roasted offline",
    "AD-A-08": "an account does without Kerberos pre-authentication",
    "AD-A-09": "a privileged account may be delegated to another service",
    "AD-A-10": "an object holds a key credential link",
    "AD-A-11": "a computer is trusted for unconstrained delegation",
    "AD-A-12": "a computer is configured for constrained delegation",
    "AD-A-13": "a computer holds a resource-based constrained delegation "
    "descriptor",
    "AD-A-14": "an account offers only weak Kerberos encryption types",
    "AD-A-16": "an account does not require a password",
    "AD-A-17": "an account holds a password that never expires",
    "AD-A-18": "an account stores its password with reversible encryption",
    "AD-A-19": "an object carries the SID history of another principal",
    "AD-A-20": "an object holds a password in a text attribute",
    "AD-A-21": "an enabled account must change password at next logon",
    "AD-A-22": "an enabled account holds an expiry date that has passed",
    "AD-A-23": "a service account holds a password that is older than a year",
    "AD-A-24": "an enabled account has not logged on for a long time",
    "AD-A-25": "a computer account holds a trust that has gone stale",
    "AD-A-26": "an account needs a smart card and keeps an old password",
    "AD-A-27": "the password of the key distribution account is old",
    "AD-A-30": "the pre-windows 2000 compatible access group holds everyone",
    "AD-A-31": "the domain holds the accounts of a hybrid tenant",
    "AD-A-32": "the password replication policy of the read-only domain "
    "controllers is broad",
}

# The references of every check, from the GAPS catalogue.
MAPS_TO: dict[str, tuple[str, ...]] = {
    "AD-A-01": ("MS Learn well-known SIDs", "ANSSI (unverified)"),
    "AD-A-02": ("MS Learn well-known SIDs",),
    "AD-A-03": (
        "MS Learn well-known SIDs",
        "MS Learn security best practices",
        "ATT&CK T1574",
    ),
    "AD-A-04": ("MS-ADTS primaryGroupID",),
    "AD-A-05": ("MS Learn security best practices", "ANSSI (unverified)"),
    "AD-A-06": ("MS Learn Protected Users",),
    "AD-A-07": ("ATT&CK T1558.003",),
    "AD-A-08": ("ATT&CK T1558.004",),
    "AD-A-09": ("MS Learn security best practices",),
    "AD-A-10": ("SpecterOps Shadow Credentials", "ATT&CK T1556"),
    "AD-A-11": ("ATT&CK T1558", "SpecterOps unconstrained delegation"),
    "AD-A-12": ("SpecterOps S4U",),
    "AD-A-13": ("SpecterOps Wagging the Dog", "ATT&CK T1558"),
    "AD-A-14": ("MS Learn Kerberos encryption types",),
    "AD-A-16": ("CIS (unverified)",),
    "AD-A-17": ("CIS (unverified)",),
    "AD-A-18": ("CIS (unverified)",),
    "AD-A-19": ("MS Learn well-known SIDs", "ATT&CK T1134.005"),
    "AD-A-20": ("ATT&CK T1552",),
    "AD-A-21": ("CIS (unverified)",),
    "AD-A-22": ("MS Learn account lifecycle",),
    "AD-A-23": ("MS Learn group managed service accounts",),
    "AD-A-24": ("CIS (unverified)",),
    "AD-A-25": ("CIS (unverified)",),
    "AD-A-26": ("MS Learn smart card security",),
    "AD-A-27": ("MS Learn AD DS recovery krbtgt guidance",),
    "AD-A-30": ("MS Learn well-known SIDs",),
    "AD-A-31": ("MS Learn Azure AD SSO account rollover",),
    "AD-A-32": ("MS Learn AD access control", "MS-ADTS password replication"),
}


# ---- the readers of one row ------------------------------------------------


def _rows(document: Document, query_id: str) -> tuple[Row, ...]:
    """The rows of one query of the document."""
    result = document.queries.get(query_id)
    if result is None:
        return ()
    return result.rows


def _row_sid(row: Row) -> str | None:
    """The SID of a row, when it has one Newton can read."""
    for value in row.a.get("objectSid", ()):
        try:
            return sid_from_base64(value)
        except ValueError:
            continue
    return None


def _row_name(row: Row) -> str | None:
    """The account name of a row, when it has one."""
    values = row.a.get("sAMAccountName", ())
    return values[0] if values else None


def _int_value(row: Row, attribute: str) -> int | None:
    """The value of an integer attribute of a row, when it has one."""
    for value in row.a.get(attribute, ()):
        try:
            return int(value)
        except ValueError:
            continue
    return None


def _uac(row: Row) -> int | None:
    """The userAccountControl of a row, when it has one."""
    return _int_value(row, "userAccountControl")


def _uac_evidence(value: int) -> str:
    """The evidence of a userAccountControl value."""
    flags = ", ".join(uac_flag_names(value))
    return f"userAccountControl={value} ({flags})"


def _enabled(value: int) -> bool:
    """True when the account is not disabled."""
    return not value & UAC_ACCOUNTDISABLE


def _affected(
    sid: str,
    name: str | None,
    dn: str | None,
    evidence: str | None,
) -> Affected:
    """One object a finding is about."""
    return Affected(sid=sid, name=name, dn=dn, evidence=evidence)


# ---- the sets of principals -------------------------------------------------


def _protected_set(directory: Directory) -> set[str]:
    """The principals the directory protects.

    The protected set is the AdminSDHolder set: the seven groups of the
    domain and the six builtin groups the directory protects, everything
    nested in one of them, and the two well-known accounts it protects
    with them (the administrator of the domain and the key distribution
    account of the domain).
    """
    groups = {
        f"{directory.domain_sid}-{rid}" for rid in PROTECTED_DOMAIN_RIDS
    }
    groups.update(PROTECTED_BUILTIN_SIDS)
    protected = set(groups)
    for group_sid in groups:
        protected |= directory.members_recursive(group_sid)
    protected.update(
        f"{directory.domain_sid}-{rid}" for rid in PROTECTED_USER_RIDS
    )
    return protected


def _protected_group_sids(directory: Directory) -> set[str]:
    """The groups the directory protects."""
    groups = {
        f"{directory.domain_sid}-{rid}" for rid in PROTECTED_DOMAIN_RIDS
    }
    groups.update(PROTECTED_BUILTIN_SIDS)
    return groups


def _hidden_members(directory: Directory, group_sids: Iterable[str]) -> int:
    """The number of member values of the groups that named no object.

    The names of those members are never counted twice: the same missing
    member of two groups is one hidden principal.
    """
    names: set[str] = set()
    for group_sid in group_sids:
        names.update(directory.unresolved_members(group_sid))
    return len(names)


def _hidden_note(count: int) -> str:
    """The note of a check that cannot see every member of a group."""
    values = "value" if count == 1 else "values"
    return (
        f"{count} member {values} of the groups this check reads named no "
        "object of the document; the principals they name are hidden from "
        "the audit"
    )


# ---- the fixes -------------------------------------------------------------


def _fix(
    summary: str,
    windows: tuple[str, ...],
    samba: tuple[str, ...],
    changes: str,
    revert: str,
) -> Fix:
    """One fix: a step per platform."""
    return Fix(
        windows=FixStep(
            summary=summary, commands=windows, changes=changes, revert=revert
        ),
        samba=FixStep(
            summary=summary, commands=samba, changes=changes, revert=revert
        ),
    )


def _explain(summary: str, changes: str, revert: str) -> Fix:
    """One fix that explains what the owner does and runs no command.

    A step that claims a change may not hold a command that only reads,
    and the text of the objects a command would need is directory text
    that never goes inside a command.  Such a fix explains and the owner
    runs the change.
    """
    return Fix(
        windows=FixStep(summary=summary, commands=(), changes=changes, revert=revert),
        samba=FixStep(summary=summary, commands=(), changes=changes, revert=revert),
    )


def _samba_modify(attribute: str, value: str) -> str:
    """The Samba way to write one attribute of the object named by a SID.

    The object is named by the ``<SID=...>`` form ``ldbmodify`` takes, so
    no distinguished name ends up inside the command.  An attribute is
    taken away with the ``delete:`` modifier of the LDIF, never with an
    empty value.

    The command is one line: the line breaks of the LDIF are the two
    characters ``\\n`` of the format string, so ``printf`` turns them
    into the line breaks of the record it writes.
    """
    if not value:
        lines = f"delete: {attribute}"
    else:
        lines = f"replace: {attribute}\\n{attribute}: {value}"
    return (
        "printf 'dn: <SID={sid}>\\nchangetype: modify\\n"
        f"{lines}\\n' "
        "| ldbmodify -H /var/lib/samba/private/sam.ldb"
    )


def _samba_add_protected_user() -> str:
    """The Samba way to add an account to the protected users group.

    The group is the one of the domain with the relative identifier 525
    (Protected Users).  Its SID is the SID of the account with the last
    part replaced, so the command names the group and the account by SID
    and no distinguished name ends up inside it.
    """
    return (
        "sid='{sid}'; "
        "printf 'dn: <SID=%s-525>\\nchangetype: modify\\nadd: member\\n"
        "member: <SID={sid}>\\n' \"${sid%-*}\" "
        "| ldbmodify -H /var/lib/samba/private/sam.ldb"
    )


def _samba_remove_member(member_sid: str) -> str:
    """The Samba way to take one member value out of a group.

    The group is named by the SID in the ``<SID=...>`` form
    ``ldbmodify`` takes, so no distinguished name ends up inside the
    command.  One member value is deleted from the member attribute: the
    value of the member is the well-known SID of the principal that is
    to leave the group.
    """
    return (
        "printf 'dn: <SID={sid}>\\nchangetype: modify\\ndelete: member\\n"
        f"member: <SID={member_sid}>\\n' "
        "| ldbmodify -H /var/lib/samba/private/sam.ldb"
    )


# ---- the results -----------------------------------------------------------


def _pass(
    check_id: str,
    severity: Severity,
    note: str,
) -> CheckResult:
    """The result of a check that found nothing."""
    return CheckResult(
        check_id=check_id,
        title=TITLE[check_id],
        severity=severity,
        status=Status.PASS,
        note=note,
    )


def _finding(
    check_id: str,
    severity: Severity,
    note: str,
    findings: tuple[Finding, ...],
) -> CheckResult:
    """The result of a check that found something."""
    return CheckResult(
        check_id=check_id,
        title=TITLE[check_id],
        severity=severity,
        status=Status.FINDING,
        note=note,
        findings=findings,
    )


def _unknown(
    check_id: str,
    severity: Severity,
    reason: UnknownReason,
    note: str,
) -> CheckResult:
    """The result of a check that could not prove anything."""
    return CheckResult(
        check_id=check_id,
        title=TITLE[check_id],
        severity=severity,
        status=Status.UNKNOWN,
        reason=reason,
        note=note,
    )


# ---- AD-A-01: the built-in administrator -----------------------------------


def _ad_a_01(document: Document) -> CheckResult:
    """The account with the relative identifier 500 of the domain."""
    domain_sid = document.domain.domain_sid
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) != RID_ADMINISTRATOR:
            continue
        value = _uac(row)
        if value is None:
            return _unknown(
                "AD-A-01",
                Severity.MEDIUM,
                UnknownReason.ACCESS_DENIED,
                "the account carries no readable userAccountControl",
            )
        if not _enabled(value):
            return _pass(
                "AD-A-01",
                Severity.MEDIUM,
                "the account with the relative identifier 500 of the "
                "domain is disabled",
            )
        finding = Finding(
            check_id="AD-A-01",
            severity=Severity.MEDIUM,
            title="the built-in administrator account of the domain is "
            "enabled",
            objects=(
                _affected(
                    sid,
                    _row_name(row),
                    row.dn,
                    _uac_evidence(value),
                ),
            ),
            maps_to=MAPS_TO["AD-A-01"],
            fix=_fix(
                "disable the built-in administrator account of the domain",
                ("Disable-ADAccount -Identity '{sid}'",),
                (
                    _samba_modify(
                        "userAccountControl",
                        str(value | UAC_ACCOUNTDISABLE),
                    ),
                ),
                "the ACCOUNTDISABLE bit of userAccountControl is set on the "
                "account named by the SID, so the account cannot be used to "
                "log on",
                "clear the bit again with Enable-ADAccount and the same "
                "identity, or with the value of userAccountControl in the "
                "evidence of this finding",
            ),
        )
        return _finding(
            "AD-A-01",
            Severity.MEDIUM,
            "the account with the relative identifier 500 of the domain is "
            "enabled",
            (finding,),
        )
    return _pass(
        "AD-A-01",
        Severity.MEDIUM,
        "the document holds no account with the relative identifier 500 of "
        "the domain",
    )


# ---- AD-A-02: the built-in guest -------------------------------------------


def _ad_a_02(document: Document) -> CheckResult:
    """The account with the relative identifier 501 of the domain.

    A document that holds no such account holds no proof about it: the
    account may be there and the audit may not see it, so the check is
    UNKNOWN and never PASS.
    """
    domain_sid = document.domain.domain_sid
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) != RID_GUEST:
            continue
        value = _uac(row)
        if value is None:
            return _unknown(
                "AD-A-02",
                Severity.LOW,
                UnknownReason.ACCESS_DENIED,
                "the account carries no readable userAccountControl",
            )
        if not _enabled(value):
            return _pass(
                "AD-A-02",
                Severity.LOW,
                "the account with the relative identifier 501 of the "
                "domain is disabled",
            )
        finding = Finding(
            check_id="AD-A-02",
            severity=Severity.LOW,
            title="the built-in guest account of the domain is enabled",
            objects=(
                _affected(
                    sid,
                    _row_name(row),
                    row.dn,
                    _uac_evidence(value),
                ),
            ),
            maps_to=MAPS_TO["AD-A-02"],
            fix=_fix(
                "disable the built-in guest account of the domain",
                ("Disable-ADAccount -Identity '{sid}'",),
                (
                    _samba_modify(
                        "userAccountControl",
                        str(value | UAC_ACCOUNTDISABLE),
                    ),
                ),
                "the ACCOUNTDISABLE bit of userAccountControl is set on the "
                "account named by the SID",
                "clear the bit again with Enable-ADAccount and the same "
                "identity, or with the value of userAccountControl in the "
                "evidence of this finding",
            ),
        )
        return _finding(
            "AD-A-02",
            Severity.LOW,
            "the account with the relative identifier 501 of the domain is "
            "enabled",
            (finding,),
        )
    return _unknown(
        "AD-A-02",
        Severity.LOW,
        UnknownReason.ACCESS_DENIED,
        "the document holds no account with the relative identifier 501 of "
        "the domain",
    )


# ---- AD-A-03: the inventory of the privileged groups -----------------------


def _ad_a_03(document: Document) -> CheckResult:
    """The privileged groups, their members and the members that surprise."""
    directory = Directory(document)
    domain_sid = document.domain.domain_sid
    covered = [f"{domain_sid}-{rid}" for rid in ADMIN_GROUP_RIDS]
    covered.append(BUILTIN_ADMINISTRATORS_SID)
    defaults = set(directory.privileged_group_sids())
    defaults.add(f"{domain_sid}-{RID_ADMINISTRATOR}")

    inventory: list[str] = []
    for group_sid in directory.privileged_group_sids():
        group = directory.principal(group_sid)
        name = group.name if group is not None else group_sid
        members = directory.members_recursive(group_sid)
        inventory.append(f"{name}: {len(members)}")
    note = "privileged groups and their recursive member counts: " + "; ".join(
        inventory
    )

    findings: list[Finding] = []
    for group_sid in covered:
        group = directory.principal(group_sid)
        if group is None:
            continue
        members = directory.members_recursive(group_sid)
        others = sorted(sid for sid in members if sid not in defaults)
        if not others:
            continue
        objects = [_affected(group_sid, group.name, group.dn, None)]
        for sid in others:
            principal = directory.principal(sid)
            objects.append(
                _affected(
                    sid,
                    principal.name if principal is not None else None,
                    principal.dn if principal is not None else None,
                    None,
                )
            )
        findings.append(
            Finding(
                check_id="AD-A-03",
                severity=Severity.HIGH,
                title="a privileged group holds a principal that is not one "
                "of its default members",
                objects=tuple(objects),
                maps_to=MAPS_TO["AD-A-03"],
                fix=_explain(
                    "take the principals that do not belong out of the "
                    "privileged group",
                    "the group named by the SID holds principals that are "
                    "not its default members; the member values to take "
                    "out are the ones of the objects listed after the "
                    "group in this finding. On Windows the owner removes "
                    "every one of them from the group, on Samba the owner "
                    "deletes the member value from the member attribute of "
                    "the group",
                    "put a member back with Add-ADGroupMember on Windows, or "
                    "with an ldbmodify that appends the member value to the "
                    "member attribute of the group on Samba",
                ),
            )
        )
    hidden = _hidden_members(directory, directory.privileged_group_sids())
    if hidden:
        note = f"{note}; {_hidden_note(hidden)}"
    if not findings:
        if hidden:
            return _unknown(
                "AD-A-03",
                Severity.HIGH,
                UnknownReason.ACCESS_DENIED,
                note,
            )
        return _pass("AD-A-03", Severity.HIGH, note)
    return _finding("AD-A-03", Severity.HIGH, note, tuple(findings))


# ---- AD-A-04: the privilege of a primary group ----------------------------


def _ad_a_04(document: Document) -> CheckResult:
    """The accounts whose primary group is a privileged group."""
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) == RID_ADMINISTRATOR:
            # The built-in account of the domain: its primary group is a
            # privileged group by the design of the directory.
            continue
        group_id = _int_value(row, "primaryGroupID")
        if group_id is None or group_id not in PRIVILEGED_RIDS:
            continue
        findings.append(
            Finding(
                check_id="AD-A-04",
                severity=Severity.MEDIUM,
                title="an account is privileged through its primary group",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        f"primaryGroupID={group_id}",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-04"],
                fix=_fix(
                    "move the account out of the privileged primary group",
                    (
                        "Set-ADUser -Identity '{sid}' "
                        f"-Replace @{{primaryGroupID={RID_DOMAIN_USERS}}}",
                    ),
                    (_samba_modify("primaryGroupID", str(RID_DOMAIN_USERS)),),
                    "the primary group of the account named by the SID "
                    "becomes the ordinary domain group with the relative "
                    "identifier 513; pick another ordinary group of the "
                    "domain when that group does not exist",
                    "put the old value back with Set-ADUser and the value of "
                    "primaryGroupID in the evidence of this finding",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-04",
            Severity.MEDIUM,
            "no account holds a privileged group as its primary group",
        )
    return _finding(
        "AD-A-04",
        Severity.MEDIUM,
        "an account holds a privileged group as its primary group",
        tuple(findings),
    )


# ---- AD-A-05: the adminCount orphans ---------------------------------------


def _ad_a_05(document: Document) -> CheckResult:
    """The accounts with adminCount that the directory does not protect.

    The account that holds adminCount and is not in a protected group is
    the orphan of the check: the directory stopped protecting its
    security descriptor and the account kept the hint of the privilege
    it had.
    """
    directory = Directory(document)
    protected = _protected_set(directory)
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        count = _int_value(row, "adminCount")
        if count != 1:
            continue
        if sid in protected:
            continue
        findings.append(
            Finding(
                check_id="AD-A-05",
                severity=Severity.MEDIUM,
                title="an account holds adminCount without a membership in "
                "a protected group",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        "adminCount=1",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-05"],
                fix=_fix(
                    "clear the adminCount of the account",
                    (
                        "Set-ADUser -Identity '{sid}' "
                        "-Replace @{adminCount=0}",
                    ),
                    (_samba_modify("adminCount", "0"),),
                    "the adminCount attribute of the object named by the SID "
                    "becomes 0, so the directory stops protecting its "
                    "security descriptor",
                    "set adminCount back to the value in the evidence of "
                    "this finding with Set-ADUser and -Replace",
                ),
            )
        )
    hidden = _hidden_members(directory, _protected_group_sids(directory))
    if not findings:
        if hidden:
            return _unknown(
                "AD-A-05",
                Severity.MEDIUM,
                UnknownReason.ACCESS_DENIED,
                _hidden_note(hidden),
            )
        return _pass(
            "AD-A-05",
            Severity.MEDIUM,
            "no account holds adminCount without a membership in a "
            "protected group",
        )
    note = "an account holds adminCount without a membership in a protected group"
    if hidden:
        note = f"{note}; {_hidden_note(hidden)}"
    return _finding("AD-A-05", Severity.MEDIUM, note, tuple(findings))


# ---- AD-A-06: the privileged accounts outside the protected users ----------


def _ad_a_06(document: Document) -> CheckResult:
    """The privileged accounts that are not protected users."""
    directory = Directory(document)
    domain_sid = document.domain.domain_sid
    protected_group = f"{domain_sid}-{RID_PROTECTED_USERS}"
    protected = directory.members_recursive(protected_group)
    privileged = directory.privileged_set()
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if sid not in privileged:
            continue
        if sid in protected:
            continue
        groups = sorted(
            group_sid
            for group_sid in directory.groups_of(sid)
            if group_sid in directory.privileged_group_sids()
        )
        findings.append(
            Finding(
                check_id="AD-A-06",
                severity=Severity.MEDIUM,
                title="a privileged account is not a member of the protected "
                "users group",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        groups[0] if groups else None,
                    ),
                ),
                maps_to=MAPS_TO["AD-A-06"],
                fix=_fix(
                    "put the privileged account into the protected users group",
                    (
                        "Add-ADGroupMember -Identity "
                        "(((Get-ADUser -Identity '{sid}').SID) "
                        "-replace '-\\d+$','-525') -Members '{sid}'",
                    ),
                    (_samba_add_protected_user(),),
                    "the account named by the SID becomes a member of the "
                    "protected users group of the domain, the well-known "
                    "group with the relative identifier 525; on Samba the "
                    "member value of a group is the distinguished name of "
                    "the member, and the SID form of that name is the one "
                    "this command writes",
                    "take the member out again with Remove-ADGroupMember on "
                    "Windows, or with an ldbmodify that deletes the member "
                    "value from the member attribute of the group on Samba",
                ),
            )
        )
    hidden = _hidden_members(
        directory,
        directory.privileged_group_sids() | {protected_group},
    )
    if not findings:
        if hidden:
            return _unknown(
                "AD-A-06",
                Severity.MEDIUM,
                UnknownReason.ACCESS_DENIED,
                _hidden_note(hidden),
            )
        return _pass(
            "AD-A-06",
            Severity.MEDIUM,
            "every privileged account is a member of the protected users "
            "group",
        )
    note = "a privileged account is not a member of the protected users group"
    if hidden:
        note = f"{note}; {_hidden_note(hidden)}"
    return _finding("AD-A-06", Severity.MEDIUM, note, tuple(findings))


# ---- AD-A-07: the roastable service accounts -------------------------------


def _ad_a_07(document: Document) -> CheckResult:
    """The accounts that carry a service principal name.

    The ticket of a service account can be asked for and cracked
    offline.  The finding of an account that is not privileged is a
    medium one; the finding of a privileged account is a high one.
    """
    directory = Directory(document)
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) == RID_KRBTGT:
            # The key distribution account of the domain: its service
            # principal name belongs to the directory.
            continue
        names = row.a.get("servicePrincipalName", ())
        if not names:
            continue
        privileged = directory.is_privileged(sid)
        evidence = ", ".join(names)
        if privileged:
            evidence = f"{evidence}; the account is privileged"
        findings.append(
            Finding(
                check_id="AD-A-07",
                severity=Severity.HIGH if privileged else Severity.MEDIUM,
                title="an account carries a service principal name and its "
                "ticket can be roasted offline",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        evidence,
                    ),
                ),
                maps_to=MAPS_TO["AD-A-07"],
                fix=_fix(
                    "take the service principal names off the account",
                    (
                        "Set-ADUser -Identity '{sid}' "
                        "-Clear 'servicePrincipalName'",
                    ),
                    (_samba_modify("servicePrincipalName", ""),),
                    "every service principal name of the account named by "
                    "the SID is removed, so no ticket of it can be asked for "
                    "and cracked offline; the names that must stay are in "
                    "the evidence of this finding",
                    "put the names back with Set-ADUser and the value of "
                    "servicePrincipalName in the evidence of this finding",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-07",
            Severity.HIGH,
            "no account carries a service principal name",
        )
    return _finding(
        "AD-A-07",
        Severity.HIGH,
        "an account carries a service principal name",
        tuple(findings),
    )


# ---- AD-A-08: the roastable accounts without pre-authentication ------------


def _ad_a_08(document: Document) -> CheckResult:
    """The accounts that do not require Kerberos pre-authentication."""
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        value = _uac(row)
        if value is None:
            continue
        if not value & UAC_DONT_REQUIRE_PREAUTH:
            continue
        findings.append(
            Finding(
                check_id="AD-A-08",
                severity=Severity.HIGH,
                title="an account does without Kerberos pre-authentication "
                "and its ticket can be asked for",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        _uac_evidence(value),
                    ),
                ),
                maps_to=MAPS_TO["AD-A-08"],
                fix=_fix(
                    "require Kerberos pre-authentication on the account",
                    (
                        "Set-ADAccountControl -Identity '{sid}' "
                        "-DoesNotRequirePreAuth $false",
                    ),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value & ~UAC_DONT_REQUIRE_PREAUTH),
                        ),
                    ),
                    "the DONT_REQUIRE_PREAUTH bit of userAccountControl is "
                    "cleared on the account named by the SID",
                    "set the bit again with Set-ADAccountControl and "
                    "-DoesNotRequirePreAuth $true",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-08",
            Severity.HIGH,
            "no account does without Kerberos pre-authentication",
        )
    return _finding(
        "AD-A-08",
        Severity.HIGH,
        "an account does without Kerberos pre-authentication",
        tuple(findings),
    )


# ---- AD-A-09: the delegable privileged accounts ---------------------------


def _ad_a_09(document: Document) -> CheckResult:
    """The privileged accounts that may be delegated.

    A member of the protected users group cannot be delegated to
    another service: the group says so.  Such an account is no finding.
    """
    directory = Directory(document)
    domain_sid = document.domain.domain_sid
    protected_group = f"{domain_sid}-{RID_PROTECTED_USERS}"
    protected = directory.members_recursive(protected_group)
    privileged = directory.privileged_set()
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if sid not in privileged:
            continue
        if sid in protected:
            continue
        value = _uac(row)
        if value is None:
            return _unknown(
                "AD-A-09",
                Severity.MEDIUM,
                UnknownReason.ACCESS_DENIED,
                "a privileged account carries no readable userAccountControl",
            )
        if value & UAC_NOT_DELEGATED:
            continue
        findings.append(
            Finding(
                check_id="AD-A-09",
                severity=Severity.MEDIUM,
                title="a privileged account may be delegated to another "
                "service",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        _uac_evidence(value),
                    ),
                ),
                maps_to=MAPS_TO["AD-A-09"],
                fix=_fix(
                    "stop the privileged account from being delegated",
                    (
                        "Set-ADAccountControl -Identity '{sid}' "
                        "-AccountNotDelegated $true",
                    ),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value | UAC_NOT_DELEGATED),
                        ),
                    ),
                    "the NOT_DELEGATED bit of userAccountControl is set on "
                    "the account named by the SID, so its credentials "
                    "cannot be delegated to another service",
                    "clear the bit again with Set-ADAccountControl and "
                    "-AccountNotDelegated $false",
                ),
            )
        )
    hidden = _hidden_members(
        directory,
        directory.privileged_group_sids() | {protected_group},
    )
    if not findings:
        if hidden:
            return _unknown(
                "AD-A-09",
                Severity.MEDIUM,
                UnknownReason.ACCESS_DENIED,
                _hidden_note(hidden),
            )
        return _pass(
            "AD-A-09",
            Severity.MEDIUM,
            "no privileged account may be delegated",
        )
    note = "a privileged account may be delegated to another service"
    if hidden:
        note = f"{note}; {_hidden_note(hidden)}"
    return _finding("AD-A-09", Severity.MEDIUM, note, tuple(findings))


# ---- AD-A-10: the shadow credentials ---------------------------------------


def _ad_a_10(document: Document) -> CheckResult:
    """The objects that hold a key credential link.

    The query is a presence query: it returns the objects that carry the
    attribute and nothing else, so the finding is about the presence of
    the attribute and never about its value.
    """
    directory = Directory(document)
    findings: list[Finding] = []
    for row in _rows(document, "keycred_presence"):
        sid = _row_sid(row)
        if sid is None:
            continue
        principal = directory.principal(sid)
        windows: tuple[str, ...] = ()
        if principal is not None and principal.kind == KIND_USER:
            windows = (
                "Set-ADUser -Identity '{sid}' "
                "-Clear 'msDS-KeyCredentialLink'",
            )
        elif principal is not None and principal.kind == KIND_COMPUTER:
            windows = (
                "Set-ADComputer -Identity '{sid}' "
                "-Clear 'msDS-KeyCredentialLink'",
            )
        changes = (
            "every key credential link of the object named by the SID is "
            "removed, so no shadow credential can be used to log on as it"
        )
        if not windows:
            changes = (
                "every key credential link of the object named by the SID is "
                "removed, so no shadow credential can be used to log on as "
                "it; the document does not say whether the object is a user "
                "or a computer, so the owner takes the attribute off with "
                "the cmdlet of its object class"
            )
        findings.append(
            Finding(
                check_id="AD-A-10",
                severity=Severity.HIGH,
                title="an object holds a key credential link and can be "
                "logged on with a shadow credential",
                objects=(_affected(sid, None, row.dn, None),),
                maps_to=MAPS_TO["AD-A-10"],
                fix=Fix(
                    windows=FixStep(
                        summary=(
                            "take the key credential links off the object"
                        ),
                        commands=windows,
                        changes=changes,
                        revert=(
                            "put the links back with the key the owner still "
                            "trusts; the audit never reads the links "
                            "themselves"
                        ),
                    ),
                    samba=FixStep(
                        summary=(
                            "take the key credential links off the object"
                        ),
                        commands=(_samba_modify("msDS-KeyCredentialLink", ""),),
                        changes=changes,
                        revert=(
                            "put the links back with the key the owner still "
                            "trusts; the audit never reads the links "
                            "themselves"
                        ),
                    ),
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-10",
            Severity.HIGH,
            "no object holds a key credential link",
        )
    return _finding(
        "AD-A-10",
        Severity.HIGH,
        "an object holds a key credential link",
        tuple(findings),
    )


# ---- AD-A-11: the unconstrained delegation ---------------------------------


def _ad_a_11(document: Document) -> CheckResult:
    """The computers that are trusted for unconstrained delegation.

    A domain controller is trusted for delegation by the design of the
    directory, so the check skips the server trust accounts: a domain
    controller is one of them.  The primary group of the account is the
    second signal of a domain controller and skips it as well.
    """
    findings: list[Finding] = []
    for row in _rows(document, "computers"):
        sid = _row_sid(row)
        if sid is None:
            continue
        value = _uac(row)
        if value is None:
            continue
        if not value & UAC_TRUSTED_FOR_DELEGATION:
            continue
        if value & UAC_SERVER_TRUST:
            # A server trust account: a domain controller.
            continue
        if _int_value(row, "primaryGroupID") in (
            RID_DOMAIN_CONTROLLERS,
            RID_READ_ONLY_DOMAIN_CONTROLLERS,
        ):
            continue
        findings.append(
            Finding(
                check_id="AD-A-11",
                severity=Severity.HIGH,
                title="a computer is trusted for unconstrained delegation and "
                "can hand its ticket to another one",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        _uac_evidence(value),
                    ),
                ),
                maps_to=MAPS_TO["AD-A-11"],
                fix=_fix(
                    "take the unconstrained delegation off the computer",
                    (
                        "Set-ADComputer -Identity '{sid}' "
                        "-TrustedForDelegation $false",
                    ),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value & ~UAC_TRUSTED_FOR_DELEGATION),
                        ),
                    ),
                    "the TRUSTED_FOR_DELEGATION bit of userAccountControl is "
                    "cleared on the computer named by the SID",
                    "set the bit again with Set-ADComputer and "
                    "-TrustedForDelegation $true",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-11",
            Severity.HIGH,
            "no computer is trusted for unconstrained delegation",
        )
    return _finding(
        "AD-A-11",
        Severity.HIGH,
        "a computer is trusted for unconstrained delegation",
        tuple(findings),
    )


# ---- AD-A-12: the constrained delegation -----------------------------------


def _ad_a_12(document: Document) -> CheckResult:
    """The computers that are configured for constrained delegation.

    The finding of a computer that only carries the delegation targets is
    a medium one; the finding of a computer that carries the protocol
    transition bit as well is a high one.
    """
    findings: list[Finding] = []
    severity = Severity.MEDIUM
    for row in _rows(document, "computers"):
        sid = _row_sid(row)
        if sid is None:
            continue
        targets = row.a.get("msDS-AllowedToDelegateTo", ())
        if not targets:
            continue
        value = _uac(row)
        if value is None:
            continue
        transition = bool(value & UAC_PROTOCOL_TRANSITION)
        if transition:
            severity = Severity.HIGH
        findings.append(
            Finding(
                check_id="AD-A-12",
                severity=Severity.HIGH if transition else Severity.MEDIUM,
                title="a computer is configured for constrained delegation "
                "and may act for another one",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        f"{_uac_evidence(value)}; targets: "
                        f"{', '.join(targets)}",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-12"],
                fix=_fix(
                    "take the constrained delegation targets off the computer",
                    (
                        "Set-ADComputer -Identity '{sid}' "
                        "-Clear 'msDS-AllowedToDelegateTo'",
                    ),
                    (_samba_modify("msDS-AllowedToDelegateTo", ""),),
                    "every target of msDS-AllowedToDelegateTo is removed from "
                    "the computer named by the SID, so it can no longer act "
                    "for another one",
                    "put the targets back with Set-ADComputer and the "
                    "targets in the evidence of this finding",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-12",
            Severity.HIGH,
            "no computer is configured for constrained delegation",
        )
    return _finding(
        "AD-A-12",
        severity,
        "a computer is configured for constrained delegation",
        tuple(findings),
    )


# ---- AD-A-13: the resource-based constrained delegation --------------------


def _ad_a_13(document: Document) -> CheckResult:
    """The computers that hold a resource-based constrained delegation.

    The descriptor names the principals that may act on the computer, so
    the finding carries the SIDs inside it.  The blob itself is never
    shown: only the trustees are.
    """
    findings: list[Finding] = []
    for row in _rows(document, "computers"):
        sid = _row_sid(row)
        if sid is None:
            continue
        raw = row.a.get("msDS-AllowedToActOnBehalfOfOtherIdentity", ())
        if not raw:
            continue
        try:
            descriptor = secdesc.parse(base64.b64decode(raw[0], validate=True))
        except (ValueError, secdesc.SecDescError):
            return _unknown(
                "AD-A-13",
                Severity.HIGH,
                UnknownReason.ERROR,
                "the resource-based constrained delegation descriptor of an "
                "object could not be read",
            )
        trustees = sorted(
            ace.trustee
            for ace in descriptor.dacl
            if isinstance(ace, secdesc.Ace) and ace.trustee
        )
        findings.append(
            Finding(
                check_id="AD-A-13",
                severity=Severity.HIGH,
                title="a computer holds a resource-based constrained "
                "delegation descriptor and may be taken over",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        "trustees: " + ", ".join(trustees) if trustees else None,
                    ),
                ),
                maps_to=MAPS_TO["AD-A-13"],
                fix=_fix(
                    "take the resource-based constrained delegation "
                    "descriptor off the computer",
                    (
                        "Set-ADComputer -Identity '{sid}' "
                        "-Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'",
                    ),
                    (
                        _samba_modify(
                            "msDS-AllowedToActOnBehalfOfOtherIdentity", ""
                        ),
                    ),
                    "the descriptor is removed from the computer named by the "
                    "SID, so no principal may act on its behalf",
                    "put the descriptor back with Set-ADComputer and the "
                    "trustees in the evidence of this finding",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-13",
            Severity.HIGH,
            "no computer holds a resource-based constrained delegation "
            "descriptor",
        )
    return _finding(
        "AD-A-13",
        Severity.HIGH,
        "a computer holds a resource-based constrained delegation "
        "descriptor",
        tuple(findings),
    )


# ---- AD-A-14: the weak Kerberos encryption types ---------------------------


def _ad_a_14(document: Document) -> CheckResult:
    """The accounts that offer only weak Kerberos encryption types.

    An account that does not set the attribute at all uses the default of
    the domain, and the default of the domain is not in the query set of
    this audit, so such an account is judged only when it carries a
    service principal name: the ticket of a service account is asked for
    with the types of the domain, and the domain default is not known to
    be AES.

    A computer account is judged by the value it sets and by nothing else.
    The host name of a computer is a service principal name, and every
    computer of a domain carries one, so a computer that sets no
    encryption type takes the default of the domain and is left alone.

    The key distribution account of the domain is left alone as well: its
    ticket is the one of the directory itself, and a disabled account is
    not a ticket anybody can ask for.
    """
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    for query_id in ("users", "computers"):
        for row in _rows(document, query_id):
            sid = _row_sid(row)
            if sid is None:
                continue
            if rid_in_domain(sid, domain_sid) == RID_KRBTGT:
                continue
            value = _uac(row)
            if value is not None and not _enabled(value):
                continue
            types = _int_value(row, "msDS-SupportedEncryptionTypes")
            names = row.a.get("servicePrincipalName", ())
            if types is None or types == 0:
                if query_id != "users":
                    # A computer account is judged by the value it sets.
                    continue
                if not names:
                    continue
                value_text = "is not set" if types is None else f"is {types}"
                evidence = (
                    f"msDS-SupportedEncryptionTypes {value_text}, so the "
                    "account takes the default of the domain, which the "
                    "audit cannot read; the account carries a service "
                    "principal name"
                )
            elif types & ENC_WEAK and not types & ENC_AES:
                evidence = f"msDS-SupportedEncryptionTypes={types}"
            else:
                continue
            windows = (
                "Set-ADComputer -Identity '{sid}' "
                f"-Replace @{{'msDS-SupportedEncryptionTypes'={ENC_AES_ONLY}}}"
                if query_id == "computers"
                else "Set-ADUser -Identity '{sid}' "
                f"-Replace @{{'msDS-SupportedEncryptionTypes'={ENC_AES_ONLY}}}"
            )
            findings.append(
                Finding(
                    check_id="AD-A-14",
                    severity=Severity.MEDIUM,
                    title="an account offers only weak Kerberos encryption "
                    "types and its ticket can be cracked",
                    objects=(
                        _affected(
                            sid,
                            _row_name(row),
                            row.dn,
                            evidence,
                        ),
                    ),
                    maps_to=MAPS_TO["AD-A-14"],
                    fix=_fix(
                        "offer only the strong Kerberos encryption types",
                        (windows,),
                        (
                            _samba_modify(
                                "msDS-SupportedEncryptionTypes",
                                str(ENC_AES_ONLY),
                            ),
                        ),
                        "msDS-SupportedEncryptionTypes of the object named by "
                        "the SID becomes 24, AES128 and AES256, so no ticket "
                        "of it can be asked for with RC4 or DES",
                        "put the old value back; the value in the evidence of "
                        "this finding is the one to restore",
                    ),
                )
            )
    if not findings:
        return _pass(
            "AD-A-14",
            Severity.MEDIUM,
            "no account offers weak Kerberos encryption types",
        )
    return _finding(
        "AD-A-14",
        Severity.MEDIUM,
        "an account offers only weak Kerberos encryption types",
        tuple(findings),
    )


# ---- AD-A-16: the accounts that need no password ---------------------------


def _ad_a_16(document: Document) -> CheckResult:
    """The accounts that do not require a password.

    The built-in guest account of the domain is the business of AD-A-02
    and a trust account belongs to the trust, so neither is a finding
    here.  A disabled account cannot be used with an empty password, so
    its finding is a low one.
    """
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    disabled_count = 0
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) == RID_GUEST:
            continue
        value = _uac(row)
        if value is None:
            continue
        if value & UAC_INTERDOMAIN_TRUST:
            # An interdomain trust account: the password belongs to the
            # trust, not to the domain.
            continue
        if not value & UAC_PASSWD_NOTREQD:
            continue
        disabled = not _enabled(value)
        if disabled:
            disabled_count += 1
        evidence = _uac_evidence(value)
        if disabled:
            evidence = f"{evidence}; the account is disabled"
        findings.append(
            Finding(
                check_id="AD-A-16",
                severity=Severity.LOW if disabled else Severity.HIGH,
                title="an account does not require a password and can be "
                "used with an empty one",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        evidence,
                    ),
                ),
                maps_to=MAPS_TO["AD-A-16"],
                fix=_fix(
                    "make the account require a password",
                    (
                        "Set-ADAccountControl -Identity '{sid}' "
                        "-PasswordNotRequired $false",
                    ),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value & ~UAC_PASSWD_NOTREQD),
                        ),
                    ),
                    "the PASSWD_NOTREQD bit of userAccountControl is cleared "
                    "on the account named by the SID, so it cannot be used "
                    "with an empty password",
                    "set the bit again with Set-ADAccountControl and "
                    "-PasswordNotRequired $true",
                ),
            )
        )
    note = "an account does not require a password"
    if disabled_count:
        if disabled_count == 1:
            note = (
                f"{note}; 1 of them is disabled and is reported with a low "
                "severity"
            )
        else:
            note = (
                f"{note}; {disabled_count} of them are disabled and are "
                "reported with a low severity"
            )
    if not findings:
        return _pass(
            "AD-A-16",
            Severity.HIGH,
            "no account does without a password",
        )
    return _finding("AD-A-16", Severity.HIGH, note, tuple(findings))


# ---- the clock of the ages -------------------------------------------------


def _now(document: Document) -> datetime:
    """The moment the audit started: the clock of the document.

    The wall clock of the machine Newton runs on is never read.  The
    document says when the collector ran, and every age of this module
    is measured from that moment, so the same document always gives the
    same ages.
    """
    return parse_gentime(document.started)


def _moment(row: Row, attribute: str) -> datetime | None:
    """The time of a GeneralizedTime attribute, None when it is not set."""
    values = row.a.get(attribute, ())
    if not values:
        return None
    return parse_gentime(values[0])


def _filetime_moment(row: Row, attribute: str) -> datetime | None:
    """The time of a FILETIME attribute, None when it was never set.

    A FILETIME of zero and the largest value of the type both mean
    "never": the account never logged on, the password was never set or
    the account never expires.
    """
    value = _int_value(row, attribute)
    if value is None:
        return None
    return filetime_to_datetime(value)


def _older_than(moment: datetime | None, now: datetime, days: int) -> bool:
    """True when the moment is more than that many days in the past.

    A moment that is not there is not old: the checks that care about a
    missing time say so themselves.
    """
    if moment is None:
        return False
    return (now - moment).days > days


def _days(moment: datetime, now: datetime) -> int:
    """The age of a moment, in days."""
    return (now - moment).days


# ---- AD-A-17: the passwords that never expire ------------------------------


def _with_audit_account(note: str, skipped: bool) -> str:
    """The note of AD-A-17, with the line of the skipped account.

    The line is there only when the account the audit ran as was in the
    document and was left alone.
    """
    if not skipped:
        return note
    return f"{note}; {AUDIT_ACCOUNT_NOTE}"


def _ad_a_17(document: Document) -> CheckResult:
    """The accounts whose password never expires.

    The built-in accounts of the domain are left alone: their password
    never expires by the design of the directory, and AD-A-01 and
    AD-A-02 are their business.  A trust account belongs to the trust.

    The account the audit ran as is left alone too: it is the audit
    account of Newton's own setup, it holds a random password that
    nobody holds and it signs in by key only.  The result says that it
    was not judged.

    An account that carries a service principal name is a service
    account.  A service account whose password never expires is often
    deliberate, so its finding is a low one and the note says so.
    """
    domain_sid = document.domain.domain_sid
    identity_sid = document.identity.sid
    findings: list[Finding] = []
    services = 0
    skipped = False
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if sid == identity_sid:
            # The account the audit ran as: the audit account of
            # Newton's own setup.
            skipped = True
            continue
        if rid_in_domain(sid, domain_sid) in BUILTIN_ACCOUNT_RIDS:
            continue
        value = _uac(row)
        if value is None:
            continue
        if value & UAC_INTERDOMAIN_TRUST:
            continue
        if not value & UAC_DONT_EXPIRE_PASSWORD:
            continue
        names = row.a.get("servicePrincipalName", ())
        if names:
            services += 1
        evidence = _uac_evidence(value)
        if names:
            evidence = (
                f"{evidence}; the account carries a service principal name"
            )
        findings.append(
            Finding(
                check_id="AD-A-17",
                severity=Severity.LOW if names else Severity.MEDIUM,
                title="an account holds a password that never expires",
                objects=(_affected(sid, _row_name(row), row.dn, evidence),),
                maps_to=MAPS_TO["AD-A-17"],
                fix=_fix(
                    "let the password of the account expire again",
                    (
                        "Set-ADAccountControl -Identity '{sid}' "
                        "-PasswordNeverExpires $false",
                    ),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value & ~UAC_DONT_EXPIRE_PASSWORD),
                        ),
                    ),
                    "the DONT_EXPIRE_PASSWORD bit of userAccountControl is "
                    "cleared on the account named by the SID, so its "
                    "password expires like the password of every other "
                    "account of the domain",
                    "set the bit again with Set-ADAccountControl and "
                    "-PasswordNeverExpires $true",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-17",
            Severity.MEDIUM,
            _with_audit_account(
                "no account holds a password that never expires", skipped
            ),
        )
    note = "an account holds a password that never expires"
    if services:
        note = (
            f"{note}; {services} of them carry a service principal name and "
            "are reported with a low severity"
        )
    return _finding(
        "AD-A-17",
        Severity.MEDIUM,
        _with_audit_account(note, skipped),
        tuple(findings),
    )


# ---- AD-A-18: the reversible encryption -------------------------------------


def _ad_a_18(document: Document) -> CheckResult:
    """The passwords the directory stores with reversible encryption.

    An account that asks for reversible encryption keeps the password of
    the user in the clear: anybody who reads the attribute reads the
    password.

    The domain policy is part of the check: when the domain stores every
    password reversibly, the accounts that inherit the policy are as
    exposed as the accounts that ask for it.
    """
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        value = _uac(row)
        if value is None:
            return _unknown(
                "AD-A-18",
                Severity.HIGH,
                UnknownReason.ACCESS_DENIED,
                "an account carries no readable userAccountControl",
            )
        if not value & UAC_ENCRYPTED_TEXT_PWD_ALLOWED:
            continue
        findings.append(
            Finding(
                check_id="AD-A-18",
                severity=Severity.HIGH,
                title="an account stores its password with reversible "
                "encryption",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        _uac_evidence(value),
                    ),
                ),
                maps_to=MAPS_TO["AD-A-18"],
                fix=_fix(
                    "store the password of the account without reversible "
                    "encryption",
                    (
                        "Set-ADAccountControl -Identity '{sid}' "
                        "-AllowReversiblePasswordEncryption $false",
                    ),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value & ~UAC_ENCRYPTED_TEXT_PWD_ALLOWED),
                        ),
                    ),
                    "the ENCRYPTED_TEXT_PWD_ALLOWED bit of "
                    "userAccountControl is cleared on the account named by "
                    "the SID, so the directory does not keep the password "
                    "of the account in the clear",
                    "set the bit again with Set-ADAccountControl and "
                    "-AllowReversiblePasswordEncryption $true",
                ),
            )
        )
    head = _rows(document, "domain_head")
    policy = _int_value(head[0], "pwdProperties") if head else None
    unreadable = ""
    if policy is None:
        unreadable = (
            "the domain head carries no readable pwdProperties"
            if head
            else "the document holds no domain head"
        )
    elif policy & PWD_PROPERTIES_REVERSIBLE_ENCRYPTION:
        findings.append(
            Finding(
                check_id="AD-A-18",
                severity=Severity.HIGH,
                title="the domain stores the passwords of its accounts with "
                "reversible encryption",
                objects=(
                    _affected(
                        document.domain.domain_sid,
                        None,
                        head[0].dn,
                        f"pwdProperties={policy}",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-18"],
                fix=_explain(
                    "stop the domain from storing the passwords of its "
                    "accounts with reversible encryption",
                    "the password policy of the domain no longer allows "
                    "reversible encryption, so the password of an account "
                    "is never stored in the clear; the owner turns the "
                    "setting off in the password policy of the domain",
                    "the setting is turned on again in the password policy "
                    "of the domain, and the accounts that ask for "
                    "reversible encryption are named in the findings of "
                    "this check",
                ),
            )
        )
    if not findings:
        if unreadable:
            return _unknown(
                "AD-A-18",
                Severity.HIGH,
                UnknownReason.ACCESS_DENIED,
                unreadable,
            )
        return _pass(
            "AD-A-18",
            Severity.HIGH,
            "no account stores its password with reversible encryption and "
            "the domain does not ask for it",
        )
    note = "a password is stored with reversible encryption"
    if unreadable:
        note = f"{note}; {unreadable}"
    return _finding("AD-A-18", Severity.HIGH, note, tuple(findings))


# ---- AD-A-19: the SID history ----------------------------------------------


def _privileged_history_evidence(sid: str, domain_sid: str) -> str | None:
    """The evidence of a SID of a privileged group in a SID history.

    A SID of a privileged group of this domain in the history of an
    object is the privilege of this domain, handed to an object that may
    not hold it.  The evidence names the relative identifier of the
    group.  The builtin administrators are the same thing, and their SID
    is not a domain SID at all.
    """
    number = rid_in_domain(sid, domain_sid)
    if number is not None:
        if number in SAME_DOMAIN_PRIVILEGED_RIDS:
            return f"the RID {number} is a privileged group of this domain"
        return None
    if sid == BUILTIN_ADMINISTRATORS_SID:
        return "the RID 544 is a privileged group of this domain"
    return None


def _ad_a_19(document: Document) -> CheckResult:
    """The objects that carry the SID history of another principal.

    A SID history is the record of the SIDs an object held in another
    domain.  An object that carries one was migrated, and the privilege
    of the old SID may follow it.

    The history is read on the users, the groups and the computers: a
    group that was migrated carries its old SID as well.

    A SID of a privileged group of this domain in the history of an
    object is the privilege of this domain, handed to an object that may
    not hold it.  The evidence names the group and the relative
    identifier it has.

    A privileged group that holds a member value the audit cannot
    resolve hides a principal: the check cannot prove anything about
    that group and says so.
    """
    directory = Directory(document)
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    for query_id in ("users", "groups", "computers"):
        for row in _rows(document, query_id):
            sid = _row_sid(row)
            if sid is None:
                continue
            history = row.a.get("sIDHistory", ())
            if not history:
                continue
            texts: list[str] = []
            for value in history:
                try:
                    texts.append(sid_from_base64(value))
                except ValueError:
                    return _unknown(
                        "AD-A-19",
                        Severity.HIGH,
                        UnknownReason.ERROR,
                        "the SID history of an object could not be read",
                    )
            severity = Severity.HIGH
            own = [
                text
                for text in texts
                if rid_in_domain(text, domain_sid) is not None
            ]
            other = [
                text
                for text in texts
                if rid_in_domain(text, domain_sid) is None
            ]
            parts: list[str] = []
            if own:
                parts.append(
                    "sIDHistory holds the SID of this domain: "
                    + ", ".join(own)
                )
            if other:
                parts.append(
                    "sIDHistory holds the SID of another domain: "
                    + ", ".join(other)
                )
            for text in texts:
                evidence = _privileged_history_evidence(text, domain_sid)
                if evidence is not None:
                    parts.append(evidence)
            findings.append(
                Finding(
                    check_id="AD-A-19",
                    severity=severity,
                    title=(
                        "an object carries the SID history of its own domain"
                        if own
                        else "an object carries the SID history of another "
                        "domain"
                    ),
                    objects=(
                        _affected(
                            sid,
                            _row_name(row),
                            row.dn,
                            "; ".join(parts),
                        ),
                    ),
                    maps_to=MAPS_TO["AD-A-19"],
                    fix=_explain(
                        "take the SID history off the object",
                        "the SID history of the object named by the SID is "
                        "removed; the history is the record of the SIDs the "
                        "object held in another domain, and clearing it is a "
                        "deliberate act because those old SIDs may still be "
                        "trusted somewhere else in the forest",
                        "the SID history is not restored by this step: the "
                        "old SIDs of the object go back into the history of "
                        "the directory only when the owner puts them there "
                        "by hand",
                    ),
                )
            )
    hidden = _hidden_members(directory, directory.privileged_group_sids())
    if not findings:
        if hidden:
            return _unknown(
                "AD-A-19",
                Severity.HIGH,
                UnknownReason.ACCESS_DENIED,
                _hidden_note(hidden),
            )
        return _pass(
            "AD-A-19",
            Severity.HIGH,
            "no object carries the SID history of another principal and no "
            "privileged group hides a member",
        )
    note = "an object carries the SID history of another principal"
    if hidden:
        note = f"{note}; {_hidden_note(hidden)}"
    return _finding("AD-A-19", Severity.HIGH, note, tuple(findings))


# ---- AD-A-20: the passwords in text attributes ------------------------------


def _ad_a_20(document: Document) -> CheckResult:
    """The objects that hold a password in a text attribute.

    The query is a presence query: it names the objects that carry one
    of the password-bearing attributes and asks for nothing else.  The
    values are never read, and the finding is about the presence of the
    attribute and never about its value.
    """
    findings: list[Finding] = []
    for row in _rows(document, "pw_attr_presence"):
        sid = _row_sid(row)
        if sid is None:
            continue
        findings.append(
            Finding(
                check_id="AD-A-20",
                severity=Severity.MEDIUM,
                title="an object holds a password in a text attribute that "
                "everybody may read",
                objects=(
                    _affected(
                        sid,
                        None,
                        row.dn,
                        "the object carries one of the password attributes "
                        "the collector looked for",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-20"],
                fix=_explain(
                    "take the password out of the text attribute",
                    "the text attribute that holds the password is removed "
                    "from the object named by the SID; Newton never reads "
                    "the value of the attribute and never writes it, and "
                    "the owner finds the attribute by the filter of the "
                    "collector",
                    "the value of the attribute is not restored by this "
                    "step: a password that was in the clear is changed by "
                    "the owner, never put back",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-20",
            Severity.MEDIUM,
            "no object holds a password in a text attribute",
        )
    return _finding(
        "AD-A-20",
        Severity.MEDIUM,
        "an object holds a password in a text attribute",
        tuple(findings),
    )


# ---- AD-A-21: the accounts without a password ------------------------------


def _ad_a_21(document: Document) -> CheckResult:
    """The enabled accounts whose password was never set.

    An account with no password can be used with an empty one by
    anybody who reaches it, and a disabled account cannot be used at
    all.  The built-in guest account and the key distribution account
    are left alone: their password is not the business of the domain.
    """
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) in BUILTIN_ACCOUNT_RIDS:
            continue
        value = _uac(row)
        if value is None:
            continue
        if value & UAC_ACCOUNTDISABLE:
            continue
        if value & UAC_INTERDOMAIN_TRUST:
            continue
        if _int_value(row, "pwdLastSet") != 0:
            continue
        findings.append(
            Finding(
                check_id="AD-A-21",
                severity=Severity.MEDIUM,
                title="an enabled account must change password at next logon",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        "pwdLastSet=0, so the account must change password "
                        "at next logon",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-21"],
                fix=_fix(
                    "stop the account from being used without a password",
                    ("Disable-ADAccount -Identity '{sid}'",),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value | UAC_ACCOUNTDISABLE),
                        ),
                    ),
                    "the ACCOUNTDISABLE bit of userAccountControl is set on "
                    "the account named by the SID, so the account cannot "
                    "be used until the owner gives it a password; Newton "
                    "never writes a password",
                    "clear the bit again with Enable-ADAccount and the "
                    "same identity, once the owner has set a password of "
                    "their own",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-21",
            Severity.MEDIUM,
            "no enabled account must change password at next logon",
        )
    return _finding(
        "AD-A-21",
        Severity.MEDIUM,
        "an enabled account must change password at next logon",
        tuple(findings),
    )


# ---- AD-A-22: the accounts that expired ------------------------------------


def _ad_a_22(document: Document) -> CheckResult:
    """The enabled accounts whose expiry date has passed.

    An expired account cannot log on, so it is left enabled by nobody.
    An account that never expires is reported in the note and not as a
    finding: the catalogue names no date for the ordinary accounts of a
    domain, so the owner of a contract decides when it ends.
    """
    now = _now(document)
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    never = 0
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) in BUILTIN_ACCOUNT_RIDS:
            continue
        value = _uac(row)
        if value is None:
            continue
        if value & UAC_ACCOUNTDISABLE:
            continue
        if value & UAC_INTERDOMAIN_TRUST:
            continue
        moment = _filetime_moment(row, "accountExpires")
        if moment is None:
            never += 1
            continue
        if moment > now:
            continue
        findings.append(
            Finding(
                check_id="AD-A-22",
                severity=Severity.LOW,
                title="an enabled account holds an expiry date that has "
                "passed",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        f"accountExpires={row.a.get('accountExpires', ('',))[0]},"
                        f" the date passed {_days(moment, now)} days ago",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-22"],
                fix=_explain(
                    "give the account an expiry date that is still in the "
                    "future, or turn it off",
                    "the owner sets an expiry date on the account named by "
                    "the SID with Set-ADUser and -AccountExpirationDate, or "
                    "turns the account off with Disable-ADAccount; the "
                    "date the owner picks is the date the contract of the "
                    "account ends",
                    "the expiry date is put back with Set-ADUser and "
                    "-AccountExpirationDate and the date it held, and an "
                    "account that was turned off is turned on again with "
                    "Enable-ADAccount and the same identity",
                ),
            )
        )
    note = f"{never} of the enabled accounts hold an expiry date that never comes"
    if not findings:
        return _pass(
            "AD-A-22",
            Severity.LOW,
            f"no enabled account holds an expiry date that has passed; "
            f"{note}",
        )
    return _finding(
        "AD-A-22",
        Severity.LOW,
        f"an enabled account holds an expiry date that has passed; {note}",
        tuple(findings),
    )


# ---- AD-A-23: the service accounts ------------------------------------------


def _gmsa_readers(row: Row) -> tuple[str, ...]:
    """The principals that may retrieve the managed password.

    The membership of a group managed service account is one security
    descriptor (MS-ADTS 6.1.8.3.1): the readers are the trustees of its
    allowed ACEs, and a trustee that is named twice is one reader.

    Raises ``ValueError`` or ``SecDescError`` when the membership is not
    a descriptor Newton can read.
    """
    raw = row.a.get("msDS-GroupMSAMembership", ())
    if not raw:
        return ()
    descriptor = secdesc.parse(base64.b64decode(raw[0], validate=True))
    trustees = {
        ace.trustee
        for ace in descriptor.dacl
        if isinstance(ace, secdesc.Ace)
        and ace.type
        in (
            secdesc.ACCESS_ALLOWED_ACE,
            secdesc.ACCESS_ALLOWED_OBJECT_ACE,
        )
        and ace.trustee
    }
    return tuple(sorted(trustees))


def _ad_a_23(document: Document) -> CheckResult:
    """The service accounts and the group managed service accounts.

    A group managed service account rotates its own password and is
    never a static secret.  A service account that is not one of them
    keeps a password that stays the same until a person changes it, and
    a password that is older than a year is a secret that has been in
    the open for a year.

    The group managed service accounts are listed in the note with the
    number of principals that may retrieve them: the catalogue names no
    breadth that is too broad, so the owner reads the number.

    An ordinary account may not see the managed service accounts at all.
    An empty query is "could not read", never "nothing there": when the
    query came back empty and the other half of the check found
    nothing, the check is UNKNOWN(access_denied).  When the other half
    did find something, the finding is reported and the note says in
    one line that the managed ones were not visible.

    The managed half of the check is judged only when the query of the
    managed accounts completed.  A query that was truncated or denied
    does not say that there is no managed account: that half is left
    unjudged, the note says in one line that the inventory is not
    complete, and the check proves nothing about it.
    """
    now = _now(document)
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    managed: list[str] = []
    gmsa = document.queries.get("gmsa")
    gmsa_status = gmsa.status if gmsa is not None else "not_collected"
    complete = gmsa_status == "ok"
    managed_rows = gmsa.rows if complete else ()
    read_nothing = complete and not managed_rows
    for row in managed_rows:
        sid = _row_sid(row)
        if sid is None:
            continue
        name = _row_name(row)
        try:
            readers = _gmsa_readers(row)
        except (ValueError, secdesc.SecDescError):
            return _unknown(
                "AD-A-23",
                Severity.MEDIUM,
                UnknownReason.ERROR,
                "the membership of a group managed service account could "
                "not be read",
            )
        managed.append(f"{name or sid}: {len(readers)}")
        moment = _filetime_moment(row, "pwdLastSet")
        if moment is None:
            continue
        if not _older_than(moment, now, SERVICE_ACCOUNT_PASSWORD_DAYS):
            continue
        findings.append(
            Finding(
                check_id="AD-A-23",
                severity=Severity.MEDIUM,
                title="a group managed service account has not rotated its "
                "managed password for more than a year",
                objects=(
                    _affected(
                        sid,
                        name,
                        row.dn,
                        "the managed password of the account is "
                        f"{_days(moment, now)} days old",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-23"],
                fix=_explain(
                    "let the group managed service account rotate its "
                    "password again",
                    "the key distribution service of the forest gives the "
                    "group managed service account its password again, "
                    "which it does when the root key of the forest is "
                    "there and the managed password interval of the "
                    "account is in reach; the owner looks at the root key "
                    "of the forest, because a managed password that does "
                    "not rotate means the root key is missing or too old",
                    "the managed password is not restored by this step: a "
                    "managed password that did not rotate is rotated again "
                    "by the directory once its root key is in place",
                ),
            )
        )
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) == RID_KRBTGT:
            continue
        names = row.a.get("servicePrincipalName", ())
        if not names:
            continue
        moment = _filetime_moment(row, "pwdLastSet")
        if moment is None:
            continue
        if not _older_than(moment, now, SERVICE_ACCOUNT_PASSWORD_DAYS):
            continue
        value = _uac(row)
        disabled = value is not None and not _enabled(value)
        evidence = (
            f"the password of the service account is {_days(moment, now)} "
            "days old"
        )
        if disabled:
            evidence = f"{evidence}; the account is disabled"
        findings.append(
            Finding(
                check_id="AD-A-23",
                severity=Severity.LOW if disabled else Severity.MEDIUM,
                title="a service account that is not a managed service "
                "account holds a password that is older than a year",
                objects=(_affected(sid, _row_name(row), row.dn, evidence),),
                maps_to=MAPS_TO["AD-A-23"],
                fix=_explain(
                    "move the service account to a managed service account",
                    "the owner creates a group managed service account for "
                    "the service and gives the hosts that use the service "
                    "the right to retrieve its password; the password of "
                    "the old account is then removed by the owner, because "
                    "Newton never writes a password",
                    "the old service account is turned on again with "
                    "Enable-ADAccount and the same identity when the "
                    "managed service account is not in place yet",
                ),
            )
        )
    if not complete:
        inventory = f"gMSA inventory not complete (status {gmsa_status})"
    elif managed:
        inventory = (
            "group managed service accounts and the principals that may "
            f"retrieve them: {', '.join(managed)}"
        )
    elif document.collector == "samba":
        # A root read: an empty result is a real empty.
        inventory = "the domain holds no group managed service account"
    else:
        inventory = "gMSA objects not visible to this account"
    if findings:
        return _finding(
            "AD-A-23",
            Severity.MEDIUM,
            f"a service account holds a password that is older than a year; "
            f"{inventory}",
            tuple(findings),
        )
    if not complete:
        return _unknown(
            "AD-A-23",
            Severity.MEDIUM,
            runner.reason_for_status(gmsa_status),
            f"the service accounts were read; {inventory}",
        )
    if read_nothing and document.collector != "samba":
        # An ordinary account may not see the managed service accounts:
        # an empty query is "could not read", never "nothing there".
        return _unknown(
            "AD-A-23",
            Severity.MEDIUM,
            UnknownReason.ACCESS_DENIED,
            "none visible to the audit account",
        )
    return _pass(
        "AD-A-23",
        Severity.MEDIUM,
        f"no service account holds a password that is older than a "
        f"year; {inventory}",
    )


# ---- AD-A-24: the stale users ----------------------------------------------


def _ad_a_24(document: Document) -> CheckResult:
    """The enabled accounts that have not logged on for a long time.

    An account that never logged on is stale only when it is old enough
    to have been used: the account must be a quarter old before the
    check calls it stale.  A disabled account logs on nowhere and is
    left alone.
    """
    now = _now(document)
    domain_sid = document.domain.domain_sid
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) in BUILTIN_ACCOUNT_RIDS:
            continue
        value = _uac(row)
        if value is None:
            continue
        if value & UAC_ACCOUNTDISABLE:
            continue
        if value & UAC_INTERDOMAIN_TRUST:
            continue
        created = _moment(row, "whenCreated")
        if created is None:
            continue
        if not _older_than(created, now, STALE_DAYS):
            continue
        logon = _filetime_moment(row, "lastLogonTimestamp")
        if logon is not None and not _older_than(logon, now, STALE_DAYS):
            continue
        if logon is None:
            evidence = (
                f"the account was created {_days(created, now)} days ago "
                "and has never logged on"
            )
        else:
            evidence = (
                f"the account was created {_days(created, now)} days ago and "
                f"its last logon was {_days(logon, now)} days ago"
            )
        findings.append(
            Finding(
                check_id="AD-A-24",
                severity=Severity.LOW,
                title="an enabled account has not logged on for a long time",
                objects=(_affected(sid, _row_name(row), row.dn, evidence),),
                maps_to=MAPS_TO["AD-A-24"],
                fix=_fix(
                    "turn the stale account off until somebody uses it "
                    "again",
                    ("Disable-ADAccount -Identity '{sid}'",),
                    (
                        _samba_modify(
                            "userAccountControl",
                            str(value | UAC_ACCOUNTDISABLE),
                        ),
                    ),
                    "the ACCOUNTDISABLE bit of userAccountControl is set on "
                    "the account named by the SID, so the stale account "
                    "cannot be used while nobody looks after it",
                    "clear the bit again with Enable-ADAccount and the "
                    "same identity when the account is used again",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-24",
            Severity.LOW,
            "no enabled account has gone stale",
        )
    return _finding(
        "AD-A-24",
        Severity.LOW,
        "an enabled account has not logged on for a long time",
        tuple(findings),
    )


# ---- AD-A-25: the stale computers -------------------------------------------


def _ad_a_25(document: Document) -> CheckResult:
    """The computers whose trust has gone stale.

    A computer account holds two ages: the age of its machine password,
    which the computer rotates itself when it logs on, and the age of its
    last logon.  A computer whose machine password never rotates is a
    broken trust, and a computer that has not logged on for a long time
    is one nobody uses any more.

    A computer whose machine password was never set is a broken trust
    only when the computer is old enough to have used one: a computer
    that was created today has a password to set and not one to miss.
    """
    now = _now(document)
    findings: list[Finding] = []
    for row in _rows(document, "computers"):
        sid = _row_sid(row)
        if sid is None:
            continue
        value = _uac(row)
        if value is None:
            continue
        if value & UAC_ACCOUNTDISABLE:
            continue
        if value & UAC_SERVER_TRUST:
            continue
        if _int_value(row, "primaryGroupID") in (
            RID_DOMAIN_CONTROLLERS,
            RID_READ_ONLY_DOMAIN_CONTROLLERS,
        ):
            continue
        password = _filetime_moment(row, "pwdLastSet")
        logon = _filetime_moment(row, "lastLogonTimestamp")
        created = _moment(row, "whenCreated")
        old_created = created is not None and _older_than(
            created, now, STALE_DAYS
        )
        if password is None:
            # The machine password was never set: the computer is stale
            # only when it is old enough to have used one.
            old_password = old_created
        else:
            old_password = _older_than(password, now, STALE_DAYS)
        old_logon = logon is not None and _older_than(logon, now, STALE_DAYS)
        never_logged = logon is None and old_password
        if not (old_password or old_logon or never_logged):
            continue
        reasons: list[str] = []
        if password is None:
            reasons.append("the machine password was never set")
        elif old_password:
            reasons.append(
                f"the machine password is {_days(password, now)} days old"
            )
        if never_logged:
            reasons.append("the computer has never logged on")
        elif old_logon:
            reasons.append(
                f"the last logon was {_days(logon, now)} days ago"
            )
        findings.append(
            Finding(
                check_id="AD-A-25",
                severity=Severity.MEDIUM,
                title="a computer account holds a trust that has gone stale",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        "; ".join(reasons),
                    ),
                ),
                maps_to=MAPS_TO["AD-A-25"],
                fix=_explain(
                    "bring the computer back into the domain or take it "
                    "out of it",
                    "the owner re-joins the computer to the domain, which "
                    "gives it a new machine password, or removes the "
                    "computer account of the stale computer from the "
                    "directory; the machine password of a computer that is "
                    "gone is a secret that nobody has to keep any more",
                    "a removed computer account is not restored by this "
                    "step: the computer joins the domain again with a new "
                    "machine account of its own",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-25",
            Severity.MEDIUM,
            "no computer account holds a trust that has gone stale",
        )
    return _finding(
        "AD-A-25",
        Severity.MEDIUM,
        "a computer account holds a trust that has gone stale",
        tuple(findings),
    )


# ---- AD-A-26: the smart card accounts ---------------------------------------


def _ad_a_26(document: Document) -> CheckResult:
    """The accounts that need a smart card and keep an old password.

    An account that needs a smart card still holds the hash of its last
    password on the server, and that hash is what is cracked.  An
    account whose password was never set holds no hash and is no
    finding.
    """
    now = _now(document)
    findings: list[Finding] = []
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        value = _uac(row)
        if value is None:
            continue
        if not value & UAC_SMARTCARD_REQUIRED:
            continue
        moment = _filetime_moment(row, "pwdLastSet")
        if moment is None:
            continue
        if not _older_than(moment, now, SMARTCARD_PASSWORD_DAYS):
            continue
        findings.append(
            Finding(
                check_id="AD-A-26",
                severity=Severity.MEDIUM,
                title="an account needs a smart card and keeps a password "
                "that is older than a quarter",
                objects=(
                    _affected(
                        sid,
                        _row_name(row),
                        row.dn,
                        f"{_uac_evidence(value)}; the password of the "
                        f"account is {_days(moment, now)} days old",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-26"],
                fix=_explain(
                    "let the password of the account change",
                    "the owner changes the password of the account named by "
                    "the SID, which replaces the hash of the old password "
                    "on the server; a smart card account changes its "
                    "password on a schedule, and Newton never writes a "
                    "password",
                    "the old password is not restored by this step: a "
                    "password that was in the directory is changed again by "
                    "the owner, never put back",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-26",
            Severity.MEDIUM,
            "no account that needs a smart card keeps an old password",
        )
    return _finding(
        "AD-A-26",
        Severity.MEDIUM,
        "an account needs a smart card and keeps an old password",
        tuple(findings),
    )


# ---- AD-A-27: the key distribution account ---------------------------------


def _ad_a_27(document: Document) -> CheckResult:
    """The age of the password of the key distribution account.

    The key distribution account of the domain holds the key material
    of the tickets of the whole forest.  A password that is older than
    half a year is a key that has been in the open for half a year.

    The reset of that password is a two-step procedure the owner runs
    deliberately: a reset in the wrong order takes the tickets of the
    domain with it.
    """
    now = _now(document)
    domain_sid = document.domain.domain_sid
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, domain_sid) != RID_KRBTGT:
            continue
        moment = _filetime_moment(row, "pwdLastSet")
        if moment is None:
            return _finding(
                "AD-A-27",
                Severity.HIGH,
                "the password last set time of the key distribution account "
                "is 0 (never recorded)",
                (
                    Finding(
                        check_id="AD-A-27",
                        severity=Severity.HIGH,
                        title="the password last set time is 0 (never "
                        "recorded) on the key distribution account",
                        objects=(
                            _affected(
                                sid,
                                _row_name(row),
                                row.dn,
                                "pwdLastSet=0, so the password last set time "
                                "is 0 (never recorded)",
                            ),
                        ),
                        maps_to=MAPS_TO["AD-A-27"],
                        fix=_krbtgt_fix(),
                    ),
                ),
            )
        if not _older_than(moment, now, KRBtGT_PASSWORD_DAYS):
            return _pass(
                "AD-A-27",
                Severity.HIGH,
                "the password of the key distribution account of the domain "
                "is not old",
            )
        return _finding(
            "AD-A-27",
            Severity.HIGH,
            "the password of the key distribution account of the domain is "
            "old",
            (
                Finding(
                    check_id="AD-A-27",
                    severity=Severity.HIGH,
                    title="the password of the key distribution account is "
                    "older than half a year",
                    objects=(
                        _affected(
                            sid,
                            _row_name(row),
                            row.dn,
                            "the password of the key distribution account "
                            f"is {_days(moment, now)} days old",
                        ),
                    ),
                    maps_to=MAPS_TO["AD-A-27"],
                    fix=_krbtgt_fix(),
                ),
            ),
        )
    return _unknown(
        "AD-A-27",
        Severity.HIGH,
        UnknownReason.ACCESS_DENIED,
        "the document holds no account with the relative identifier 502 of "
        "the domain",
    )


def _krbtgt_fix() -> Fix:
    """The fix of the key distribution account: the owner runs it.

    The reset of the password of the key distribution account is a
    two-step procedure: the owner runs it deliberately, with the script
    of Microsoft, and never by a command of the audit.
    """
    return _explain(
        "reset the password of the key distribution account with the "
        "New-KrbtgtKeys script of Microsoft",
        "the password of the key distribution account of the domain is "
        "reset twice, once on the primary domain controller and once on "
        "the other domain controllers, with the New-KrbtgtKeys script of "
        "Microsoft; the owner runs the procedure deliberately, because a "
        "reset in the wrong order takes the tickets of the domain with "
        "it",
        "the old password of the key distribution account is not restored "
        "by this step: a reset changes the key material of the forest, "
        "and the way back is another reset with the same script",
    )


# ---- AD-A-30: the pre-windows 2000 compatible access group ------------------


def _ad_a_30(document: Document) -> CheckResult:
    """The pre-windows 2000 compatible access group and its members.

    The group gives its members the right to log on to the domain the
    way the old systems did.  Everybody and Anonymous in the group are
    the members that make the enumeration of the domain open to the
    world.

    A member value the audit cannot resolve is a member the audit
    cannot see: the check cannot prove what the group holds and says
    so.
    """
    directory = Directory(document)
    group = directory.principal(PRE_WINDOWS_2000_GROUP_SID)
    if group is None:
        return _unknown(
            "AD-A-30",
            Severity.MEDIUM,
            UnknownReason.ACCESS_DENIED,
            "the document holds no pre-windows 2000 compatible access group",
        )
    members = directory.members_recursive(PRE_WINDOWS_2000_GROUP_SID)
    hidden = len(directory.unresolved_members(PRE_WINDOWS_2000_GROUP_SID))
    findings: list[Finding] = []
    for member_sid in sorted(members & {EVERYONE_SID, ANONYMOUS_SID}):
        name = "Everyone" if member_sid == EVERYONE_SID else "Anonymous"
        findings.append(
            Finding(
                check_id="AD-A-30",
                severity=Severity.MEDIUM,
                title="the pre-windows 2000 compatible access group holds "
                f"{name}",
                objects=(
                    _affected(
                        PRE_WINDOWS_2000_GROUP_SID,
                        group.name,
                        group.dn,
                        f"the group holds {name} ({member_sid})",
                    ),
                    _affected(member_sid, name, None, None),
                ),
                maps_to=MAPS_TO["AD-A-30"],
                fix=Fix(
                    windows=FixStep(
                        summary=(
                            "take ANONYMOUS LOGON and Everyone out of the "
                            "pre-windows 2000 compatible access group"
                        ),
                        commands=(),
                        changes=(
                            "the owner opens Active Directory Users and "
                            "Computers, goes to the Builtin container and "
                            "takes ANONYMOUS LOGON and Everyone out of the "
                            "group 'Pre-Windows 2000 Compatible Access', so "
                            "the old way of logging on to the domain is "
                            "closed to the world"
                        ),
                        revert=(
                            "the owner puts the member back in the same "
                            "group of the Builtin container, in Active "
                            "Directory Users and Computers"
                        ),
                    ),
                    samba=FixStep(
                        summary=(
                            "take the member out of the pre-windows 2000 "
                            "compatible access group"
                        ),
                        commands=(_samba_remove_member(member_sid),),
                        changes=(
                            f"{name} is no longer a member of the group "
                            "named by the SID, so the old way of logging on "
                            "to the domain is closed to the world"
                        ),
                        revert=(
                            "put the member back with an ldbmodify that "
                            "appends the member value to the member "
                            "attribute of the group"
                        ),
                    ),
                ),
            )
        )
    if hidden:
        note = _hidden_note(hidden)
        if not findings:
            return _unknown(
                "AD-A-30",
                Severity.MEDIUM,
                UnknownReason.ACCESS_DENIED,
                note,
            )
        return _finding(
            "AD-A-30",
            Severity.MEDIUM,
            "the pre-windows 2000 compatible access group holds Everybody or "
            f"Anonymous; {note}",
            tuple(findings),
        )
    if not findings:
        return _pass(
            "AD-A-30",
            Severity.MEDIUM,
            "the pre-windows 2000 compatible access group holds neither "
            "Everybody nor Anonymous",
        )
    return _finding(
        "AD-A-30",
        Severity.MEDIUM,
        "the pre-windows 2000 compatible access group holds Everybody or "
        "Anonymous",
        tuple(findings),
    )


# ---- AD-A-31: the hybrid sync accounts --------------------------------------


def _is_single_sign_on(name: str | None) -> bool:
    """True when the name is the account of the single sign-on.

    The name of a computer account ends with a dollar sign, and the name
    of the single sign-on account of a tenant is the same whatever the
    case it is written in.
    """
    if not name:
        return False
    return name.upper() == SINGLE_SIGN_ON_ACCOUNT.upper()


def _is_hybrid_account(name: str | None) -> bool:
    """True when the name is the name of an account of a hybrid tenant.

    The accounts of the cloud in the directory of the on-premises domain
    are named MSOL_ or AAD_ and the name the cloud gives them.  The name
    is read in any case, and a name that only starts like one of them is
    not one of them.
    """
    if not name:
        return False
    upper = name.upper()
    return any(upper.startswith(prefix) for prefix in HYBRID_ACCOUNT_PREFIXES)


def _ad_a_31(document: Document) -> CheckResult:
    """The accounts of a hybrid tenant.

    The accounts of a hybrid tenant are the accounts of the cloud in the
    directory of the on-premises domain.  The account of the single
    sign-on is the one that can synchronize the directory, and it is a
    computer object: its name ends with the dollar sign of a computer
    account.

    The account is rolled over on a schedule, and a machine password that
    is older than a month is one the tenant did not roll over.  A machine
    password that was never set is one the tenant never rolled over
    either, and the check says so.

    The other accounts of the tenant are the users the cloud writes into
    the directory of the domain.  Every one of them is reported, one
    object of its own, and the owner reads the names of them.
    """
    now = _now(document)
    findings: list[Finding] = []
    for row in _rows(document, "computers"):
        sid = _row_sid(row)
        if sid is None:
            continue
        name = _row_name(row)
        if not _is_single_sign_on(name):
            continue
        moment = _filetime_moment(row, "pwdLastSet")
        if moment is None:
            # A password that was never set was never rolled over.
            title = (
                "the single sign-on account of the hybrid tenant never "
                "rolled its machine password over"
            )
            evidence = (
                "password last set time is 0 or absent (never rolled over)"
            )
        else:
            if not _older_than(moment, now, HYBRID_ACCOUNT_PASSWORD_DAYS):
                continue
            title = (
                "the single sign-on account of the hybrid tenant has an old "
                "machine password"
            )
            evidence = (
                "the machine password of the single sign-on account "
                f"is {_days(moment, now)} days old"
            )
        findings.append(
            Finding(
                check_id="AD-A-31",
                severity=Severity.HIGH,
                title=title,
                objects=(_affected(sid, name, row.dn, evidence),),
                maps_to=MAPS_TO["AD-A-31"],
                fix=_explain(
                    "roll the single sign-on account over",
                    "the owner rolls the account of the single sign-on over "
                    "with the tooling of the tenant, and takes the accounts "
                    "of the hybrid tenant that the cloud does not use any "
                    "more out of the directory; the account of the single "
                    "sign-on is rolled over on the schedule the tenant asks "
                    "for",
                    "an account that was taken out of the directory is not "
                    "restored by this step: the owner creates it again "
                    "with the tooling of the tenant when it is needed",
                ),
            )
        )
    for row in _rows(document, "users"):
        sid = _row_sid(row)
        if sid is None:
            continue
        name = _row_name(row)
        if not _is_hybrid_account(name):
            continue
        findings.append(
            Finding(
                check_id="AD-A-31",
                severity=Severity.HIGH,
                title="the domain holds an account of the hybrid tenant that "
                "synchronizes it",
                objects=(
                    _affected(
                        sid,
                        name,
                        row.dn,
                        "the account synchronizes the directory of the "
                        "on-premises domain with the tenant of the cloud",
                    ),
                ),
                maps_to=MAPS_TO["AD-A-31"],
                fix=_explain(
                    "take the account of the hybrid tenant out of the "
                    "directory",
                    "the owner takes the accounts of the hybrid tenant that "
                    "the cloud does not use any more out of the directory, "
                    "with the tooling of the tenant, because an account of "
                    "the tenant that stays behind is an account the cloud "
                    "may still write with",
                    "an account that was taken out of the directory is not "
                    "restored by this step: the owner creates it again "
                    "with the tooling of the tenant when it is needed",
                ),
            )
        )
    if not findings:
        return _pass(
            "AD-A-31",
            Severity.HIGH,
            "the domain holds no account of a hybrid tenant and no "
            "single sign-on account with an old machine password",
        )
    return _finding(
        "AD-A-31",
        Severity.HIGH,
        "the domain holds the accounts of a hybrid tenant",
        tuple(findings),
    )


# ---- AD-A-32: the read-only domain controllers -----------------------------


def _ad_a_32(document: Document) -> CheckResult:
    """The password replication policy of the read-only domain controllers.

    A read-only domain controller caches the passwords of the principals
    that may be replicated to it.  The broader the group of the allowed
    password replication is, the more principals sit in the cache of
    every read-only domain controller of the forest.

    The feature is a Windows one: a Samba collector cannot see it.
    """
    if document.collector == "samba":
        return _unknown(
            "AD-A-32",
            Severity.HIGH,
            UnknownReason.UNSUPPORTED,
            "the read-only domain controller policy is a Windows feature "
            "and the Samba collector cannot see it",
        )
    directory = Directory(document)
    rodcs: list[str] = []
    for row in _rows(document, "computers"):
        if _int_value(row, "primaryGroupID") != RID_READ_ONLY_DOMAIN_CONTROLLERS:
            continue
        sid = _row_sid(row)
        if sid is not None:
            rodcs.append(sid)
    if not rodcs:
        return _pass(
            "AD-A-32",
            Severity.HIGH,
            "the domain holds no read-only domain controller, so the "
            "password replication policy caches no principal",
        )
    allowed = (
        f"{document.domain.domain_sid}-{RID_ALLOWED_RODC_REPLICATION}"
    )
    members = directory.members_recursive(allowed)
    hidden = len(directory.unresolved_members(allowed))
    if hidden:
        return _unknown(
            "AD-A-32",
            Severity.HIGH,
            UnknownReason.ACCESS_DENIED,
            _hidden_note(hidden),
        )
    if not members:
        return _pass(
            "AD-A-32",
            Severity.HIGH,
            "no principal may be replicated to the read-only domain "
            "controllers of the domain",
        )
    group = directory.principal(allowed)
    objects: list[Affected] = []
    for sid in rodcs:
        principal = directory.principal(sid)
        objects.append(
            _affected(
                sid,
                principal.name if principal is not None else None,
                principal.dn if principal is not None else None,
                "the read-only domain controller caches the passwords of "
                "the principals of the allowed group",
            )
        )
    objects.append(
        _affected(
            allowed,
            group.name if group is not None else None,
            group.dn if group is not None else None,
            f"the allowed group holds {len(members)} principals",
        )
    )
    for sid in sorted(members):
        principal = directory.principal(sid)
        objects.append(
            _affected(
                sid,
                principal.name if principal is not None else None,
                principal.dn if principal is not None else None,
                None,
            )
        )
    return _finding(
        "AD-A-32",
        Severity.HIGH,
        "the password replication policy of the read-only domain "
        "controllers is broad",
        (
            Finding(
                check_id="AD-A-32",
                severity=Severity.HIGH,
                title="every principal of the allowed password replication "
                "group is cached by the read-only domain controllers",
                objects=tuple(objects),
                maps_to=MAPS_TO["AD-A-32"],
                fix=_explain(
                    "take the principals out of the allowed password "
                    "replication group",
                    "the principals that do not have to be replicated to "
                    "the read-only domain controllers are taken out of the "
                    "group named by the SID; the owner keeps in the group "
                    "only the principals a branch office has to use when "
                    "the link to the domain is down",
                    "a principal is put back into the group with "
                    "Add-ADGroupMember and the same two identities, and "
                    "the read-only domain controllers cache it again at "
                    "their next password change",
                ),
            ),
        ),
    )


# ---- the catalogue ---------------------------------------------------------


CHECKS: list[Check] = [
    Check(
        id="AD-A-01",
        title=TITLE["AD-A-01"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_01,
        queries=("users",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-01"],
    ),
    Check(
        id="AD-A-02",
        title=TITLE["AD-A-02"],
        severity=Severity.LOW,
        evaluate=_ad_a_02,
        queries=("users",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-02"],
    ),
    Check(
        id="AD-A-03",
        title=TITLE["AD-A-03"],
        severity=Severity.HIGH,
        evaluate=_ad_a_03,
        queries=("users", "groups"),
        lookups=("computers", "fsps"),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-03"],
    ),
    Check(
        id="AD-A-04",
        title=TITLE["AD-A-04"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_04,
        queries=("users",),
        required_attrs=("objectSid", "primaryGroupID", "sAMAccountName"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-04"],
    ),
    Check(
        id="AD-A-05",
        title=TITLE["AD-A-05"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_05,
        queries=("users", "groups"),
        lookups=("computers", "fsps"),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-05"],
    ),
    Check(
        id="AD-A-06",
        title=TITLE["AD-A-06"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_06,
        queries=("users", "groups"),
        lookups=("computers", "fsps"),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-06"],
    ),
    Check(
        id="AD-A-07",
        title=TITLE["AD-A-07"],
        severity=Severity.HIGH,
        evaluate=_ad_a_07,
        queries=("users",),
        lookups=("groups", "computers", "fsps"),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-07"],
    ),
    Check(
        id="AD-A-08",
        title=TITLE["AD-A-08"],
        severity=Severity.HIGH,
        evaluate=_ad_a_08,
        queries=("users",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-08"],
    ),
    Check(
        id="AD-A-09",
        title=TITLE["AD-A-09"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_09,
        queries=("users", "groups"),
        lookups=("computers", "fsps"),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-09"],
    ),
    Check(
        id="AD-A-10",
        title=TITLE["AD-A-10"],
        severity=Severity.HIGH,
        evaluate=_ad_a_10,
        queries=("keycred_presence",),
        lookups=("users", "groups", "computers", "fsps"),
        required_attrs=("objectSid",),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-10"],
    ),
    Check(
        id="AD-A-11",
        title=TITLE["AD-A-11"],
        severity=Severity.HIGH,
        evaluate=_ad_a_11,
        queries=("computers",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("computers",),
        maps_to=MAPS_TO["AD-A-11"],
    ),
    Check(
        id="AD-A-12",
        title=TITLE["AD-A-12"],
        severity=Severity.HIGH,
        evaluate=_ad_a_12,
        queries=("computers",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("computers",),
        maps_to=MAPS_TO["AD-A-12"],
    ),
    Check(
        id="AD-A-13",
        title=TITLE["AD-A-13"],
        severity=Severity.HIGH,
        evaluate=_ad_a_13,
        queries=("computers",),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("computers",),
        maps_to=MAPS_TO["AD-A-13"],
    ),
    Check(
        id="AD-A-14",
        title=TITLE["AD-A-14"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_14,
        queries=("users", "computers"),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("users", "computers"),
        maps_to=MAPS_TO["AD-A-14"],
    ),
    Check(
        id="AD-A-16",
        title=TITLE["AD-A-16"],
        severity=Severity.HIGH,
        evaluate=_ad_a_16,
        queries=("users",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-16"],
    ),
    Check(
        id="AD-A-17",
        title=TITLE["AD-A-17"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_17,
        queries=("users",),
        required_attrs=("objectSid", "userAccountControl", "sAMAccountName"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-17"],
    ),
    Check(
        id="AD-A-18",
        title=TITLE["AD-A-18"],
        severity=Severity.HIGH,
        evaluate=_ad_a_18,
        queries=("users", "domain_head"),
        required_attrs=("objectSid",),
        sentinels=("users", "domain_head"),
        maps_to=MAPS_TO["AD-A-18"],
    ),
    Check(
        id="AD-A-19",
        title=TITLE["AD-A-19"],
        severity=Severity.HIGH,
        evaluate=_ad_a_19,
        queries=("users", "groups", "computers"),
        lookups=("fsps",),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("users", "groups", "computers", "fsps"),
        maps_to=MAPS_TO["AD-A-19"],
    ),
    Check(
        id="AD-A-20",
        title=TITLE["AD-A-20"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_20,
        queries=("pw_attr_presence",),
        required_attrs=("objectSid",),
        maps_to=MAPS_TO["AD-A-20"],
    ),
    Check(
        id="AD-A-21",
        title=TITLE["AD-A-21"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_21,
        queries=("users",),
        required_attrs=(
            "objectSid",
            "userAccountControl",
            "sAMAccountName",
            "pwdLastSet",
        ),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-21"],
    ),
    Check(
        id="AD-A-22",
        title=TITLE["AD-A-22"],
        severity=Severity.LOW,
        evaluate=_ad_a_22,
        queries=("users",),
        required_attrs=(
            "objectSid",
            "userAccountControl",
            "sAMAccountName",
            "accountExpires",
        ),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-22"],
    ),
    Check(
        id="AD-A-23",
        title=TITLE["AD-A-23"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_23,
        queries=("users",),
        required_attrs=("objectSid", "sAMAccountName", "pwdLastSet"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-23"],
    ),
    Check(
        id="AD-A-24",
        title=TITLE["AD-A-24"],
        severity=Severity.LOW,
        evaluate=_ad_a_24,
        queries=("users",),
        required_attrs=(
            "objectSid",
            "userAccountControl",
            "sAMAccountName",
            "whenCreated",
        ),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-24"],
    ),
    Check(
        id="AD-A-25",
        title=TITLE["AD-A-25"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_25,
        queries=("computers",),
        required_attrs=(
            "objectSid",
            "userAccountControl",
            "sAMAccountName",
            "pwdLastSet",
        ),
        sentinels=("computers",),
        maps_to=MAPS_TO["AD-A-25"],
    ),
    Check(
        id="AD-A-26",
        title=TITLE["AD-A-26"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_26,
        queries=("users",),
        required_attrs=(
            "objectSid",
            "userAccountControl",
            "sAMAccountName",
            "pwdLastSet",
        ),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-26"],
    ),
    Check(
        id="AD-A-27",
        title=TITLE["AD-A-27"],
        severity=Severity.HIGH,
        evaluate=_ad_a_27,
        queries=("users",),
        required_attrs=("objectSid", "sAMAccountName", "pwdLastSet"),
        sentinels=("users",),
        maps_to=MAPS_TO["AD-A-27"],
    ),
    Check(
        id="AD-A-30",
        title=TITLE["AD-A-30"],
        severity=Severity.MEDIUM,
        evaluate=_ad_a_30,
        queries=("groups", "fsps"),
        lookups=("users", "computers"),
        required_attrs=("objectSid",),
        sentinels=("groups", "fsps", "users", "computers"),
        maps_to=MAPS_TO["AD-A-30"],
    ),
    Check(
        id="AD-A-31",
        title=TITLE["AD-A-31"],
        severity=Severity.HIGH,
        evaluate=_ad_a_31,
        queries=("computers", "users"),
        required_attrs=("objectSid", "sAMAccountName"),
        sentinels=("computers", "users"),
        maps_to=MAPS_TO["AD-A-31"],
    ),
    Check(
        id="AD-A-32",
        title=TITLE["AD-A-32"],
        severity=Severity.HIGH,
        evaluate=_ad_a_32,
        queries=("computers", "groups"),
        lookups=("users", "fsps"),
        required_attrs=("objectSid",),
        sentinels=("computers", "groups", "users", "fsps"),
        maps_to=MAPS_TO["AD-A-32"],
    ),
]
