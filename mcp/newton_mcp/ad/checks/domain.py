"""The domain policy checks.

The checks of this module read the domain, the policy, the GPOs and the
trusts of one directory.  Each of them is a pure function of the
collector document: the runner has already proved that the audit was
allowed to see the data (the status of every query, the sentinels, the
required attributes and the queries an ordinary account may not see),
so a check reads the data and judges it.

Two rules shape the module:

- a check that cannot prove PASS is UNKNOWN, and the reason says why;
- a fix names the object it changes by SID or by GUID, so a
  directory-originated string never ends up inside a command.

The severity and the reference of every check come from GAPS.md, and
the ids are the ones of GAPS.md, so a finding of this module and a row
of the catalogue are the same thing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..catalogue import Check
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
    DS_HEURISTICS_ADMINSD_EXCLUDE,
    DS_HEURISTICS_ADMINSD_MASK,
    DS_HEURISTICS_BLOCK_ANONYMOUS_OPS,
    DS_HEURISTICS_LIST_OBJECT,
    TRUST_ATTRIBUTE_FOREST_TRANSITIVE,
    TRUST_ATTRIBUTE_QUARANTINED_DOMAIN,
    TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL,
    TRUST_ATTRIBUTE_WITHIN_FOREST,
    ds_heuristics_positions,
    functional_level_name,
    is_guid,
    sid_from_base64,
    timespan_seconds,
    trust_attribute_names,
)
from ..wire import Document, FileSection, GppItem, GptTmplItem, Row


# The label every protocol check carries: the audit reads the
# configuration, never the events that would show what happened.
CONFIGURED_LABEL = "configured; observed not collected"

# The password length the domain policy is measured against.  It is the
# floor of the CIS benchmark the maps_to of AD-A-33 names.
MIN_PASSWORD_LENGTH_FLOOR = 14

# The lockout threshold the domain policy is measured against.
LOCKOUT_THRESHOLD_FLOOR = 5

# The value of LDAPServerIntegrity that requires the signing of every
# LDAP bind (MS KB4520412).  A value below it is weaker.
LDAP_SIGNING_REQUIRED = 2

# The value of LdapEnforceChannelBinding that enforces channel binding.
CHANNEL_BINDING_ENFORCED = 1

# The value of LmCompatibilityLevel that sends NTLMv2 answers only.
LM_COMPATIBILITY_NTLMV2_ONLY = 5

# The functional level of Windows Server 2016.  A domain or a forest
# below it does not carry the features of the later releases.
FUNCTIONAL_LEVEL_2016 = 7

# The Kerberos policy limits of AD-A-34: the maximum ticket age in
# hours, the maximum renewal age in days and the maximum clock skew in
# minutes.
MAX_TICKET_AGE_HOURS = 10
MAX_RENEW_AGE_DAYS = 7
MAX_CLOCK_SKEW_MINUTES = 5

# A gPLink entry: "[LDAP://cn={GUID},CN=Policies,CN=System,DC=...;0]".
# The GUID is the object of the GPO the link points at, and the number
# after the semicolon is the link option: 0 is an enabled link, 1 a
# disabled one.
_GPLINK_RE = re.compile(
    r"\[LDAP://cn=\{(?P<guid>[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}"
    r"[^;\]]*;(?P<option>\d+)\]",
    re.IGNORECASE,
)

# The GPO folder name: a GUID in braces.
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
    files: tuple[str, ...] = (),
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
        files=files,
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


def _reason_for_status(status: str) -> UnknownReason:
    """The reason a status other than ``ok`` maps to."""
    return {
        "truncated": UnknownReason.TRUNCATED,
        "denied": UnknownReason.ACCESS_DENIED,
        "unsupported": UnknownReason.UNSUPPORTED,
        "unavailable": UnknownReason.UNAVAILABLE,
        "not_collected": UnknownReason.NOT_COLLECTED,
        "error": UnknownReason.ERROR,
    }.get(status, UnknownReason.ERROR)


def _refused_result(
    spec: Spec,
    section: FileSection | None,
    label: str,
) -> CheckResult | None:
    """The result of a check that read a section that refused files.

    A file section that refused a file or skipped a special one is not
    the whole of the data: a check that reads it cannot prove that
    there is nothing in the files it never read.  The result is UNKNOWN
    with the reason ``parse_refused`` and a note that gives both
    counts.  ``None`` means that the section refused nothing.

    A refusal is not always a file: a key of a template that a check
    reads and whose value is not a number is an item that was refused,
    so the note counts the items and the special files apart.
    """
    if section is None:
        return None
    refused = int(section.parse_refused)
    skipped = int(section.skipped_special)
    if not refused and not skipped:
        return None
    return _result(
        spec,
        Status.UNKNOWN,
        reason=UnknownReason.PARSE_REFUSED,
        note=(
            f"the collector refused {refused} item(s) and skipped {skipped} "
            f"special file(s) of the {label}, so the scan is not complete"
        ),
    )


# ---- small readers ---------------------------------------------------------


def _rows(document: Document, query_id: str) -> tuple[Row, ...]:
    """The rows of a query."""
    result = document.queries.get(query_id)
    if result is None:
        return ()
    return result.rows


def _text(row: Row, name: str) -> str | None:
    """The first value of an attribute, when the row carries one."""
    values = row.a.get(name)
    if not values:
        return None
    return values[0]


def _number(row: Row, name: str) -> int | None:
    """The first value of an attribute as a number, when it is one."""
    text = _text(row, name)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _sid_of(row: Row) -> str | None:
    """The SID of a row, when it carries a usable one."""
    for value in row.a.get("objectSid", ()):
        try:
            return sid_from_base64(value)
        except ValueError:
            continue
    return None


def _guid_text(text: str) -> str | None:
    """The canonical form of a GUID that is written in braces."""
    match = _GPO_NAME_RE.match(text.strip())
    if match is None:
        return None
    guid = match.group("guid").lower()
    return guid if is_guid(guid) else None


def _gplink_entries(value: str) -> list[tuple[str, bool]]:
    """The GPOs a gPLink value points at, and whether the link is enabled.

    The link option after the semicolon is 0 for an enabled link and 1
    for a disabled one: a disabled link configures nothing.
    """
    entries: list[tuple[str, bool]] = []
    for match in _GPLINK_RE.finditer(value):
        entries.append((match.group("guid").lower(), match.group("option") == "0"))
    return entries


def _linked_gpos(document: Document, rows: tuple[Row, ...]) -> list[str]:
    """The GUIDs of the GPOs the gPLink of the rows points at.

    A link that is disabled points at a GPO that configures nothing, so
    it is not in the list.
    """
    found: list[str] = []
    for row in rows:
        for value in row.a.get("gPLink", ()):
            for guid, enabled in _gplink_entries(value):
                if not enabled:
                    continue
                if guid not in found:
                    found.append(guid)
    return found


def _dc_ou_rows(document: Document) -> tuple[Row, ...]:
    """The row of the organizational unit of the domain controllers.

    The query that reads the unit asks for its descriptor only, so the
    link of the unit is read from the row of the organizational units.
    """
    keys = {row.dn.strip().lower() for row in _rows(document, "dc_ou")}
    if not keys:
        return ()
    return tuple(
        row for row in _rows(document, "ous") if row.dn.strip().lower() in keys
    )


def _dc_ou_gpos(document: Document) -> list[str]:
    """The GUIDs of the GPOs linked at the unit of the domain controllers.

    These are the GPOs that configure the domain controllers, and they
    are the ones a protocol setting of the collector host is read from
    when the registry of the host does not carry it.
    """
    return _linked_gpos(document, _dc_ou_rows(document))


def _first_enabled_gpo(document: Document, rows: tuple[Row, ...]) -> str | None:
    """The GUID of the first GPO the gPLink of the rows links.

    The links are read in the order they are written in, and a link
    that is disabled is skipped: the first enabled link is the GPO that
    configures the object.
    """
    for row in rows:
        for value in row.a.get("gPLink", ()):
            for guid, enabled in _gplink_entries(value):
                if enabled:
                    return guid
    return None


def _gpo_row_for(document: Document, guid: str) -> Row | None:
    """The GPO row of one GUID, when the document holds one."""
    for row in _rows(document, "gpos"):
        for part in row.dn.split(","):
            candidate = _guid_text(part.split("=", 1)[-1])
            if candidate == guid:
                return row
    return None


def _gpo_guid(row: Row) -> str | None:
    """The GUID of a GPO row, taken from the name of its container."""
    for part in row.dn.split(","):
        candidate = _guid_text(part.split("=", 1)[-1])
        if candidate is not None:
            return candidate
    return None


# ---- AD-A-33: the domain password and lockout policy -----------------------

_SPEC_33 = Spec(
    id="AD-A-33",
    title="Domain password and lockout policy",
    severity=Severity.MEDIUM,
    maps_to=("CIS DC (unverified)",),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Raise the password length of the domain policy and turn the "
                "account lockout on: run Set-ADDefaultDomainPasswordPolicy "
                "with -MinPasswordLength 14, -HistoryCount 24, "
                "-LockoutThreshold 5, -LockoutDuration 00:30:00 and "
                "-LockoutObservationWindow 00:30:00. The two lockout values "
                "are TimeSpans: 00:30:00 is thirty minutes, and a plain "
                "number would be read as days."
            ),
            commands=(),
            changes=(
                "the domain password policy: the minimum password length, "
                "the history size and the lockout settings"
            ),
            revert=(
                "run the same cmdlet with the values the policy had before "
                "the change"
            ),
        ),
        samba=FixStep(
            summary=(
                "Raise the password length of the domain policy and turn the "
                "account lockout on: run samba-tool domain passwordsettings "
                "set with the values to choose, for example "
                "--min-pwd-length=14 --history-size=24 --lockout-threshold=5 "
                "and --lockout-duration=30, where the duration of the "
                "lockout is counted in minutes."
            ),
            commands=(),
            changes=(
                "the domain password policy: the minimum password length, "
                "the history size and the lockout settings"
            ),
            revert=(
                "run the same command with the values the policy had before "
                "the change"
            ),
        ),
    ),
)


def _evaluate_33(document: Document, spec: Spec) -> CheckResult:
    head = _rows(document, "domain_head")[0]
    minimum = _number(head, "minPwdLength")
    threshold = _number(head, "lockoutThreshold")
    findings: list[Finding] = []
    if minimum is None or minimum < MIN_PASSWORD_LENGTH_FLOOR:
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="The domain policy accepts passwords shorter than 14 characters",
                objects=(
                    Affected(
                        sid=_sid_of(head),
                        dn=head.dn,
                        evidence=(
                            "the minimum password length of the domain policy "
                            f"is {minimum if minimum is not None else 'unknown'}"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    if threshold is None or threshold < LOCKOUT_THRESHOLD_FLOOR:
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="The domain policy does not lock accounts out",
                objects=(
                    Affected(
                        sid=_sid_of(head),
                        dn=head.dn,
                        evidence=(
                            "the lockout threshold of the domain policy is "
                            f"{threshold if threshold is not None else 'unknown'}"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    history = _number(head, "pwdHistoryLength")
    max_age = _number(head, "maxPwdAge")
    min_age = _number(head, "minPwdAge")
    note = (
        "the domain password policy: minimum password length "
        f"{minimum}, history {history}, lockout threshold {threshold}, "
        "the password expires after "
        f"{timespan_seconds(max_age) / 86400:.0f} days and may be changed after "
        f"{timespan_seconds(min_age) / 86400:.0f} days"
        if max_age is not None and min_age is not None
        else (
            "the domain password policy: minimum password length "
            f"{minimum}, history {history}, lockout threshold {threshold}"
        )
    )
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note=note,
        findings=tuple(findings),
    )


# ---- AD-A-34: the Kerberos policy -----------------------------------------

_SPEC_34 = Spec(
    id="AD-A-34",
    title="Kerberos policy of the GPOs linked at the domain head",
    severity=Severity.MEDIUM,
    maps_to=("CIS DC (unverified)",),
)

# The Kerberos settings the collector reads from the GPO templates.
KERBEROS_SETTINGS = (
    "MaxTicketAge",
    "MaxServiceAge",
    "MaxRenewAge",
    "MaxClockSkew",
)

# The Kerberos settings AD-A-34 judges, and the limit of each one: the
# ticket age in hours, the renewal age in days and the clock skew in
# minutes.
KERBEROS_LIMITS: tuple[tuple[str, int, str], ...] = (
    ("MaxTicketAge", MAX_TICKET_AGE_HOURS, "hours"),
    ("MaxRenewAge", MAX_RENEW_AGE_DAYS, "days"),
    ("MaxClockSkew", MAX_CLOCK_SKEW_MINUTES, "minutes"),
)


def _evaluate_34(document: Document, spec: Spec) -> CheckResult:
    head = _rows(document, "domain_head")[0]
    guid = _first_enabled_gpo(document, (head,))
    if guid is None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.NOT_COLLECTED,
            note="the domain head links no enabled GPO",
        )
    section = document.files.get("gpttmpl")
    if section is None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ERROR,
            note="the collector did not read the GPO templates",
        )
    values: dict[str, str] = {}
    for item in section.items:
        if not isinstance(item, GptTmplItem):
            continue
        if item.section.strip().lower() != "kerberos policy":
            continue
        if _guid_text(item.gpo) != guid:
            continue
        values[item.key] = item.value
    refused = _refused_result(spec, section, "GPO templates")
    if not values:
        if refused is not None:
            return refused
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.NOT_COLLECTED,
            note=(
                "no Kerberos policy was read from the GPO the domain head "
                "links"
            ),
        )
    missing = [name for name in KERBEROS_SETTINGS if name not in values]
    note = (
        "the Kerberos policy of the GPO the domain head links: "
        + ", ".join(
            f"{name} {values[name]}" for name in KERBEROS_SETTINGS if name in values
        )
    )
    if missing:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.NOT_COLLECTED,
            note=note + "; the policy does not carry every setting Newton reads",
        )
    findings: list[Finding] = []
    for name, limit, unit in KERBEROS_LIMITS:
        text = values[name].strip()
        if not text.isdigit():
            return _result(
                spec,
                Status.UNKNOWN,
                reason=UnknownReason.NOT_COLLECTED,
                note=(
                    f"{note}; the setting {name} is not a number, so it "
                    "cannot be judged"
                ),
            )
        value = int(text)
        if value <= limit:
            continue
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title=f"The Kerberos policy allows more than {limit} {unit}",
                objects=(
                    Affected(
                        evidence=(
                            f"the setting {name} of the Kerberos policy is "
                            f"{value} {unit}, so a ticket may live longer than "
                            f"the {limit} {unit} the policy should allow"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    if findings:
        # A policy that was read and is weak is a finding, whatever the
        # collector refused or skipped.
        return _result(
            spec,
            Status.FINDING,
            note=note,
            findings=tuple(findings),
        )
    if refused is not None:
        return refused
    return _result(
        spec,
        Status.PASS,
        note=note,
    )


# ---- AD-A-35: the fine-grained password policies ---------------------------

_SPEC_35 = Spec(
    id="AD-A-35",
    title="Fine-grained password policies",
    severity=Severity.MEDIUM,
    maps_to=("MS FGPP",),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Raise the minimum password length of every fine-grained "
                "password policy and give it a lockout threshold: set the "
                "minimum password length and the lockout threshold of each "
                "policy with the fine-grained password policy cmdlet of the "
                "Active Directory module."
            ),
            commands=(),
            changes=(
                "every fine-grained password policy: the minimum password "
                "length and the lockout threshold"
            ),
            revert=(
                "run the same cmdlet with the values each policy had before "
                "the change"
            ),
        ),
        samba=FixStep(
            summary=(
                "Raise the minimum password length of every fine-grained "
                "password policy and give it a lockout threshold: set the "
                "minimum password length and the lockout threshold of each "
                "policy with the password settings tooling of the Samba "
                "tools."
            ),
            commands=(),
            changes=(
                "the fine-grained password policy named in the envelope: the "
                "minimum password length and the lockout threshold"
            ),
            revert=(
                "run the same command with the values the policy had before "
                "the change"
            ),
        ),
    ),
)


def _evaluate_35(document: Document, spec: Spec) -> CheckResult:
    findings: list[Finding] = []
    notes: list[str] = []
    for row in _rows(document, "psos"):
        minimum = _number(row, "msDS-MinimumPasswordLength")
        threshold = _number(row, "msDS-LockoutThreshold")
        precedence = _number(row, "msDS-PasswordSettingsPrecedence")
        applies = _text(row, "msDS-PSOAppliesTo")
        weak: list[str] = []
        if minimum is None or minimum < MIN_PASSWORD_LENGTH_FLOOR:
            weak.append(
                "the minimum password length is "
                f"{minimum if minimum is not None else 'unknown'}"
            )
        if threshold is None or threshold < LOCKOUT_THRESHOLD_FLOOR:
            weak.append(
                "the lockout threshold is "
                f"{threshold if threshold is not None else 'unknown'}"
            )
        notes.append(f"a fine-grained password policy with precedence {precedence}")
        if not weak:
            continue
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="A fine-grained password policy is weaker than the domain policy",
                objects=(
                    Affected(
                        dn=row.dn,
                        evidence="; ".join(weak),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
        if applies:
            notes.append(f"it applies to {applies}")
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note="; ".join(notes) if notes else "no fine-grained password policy was read",
        findings=tuple(findings),
    )


# ---- AD-A-36, AD-A-37 and AD-A-38: the configured protocols ----------------

# The settings of the collector host that each check reads (SPEC-1.3
# section 7).  The name is the tail of the registry key the collector
# reports.
LDAP_SIGNING_SETTING = "LDAPServerIntegrity"
CHANNEL_BINDING_SETTING = "LdapEnforceChannelBinding"


@dataclass(frozen=True)
class NtlmSetting:
    """One NTLM setting of the collector host and the state that is good.

    ``floor`` is the value the setting must reach, ``exact`` the value
    it must have, ``presence`` says that the setting is read as a
    presence and not as a number, and ``absent_is_good`` says that the
    registry holds no value of the setting and that this is the good
    state.
    """

    name: str
    floor: int | None = None
    exact: int | None = None
    presence: bool = False
    absent_is_good: bool = False
    why: str = ""


# The NTLM settings AD-A-38 reads, and the state that is good for each
# one.  Every setting is judged on its own: a setting that was read is
# judged, a setting the collector could not read is UNKNOWN for that
# setting alone.
NTLM_SETTINGS: tuple[NtlmSetting, ...] = (
    NtlmSetting(
        name="LmCompatibilityLevel",
        floor=LM_COMPATIBILITY_NTLMV2_ONLY,
        why=(
            "the LM compatibility level is below 5, so the host answers "
            "with LM and NTLMv1"
        ),
    ),
    NtlmSetting(
        name="NoLMHash",
        exact=1,
        why="the LM hash of the password is still stored",
    ),
    NtlmSetting(
        name="RestrictAnonymous",
        why="the anonymous access is restricted",
    ),
    NtlmSetting(
        name="RestrictSendingNTLMTraffic",
        floor=2,
        why=(
            "the NTLM traffic to the outside of the domain is not denied "
            "outright"
        ),
    ),
    NtlmSetting(
        name="RestrictReceivingNTLMTraffic",
        floor=2,
        why=(
            "the NTLM traffic from the outside of the domain is not denied "
            "outright"
        ),
    ),
    NtlmSetting(
        name="RestrictNTLMInDomain",
        floor=1,
        why="the NTLM traffic inside the domain is not restricted",
    ),
    NtlmSetting(
        name="FullSecureChannelProtection",
        floor=1,
        why=(
            "the secure channel of the domain controller is not protected "
            "against the Zerologon attack"
        ),
    ),
    NtlmSetting(
        name="VulnerableChannelAllowList",
        presence=True,
        absent_is_good=True,
        why=(
            "the registry holds an allow list of the vulnerable channels, so "
            "NTLM may still be used with them"
        ),
    ),
)


def _host_setting(document: Document, name: str) -> tuple[str | None, str]:
    """The value of a setting of the collector host and the status of the read.

    The status is "ok" when the collector read the value and
    "unavailable" when the registry holds no value of the setting; any
    other status is the status of the item, and the collector could
    not read the value.
    """
    for item in document.settings.items:
        if item.key.lower().endswith(name.lower()):
            if item.status == "ok":
                return item.value, "ok"
            return None, item.status
    return None, "not_collected"


def _gpo_setting(document: Document, name: str, linked: list[str]) -> list[str]:
    """The values the GPO templates of the linked GPOs give the setting.

    Only the GPOs that are linked at the unit of the domain
    controllers count: a GPO that is linked somewhere else does not
    configure the domain controllers.
    """
    section = document.files.get("gpttmpl")
    if section is None:
        return []
    found: list[str] = []
    for item in section.items:
        if not isinstance(item, GptTmplItem):
            continue
        if item.section.strip().lower() != "registry values":
            continue
        guid = _guid_text(item.gpo)
        if guid is None or guid not in linked:
            continue
        if item.key.lower().endswith(name.lower()):
            found.append(item.value)
    return found


def _effective_values(
    document: Document,
    name: str,
    linked: list[str],
) -> tuple[list[str], str]:
    """The effective values of a setting and the status of the read.

    The value of the registry of the collector host wins when it is
    there: it is the setting the domain controller really uses.  The
    GPOs that are linked at the unit of the domain controllers
    configure it otherwise.
    """
    value, status = _host_setting(document, name)
    if status == "ok":
        return [value], "ok"
    found = _gpo_setting(document, name, linked)
    if found:
        return found, "ok"
    return [], status


def _protocol_note(values: dict[str, list[str]]) -> str:
    """The note of a protocol check: what is configured."""
    parts = []
    for name, found in values.items():
        parts.append(f"{name} {' '.join(found)}".strip())
    return CONFIGURED_LABEL + ". " + "; ".join(parts)


def _is_weak(setting: NtlmSetting, value: str) -> bool | None:
    """True when the value is weak, None when it is not a number."""
    if setting.presence:
        return bool(value.strip())
    text = value.strip()
    if not text.isdigit():
        return None
    number = int(text)
    if setting.exact is not None:
        return number != setting.exact
    if setting.floor is not None:
        return number < setting.floor
    return False


def _settings_status(document: Document) -> tuple[bool, UnknownReason, str]:
    """Whether the settings of the host were read at all."""
    if document.settings.status == "ok":
        return True, UnknownReason.NOT_COLLECTED, ""
    return (
        False,
        _reason_for_status(document.settings.status),
        "the collector did not read the settings of the host",
    )


def _missing_note(name: str, status: str) -> str:
    """The note of a setting the collector did not read a value of."""
    if status == "unavailable":
        return (
            f"the registry of the collector host holds no value of the "
            f"setting {name} and no GPO sets it"
        )
    return f"the collector did not read the setting {name}"


def _minimum_setting_result(
    spec: Spec,
    document: Document,
    name: str,
    floor: int,
    linked: list[str],
    *,
    title: str,
    why: str,
) -> CheckResult:
    """The result of a check that reads one setting with a minimum.

    The setting is judged on its effective value: the value of the
    registry of the collector host when it is there, the value of the
    GPOs that are linked at the unit of the domain controllers
    otherwise.  A value that was not read leaves the setting unknown.
    """
    read, reason, note = _settings_status(document)
    if not read:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=reason,
            note=f"{CONFIGURED_LABEL}. {note}",
        )
    values, status = _effective_values(document, name, linked)
    if status != "ok":
        return _result(
            spec,
            Status.UNKNOWN,
            reason=_reason_for_status(status),
            note=f"{CONFIGURED_LABEL}. {_missing_note(name, status)}",
        )
    weak: list[str] = []
    for value in values:
        text = value.strip()
        if not text.isdigit():
            return _result(
                spec,
                Status.UNKNOWN,
                reason=UnknownReason.NOT_COLLECTED,
                note=(
                    f"{CONFIGURED_LABEL}. the value of {name} is not a number, "
                    "so it cannot be judged"
                ),
            )
        if int(text) < floor:
            weak.append(text)
    note = _protocol_note({name: values})
    if not weak:
        refused = _refused_result(spec, document.files.get("gpttmpl"), "GPO templates")
        if refused is not None:
            return refused
        return _result(spec, Status.PASS, note=note)
    return _result(
        spec,
        Status.FINDING,
        note=note,
        findings=tuple(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title=title,
                objects=(
                    Affected(
                        evidence=(
                            f"the configured value of {name} on the collector "
                            f"host is {value}, so {why}"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
            for value in weak
        ),
    )


_SPEC_36 = Spec(
    id="AD-A-36",
    title="LDAP signing is enforced",
    severity=Severity.HIGH,
    maps_to=("MS KB935834", "ADV190023", "KB4520412"),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Require every LDAP bind on the collector host to be signed: "
                "set the registry value "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
                "\\LDAPServerIntegrity to the DWORD 2, then restart the NTDS "
                "service on the domain controller."
            ),
            commands=(),
            changes=(
                "the signing requirement of the LDAP service of the collector "
                "host: the registry value LDAPServerIntegrity becomes 2"
            ),
            revert=(
                "remove the LDAPServerIntegrity value of the NTDS parameters "
                "key, or set it back to the value it had, and restart the "
                "NTDS service"
            ),
        ),
        samba=FixStep(
            summary=(
                "Require every LDAP bind to be signed: set the parameter "
                "'ldap server require strong auth' to yes in smb.conf, then "
                "restart the Samba service."
            ),
            commands=(),
            changes=(
                "the value of the strong authentication requirement of the "
                "Samba LDAP server"
            ),
            revert=(
                "put the value the parameter had before the change back into "
                "smb.conf and restart the Samba service"
            ),
        ),
    ),
)


def _evaluate_36(document: Document, spec: Spec) -> CheckResult:
    return _minimum_setting_result(
        spec,
        document,
        LDAP_SIGNING_SETTING,
        LDAP_SIGNING_REQUIRED,
        _dc_ou_gpos(document),
        title="The LDAP service of the collector host does not require signing",
        why="a bind that is not signed is accepted",
    )


_SPEC_37 = Spec(
    id="AD-A-37",
    title="LDAP channel binding is enforced",
    severity=Severity.HIGH,
    maps_to=("ADV190023", "KB4520412"),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Require channel binding on every LDAP bind of the collector "
                "host: set the registry value "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
                "\\LdapEnforceChannelBinding to the DWORD 1, then restart the "
                "NTDS service on the domain controller."
            ),
            commands=(),
            changes=(
                "the channel binding requirement of the LDAP service of the "
                "collector host: the registry value LdapEnforceChannelBinding "
                "becomes 1"
            ),
            revert=(
                "remove the LdapEnforceChannelBinding value of the NTDS "
                "parameters key, or set it back to the value it had, and "
                "restart the NTDS service"
            ),
        ),
        samba=FixStep(
            summary=(
                "Samba does not implement LDAP channel binding; there is "
                "nothing to change on this platform."
            ),
            commands=(),
            changes="nothing",
            revert="nothing to revert",
        ),
    ),
)


def _evaluate_37(document: Document, spec: Spec) -> CheckResult:
    return _minimum_setting_result(
        spec,
        document,
        CHANNEL_BINDING_SETTING,
        CHANNEL_BINDING_ENFORCED,
        _dc_ou_gpos(document),
        title=(
            "The LDAP service of the collector host does not enforce channel "
            "binding"
        ),
        why="a bind without a channel binding is accepted",
    )


_SPEC_38 = Spec(
    id="AD-A-38",
    title="NTLM is restricted",
    severity=Severity.MEDIUM,
    maps_to=("MS Restrict NTLM settings",),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Turn the NTLM restrictions on: no LM hash, NTLMv2 answers "
                "only, no NTLM to or from outside the domain, and no "
                "vulnerable channels. The values are registry values of the "
                "collector host, so set them under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa and "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters, "
                "then restart the domain controller."
            ),
            commands=(),
            changes=(
                "the NTLM restrictions of the collector host: the LM hash "
                "storage, the LM compatibility level and the sending and "
                "receiving restrictions"
            ),
            revert=(
                "put the values the keys had before the change back, or "
                "remove the values the collector did not find"
            ),
        ),
        samba=FixStep(
            summary=(
                "Restrict NTLM on the Samba server: set the parameter "
                "'ntlm auth' to 'ntlmv2-only' in smb.conf, then restart the "
                "Samba service."
            ),
            commands=(),
            changes=(
                "the value of the NTLM authentication requirement of the Samba "
                "server"
            ),
            revert=(
                "put the value the parameter had before the change back into "
                "smb.conf and restart the Samba service"
            ),
        ),
    ),
)


def _evaluate_38(document: Document, spec: Spec) -> CheckResult:
    read, reason, note = _settings_status(document)
    if not read:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=reason,
            note=f"{CONFIGURED_LABEL}. {note}",
        )
    linked = _dc_ou_gpos(document)
    findings: list[Finding] = []
    values: dict[str, list[str]] = {}
    absent: list[str] = []
    unread: list[str] = []
    unread_reason: UnknownReason = UnknownReason.NOT_COLLECTED
    for setting in NTLM_SETTINGS:
        found, status = _effective_values(document, setting.name, linked)
        if status != "ok":
            if setting.absent_is_good and status == "unavailable":
                # The registry holds no value of the setting: this is the
                # good state for the allow list of the vulnerable
                # channels, and the setting is fine.
                values[setting.name] = []
                continue
            if status == "unavailable":
                absent.append(setting.name)
            else:
                unread.append(setting.name)
                unread_reason = _reason_for_status(status)
            continue
        weak: list[str] = []
        unread_value = False
        for value in found:
            verdict = _is_weak(setting, value)
            if verdict is None:
                unread_value = True
                break
            if verdict:
                weak.append(value.strip())
        if unread_value:
            unread.append(setting.name)
            unread_reason = UnknownReason.NOT_COLLECTED
            continue
        values[setting.name] = found
        for value in weak:
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="The NTLM restrictions of the collector host are not on",
                    objects=(
                        Affected(
                            evidence=(
                                f"the configured value of {setting.name} on the "
                                f"collector host is {value}, so {setting.why}"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=spec.fix,
                )
            )
    note = _protocol_note(values)
    if absent:
        note = f"{note}; the registry holds no value of: {', '.join(absent)}"
    if unread:
        note = f"{note}; the collector did not read: {', '.join(unread)}"
    if findings:
        return _result(
            spec,
            Status.FINDING,
            note=note,
            findings=tuple(findings),
        )
    if absent or unread:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=unread_reason if unread else UnknownReason.UNAVAILABLE,
            note=note,
        )
    refused = _refused_result(spec, document.files.get("gpttmpl"), "GPO templates")
    if refused is not None:
        return refused
    return _result(spec, Status.PASS, note=note)


# ---- AD-A-43: the dSHeuristics of the directory service --------------------

_SPEC_43 = Spec(
    id="AD-A-43",
    title="Anonymous LDAP and the dSHeuristics of the directory service",
    severity=Severity.MEDIUM,
    maps_to=("MS-ADTS 7.1.1.2.4.1.2", "ANSSI (unverified)"),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Block the anonymous operations of the directory service: "
                "the dSHeuristics attribute of the Directory Service object of "
                "the configuration naming context holds a 2 at position 7, and "
                "a 2 allows them. Set that position to 1, or to 0, which is "
                "the default and blocks them as well, and leave the other "
                "positions the value they have. A directory service that "
                "hides the objects that are not needed from a list holds a 1 "
                "at position 3; that is hardening and not the default."
            ),
            commands=(),
            changes=(
                "the dSHeuristics attribute of the directory service object of "
                "the configuration naming context: the character at position 7"
            ),
            revert=(
                "set the attribute back to the value it had before the change"
            ),
        ),
        samba=FixStep(
            summary=(
                "Block the anonymous operations of the directory service: "
                "the dSHeuristics attribute of the Directory Service object of "
                "the configuration naming context holds a 2 at position 7, and "
                "a 2 allows them. Set that position to 1, or to 0, which is "
                "the default and blocks them as well, and leave the other "
                "positions the value they have. A directory service that "
                "hides the objects that are not needed from a list holds a 1 "
                "at position 3; that is hardening and not the default."
            ),
            commands=(),
            changes=(
                "the dSHeuristics attribute of the directory service object of "
                "the configuration naming context: the character at position 7"
            ),
            revert=(
                "set the attribute back to the value it had before the change"
            ),
        ),
    ),
)


def _evaluate_43(document: Document, spec: Spec) -> CheckResult:
    row = _rows(document, "dir_service")[0]
    text = _text(row, "dSHeuristics")
    positions: dict[int, int] = {}
    if text is not None:
        try:
            positions = ds_heuristics_positions(text)
        except ValueError:
            return _result(
                spec,
                Status.UNKNOWN,
                reason=UnknownReason.ERROR,
                note="the dSHeuristics attribute is not a string of hex digits",
            )
    findings: list[Finding] = []
    # The heuristic of the anonymous operations is the seventh
    # character (MS-ADTS 7.1.1.2.4.1.2).  A 2 there allows the
    # anonymous operations; every other value, the absence of the
    # attribute included, is the default and blocks them.
    anonymous = positions.get(DS_HEURISTICS_BLOCK_ANONYMOUS_OPS, 0)
    if anonymous == 2:
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="The directory service allows the anonymous operations",
                objects=(
                    Affected(
                        dn=row.dn,
                        evidence=(
                            "the heuristic at position "
                            f"{DS_HEURISTICS_BLOCK_ANONYMOUS_OPS} is 2, so an "
                            "anonymous bind may enumerate the directory"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    # The heuristic that hides the objects that are not needed from a
    # list is off by default: it is hardening, so it is noted and not
    # judged.
    for position in (DS_HEURISTICS_ADMINSD_MASK, DS_HEURISTICS_ADMINSD_EXCLUDE):
        if position not in positions:
            continue
        if positions[position] == 1:
            continue
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title=(
                    "The heuristic that protects the AdminSDHolder objects is "
                    "not set"
                ),
                objects=(
                    Affected(
                        dn=row.dn,
                        evidence=(
                            f"the heuristic at position {position} is "
                            f"{positions[position]} and not 1, so the objects "
                            "of the AdminSDHolder are not protected the way "
                            "the domain should protect them"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    read_positions = {
        DS_HEURISTICS_LIST_OBJECT,
        DS_HEURISTICS_BLOCK_ANONYMOUS_OPS,
        DS_HEURISTICS_ADMINSD_MASK,
        DS_HEURISTICS_ADMINSD_EXCLUDE,
    }
    unknown = {
        index: value
        for index, value in positions.items()
        if value and index not in read_positions
    }
    note = (
        "the heuristics of the directory service: the anonymous operations "
        f"{'allowed' if anonymous == 2 else 'blocked'}, "
        "the list object "
        f"{'hidden' if positions.get(DS_HEURISTICS_LIST_OBJECT) else 'not hidden'}"
    )
    if not text:
        note = (
            "the directory service carries no dSHeuristics, so the defaults "
            "apply; " + note
        )
    if unknown:
        note += "; the positions Newton does not read: " + ", ".join(
            f"{index} is {value}" for index, value in sorted(unknown.items())
        )
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note=note,
        findings=tuple(findings),
    )


# ---- AD-A-44: the machine account quota ------------------------------------

_SPEC_44 = Spec(
    id="AD-A-44",
    title="The machine account quota of the domain",
    severity=Severity.MEDIUM,
    maps_to=("MS KB5020276", "SpecterOps"),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Stop the domain from letting an ordinary account join a "
                "computer: set the ms-DS-MachineAccountQuota attribute of the "
                "domain object to 0 with Set-ADObject, naming the domain by "
                "its SID."
            ),
            commands=(),
            changes="the machine account quota of the domain",
            revert=(
                "run the same command with the quota the domain had before the "
                "change"
            ),
        ),
        samba=FixStep(
            summary="Stop the domain from letting an ordinary account join a computer.",
            commands=(
                "ldbmodify -H /var/lib/samba/private/sam.ldb <<'LDIF'\n"
                "dn: <SID={sid}>\n"
                "changetype: modify\n"
                "replace: ms-DS-MachineAccountQuota\n"
                "ms-DS-MachineAccountQuota: 0\n"
                "LDIF",
            ),
            changes="the machine account quota of the domain",
            revert=(
                "run the same command with the quota the domain had before the "
                "change"
            ),
        ),
    ),
)


def _evaluate_44(document: Document, spec: Spec) -> CheckResult:
    head = _rows(document, "domain_head")[0]
    quota = _number(head, "ms-DS-MachineAccountQuota")
    if quota is None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.NOT_COLLECTED,
            note="the domain head did not carry the machine account quota",
        )
    if quota <= 0:
        return _result(
            spec,
            Status.PASS,
            note=f"the machine account quota of the domain is {quota}",
        )
    return _result(
        spec,
        Status.FINDING,
        note=f"the machine account quota of the domain is {quota}",
        findings=(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="The domain lets an ordinary account join a computer",
                objects=(
                    Affected(
                        sid=_sid_of(head),
                        dn=head.dn,
                        evidence=(
                            f"the machine account quota of the domain is {quota}, "
                            "so an ordinary account may join that many computers"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            ),
        ),
    )


# ---- AD-A-45: the functional levels and the optional features -------------

_SPEC_45 = Spec(
    id="AD-A-45",
    title="Functional levels and optional features",
    severity=Severity.MEDIUM,
    maps_to=("MS functional-levels doc",),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Raise the functional level of the domain to Windows Server "
                "2016 or higher with Set-ADObject, naming the domain by its "
                "SID, and enable the Recycle Bin optional feature of the "
                "forest with the optional-feature tooling of the Active "
                "Directory module."
            ),
            commands=(),
            changes=(
                "the functional level of the domain and of the configuration "
                "set, and the enabled optional features of the forest"
            ),
            revert=(
                "a functional level cannot be lowered again: take a backup of "
                "the forest before the change"
            ),
        ),
        samba=FixStep(
            summary=(
                "Raise the functional level of the domain to Windows Server "
                "2016 or higher with the domain passwordsettings and the "
                "functional level tooling of the Samba tools."
            ),
            commands=(),
            changes=(
                "the functional level of the domain and of the configuration "
                "set"
            ),
            revert=(
                "a functional level cannot be lowered again: take a backup of "
                "the domain before the change"
            ),
        ),
    ),
)


def _evaluate_45(document: Document, spec: Spec) -> CheckResult:
    head = _rows(document, "domain_head")[0]
    partitions = _rows(document, "partitions")[0]
    schema = _rows(document, "schema_head")[0]
    domain_level = _number(head, "msDS-Behavior-Version")
    partition_level = _number(partitions, "msDS-Behavior-Version")
    schema_version = _number(schema, "objectVersion")
    if domain_level is None or partition_level is None or schema_version is None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.NOT_COLLECTED,
            note=(
                "the functional level of the domain or of the configuration "
                "set was not read"
            ),
        )
    findings: list[Finding] = []
    for level, name, where in (
        (domain_level, "the domain", "the domain head"),
        (partition_level, "the configuration set", "the partitions object"),
    ):
        if level >= FUNCTIONAL_LEVEL_2016:
            continue
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title=f"The functional level of {name} is below Windows Server 2016",
                objects=(
                    Affected(
                        sid=_sid_of(head) if where == "the domain head" else None,
                        dn=head.dn if where == "the domain head" else partitions.dn,
                        evidence=(
                            f"the functional level of {name} is {level} "
                            f"({functional_level_name(level)}), below the level "
                            f"{FUNCTIONAL_LEVEL_2016} "
                            f"({functional_level_name(FUNCTIONAL_LEVEL_2016)})"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    recycle_bin = "not enabled"
    other: list[str] = []
    enabled_rows = 0
    for row in _rows(document, "optional_features"):
        enabled = row.a.get("msDS-EnabledFeatureBL")
        name = row.dn.split(",", 1)[0]
        if enabled:
            enabled_rows += 1
            if "Recycle Bin" in name:
                recycle_bin = f"enabled in {len(enabled)} places"
            else:
                other.append(f"{name} enabled in {len(enabled)} places")
        elif "Recycle Bin" in name:
            recycle_bin = "not enabled"
    if recycle_bin == "not enabled":
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="The Recycle Bin of the forest is not enabled",
                objects=(
                    Affected(
                        evidence=(
                            "the optional features of the forest do not enable "
                            "the Recycle Bin, so a deleted object is gone for "
                            "good"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    note = (
        "the functional level of the domain is "
        f"{functional_level_name(domain_level)}, of the configuration set "
        f"{functional_level_name(partition_level)}, the schema is at object "
        f"version {schema_version}; the Recycle Bin is {recycle_bin}"
    )
    if other:
        note += "; " + "; ".join(other)
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note=note,
        findings=tuple(findings),
    )


# ---- AD-A-46: the LAPS deployment ------------------------------------------

# The attributes that carry the time a LAPS password expires.  They
# carry a time, never a password.
LAPS_EXPIRATION_ATTRIBUTES = (
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
)

_SPEC_46 = Spec(
    id="AD-A-46",
    title="LAPS is deployed",
    severity=Severity.MEDIUM,
    maps_to=("MS LAPS",),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Extend the schema with the LAPS attributes and turn LAPS on "
                "for the domain controllers: add the attribute ms-Mcs-AdmPwd "
                "(octetString) and the attribute ms-Mcs-AdmPwdExpirationTime "
                "(LargeInteger) to the schema of the configuration naming "
                "context with the schema tooling of the Active Directory "
                "module, then turn LAPS on in the domain controller policy."
            ),
            commands=(),
            changes=(
                "the schema of the directory: the two LAPS attributes are "
                "added to it, and the domain controller policy then turns LAPS "
                "on"
            ),
            revert=(
                "remove the two attributes from the schema again and turn LAPS "
                "off in the domain controller policy"
            ),
        ),
        samba=FixStep(
            summary=(
                "Samba does not implement LAPS; there is nothing to change on "
                "this platform."
            ),
            commands=(),
            changes="nothing",
            revert="nothing to revert",
        ),
    ),
)


def _evaluate_46(document: Document, spec: Spec) -> CheckResult:
    schema_rows = _rows(document, "schema_laps")
    names = sorted(
        {
            _text(row, "lDAPDisplayName") or ""
            for row in schema_rows
            if _text(row, "lDAPDisplayName")
        }
    )
    expiry: list[str] = []
    for row in _rows(document, "computers"):
        for attribute in LAPS_EXPIRATION_ATTRIBUTES:
            if row.a.get(attribute):
                expiry.append(row.dn)
                break
    findings: list[Finding] = []
    if not names:
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="The schema does not carry the LAPS attributes",
                objects=(
                    Affected(
                        dn=document.domain.schema_dn,
                        evidence=(
                            "the schema holds none of the LAPS attributes, so "
                            "the directory cannot hold a LAPS password"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    if not expiry:
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title="No computer account carries a LAPS expiration time",
                objects=(
                    Affected(
                        evidence=(
                            "none of the computer accounts carries the time a "
                            "LAPS password expires"
                        ),
                    ),
                ),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    note = (
        "the LAPS attributes of the schema: "
        + (", ".join(names) if names else "none")
        + f"; the computer accounts that carry a LAPS expiration time: {len(expiry)}"
    )
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note=note,
        findings=tuple(findings),
    )


# ---- AD-A-48: the trusts ----------------------------------------------------

_SPEC_48 = Spec(
    id="AD-A-48",
    title="Trusts of the domain",
    severity=Severity.HIGH,
    maps_to=("MS trust design", "ATT&CK T1134.005"),
)


def _trust_sid(row: Row) -> str | None:
    """The SID of a trust object, when the document carries one."""
    for value in row.a.get("securityIdentifier", ()):
        try:
            return sid_from_base64(value)
        except ValueError:
            continue
    return None


def _trust_fix(attributes: int) -> Fix:
    """The fix of a trust that does not filter the SIDs of its partner.

    The trust attributes of the object are changed by the owner: no
    documented cmdlet changes them, and the value that is written would
    be a number that came out of the directory.  The summary says which
    attribute to set and to which value, and the owner applies it.
    """
    return Fix(
        windows=FixStep(
            summary=(
                "Make the trust filter the SIDs of the other domain: set the "
                "trustAttributes attribute of the trusted domain object to "
                f"{attributes}, the quarantined-domain bit among them, so "
                "the SIDs of the other domain are filtered."
            ),
            commands=(),
            changes="the trustAttributes of the trust object",
            revert=(
                "put the value the attribute had before the change back"
            ),
        ),
        samba=FixStep(
            summary=(
                "Make the trust filter the SIDs of the other domain: set the "
                "trustAttributes attribute of the trusted domain object to "
                f"{attributes}, the quarantined-domain bit among them, so "
                "the SIDs of the other domain are filtered."
            ),
            commands=(),
            changes="the trustAttributes of the trust object",
            revert=(
                "put the value the attribute had before the change back"
            ),
        ),
    )


def _evaluate_48(document: Document, spec: Spec) -> CheckResult:
    rows = _rows(document, "trusts")
    findings: list[Finding] = []
    notes: list[str] = []
    for row in rows:
        partner = _text(row, "trustPartner") or "a partner the audit cannot name"
        attributes = _number(row, "trustAttributes")
        direction = _number(row, "trustDirection")
        kind = _number(row, "trustType")
        if attributes is None:
            return _result(
                spec,
                Status.UNKNOWN,
                reason=UnknownReason.NOT_COLLECTED,
                note=(
                    f"the trust with the partner {partner} carries no "
                    "trustAttributes, so the protections it holds cannot be "
                    "read"
                ),
            )
        flags = trust_attribute_names(attributes)
        notes.append(
            f"a trust with the partner {partner}, direction {direction}, "
            f"type {kind}, attributes {', '.join(flags) if flags else 'none'}"
        )
        quarantined = bool(attributes & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)
        within_forest = bool(attributes & TRUST_ATTRIBUTE_WITHIN_FOREST)
        forest_transitive = bool(attributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE)
        treat_as_external = bool(attributes & TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL)
        if (forest_transitive or not within_forest) and not quarantined:
            if not within_forest:
                notes.append(
                    "a trust that is not inside the forest does not filter the "
                    "SIDs of the other domain"
                )
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A trust does not filter the SIDs of the other domain",
                    objects=(
                        Affected(
                            sid=_trust_sid(row),
                            evidence=(
                                "the trust does not carry the attribute that "
                                "quarantines the domain, so a principal of the "
                                "other domain may be a principal of this one"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_trust_fix(
                        attributes | TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
                    ),
                )
            )
        if treat_as_external and forest_transitive:
            notes.append(
                "a forest trust treats the other domain as external, so the "
                "identifiers of the forest are filtered as well"
            )
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A forest trust treats the other domain as external",
                    objects=(
                        Affected(
                            sid=_trust_sid(row),
                            evidence=(
                                "the trust is a forest trust and treats the "
                                "other domain as external, so the "
                                "identifiers of the forest are filtered where "
                                "they must not be"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=_trust_fix(attributes & ~TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL),
                )
            )
    if not rows:
        notes.append("the domain has no trust")
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note="; ".join(notes),
        findings=tuple(findings),
    )


# ---- AD-A-55: the SYSVOL content -------------------------------------------

_SPEC_55 = Spec(
    id="AD-A-55",
    title="SYSVOL holds a credential",
    severity=Severity.HIGH,
    maps_to=("MS14-025", "ATT&CK T1552.006"),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Take the cpassword item out of the group policy file: open "
                "the GPO in the group policy editor, remove the preference "
                "that carries the credential from the groups file, and save "
                "the GPO."
            ),
            commands=(),
            changes=(
                "the group preference file of the GPO: the file that holds the "
                "cpassword item loses the item"
            ),
            revert=(
                "restore the file from the backup of the GPO, or from the "
                "versioned copy the GPO keeps"
            ),
        ),
        samba=FixStep(
            summary=(
                "Take the cpassword item out of the group policy file: open "
                "the SYSVOL folder of the GPO, remove the preference that "
                "carries the credential from the groups file, and let the "
                "domain controllers replicate the change."
            ),
            commands=(),
            changes=(
                "the group preference file of the GPO: the file that holds the "
                "cpassword item loses the item"
            ),
            revert=(
                "restore the file from the backup of the GPO, or from the "
                "versioned copy the GPO keeps"
            ),
        ),
    ),
)


def _evaluate_55(document: Document, spec: Spec) -> CheckResult:
    section = document.files.get("gpp")
    if section is None:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.ERROR,
            note="the collector did not read the SYSVOL files",
        )
    findings: list[Finding] = []
    for item in section.items:
        if not isinstance(item, GppItem):
            continue
        guid = _guid_text(item.gpo)
        if guid is None:
            continue
        row = _gpo_row_for(document, guid)
        name = _text(row, "displayName") if row is not None else None
        affected = Affected(
            guid=guid,
            name=name,
            dn=row.dn if row is not None else None,
            evidence=(
                f"the SYSVOL file {item.path} of this GPO holds {item.count} "
                f"{item.kind} item"
            ),
        )
        findings.append(
            Finding(
                check_id=spec.id,
                severity=spec.severity,
                title=f"The GPO holds a {item.kind} item in its SYSVOL file",
                objects=(affected,),
                maps_to=spec.maps_to,
                fix=spec.fix,
            )
        )
    if findings:
        return _result(
            spec,
            Status.FINDING,
            note=(
                "the SYSVOL files hold "
                f"{len(section.items)} item(s) that carry a credential"
            ),
            findings=tuple(findings),
        )
    refused = _refused_result(spec, section, "SYSVOL")
    if refused is not None:
        return refused
    return _result(
        spec,
        Status.PASS,
        note="the SYSVOL files hold no credential",
    )


# ---- AD-A-60: the FSMO roles ------------------------------------------------

_SPEC_60 = Spec(
    id="AD-A-60",
    title="The holders of the FSMO roles",
    severity=Severity.MEDIUM,
    maps_to=("MS FSMO",),
    fix=Fix(
        windows=FixStep(
            summary=(
                "Move the role to a domain controller that is one: the cmdlet "
                "takes the name of the target, and the owner picks it."
            ),
            commands=(),
            changes="the holder of the FSMO role",
            revert=(
                "move the role back to the holder it had before the change"
            ),
        ),
        samba=FixStep(
            summary=(
                "Move the role to a domain controller that is one: the cmdlet "
                "takes the name of the target, and the owner picks it."
            ),
            commands=(),
            changes="the holder of the FSMO role",
            revert=(
                "move the role back to the holder it had before the change"
            ),
        ),
    ),
)


def _dc_names(document: Document) -> set[str]:
    """The names of the computer accounts that are domain controllers."""
    names: set[str] = set()
    for row in _rows(document, "computers"):
        if _number(row, "primaryGroupID") != 516:
            continue
        name = _text(row, "sAMAccountName") or ""
        names.add(name.rstrip("$").upper())
    return names


def _evaluate_60(document: Document, spec: Spec) -> CheckResult:
    head = _rows(document, "domain_head")[0]
    holders = head.a.get("fSMORoleOwner", ())
    controllers = _dc_names(document)
    findings: list[Finding] = []
    notes: list[str] = []
    for holder in holders:
        parts = [part.strip() for part in holder.split(",")]
        notes.append(f"a role is held by {holder}")
        if len(parts) < 2 or not parts[0].lower().startswith("cn=ntds settings"):
            continue
        name = parts[1].split("=", 1)[-1].upper()
        if controllers and name not in controllers:
            findings.append(
                Finding(
                    check_id=spec.id,
                    severity=spec.severity,
                    title="A role is held by an object that is not a domain controller",
                    objects=(
                        Affected(
                            evidence=(
                                "the holder of the role is not one of the "
                                "computer accounts that carry the primary group "
                                "of the domain controllers"
                            ),
                        ),
                    ),
                    maps_to=spec.maps_to,
                    fix=spec.fix,
                )
            )
    return _result(
        spec,
        Status.FINDING if findings else Status.PASS,
        note="; ".join(notes) if notes else "the domain head carries no role holder",
        findings=tuple(findings),
    )


# ---- AD-A-67: the operating system of the domain controllers ---------------

_SPEC_67 = Spec(
    id="AD-A-67",
    title="The operating system of the domain controllers",
    severity=Severity.LOW,
    maps_to=("MS Security Update Guide", "Samba advisories"),
)


def _evaluate_67(document: Document, spec: Spec) -> CheckResult:
    notes: list[str] = []
    for row in _rows(document, "computers"):
        if _number(row, "primaryGroupID") != 516:
            continue
        system = _text(row, "operatingSystem") or "an operating system the audit cannot name"
        version = _text(row, "operatingSystemVersion") or "an unknown build"
        notes.append(f"{system}, {version}")
    return _result(
        spec,
        Status.PASS,
        note=(
            "the domain controllers run: " + "; ".join(notes)
            if notes
            else "the document holds no domain controller"
        ),
    )


CHECKS: list[Check] = [
    _make(
        _SPEC_33,
        _evaluate_33,
        queries=("domain_head",),
        required_attrs=("minPwdLength", "lockoutThreshold"),
        sentinels=("domain_head",),
    ),
    _make(
        _SPEC_34,
        _evaluate_34,
        queries=("domain_head",),
        files=("gpttmpl",),
        sentinels=("domain_head",),
    ),
    _make(
        _SPEC_35,
        _evaluate_35,
        queries=("psos",),
        sentinels=(),
    ),
    _make(
        _SPEC_36,
        _evaluate_36,
        queries=("dc_ou", "ous"),
        files=("gpttmpl",),
        sentinels=("dc_ou", "ous"),
    ),
    _make(
        _SPEC_37,
        _evaluate_37,
        queries=("dc_ou", "ous"),
        files=("gpttmpl",),
        sentinels=("dc_ou", "ous"),
    ),
    _make(
        _SPEC_38,
        _evaluate_38,
        queries=("dc_ou", "ous"),
        files=("gpttmpl",),
        sentinels=("dc_ou", "ous"),
    ),
    _make(
        _SPEC_43,
        _evaluate_43,
        queries=("dir_service",),
        sentinels=("dir_service",),
    ),
    _make(
        _SPEC_44,
        _evaluate_44,
        queries=("domain_head",),
        required_attrs=("ms-DS-MachineAccountQuota",),
        sentinels=("domain_head",),
    ),
    _make(
        _SPEC_45,
        _evaluate_45,
        queries=("domain_head", "partitions", "schema_head", "optional_features"),
        sentinels=(
            "domain_head",
            "partitions",
            "schema_head",
            "optional_features",
        ),
    ),
    _make(
        _SPEC_46,
        _evaluate_46,
        queries=("schema_laps", "computers"),
        sentinels=("computers",),
    ),
    _make(
        _SPEC_48,
        _evaluate_48,
        queries=("trusts",),
    ),
    _make(
        _SPEC_55,
        _evaluate_55,
        files=("gpp",),
    ),
    _make(
        _SPEC_60,
        _evaluate_60,
        queries=("domain_head", "computers"),
        sentinels=("domain_head", "computers"),
    ),
    _make(
        _SPEC_67,
        _evaluate_67,
        queries=("computers",),
        sentinels=("computers",),
    ),
]
