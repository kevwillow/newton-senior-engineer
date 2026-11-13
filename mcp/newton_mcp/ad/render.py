"""Render the report for the model (envelope and redaction).

Every directory-originated string a report holds - a distinguished name,
an account name, an SPN, a GPO display name, a trust partner - travels
through the untrusted envelope and through the redactor, so the model
reads it as data and never as an instruction.  The envelope and the
redactor are the ones Newton already has; this module does not write new
ones.

An object the directory gave no name to is shown under the name its
distinguished name holds: the value of the first RDN of that name, with
the escapes decoded.  That name is a directory string like any other: it
travels through the envelope and through the redactor, and it is proven
free of the commands like every other one.

A fix command names the objects by SID or GUID only.  The commands are
templates whose only substitutions are those identifiers, which Newton
formats from the binary value, and ``assert_no_directory_text`` proves
that no directory string ended up inside one of them.  A command that
fails the proof is not rendered: the report is refused rather than
handed over with a directory string in it.
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import envelope as _envelope
from .. import redact as _redact
from .model import Affected, AuditReport, CheckResult, Finding, Fix, FixStep
from .values import canonical_sid, dn_display_name, is_guid, is_sid


# The source of the envelopes of this report.
ENVELOPE_SOURCE = "ad:audit"


# The characters a command uses to quote an argument, plus the quotes a
# shell would read as such.  They are removed from both sides before the
# comparison: a name that is only punctuation is not a false alarm, and
# a name that hides behind quoting is still found.
_QUOTING_CHARACTERS = "'\"`‘’‛“”"


class RenderError(Exception):
    """The report cannot be rendered safely.

    The message never carries any text of the report.
    """


def _without_quoting(text: str) -> str:
    """The text with the quoting characters removed."""
    return "".join(
        char for char in text if char not in _QUOTING_CHARACTERS
    )


def assert_no_directory_text(command: str, strings: Iterable[str]) -> None:
    """Refuse a command that holds a directory string.

    The comparison is a substring test on both sides with the quoting
    characters removed, and it is strict on purpose: a name that is
    short enough to be a part of a SID still stops the command, because
    a false alarm only costs a report and a false command costs a
    domain.
    """
    needle_command = _without_quoting(command)
    for text in strings:
        if not text:
            continue
        needle = _without_quoting(text)
        if not needle:
            # A name that is only punctuation cannot be told apart from
            # the punctuation of a command.
            continue
        if needle in needle_command:
            raise RenderError("the fix command holds a directory string")


def _wrap(text: str) -> dict[str, str]:
    """Put a directory string in the untrusted envelope."""
    result = _envelope.sanitise(
        ENVELOPE_SOURCE,
        text,
        redact=_redact.redact_text,
    )
    return result.envelope


def _is_canonical_sid(text: str | None) -> bool:
    """True when the text is a canonical SID.

    The value of a placeholder has to be the identifier itself, whole:
    a SID that is written in another way, or that ends in a newline, is
    not one.
    """
    if text is None:
        return False
    try:
        return canonical_sid(text) == text
    except ValueError:
        return False


def _substitute(template: str, sid: str | None, guid: str | None) -> str:
    """Fill the placeholders of a command template.

    Only a SID and a GUID are substituted, and only when they are
    canonical: a placeholder that has no value is refused, and a
    placeholder with a value that is not an identifier is refused too.
    """
    command = template
    if "{sid}" in command:
        if sid is None or not _is_canonical_sid(sid):
            raise RenderError("the fix command needs a sid")
        command = command.replace("{sid}", sid)
    if "{guid}" in command:
        if guid is None or not is_guid(guid):
            raise RenderError("the fix command needs a guid")
        command = command.replace("{guid}", guid)
    return command


def _render_step(
    step: FixStep,
    sid: str | None,
    guid: str | None,
) -> dict[str, object]:
    """One platform's fix, with its commands rendered."""
    return {
        "summary": step.summary,
        "commands": tuple(
            _substitute(template, sid, guid) for template in step.commands
        ),
        "changes": step.changes,
        "revert": step.revert,
    }


def _render_fix(
    fix: Fix,
    sid: str | None,
    guid: str | None,
    strings: Iterable[str],
) -> dict[str, object]:
    """The fix of a finding, with every command proven free of text."""
    rendered = {
        "windows": _render_step(fix.windows, sid, guid),
        "samba": _render_step(fix.samba, sid, guid),
    }
    for step in rendered.values():
        for command in step["commands"]:  # type: ignore[index]
            assert_no_directory_text(command, strings)
    return rendered


def _identifiers(finding: Finding) -> tuple[str | None, str | None]:
    """The SID and the GUID a fix names its object by."""
    sid: str | None = None
    guid: str | None = None
    for affected in finding.objects:
        if sid is None and affected.sid:
            sid = affected.sid
        if guid is None and affected.guid:
            guid = affected.guid
    return sid, guid


def _object_name(affected: Affected) -> str | None:
    """The name an object is shown under.

    An object the directory gave a name to keeps it.  An object that
    has only a distinguished name gets the name of the first RDN of
    that name, so the report shows what the object is called.
    """
    if affected.name:
        return affected.name
    if not affected.dn:
        return None
    return dn_display_name(affected.dn)


def _directory_strings(report: AuditReport) -> list[str]:
    """Every directory string the report holds.

    An identifier is not a directory string: a SID and a GUID are
    formatted by Newton from the binary value, and the commands name
    the objects by exactly those.
    """
    strings: list[str] = []
    for result in report.results:
        for finding in result.findings:
            for affected in finding.objects:
                for text in (
                    _object_name(affected),
                    affected.dn,
                    affected.evidence,
                ):
                    if not text:
                        continue
                    if is_sid(text) or is_guid(text):
                        continue
                    strings.append(text)
    return strings


def _render_finding(
    finding: Finding,
    strings: Iterable[str],
) -> dict[str, object]:
    """One finding, with its objects enveloped."""
    sid, guid = _identifiers(finding)
    objects = []
    for affected in finding.objects:
        name = _object_name(affected)
        objects.append(
            {
                "sid": affected.sid,
                "guid": affected.guid,
                "name": _wrap(name) if name else None,
                "dn": _wrap(affected.dn) if affected.dn else None,
                "evidence": (
                    _wrap(affected.evidence) if affected.evidence else None
                ),
            }
        )
    rendered: dict[str, object] = {
        "id": finding.check_id,
        "severity": finding.severity.value,
        "title": _wrap(finding.title),
        "objects": objects,
        "maps_to": list(finding.maps_to),
        "fix": (
            _render_fix(finding.fix, sid, guid, strings)
            if finding.fix is not None
            else None
        ),
    }
    return rendered


def _render_result(result: CheckResult, strings: Iterable[str]) -> dict[str, object]:
    """One check result."""
    return {
        "id": result.check_id,
        "title": result.title,
        "severity": result.severity.value,
        "status": result.status.value,
        "reason": result.reason.value if result.reason is not None else None,
        "note": _wrap(result.note) if result.note else None,
        "maps_to": list(result.maps_to),
        "findings": [
            _render_finding(finding, strings) for finding in result.findings
        ],
    }


def render(report: AuditReport) -> dict[str, object]:
    """Render the report for the model.

    The whole tree goes through the redactor last, so a secret that
    reached a string of the report is redacted wherever it is.
    """
    strings = _directory_strings(report)
    payload: dict[str, object] = {
        "domain": _wrap(report.domain),
        "collector": report.collector,
        "counts": dict(report.counts),
        "generated": report.generated,
        "scope_note": report.scope_note,
        "results": [_render_result(result, strings) for result in report.results],
    }
    return _redact.redact_value(payload)
