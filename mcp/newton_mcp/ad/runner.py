"""The runner and the identity guard (SPEC-1.3 section 8).

The runner turns one validated document into one report.  It never trusts
the document: it proves that the audit was allowed to see the data before
a check runs, and a check that cannot prove PASS is UNKNOWN with the
reason why.

The order of the rules is the order of the trouble they catch:

1. the status of every query and of every file section the check reads; a
   status that is not ``ok`` maps to the reason of the same name;
2. a query an ordinary account may legitimately see empty: empty is
   UNKNOWN(access_denied) with the note "none visible to the audit
   account", never PASS.  A Samba collector reads as root, so an empty
   result there is a real empty;
3. the sentinels: a sentinel that fails means the collector could not
   read what an ordinary read must return, and every check that depends
   on it is UNKNOWN(access_denied).  Every query a check reads declares
   its sentinel, unless an ordinary account may see it empty (rule 2),
   its empty read is the answer (``EMPTY_IS_AN_ANSWER``) or the check
   judges an empty read itself (the list in tests/ad/test_check_reads.py);
4. the required attributes: a readable object without one of them makes
   the check UNKNOWN(access_denied);
5. the check itself.  An exception inside one check is that check's
   UNKNOWN(error) and never stops the audit.

The identity guard runs first, always, whatever the ``checks`` argument
is: Newton computes the audit account's own privileged membership from
the directory data and refuses to audit with a privileged key.  The
guard needs the data it computes the membership from: when the users,
the groups or the fsps did not complete, or when the sentinel of the
users or of the groups failed, the privileged set is partial and the
guard refuses with the reason ``cannot_verify``.

The platform of the inventory is required as well.  A document that
another collector wrote is refused: the rules of the audit are the rules
of the platform.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from . import catalogue, members
from .model import (
    SCOPE_NOTE,
    AuditReport,
    CheckResult,
    Severity,
    Status,
    UnknownReason,
)
from .values import rid_in_domain, sid_from_base64
from .wire import Document, Row


# The message of the identity guard.  It is fixed: the reason is a word
# in the exception, never in the message.
IDENTITY_GUARD_MESSAGE = (
    "this key is a privileged account; Newton refuses to audit with it"
)

# The message of a document that another collector wrote.
COLLECTOR_MISMATCH_MESSAGE = (
    "the document is not the collector of the platform of the inventory"
)

# The message of a platform that is not an AD platform.
PLATFORM_MISMATCH_MESSAGE = "the platform is not an AD platform"

# The collector each platform of the inventory runs.
COLLECTOR_BY_PLATFORM: dict[str, str] = {
    "ad-windows": "windows",
    "ad-samba": "samba",
}

# The queries the identity guard needs: without them the privileged set
# cannot be computed, and the guard may not verify anything.
GUARD_QUERIES = ("users", "groups", "fsps")

# The queries whose sentinel must pass for the guard to verify anything.
GUARD_SENTINELS = ("users", "groups")

# The note of a query an ordinary account may not see.
NOT_VISIBLE_NOTE = "none visible to the audit account"

# The queries an ordinary account may legitimately see empty
# (SPEC-1.3 section 6).  Empty is "could not read", never "nothing
# there"; a Samba collector reads as root, so empty there is real.
MAY_BE_EMPTY: frozenset[str] = frozenset(
    {
        "psos",
        "kds_root_keys",
        "dpapi_backup",
        "gmsa",
        "pw_attr_presence",
        "keycred_presence",
    }
)


# The queries whose empty read is itself the answer: every authenticated
# user may read the trusts and the schema, so no trust and no LAPS
# attribute in the schema are real answers, on both collectors.  Every
# other query a check reads has a sentinel or is in ``MAY_BE_EMPTY``
# (pinned by tests/ad/test_check_reads.py).
EMPTY_IS_AN_ANSWER: frozenset[str] = frozenset({"trusts", "schema_laps"})


class PrivilegedKey(Exception):
    """The key the audit would run with may not audit.

    The message is fixed.  The reason says which rule tripped, and it is
    one of ``rid_500``, ``privileged_member``, ``privileged_token``,
    ``not_in_users`` and ``cannot_verify``.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(IDENTITY_GUARD_MESSAGE)
        self.reason = reason


class CollectorMismatch(Exception):
    """The document is not the one the platform of the inventory runs.

    The message is fixed: it never carries any text of the document.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


def reason_for_status(status: str) -> UnknownReason:
    """The reason a status other than ``ok`` maps to.

    The checks read the same mapping: a query that did not complete
    says the same thing in a check and in the runner.
    """
    return {
        "truncated": UnknownReason.TRUNCATED,
        "denied": UnknownReason.ACCESS_DENIED,
        "unsupported": UnknownReason.UNSUPPORTED,
        "unavailable": UnknownReason.UNAVAILABLE,
        "not_collected": UnknownReason.NOT_COLLECTED,
        "error": UnknownReason.ERROR,
    }.get(status, UnknownReason.ERROR)


def _row_sid(row: Row) -> str | None:
    """The SID of a row, when it has one."""
    for value in row.a.get("objectSid", ()):
        try:
            return sid_from_base64(value)
        except ValueError:
            continue
    return None


def _one_row(rows: tuple[Row, ...], directory: members.Directory) -> bool:
    """The sentinel of a query that must return exactly one row."""
    return len(rows) == 1


def _rows_have_rid(
    rows: tuple[Row, ...],
    directory: members.Directory,
    rid: int,
) -> bool:
    """True when a row carries a SID of this domain with that RID."""
    for row in rows:
        sid = _row_sid(row)
        if sid is None:
            continue
        if rid_in_domain(sid, directory.domain_sid) == rid:
            return True
    return False


def _users_sentinel(rows: tuple[Row, ...], directory: members.Directory) -> bool:
    """The users query must hold RID 500 and RID 502.

    The accounts are found by RID and never by name: a renamed
    Administrator or krbtgt must not degrade the sentinel.
    """
    return _rows_have_rid(rows, directory, 500) and _rows_have_rid(
        rows, directory, 502
    )


def _groups_sentinel(rows: tuple[Row, ...], directory: members.Directory) -> bool:
    """The groups query must hold RID 512 and RID 513."""
    return _rows_have_rid(rows, directory, 512) and _rows_have_rid(
        rows, directory, 513
    )


def _not_empty(rows: tuple[Row, ...], directory: members.Directory) -> bool:
    """The sentinel of a query that always returns at least one row."""
    return len(rows) > 0


def _protected_sds_sentinel(
    rows: tuple[Row, ...],
    directory: members.Directory,
) -> bool:
    """The protected objects must hold RID 500 and RID 512.

    The Administrator and Domain Admins always carry adminCount 1; they
    are found by SID, never by name.
    """
    return _rows_have_rid(rows, directory, 500) and _rows_have_rid(
        rows, directory, 512
    )


def _computers_sentinel(
    rows: tuple[Row, ...],
    directory: members.Directory,
) -> bool:
    """The computers query must hold a row with primaryGroupID 516."""
    for row in rows:
        for value in row.a.get("primaryGroupID", ()):
            try:
                number = int(value)
            except ValueError:
                continue
            if number == 516:
                return True
    return False


# The sentinel of every query that has one.
SENTINELS: dict[str, Callable[[tuple[Row, ...], members.Directory], bool]] = {
    "domain_head": _one_row,
    "users": _users_sentinel,
    "groups": _groups_sentinel,
    "computers": _computers_sentinel,
    "adminsdholder": _one_row,
    "dir_service": _one_row,
    "partitions": _one_row,
    "schema_head": _one_row,
    # The Domain Controllers OU always exists, and it is an OU.
    "dc_ou": _one_row,
    "ous": _not_empty,
    "protected_sds": _protected_sds_sentinel,
    # The well-known foreign principals (S-1-5-4, -9, -11, -17) are made
    # with the domain.
    "fsps": _not_empty,
    # The Recycle Bin Feature object exists in every supported forest.
    "optional_features": _not_empty,
}


def _guard_data_is_complete(
    document: Document,
    directory: members.Directory,
) -> bool:
    """True when the guard has the data it computes the privilege from.

    The privileged set is computed from the users, the groups and the
    fsps of the document.  When one of them did not complete, or when
    the sentinel of the users or of the groups failed, the set is
    partial: a privileged key could pass, so the guard may not verify
    anything.
    """
    for query_id in GUARD_QUERIES:
        result = document.queries.get(query_id)
        if result is None or result.status != "ok":
            return False
    for query_id in GUARD_SENTINELS:
        result = document.queries.get(query_id)
        rule = SENTINELS.get(query_id)
        if result is None or rule is None:
            return False
        if not rule(result.rows, directory):
            return False
    return True


def identity_guard(document: Document, directory: members.Directory) -> None:
    """Refuse to audit with a key that may not audit.

    Newton finds the audit account in ``users`` and computes its own
    recursive privileged membership from the directory data, primary
    group included.  It does not trust the token alone.

    The guard needs the data it works on.  When it does not have it,
    the guard refuses with the reason ``cannot_verify``: a partial
    privileged set is not a verification.
    """
    if not _guard_data_is_complete(document, directory):
        raise PrivilegedKey("cannot_verify")
    sid = document.identity.sid
    if rid_in_domain(sid, directory.domain_sid) == 500:
        raise PrivilegedKey("rid_500")
    if directory.principal(sid) is None:
        raise PrivilegedKey("not_in_users")
    if sid in directory.privileged_set():
        raise PrivilegedKey("privileged_member")
    privileged_groups = directory.privileged_group_sids()
    for token_sid in document.identity.token_group_sids:
        if token_sid in privileged_groups:
            raise PrivilegedKey("privileged_token")


def _unknown(
    check: catalogue.Check,
    reason: UnknownReason,
    note: str,
) -> CheckResult:
    """The result of a check that could not prove anything."""
    return CheckResult(
        check_id=check.id,
        title=check.title,
        severity=check.severity,
        status=Status.UNKNOWN,
        reason=reason,
        note=note,
        findings=(),
        maps_to=check.maps_to,
        fix=check.fix,
    )


def _run_check(
    check: catalogue.Check,
    document: Document,
    directory: members.Directory,
) -> CheckResult:
    """Run one check, after proving the audit was allowed to look."""
    read = (*check.queries, *check.lookups)
    for query_id in read:
        result = document.queries.get(query_id)
        if result is None:
            return _unknown(
                check, UnknownReason.ERROR, "the query is not in the document"
            )
        if result.status != "ok":
            return _unknown(
                check,
                reason_for_status(result.status),
                f"the query {query_id} did not complete",
            )

    for section_id in check.files:
        section = document.files.get(section_id)
        if section is None:
            return _unknown(
                check, UnknownReason.ERROR, "the file section is not in the document"
            )
        if section.status != "ok":
            return _unknown(
                check,
                reason_for_status(section.status),
                f"the file section {section_id} did not complete",
            )

    for query_id in read:
        if query_id not in MAY_BE_EMPTY:
            continue
        if document.queries[query_id].rows:
            continue
        if document.collector == "samba":
            # A root read: an empty result is a real empty.
            continue
        return _unknown(check, UnknownReason.ACCESS_DENIED, NOT_VISIBLE_NOTE)

    for query_id in check.sentinels:
        result = document.queries.get(query_id)
        if result is None:
            return _unknown(
                check, UnknownReason.ERROR, "the query is not in the document"
            )
        rule = SENTINELS.get(query_id)
        if rule is None or not rule(result.rows, directory):
            return _unknown(
                check,
                UnknownReason.ACCESS_DENIED,
                "the collector could not read what an ordinary read must return",
            )

    for query_id in check.queries:
        for row in document.queries[query_id].rows:
            for name in check.required_attrs:
                if name not in row.a:
                    return _unknown(
                        check,
                        UnknownReason.ACCESS_DENIED,
                        "a readable object did not carry a required attribute",
                    )

    try:
        outcome = check.evaluate(document)
    except Exception:
        return _unknown(
            check, UnknownReason.ERROR, "the check could not be evaluated"
        )

    reason = outcome.reason
    if outcome.status == Status.UNKNOWN and reason is None:
        reason = UnknownReason.ERROR
    return CheckResult(
        check_id=check.id,
        title=check.title,
        severity=check.severity,
        status=outcome.status,
        reason=reason,
        note=outcome.note,
        findings=outcome.findings,
        maps_to=check.maps_to or outcome.maps_to,
        fix=check.fix or outcome.fix,
    )


def _counts(results: Sequence[CheckResult]) -> dict[str, int]:
    """The counts by status and by severity."""
    counts = {
        Status.PASS.value: 0,
        Status.FINDING.value: 0,
        Status.UNKNOWN.value: 0,
        Severity.LOW.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.HIGH.value: 0,
    }
    for result in results:
        counts[result.status.value] += 1
        counts[result.severity.value] += 1
    return counts


def _generated() -> str:
    """The moment the report was made, in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(
    document: Document,
    expected_collector: str,
    checks: Sequence[catalogue.Check] | None = None,
) -> AuditReport:
    """Run the catalogue over one document and return the report.

    The platform of the inventory is required, and the document must be
    the one that platform's collector wrote: the rules of the audit are
    the rules of the platform, and a document of another collector is
    refused.

    The identity guard runs first and always: a privileged key stops the
    audit before any check runs.
    """
    collector = COLLECTOR_BY_PLATFORM.get(expected_collector)
    if collector is None:
        raise CollectorMismatch(PLATFORM_MISMATCH_MESSAGE)
    if document.collector != collector:
        raise CollectorMismatch(COLLECTOR_MISMATCH_MESSAGE)
    selected = list(catalogue.CHECKS if checks is None else checks)
    directory = members.Directory(document)
    identity_guard(document, directory)

    results = [_run_check(check, document, directory) for check in selected]
    return AuditReport(
        domain=document.domain.dns,
        collector=document.collector,
        counts=_counts(results),
        results=tuple(results),
        generated=_generated(),
        scope_note=SCOPE_NOTE,
    )
