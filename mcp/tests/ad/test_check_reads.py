"""Every query a check reads is proven readable before the check may PASS.

SPEC-1.3 section 6: an empty read is "could not read", a failed sentinel
makes every dependent check UNKNOWN(access_denied), and a check that
cannot prove PASS is UNKNOWN.  The runner proves only what a check
declares, so these tests pin the declarations to what the checks
really read:

- the queries a check reads while it runs over the measured documents
  are all declared, in ``queries`` or in ``lookups``;
- every declared query has a sentinel the check depends on, or is a
  query an ordinary account may see empty (``runner.MAY_BE_EMPTY``), or
  is a query whose empty read is itself the answer
  (``runner.EMPTY_IS_AN_ANSWER``);
- over the measured documents (r3, r4 and the Samba one), emptying or
  denying any query a check reads never leaves the check PASS.

A new check that reads a query it does not declare, or declares one
without a sentinel, fails here before it can report a false PASS.
"""

from __future__ import annotations

import dataclasses
import functools
from collections.abc import Callable
from typing import Any

import pytest

from newton_mcp.ad import catalogue, members, runner, wire
from newton_mcp.ad.model import Status, UnknownReason

import measured


# The measured documents an ordinary audit account produced.  The
# Administrator document is not here: the identity guard refuses it.
MEASURED: dict[str, Callable[[], dict[str, Any]]] = {
    "r3": measured.audit_json,
    "r4": measured.r4_json,
    "samba": measured.samba_json,
}

PLATFORM = {"windows": "ad-windows", "samba": "ad-samba"}

# The queries a check reads and judges in its own code instead of through
# a sentinel, with what an empty read of them must give.  The empty and
# denied tests below hold every entry to it.
UNKNOWN = "unknown"  # the check itself is UNKNOWN(access_denied)
NOT_PASS = "not_pass"  # the check is UNKNOWN, or a finding read elsewhere
UNCHANGED = "unchanged"  # the rows do not decide the verdict
SELF_JUDGED: dict[tuple[str, str], str] = {
    # The check reports the stale passwords of the users even when the
    # managed accounts are not visible, so the runner may not gate it on
    # the gMSA query; an empty read is never PASS in the check itself.
    ("AD-A-23", "gmsa"): NOT_PASS,
    # The check says which linked GPOs it could not read ("the GPO
    # objects were not readable"), which a sentinel would hide.
    ("AD-A-52", "gpos"): UNKNOWN,
    ("AD-A-54", "gpos"): UNKNOWN,
    # The GPO rows only name the GPO of a SYSVOL finding; the verdict is
    # the gpp file section, which the check declares.
    ("AD-A-55", "gpos"): UNCHANGED,
}


class _Recorder(dict[str, wire.QueryResult]):
    """A query map that remembers every query the check looked up."""

    def __init__(self, queries: dict[str, wire.QueryResult]) -> None:
        super().__init__(queries)
        self.seen: set[str] = set()

    def __getitem__(self, key: str) -> wire.QueryResult:
        self.seen.add(key)
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        self.seen.add(key)
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            self.seen.add(key)
        return super().__contains__(key)


def _declared(check: catalogue.Check) -> tuple[str, ...]:
    return tuple(check.queries) + tuple(getattr(check, "lookups", ()))


@functools.cache
def _measured(name: str) -> wire.Document:
    """The validated measured document, parsed once."""
    return measured.parse(MEASURED[name]())


def _with_query(
    name: str, query_id: str, *, status: str, error_code: str
) -> wire.Document:
    """The measured document with one query read empty, with that status."""
    document = _measured(name)
    queries = dict(document.queries)
    queries[query_id] = wire.QueryResult(
        id=query_id, status=status, error_code=error_code, rows=()
    )
    return dataclasses.replace(document, queries=queries)


def _reads(check: catalogue.Check) -> set[str]:
    """The queries the check reads over the measured documents."""
    seen: set[str] = set()
    for name in MEASURED:
        document = _measured(name)
        recorder = _Recorder(document.queries)
        try:
            check.evaluate(dataclasses.replace(document, queries=recorder))
        except Exception:
            pass
        seen |= recorder.seen
    return seen


def _run(check: catalogue.Check, document: wire.Document) -> runner.PrivilegedKey | Any:
    try:
        report = runner.run(document, PLATFORM[document.collector], [check])
    except runner.PrivilegedKey as refusal:
        return refusal
    return report.results[0]


def _cases() -> list[tuple[str, str, str]]:
    cases: list[tuple[str, str, str]] = []
    for check in catalogue.CHECKS:
        for query_id in sorted(set(_declared(check)) | _reads(check)):
            for name in MEASURED:
                cases.append((name, check.id, query_id))
    return cases


CASES = _cases()


def _self_judged_holds(
    check_id: str, query_id: str, document: wire.Document, outcome: Any
) -> bool:
    """True when a self-judged query gave what its entry promises.

    False for every query that is not self-judged, and for the UNKNOWN
    entries, whose outcome the caller asserts like any other.
    """
    kind = SELF_JUDGED.get((check_id, query_id))
    if kind == NOT_PASS:
        assert outcome.status != Status.PASS
        return True
    if kind == UNCHANGED:
        before = _run(_check(check_id), document)
        assert outcome.status == before.status
        assert len(outcome.findings) == len(before.findings)
        return True
    return False


def _check(check_id: str) -> catalogue.Check:
    return next(c for c in catalogue.CHECKS if c.id == check_id)


@pytest.mark.parametrize("check", catalogue.CHECKS, ids=lambda c: c.id)
def test_every_query_a_check_reads_is_declared(check: catalogue.Check) -> None:
    undeclared = {
        query_id
        for query_id in _reads(check) - set(_declared(check))
        if (check.id, query_id) not in SELF_JUDGED
    }
    assert not undeclared, f"{check.id} reads {sorted(undeclared)} undeclared"


@pytest.mark.parametrize("check", catalogue.CHECKS, ids=lambda c: c.id)
def test_every_declared_query_is_a_sentinel(check: catalogue.Check) -> None:
    exempt = runner.MAY_BE_EMPTY | getattr(runner, "EMPTY_IS_AN_ANSWER", frozenset())
    missing = [
        query_id
        for query_id in _declared(check)
        if query_id not in check.sentinels
        and query_id not in exempt
        and (check.id, query_id) not in SELF_JUDGED
    ]
    assert not missing, f"{check.id} reads {missing} without its sentinel"
    for query_id in check.sentinels:
        assert query_id in runner.SENTINELS, f"no sentinel rule for {query_id}"


def test_the_queries_whose_empty_read_is_the_answer_are_pinned() -> None:
    # No trust and no LAPS attribute in the schema are real answers: the
    # trusts and the schema are readable by every authenticated user.
    assert runner.EMPTY_IS_AN_ANSWER == frozenset({"trusts", "schema_laps"})
    assert not runner.EMPTY_IS_AN_ANSWER & set(runner.SENTINELS)
    assert not runner.EMPTY_IS_AN_ANSWER & runner.MAY_BE_EMPTY


@pytest.mark.parametrize("name", sorted(MEASURED))
def test_every_sentinel_holds_on_the_measured_documents(name: str) -> None:
    document = _measured(name)
    directory = members.Directory(document)
    for query_id, rule in runner.SENTINELS.items():
        assert rule(document.queries[query_id].rows, directory), query_id


@pytest.mark.parametrize(("name", "check_id", "query_id"), CASES)
def test_an_empty_read_is_never_pass(name: str, check_id: str, query_id: str) -> None:
    document = _measured(name)
    if query_id in getattr(runner, "EMPTY_IS_AN_ANSWER", frozenset()):
        pytest.skip("an empty read of this query is the answer")
    if query_id in runner.MAY_BE_EMPTY and document.collector == "samba":
        pytest.skip("a Samba root read: an empty result is a real empty")
    if document.queries[query_id].status != "ok":
        pytest.skip("the measured read did not complete; the denied case covers it")
    empty = _with_query(name, query_id, status="ok", error_code="")
    outcome = _run(_check(check_id), empty)
    if isinstance(outcome, runner.PrivilegedKey):
        assert outcome.reason == "cannot_verify"
        return
    if _self_judged_holds(check_id, query_id, document, outcome):
        return
    assert outcome.status == Status.UNKNOWN, (check_id, query_id, outcome.status)
    assert outcome.reason == UnknownReason.ACCESS_DENIED


@pytest.mark.parametrize(("name", "check_id", "query_id"), CASES)
def test_a_denied_read_is_never_pass(name: str, check_id: str, query_id: str) -> None:
    denied = _with_query(name, query_id, status="denied", error_code="access_denied")
    outcome = _run(_check(check_id), denied)
    if isinstance(outcome, runner.PrivilegedKey):
        assert outcome.reason == "cannot_verify"
        return
    if _self_judged_holds(check_id, query_id, _measured(name), outcome):
        return
    assert outcome.status == Status.UNKNOWN, (check_id, query_id, outcome.status)
    assert outcome.reason == UnknownReason.ACCESS_DENIED
