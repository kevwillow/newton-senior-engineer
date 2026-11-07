"""the transaction rules of ADR-021 point 6, over a fake router.

The engine is pure logic over an injected client, so every rule is
checked here without a router:

  * one owner, never guessed: refuse when an apply is pending (ours or
    LuCI's), refuse when the session already holds changes, refuse when
    the staged changes are not exactly the ones we staged;
  * stage and apply in one retained session; the session is spent after
    the apply (a rollback puts the change back into that session as
    staged, and an apply from it would re-apply it);
  * after a lost answer, read the values back in a fresh session and
    confirm only when the pending change is provably ours;
  * never infer a rollback from elapsed time alone.
"""

from __future__ import annotations

import time

import pytest

from newton_mcp import rpcd_txn as txn
from newton_mcp.adapters import openwrt_rpcd as rpcd
from rpcd_helpers import ScriptedRouter, self_signed


# ---- the fake router -------------------------------------------------------


class FakeRouter:
    """A fake rpcd: staged changes per session, live values, one window.

    The change records are the ones the router lists (measured on
    lab-r1): ``["set", section, option, value]`` for an option, and
    ``["set", section, type]`` for a new section.  A delete is listed
    as ``["remove", section]`` or ``["remove", section, option]``.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, dict]] = []
        #: session id -> the change records the router would list
        self.staged: dict[str, list[tuple[str, str, str, str | None, str | None]]] = {}
        #: (config, section, option) -> the live value
        self.live: dict[tuple[str, str, str], str] = {}
        #: (config, section) -> (type, {option: value})
        self.sections: dict[tuple[str, str], tuple[str, dict[str, str]]] = {}
        self.pending = False
        self.apply_code = 0
        self.confirm_code = 0
        self.lose_apply_answer = False
        self.lose_apply_answer_applies = True
        self.pending_listing_fails = False
        #: the snapshot directory is not there at all ([4])
        self.snapshot_missing = False
        self.new_sessions_start_with_changes = False
        self.extra_on_set: tuple[str, str, str, str] | None = None
        self.value_override: str | None = None
        #: the change records the router lists, whatever was staged
        self.change_records: list[tuple[str, list[str]]] | None = None
        #: a malformed answer to ``uci get``
        self.malformed_get: object | None = None
        #: the router answers a missing unit with [0] and no data (measured)
        self.absence_answers_empty = False
        #: the shape of a section dump: "real" (the one rpcd answers
        #: with), "no-type" (a dump without the type) or "not-a-dict"
        #: (an answer whose "values" is not an object)
        self.section_dump = "real"
        self.sessions: list[rpcd.RpcdSession] = []
        self._counter = 0

    # -- the client interface ------------------------------------------------

    def login(self, username: str, password: str, timeout_s: int) -> rpcd.RpcdSession:
        assert username == rpcd.RPCD_USER
        assert password == "synthetic-password"
        assert 1 <= timeout_s <= 900
        self._counter += 1
        session = rpcd.RpcdSession(
            id=f"{self._counter:032x}",
            expires_at=time.time() + timeout_s,
            acls={},
            timeout_s=timeout_s,
        )
        self.sessions.append(session)
        self.staged[session.id] = []
        if self.new_sessions_start_with_changes:
            self.staged[session.id].append(("set", "dhcp", "other", "limit", "5"))
        return session

    def call(self, session, obj: str, fn: str, args: dict | None = None) -> object:
        args = dict(args or {})
        self.calls.append((session.id, obj, fn, args))
        if obj == "file" and fn == "list":
            if self.pending_listing_fails:
                raise rpcd.RpcdCallFailed(6)
            if self.snapshot_missing:
                # the directory is not there at all: the router answers
                # [4] (measured, a3m-04)
                raise rpcd.RpcdCallFailed(4)
            entries = []
            if self.pending:
                # a real window holds one file per changed config
                entries.append({"name": "dhcp", "type": "file"})
            return {"entries": entries}
        if obj == "uci" and fn == "changes":
            return {"changes": self._changes(session.id)}
        if obj == "uci" and fn == "set":
            for option, value in args.get("values", {}).items():
                if self.value_override is not None:
                    value = self.value_override
                self.staged[session.id].append(
                    ("set", args["config"], args["section"], option, value)
                )
            if self.extra_on_set is not None:
                config, section, option, value = self.extra_on_set
                self.staged[session.id].append(("set", config, section, option, value))
            return {}
        if obj == "uci" and fn == "add":
            name = args["name"]
            self.staged[session.id].append(
                ("set", args["config"], name, None, args["type"])
            )
            for option, value in args.get("values", {}).items():
                self.staged[session.id].append(
                    ("set", args["config"], name, option, value)
                )
            return {"section": name}
        if obj == "uci" and fn == "delete":
            self.staged[session.id].append(
                ("remove", args["config"], args["section"], args.get("option"), None)
            )
            return {}
        if obj == "uci" and fn == "get":
            if self.malformed_get is not None:
                return self.malformed_get
            option = args.get("option")
            if option is None:
                key = (args["config"], args["section"])
                if key not in self.sections:
                    if self.absence_answers_empty:
                        # the measured answer: [0] with no data at all
                        return {}
                    raise rpcd.RpcdCallFailed(4)
                section_type, values = self.sections[key]
                if self.section_dump == "no-type":
                    return {"values": {".name": args["section"], **values}}
                if self.section_dump == "not-a-dict":
                    return {"values": "rule"}
                if self.section_dump == "top-level":
                    # the shape nobody's router answers with: the type
                    # outside the values
                    return {"values": dict(values), ".type": section_type}
                # The shape rpcd answers with (rpcd's uci.c, the section
                # dump): the type, the name and the anonymous flag are
                # options of the section, so they live in "values" with
                # the rest -- there is no top-level ".type".
                return {
                    "values": {
                        ".type": section_type,
                        ".name": args["section"],
                        ".anonymous": "false",
                        **values,
                    }
                }
            key = (args["config"], args["section"], option)
            if key in self.live:
                return {"value": self.live[key]}
            if self.absence_answers_empty:
                # the measured answer: [0] with no data at all
                return {}
            raise rpcd.RpcdCallFailed(4)
        if obj == "uci" and fn == "apply":
            if self.lose_apply_answer:
                if self.lose_apply_answer_applies:
                    # the router applied it; the answer never came back
                    self._apply(session.id)
                    self.pending = True
                raise rpcd.RpcdTransportError("the answer was lost", sent=True)
            if self.apply_code != 0:
                raise rpcd.RpcdCallFailed(self.apply_code)
            self._apply(session.id)
            self.pending = True
            return {}
        if obj == "uci" and fn == "confirm":
            if self.confirm_code != 0:
                raise rpcd.RpcdCallFailed(self.confirm_code)
            self.pending = False
            return {}
        raise AssertionError(f"unexpected call {obj}.{fn}")

    # -- helpers -------------------------------------------------------------

    def _apply(self, session_id: str) -> None:
        """The staged changes become the live ones."""
        for verb, config, section, option, value in self.staged[session_id]:
            key = (config, section)
            if verb == "set" and option is None:
                self.sections[key] = (value or "", {})
            elif verb == "set":
                self.live[(config, section, option or "")] = value or ""
                if key not in self.sections:
                    self.sections[key] = ("", {})
                self.sections[key][1][option or ""] = value or ""
            elif option is None:
                self.sections.pop(key, None)
                for live_key in [
                    k for k in self.live if k[0] == config and k[1] == section
                ]:
                    del self.live[live_key]
            else:
                self.live.pop((config, section, option), None)
                if key in self.sections:
                    self.sections[key][1].pop(option, None)

    def _changes(self, session_id: str) -> dict[str, list[list[str]]]:
        staged = self.staged[session_id]
        if staged and self.change_records is not None:
            # the router lists these, whatever was staged
            changes: dict[str, list[list[str]]] = {}
            for config, entry in self.change_records:
                changes.setdefault(config, []).append(list(entry))
            return changes
        changes = {}
        for verb, config, section, option, value in staged:
            if verb == "set":
                if option is None:
                    entry = ["set", section, value]
                else:
                    entry = ["set", section, option, value]
            elif option is None:
                entry = ["remove", section]
            else:
                entry = ["remove", section, option]
            changes.setdefault(config, []).append(entry)
        return changes

    def calls_to(self, fn: str) -> list[tuple[str, str, str, dict]]:
        return [call for call in self.calls if call[2] == fn]

    def staged_calls(self) -> list[tuple[str, str, str, dict]]:
        return [c for c in self.calls if c[2] in {"set", "add", "delete"}]


@pytest.fixture
def router() -> FakeRouter:
    return FakeRouter()


@pytest.fixture
def engine(router: FakeRouter) -> txn.RpcdTransaction:
    return txn.RpcdTransaction(router, CREDENTIALS)


CREDENTIALS = txn.RpcdCredentials(username="newton", password="synthetic-password")


def _ops() -> list[txn.Op]:
    return [txn.set("dhcp", "lab", {"limit": "77"})]


# ---- the ops ---------------------------------------------------------------


def test_the_ops_validate_the_uci_grammar() -> None:
    with pytest.raises(txn.RpcdTxnError):
        txn.set("DHCP", "lab", {"limit": "77"})
    with pytest.raises(txn.RpcdTxnError):
        txn.set("dhcp", "lab;reboot", {"limit": "77"})
    with pytest.raises(txn.RpcdTxnError):
        txn.set("dhcp", "lab", {"limit;reboot": "77"})
    with pytest.raises(txn.RpcdTxnError):
        txn.set("dhcp", "lab", {"limit": "77", "": "x"})
    with pytest.raises(txn.RpcdTxnError):
        txn.add("dhcp", "lab", "new-name", {"limit": "77"})
    with pytest.raises(txn.RpcdTxnError):
        txn.add("dhcp", "lab", "bad name", {"limit": "77"})
    with pytest.raises(txn.RpcdTxnError):
        txn.delete("dhcp", "lab", "bad option")


def test_an_added_section_is_named_and_has_no_dash() -> None:
    op = txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})
    assert op.kind == "add"
    assert op.name == "newtonprobe"
    with pytest.raises(txn.RpcdTxnError):
        txn.add("firewall", "rule", "newton-probe", {"enabled": "0"})


# ---- the pending detector --------------------------------------------------


def test_pending_is_true_while_a_window_is_open(engine, router) -> None:
    session = router.login("newton", "synthetic-password", 30)
    assert engine.pending(session) is False
    router.pending = True
    assert engine.pending(session) is True


def test_a_failed_pending_listing_raises(engine, router) -> None:
    session = router.login("newton", "synthetic-password", 30)
    router.pending_listing_fails = True
    with pytest.raises(rpcd.RpcdError):
        engine.pending(session)


def test_an_empty_snapshot_directory_is_not_a_window(engine, router) -> None:
    """A refused apply leaves the snapshot directory behind, empty.

    That is what the lab measured (a3m-04: ``[0, {"entries": []}]``),
    and the directory stays that way: an empty directory is NOT a
    pending window.
    """
    session = router.login("newton", "synthetic-password", 30)
    router.pending = False
    assert engine.pending(session) is False


def test_a_missing_snapshot_directory_is_not_a_window(engine, router) -> None:
    """The directory is not there: the router answers [4] (measured).

    That is the answer after a confirm: both snapshot directories are
    gone.  It is not a window either.
    """
    session = router.login("newton", "synthetic-password", 30)
    router.pending = False
    router.snapshot_missing = True
    assert engine.pending(session) is False


def test_the_pending_detector_lists_the_snapshot_directory(engine, router) -> None:
    """The detector lists the snapshot directory itself.

    It does not look for a name in the listing of /var/run/rpcd: an
    empty leftover directory must not read as a window.
    """
    session = router.login("newton", "synthetic-password", 30)
    router.pending = True
    assert engine.pending(session) is True
    listings = [
        args
        for _sid, obj, fn, args in router.calls
        if obj == "file" and fn == "list"
    ]
    assert listings, router.calls
    assert listings[-1]["path"] == "/var/run/rpcd/snapshot-files"


# ---- apply -----------------------------------------------------------------


def test_apply_stages_and_applies_in_one_session(engine, router) -> None:
    before = time.time()
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.APPLIED_PENDING
    assert result.deadline is not None
    assert before + 30 <= result.deadline <= time.time() + 30
    apply_calls = router.calls_to("apply")
    assert len(apply_calls) == 1
    assert apply_calls[0][3] == {"rollback": True, "timeout": 30}
    # stage and apply in the same session
    staged_in = {call[0] for call in router.staged_calls()}
    assert staged_in == {apply_calls[0][0]}


def test_apply_refuses_when_an_apply_is_pending(engine, router) -> None:
    router.pending = True
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.BUSY
    assert router.staged_calls() == []
    assert router.calls_to("apply") == []


def test_apply_refuses_when_the_session_already_holds_changes(engine, router) -> None:
    router.new_sessions_start_with_changes = True
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.staged_calls() == []
    assert router.calls_to("apply") == []


def test_apply_refuses_when_the_staged_changes_are_not_ours(engine, router) -> None:
    router.extra_on_set = ("dhcp", "lab", "extra", "1")
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_apply_refuses_when_a_staged_value_is_not_ours(engine, router) -> None:
    router.value_override = "88"
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_apply_reports_busy_when_the_router_answers_6(engine, router) -> None:
    router.apply_code = 6
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.BUSY
    assert result.deadline is None


def test_apply_raises_when_the_router_answers_5(engine, router) -> None:
    router.apply_code = 5
    with pytest.raises(txn.NothingStaged):
        engine.apply(_ops(), 30, CREDENTIALS)


def test_the_session_is_spent_after_the_apply(engine, router) -> None:
    result = engine.apply(_ops(), 30, CREDENTIALS)
    session = result.session
    assert session is not None
    assert session.spent is True
    calls_before = len(router.calls)
    with pytest.raises(rpcd.RpcdError):
        engine.call_in_session(session, "uci", "changes", {})
    assert len(router.calls) == calls_before


def test_a_lost_answer_calls_resolve(engine, router) -> None:
    router.lose_apply_answer = True
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.LOST
    assert result.resolve == txn.OWN
    assert router.calls_to("get")


def test_a_lost_answer_that_is_not_ours_is_not_applied(engine, router) -> None:
    router.lose_apply_answer = True
    router.lose_apply_answer_applies = False
    result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.LOST
    assert result.resolve == txn.NOT_APPLIED


def test_apply_refuses_an_unbounded_window(engine, router) -> None:
    with pytest.raises(txn.RpcdTxnError):
        engine.apply(_ops(), 0, CREDENTIALS)
    with pytest.raises(txn.RpcdTxnError):
        engine.apply(_ops(), 901, CREDENTIALS)


# ---- resolve ---------------------------------------------------------------


def test_resolve_is_own_when_the_window_is_open_and_the_values_match(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "77"
    router.pending = True
    verdict = engine.resolve(_ops(), time.time() + 60)
    assert verdict == txn.OWN


def test_resolve_is_not_applied_when_nothing_is_pending(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "100"
    verdict = engine.resolve(_ops(), time.time() + 60)
    assert verdict == txn.NOT_APPLIED


def test_resolve_is_unknown_when_the_window_is_almost_over(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "77"
    router.pending = True
    # the margin: inside the last five seconds the answer is not ours yet
    verdict = engine.resolve(_ops(), time.time() + 3)
    assert verdict == txn.UNKNOWN


def test_resolve_is_unknown_when_the_values_do_not_match(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "88"
    router.pending = True
    verdict = engine.resolve(_ops(), time.time() + 60)
    assert verdict == txn.UNKNOWN


def test_resolve_never_guesses_from_the_clock_alone(engine, router) -> None:
    """A value that matches but no window is not ours to confirm."""
    router.live[("dhcp", "lab", "limit")] = "77"
    router.pending = False
    verdict = engine.resolve(_ops(), time.time() + 60)
    assert verdict == txn.UNKNOWN


# ---- confirm ---------------------------------------------------------------


def test_confirm_confirms_in_the_same_fresh_session(engine, router) -> None:
    applied = engine.apply(_ops(), 30, CREDENTIALS)
    result = engine.confirm(_ops(), time.time() + 60, True)

    assert result.state == txn.CONFIRMED
    confirm_calls = router.calls_to("confirm")
    get_calls = router.calls_to("get")
    assert len(confirm_calls) == 1
    # the confirm ran in the session that read the values back
    assert confirm_calls[0][0] == get_calls[-1][0]
    assert confirm_calls[0][0] != applied.session.id


def test_confirm_refuses_when_the_checks_failed(engine, router) -> None:
    engine.apply(_ops(), 30, CREDENTIALS)
    result = engine.confirm(_ops(), time.time() + 60, False)

    assert result.state == txn.REFUSED
    assert result.reason
    assert router.calls_to("confirm") == []


def test_confirm_refuses_when_the_change_is_not_ours(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "88"
    router.pending = True
    result = engine.confirm(_ops(), time.time() + 60, True)

    assert result.state == txn.REFUSED
    assert router.calls_to("confirm") == []


def test_confirm_reports_nothing_pending(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "77"
    router.pending = True
    router.confirm_code = 5
    result = engine.confirm(_ops(), time.time() + 60, True)

    assert result.state == txn.NOTHING_PENDING


# ---- settle ----------------------------------------------------------------


def test_settle_reports_reverted(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "100"
    engine.apply(_ops(), 30, CREDENTIALS)
    router.live[("dhcp", "lab", "limit")] = "100"
    router.pending = False
    verdict = engine.settle(_ops())
    assert verdict == txn.REVERTED


def test_settle_reports_kept(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "100"
    engine.apply(_ops(), 30, CREDENTIALS)
    router.pending = False
    verdict = engine.settle(_ops())
    assert verdict == txn.KEPT


def test_settle_reports_unknown_for_a_mixed_state(engine, router) -> None:
    ops = [txn.set("dhcp", "lab", {"limit": "77"}), txn.set("dhcp", "lab2", {"limit": "5"})]
    engine.apply(ops, 30, CREDENTIALS)
    router.live[("dhcp", "lab", "limit")] = "77"
    router.live[("dhcp", "lab2", "limit")] = "100"
    router.pending = False
    verdict = engine.settle(ops)
    assert verdict == txn.UNKNOWN


def test_settle_reads_the_values_before_the_change(engine, router) -> None:
    """The prior value is read before staging: that is what REVERTED means."""
    router.live[("dhcp", "lab", "limit")] = "100"
    engine.apply(_ops(), 30, CREDENTIALS)
    get_calls = router.calls_to("get")
    assert get_calls
    assert get_calls[0][3]["option"] == "limit"
    assert get_calls[0][3]["section"] == "lab"


# ---- a missing unit is absent, not unreadable (a4 r2, L1) ------------------


def test_a_missing_option_answered_with_no_data_is_a_proven_absence(
    engine, router
) -> None:
    """The measured answer of a missing unit is [0] with no data.

    That is the router's proof that the unit is not there.  An answer
    that is present but malformed is the other thing: it cannot be
    read, and an unreadable answer is never a proven absence.
    """
    router.absence_answers_empty = True
    router.pending = False
    verdict = engine.resolve(_ops(), time.time() + 60)
    # the option was never there, so the change is not on the router
    assert verdict == txn.NOT_APPLIED


def test_a_missing_section_answered_with_no_data_is_a_proven_absence(
    engine, router
) -> None:
    """A section the router does not hold is absent, not unreadable."""
    router.absence_answers_empty = True
    router.pending = False
    ops = [txn.add("dhcp", "host", "laptop", {"ip": "10.109.0.55"})]
    verdict = engine.resolve(ops, time.time() + 60)
    assert verdict == txn.NOT_APPLIED


def test_a_created_section_that_was_rolled_back_is_reverted(engine, router) -> None:
    """The created section is gone again: the router put the change back.

    The router answers a missing section with [0] and no data, so the
    read-back is a proven absence and the settle can say REVERTED.
    """
    router.absence_answers_empty = True
    ops = [txn.add("dhcp", "host", "laptop", {"ip": "10.109.0.55"})]
    engine.apply(ops, 30, CREDENTIALS)
    # the router rolls the change back: the section is gone again
    router.sections.pop(("dhcp", "laptop"), None)
    router.live.pop(("dhcp", "laptop", "ip"), None)
    router.pending = False
    assert engine.settle(ops) == txn.REVERTED


# ---- an empty change list -----------------------------------


def test_an_empty_op_list_is_refused_before_any_router_call(engine, router) -> None:
    """An empty change list is no change: it must never reach the router.

    With LuCI's rollback window pending, an empty list used to confirm
    someone else's apply without reading a single value.
    """
    with pytest.raises(txn.RpcdTxnError):
        engine.apply([], 30, CREDENTIALS)
    with pytest.raises(txn.RpcdTxnError):
        engine.resolve([], time.time() + 60)
    with pytest.raises(txn.RpcdTxnError):
        engine.confirm([], time.time() + 60, True)
    with pytest.raises(txn.RpcdTxnError):
        engine.settle([])
    assert router.calls == []


def test_an_empty_op_list_is_refused_even_when_the_checks_failed(engine, router) -> None:
    with pytest.raises(txn.RpcdTxnError):
        engine.confirm([], time.time() + 60, False)
    assert router.calls == []


# ---- an answer that cannot be read ---------------------------


def test_an_unreadable_value_is_never_a_proven_deletion(engine, router) -> None:
    """A value that cannot be read is unknown, not absent.

    A malformed answer used to look exactly like a proven absence, so
    a delete of a value that was never there read as ours.
    """
    router.pending = True
    router.malformed_get = {"section": "lab"}
    verdict = engine.resolve([txn.delete("dhcp", "lab", "limit")], time.time() + 60)
    assert verdict == txn.UNKNOWN


def test_an_unreadable_value_is_never_not_applied(engine, router) -> None:
    router.pending = False
    router.malformed_get = {"section": "lab"}
    verdict = engine.resolve([txn.delete("dhcp", "lab", "limit")], time.time() + 60)
    assert verdict == txn.UNKNOWN


def test_an_unreadable_value_is_never_a_proven_revert(engine, router) -> None:
    """The option was not there before: only a read can prove that."""
    engine.apply(_ops(), 30, CREDENTIALS)
    router.malformed_get = {"section": "lab"}
    router.pending = False
    assert engine.settle(_ops()) == txn.UNKNOWN


def test_an_unreadable_value_is_never_kept(engine, router) -> None:
    router.live[("dhcp", "lab", "limit")] = "100"
    engine.apply(_ops(), 30, CREDENTIALS)
    router.malformed_get = {"section": "lab"}
    router.pending = False
    assert engine.settle(_ops()) == txn.UNKNOWN


def test_a_value_of_the_wrong_type_is_unreadable(engine, router) -> None:
    router.pending = True
    router.malformed_get = {"value": 77}
    verdict = engine.resolve(_ops(), time.time() + 60)
    assert verdict == txn.UNKNOWN


def test_an_answer_without_a_value_is_unreadable(engine, router) -> None:
    router.pending = True
    router.malformed_get = {"section": "lab"}
    verdict = engine.resolve(_ops(), time.time() + 60)
    assert verdict == txn.UNKNOWN


# ---- the type of an added section ----------------------------


def test_an_added_section_is_checked_for_its_type(engine, router) -> None:
    """The read-back of an add proves the type, not only the options.

    A live section of another type with the same option is not the
    change that was asked for.
    """
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.sections[("firewall", "newtonprobe")] = ("rule", {"enabled": "0"})
    router.live[("firewall", "newtonprobe", "enabled")] = "0"
    router.pending = True
    assert engine.resolve(ops, time.time() + 60) == txn.OWN

    # the live section is a zone: the change is not ours
    router.sections[("firewall", "newtonprobe")] = ("zone", {"enabled": "0"})
    assert engine.resolve(ops, time.time() + 60) == txn.UNKNOWN


def test_a_section_of_another_type_is_never_confirmed(engine, router) -> None:
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.sections[("firewall", "newtonprobe")] = ("zone", {"enabled": "0"})
    router.live[("firewall", "newtonprobe", "enabled")] = "0"
    router.pending = True
    result = engine.confirm(ops, time.time() + 60, True)

    assert result.state == txn.REFUSED
    assert router.calls_to("confirm") == []


def test_an_added_section_that_is_not_there_is_not_ours(engine, router) -> None:
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.pending = True
    assert engine.resolve(ops, time.time() + 60) == txn.UNKNOWN


# ---- the type of an added section (a1 r3, item 3) ---------------------------


def test_the_type_is_read_from_the_values_of_the_section_dump(
    engine, router
) -> None:
    """rpcd puts the type of a section inside its values.

    A section dump is ``{"values": {".type": "rule", ".name": ...,
    ...}}`` (rpcd's ``uci.c``): the type is one of the section's own
    options.  A dump that carries the type outside the values proves
    nothing, so the change is never ours.
    """
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.sections[("firewall", "newtonprobe")] = ("rule", {"enabled": "0"})
    router.live[("firewall", "newtonprobe", "enabled")] = "0"
    router.pending = True
    assert engine.resolve(ops, time.time() + 60) == txn.OWN

    # the type outside the values is not a proof
    router.section_dump = "top-level"
    assert engine.resolve(ops, time.time() + 60) == txn.UNKNOWN


def test_a_section_without_a_type_is_never_ours(engine, router) -> None:
    """A dump whose values hold no type: the type cannot be proven."""
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.sections[("firewall", "newtonprobe")] = ("rule", {"enabled": "0"})
    router.live[("firewall", "newtonprobe", "enabled")] = "0"
    router.section_dump = "no-type"
    router.pending = True
    assert engine.resolve(ops, time.time() + 60) == txn.UNKNOWN


def test_a_section_dump_that_is_not_an_object_is_never_ours(
    engine, router
) -> None:
    """A dump whose values are not an object cannot be read at all."""
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.sections[("firewall", "newtonprobe")] = ("rule", {"enabled": "0"})
    router.live[("firewall", "newtonprobe", "enabled")] = "0"
    router.section_dump = "not-a-dict"
    router.pending = True
    assert engine.resolve(ops, time.time() + 60) == txn.UNKNOWN


def test_an_option_is_read_from_the_value_of_the_answer(engine, router) -> None:
    """The option read keeps its own shape: ``{"value": ...}``.

    The section dump and the option read are two different answers of
    rpcd; the type of a section lives in the dump, never in an option
    read, and the option read is not disturbed by it.
    """
    router.live[("dhcp", "lab", "limit")] = "77"
    router.pending = True
    ops = [txn.set("dhcp", "lab", {"limit": "77"})]
    assert engine.resolve(ops, time.time() + 60) == txn.OWN
    reads = [c for c in router.calls_to("get") if c[3].get("option") == "limit"]
    assert reads, router.calls


# ---- the change records --------------------------------------


def test_a_delete_of_an_option_matches_a_remove_record(engine, router) -> None:
    ops = [txn.delete("dhcp", "lab", "limit")]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.APPLIED_PENDING


def test_a_delete_of_a_section_matches_a_remove_record(engine, router) -> None:
    ops = [txn.delete("dhcp", "lab")]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.APPLIED_PENDING


def test_a_delete_does_not_match_a_set_record(engine, router) -> None:
    """A section-type replacement is not the deletion that was asked for."""
    ops = [txn.delete("dhcp", "lab")]
    router.change_records = [("dhcp", ["set", "lab", "interface"])]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_a_delete_of_an_option_is_not_a_delete_of_the_section(engine, router) -> None:
    ops = [txn.delete("dhcp", "lab", "limit")]
    router.change_records = [("dhcp", ["remove", "lab"])]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_a_delete_of_a_section_is_not_a_delete_of_an_option(engine, router) -> None:
    ops = [txn.delete("dhcp", "lab")]
    router.change_records = [("dhcp", ["remove", "lab", "limit"])]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_a_change_record_of_an_unknown_kind_is_refused(engine, router) -> None:
    """A record of a shape Newton does not know is never a match."""
    ops = [txn.set("dhcp", "lab", {"limit": "77"})]
    router.change_records = [("dhcp", ["frobnicate", "lab", "limit", "77"])]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_a_set_record_of_the_wrong_length_is_refused(engine, router) -> None:
    ops = [txn.set("dhcp", "lab", {"limit": "77"})]
    router.change_records = [("dhcp", ["set", "lab"])]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.REFUSED
    assert router.calls_to("apply") == []


def test_an_added_section_matches_the_records_the_router_lists(engine, router) -> None:
    """The new section is listed as a set of its type, then its options."""
    ops = [txn.add("firewall", "rule", "newtonprobe", {"enabled": "0"})]
    router.change_records = [
        ("firewall", ["set", "newtonprobe", "rule"]),
        ("firewall", ["set", "newtonprobe", "enabled", "0"]),
    ]
    result = engine.apply(ops, 30, CREDENTIALS)

    assert result.state == txn.APPLIED_PENDING


# ---- a lost answer -------------------------------------------


def _scripted_router() -> tuple[ScriptedRouter, str]:
    """A router that answers every call but cuts the apply answer off."""
    cert_pem, key_pem, cert_der = self_signed()
    state = {"applied": False, "staged": []}

    def handler(obj: str, fn: str, args: dict):
        if obj == "session" and fn == "login":
            return [
                0,
                {
                    "ubus_rpc_session": "0123456789abcdef0123456789abcdef",
                    "acls": {"access-group": {}},
                },
            ]
        if obj == "file" and fn == "list":
            entries = []
            if state["applied"]:
                entries.append({"name": "snapshot-files", "type": "directory"})
            return [0, {"entries": entries}]
        if obj == "uci" and fn == "changes":
            changes: dict[str, list[list[str]]] = {}
            for config, entry in state["staged"]:
                changes.setdefault(config, []).append(entry)
            return [0, {"changes": changes}]
        if obj == "uci" and fn == "set":
            for option, value in args.get("values", {}).items():
                state["staged"].append(
                    (args["config"], ["set", args["section"], option, value])
                )
            return [0, {}]
        if obj == "uci" and fn == "get":
            if state["applied"]:
                return [0, {"value": "77"}]
            return [0, {"value": "100"}]
        if obj == "uci" and fn == "apply":
            state["applied"] = True
            return [0, {}]
        raise AssertionError(f"unexpected call {obj}.{fn}")

    router = ScriptedRouter(cert_pem, key_pem, handler, truncate=("uci.apply",))
    return router, rpcd.spki_pin(cert_der)


def test_a_truncated_answer_makes_the_engine_resolve() -> None:
    """A body that stops in the middle is a lost answer, not a refusal.

    The change may have been applied: the engine has to read the values
    back before anything is confirmed.
    """
    router, pin = _scripted_router()
    with router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, pin)
        engine = txn.RpcdTransaction(client, CREDENTIALS)
        result = engine.apply(_ops(), 30, CREDENTIALS)

    assert result.state == txn.LOST
    assert result.resolve == txn.OWN


# ---- the clock ---------------------------------------------


class Clock:
    """The clock of the test: the caller drives it."""

    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_the_deadline_comes_from_the_clock_the_caller_gives(router) -> None:
    """The window's deadline is the caller's clock, not the wall clock.

    The settle and the confirm measure the window with the same clock,
    so a caller that drives the window itself is never mixed with the
    wall clock.
    """
    clock = Clock()
    engine = txn.RpcdTransaction(router, CREDENTIALS, now=clock)
    outcome = engine.apply(_ops(), 30, CREDENTIALS)
    assert outcome.state == txn.APPLIED_PENDING, outcome
    assert outcome.deadline == 30.0, outcome.deadline


def test_the_resolve_margin_is_measured_with_the_callers_clock(router) -> None:
    """The margin before the window ends is the caller's clock too.

    Inside the last five seconds of the window the answer is not
    provably ours yet, and the clock that says so is the caller's.
    """
    clock = Clock()
    engine = txn.RpcdTransaction(router, CREDENTIALS, now=clock)
    router.live[("dhcp", "lab", "limit")] = "77"
    router.pending = True
    deadline = clock() + 60
    # the window is nearly over
    clock.value = deadline - txn.RESOLVE_MARGIN_S + 1
    assert engine.resolve(_ops(), deadline) == txn.UNKNOWN
    # and while it is open the change is ours
    clock.value = deadline - txn.RESOLVE_MARGIN_S - 1
    assert engine.resolve(_ops(), deadline) == txn.OWN
