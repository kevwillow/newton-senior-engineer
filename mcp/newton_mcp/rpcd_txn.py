"""The transaction rules of ADR-021 point 6: one owner, never guessed.

The engine is pure logic over an injected client, so every rule can be
tested without a router:

  * before an apply, Newton checks that no apply is pending (its own or
    LuCI's) and refuses if one is;
  * it stages and applies in one retained session;
  * the session is spent after the apply: after a rollback rpcd puts the
    change back into the applying session as staged, and an apply from
    that session would re-apply it.  The user cannot ``uci revert`` it
    nor destroy the session, so it is left to expire;
  * after a lost response, it opens a fresh session and reads the live
    values.  It confirms only when it can prove the pending change is
    its own (the values equal the staged ones, inside its window).
    Otherwise it does not confirm, reports "unknown", and waits for the
    window to pass;
  * it never infers a rollback from elapsed time alone: it reads the
    values back.

Three rules keep the proof honest:

  * an empty change list is no change: it is refused before the router
    is asked anything, so it can never confirm somebody else's apply;
  * a read has three outcomes: a value, a proven absence (the router
    answered "no such option") and an answer that could not be read.
    Only a proven absence may count as a deletion; an answer that
    could not be read is "unknown" and nothing else;
  * the staged changes are compared whole: the verb is part of the
    record, so a delete is only ever a ``remove`` record, and a record
    of a shape Newton does not know is never a guess.

The values it reads back are the ones the router holds, so every string
that comes from the device is treated as data, never as a command.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from .adapters import openwrt_rpcd as rpcd
from .adapters.openwrt_rpcd import (
    RpcdCallFailed,
    RpcdCredentials,
    RpcdError,
    RpcdSession,
    RpcdTransportError,
)
from .policy import (
    CONFIG_NAME_RE,
    OPTION_NAME_RE,
    SECTION_NAME_RE,
    SECTION_TYPE_RE,
)

# The states an apply can end in.
APPLIED_PENDING = "APPLIED_PENDING"
BUSY = "BUSY"
REFUSED = "REFUSED"
LOST = "LOST"

# The verdicts of a resolve.
OWN = "OWN"
NOT_APPLIED = "NOT_APPLIED"
UNKNOWN = "UNKNOWN"

# The states a confirm can end in.
CONFIRMED = "CONFIRMED"
NOTHING_PENDING = "NOTHING_PENDING"

# The states a settle can end in.
REVERTED = "REVERTED"
KEPT = "KEPT"

#: The margin kept before the window ends.  Inside the last seconds the
#: answer is not provably ours yet, so nothing is confirmed.
RESOLVE_MARGIN_S = 5.0

#: The directory the router fills with one file per changed config
#: while a rollback window is open.  An empty one is not a window.
SNAPSHOT_DIR = "/var/run/rpcd/snapshot-files"

#: The longest window Newton opens.  The session lives window + 60 s, and
#: a session may not live longer than the router's own cap.
MAX_WINDOW_S = 840

#: The timeout of a session that only reads.
READ_TIMEOUT_S = 60

#: The name of an added section.  The spike measured that a dash is
#: refused by the router's own naming rules.
ADDED_NAME_RE = re.compile(r"^[a-z0-9_]{1,32}$")


#: How old an undo file must be before Newton says what it is.  A
#: restart of the router's web service forgets the window but leaves the
#: undo file behind for good (measured, a4m-02), so an undo file that is
#: older than this is a leftover and not a live window.
LEFTOVER_UNDO_AGE_S = 15 * 60

#: The message of a window that is still open.
PENDING_WINDOW_MESSAGE = "another change is waiting for confirmation on the router"


def undo_file_age(
    entries: Iterable[Any], now: float | None = None
) -> int | None:
    """The age in seconds of the newest undo file, or None.

    The router's own listing carries the mtime of every entry.  An
    entry whose mtime cannot be read proves nothing: the age is None
    then, and an unknown age is treated as a live window.
    """
    if now is None:
        now = time.time()
    newest: float | None = None
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        mtime = entry.get("mtime")
        if isinstance(mtime, bool) or not isinstance(mtime, (int, float)):
            continue
        if newest is None or mtime > newest:
            newest = float(mtime)
    if newest is None:
        return None
    age = int(now) - int(newest)
    return age if age > 0 else 0


def age_text(seconds: int) -> str:
    """The age in the words a person reads: "23 minutes"."""
    if seconds >= 86400:
        days = seconds // 86400
        return "1 day" if days == 1 else f"{days} days"
    if seconds >= 3600:
        hours = seconds // 3600
        return "1 hour" if hours == 1 else f"{hours} hours"
    minutes = max(1, seconds // 60)
    return "1 minute" if minutes == 1 else f"{minutes} minutes"


def leftover_undo_message(seconds: int) -> str:
    """The message of an undo file the router forgot about.

    The window is still refused: the change may be live and Newton
    cannot prove it is not.  The message says how the owner gets the
    router back into a state Newton can work with.
    """
    return (
        f"the router has a leftover undo file from {age_text(seconds)} ago "
        "(its web service restarted during a change). If nobody is changing "
        "the router right now, reboot it, or as root run: "
        "rm -rf /var/run/rpcd/snapshot-files"
    )


class RpcdTxnError(RpcdError):
    """A refusal of the transaction engine."""


class NothingStaged(RpcdTxnError):
    """The router had nothing staged to apply."""


class _Unreadable:
    """The marker of an answer Newton could not read.

    It is not the same as a proven absence.  An option the router says
    does not exist is ``None``; an answer that is malformed, that has
    no value in it or that holds a value of the wrong type is this
    marker.  Only the first one may ever count as a deletion.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "<unreadable>"


class _NotFound:
    """The router's own "there is no such option"."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<not found>"


#: The one marker of an answer that could not be read.
UNREADABLE = _Unreadable()

#: The marker of the router's own "there is no such option".
_NOT_FOUND = _NotFound()


@dataclass(frozen=True)
class _Section:
    """A section as the router answered it.

    ``type`` is the section's type (the router's ``.type``) and
    ``values`` are its options.
    """

    type: str | None
    values: dict[str, str]


# ---- the ops ---------------------------------------------------------------


@dataclass(frozen=True)
class Op:
    """One UCI change: a set, an add or a delete."""

    kind: str
    config: str
    section: str
    values: tuple[tuple[str, str], ...] = ()
    type: str | None = None
    name: str | None = None
    option: str | None = None


def _check_config(value: Any) -> None:
    if not isinstance(value, str) or CONFIG_NAME_RE.fullmatch(value) is None:
        raise RpcdTxnError("the config name fails the UCI grammar")


def _check_section(value: Any) -> None:
    if not isinstance(value, str) or SECTION_NAME_RE.fullmatch(value) is None:
        raise RpcdTxnError("the section name fails the UCI grammar")


def _check_option(value: Any) -> None:
    if not isinstance(value, str) or OPTION_NAME_RE.fullmatch(value) is None:
        raise RpcdTxnError("the option name fails the UCI grammar")


def _check_values(values: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, Mapping) or not values:
        raise RpcdTxnError("a change needs at least one value")
    items: list[tuple[str, str]] = []
    for option, value in values.items():
        _check_option(option)
        if not isinstance(value, str):
            raise RpcdTxnError("a value must be a string")
        items.append((option, value))
    return tuple(items)


def set(config: str, section: str, values: Mapping[str, str]) -> Op:
    """Set values in an existing section."""
    _check_config(config)
    _check_section(section)
    return Op("set", config, section, _check_values(values))


def add(
    config: str, type: str, name: str, values: Mapping[str, str]
) -> Op:
    """Add a named section.  Anonymous sections are not used."""
    _check_config(config)
    if not isinstance(type, str) or SECTION_TYPE_RE.fullmatch(type) is None:
        raise RpcdTxnError("the section type fails the UCI grammar")
    if not isinstance(name, str) or ADDED_NAME_RE.fullmatch(name) is None:
        raise RpcdTxnError(
            "an added section needs a name of 1 to 32 characters of [a-z0-9_]"
        )
    return Op("add", config, name, _check_values(values), type=type, name=name)


def delete(config: str, section: str, option: str | None = None) -> Op:
    """Delete one option, or a whole section when no option is named."""
    _check_config(config)
    _check_section(section)
    if option is not None:
        _check_option(option)
    return Op("delete", config, section, option=option)


def _require_ops(ops: Sequence[Op]) -> list[Op]:
    """The ops of a change, and a refusal when there are none.

    An empty change list is not a change.  It must never reach the
    router, and it must never be read as "ours": with LuCI's rollback
    window open, an empty list used to confirm someone else's apply
    without reading a single value.
    """
    ops = list(ops)
    if not ops:
        raise RpcdTxnError("there is nothing to change")
    return ops


def _units(ops: Iterable[Op]) -> list[tuple[str, str, str | None]]:
    """The (config, section, option) units the ops touch."""
    units: list[tuple[str, str, str | None]] = []
    for op in ops:
        if op.kind == "set":
            units.extend((op.config, op.section, option) for option, _ in op.values)
        elif op.kind == "add":
            units.extend((op.config, op.name or "", option) for option, _ in op.values)
        elif op.kind == "delete":
            units.append((op.config, op.section, op.option))
        else:  # pragma: no cover - the constructors are the only way in
            raise RpcdTxnError(f"unknown change kind: {op.kind}")
    return units


def _added_sections(ops: Iterable[Op]) -> list[tuple[str, str]]:
    """The (config, name) of every added section."""
    return [(op.config, op.name or "") for op in ops if op.kind == "add"]


def _staged_values(ops: Iterable[Op]) -> dict[tuple[str, str, str | None], Any]:
    """The value each unit must hold once the change is applied."""
    staged: dict[tuple[str, str, str | None], Any] = {}
    for op in ops:
        if op.kind in ("set", "add"):
            for option, value in op.values:
                staged[(op.config, op.section, option)] = value
        elif op.kind == "delete":
            staged[(op.config, op.section, op.option)] = None
    return staged


def _staged_types(ops: Iterable[Op]) -> dict[tuple[str, str], Any]:
    """The type every added section must hold once the change is applied."""
    return {
        (op.config, op.name or ""): op.type
        for op in ops
        if op.kind == "add"
    }


@dataclass(frozen=True)
class _Record:
    """One staged change, as the router lists it.

    The verb is part of the record: ``set`` for a value or for a new
    section, ``remove`` for a deletion.
    """

    verb: str
    config: str
    section: str
    option: str | None
    value: str | None


def _expected_records(ops: Iterable[Op]) -> list[_Record]:
    """The changes the ops stage, in the shape the router lists them."""
    records: list[_Record] = []
    for op in ops:
        if op.kind == "set":
            for option, value in op.values:
                records.append(_Record("set", op.config, op.section, option, value))
        elif op.kind == "add":
            # the router lists the new section itself, then its options
            records.append(_Record("set", op.config, op.name or "", None, op.type))
            for option, value in op.values:
                records.append(
                    _Record("set", op.config, op.name or "", option, value)
                )
        elif op.kind == "delete":
            records.append(_Record("remove", op.config, op.section, op.option, None))
    return records


def _all_read(readings: Mapping[Any, Any]) -> bool:
    """True when every answer could be read.

    An answer that could not be read is never a value and never a
    proven absence: it can only lead to "unknown".
    """
    return all(value is not UNREADABLE for value in readings.values())


def _holds(
    values: Mapping[Any, Any],
    types: Mapping[Any, Any],
    wanted_values: Mapping[Any, Any],
    wanted_types: Mapping[Any, Any],
) -> bool:
    """True when every touched unit holds exactly the wanted value."""
    for unit, wanted in wanted_values.items():
        if values.get(unit) != wanted:
            return False
    for key, wanted in wanted_types.items():
        if types.get(key) != wanted:
            return False
    return True


def _holds_any(
    values: Mapping[Any, Any],
    types: Mapping[Any, Any],
    wanted_values: Mapping[Any, Any],
    wanted_types: Mapping[Any, Any],
) -> bool:
    """True when at least one touched unit holds the wanted value."""
    for unit, wanted in wanted_values.items():
        if values.get(unit) == wanted:
            return True
    for key, wanted in wanted_types.items():
        if types.get(key) == wanted:
            return True
    return False


# ---- the results -----------------------------------------------------------


@dataclass(frozen=True)
class ApplyResult:
    """What an apply ended in."""

    state: str
    deadline: float | None = None
    reason: str = ""
    resolve: str | None = None
    session: RpcdSession | None = None


@dataclass(frozen=True)
class ConfirmResult:
    """What a confirm ended in."""

    state: str
    reason: str = ""


# ---- the engine ------------------------------------------------------------


class RpcdTransaction:
    """The transaction rules, over an injected client."""

    def __init__(
        self,
        client: Any,
        credentials: RpcdCredentials | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.client = client
        self.credentials = credentials or RpcdCredentials()
        # The clock of the caller: the deadline of the window and the
        # margin before it ends are measured with it, so a caller that
        # drives the window itself is never mixed with the wall clock.
        self._now = now
        self._prior: dict[tuple[str, str, str | None], Any] = {}
        self._prior_types: dict[tuple[str, str], Any] = {}

    # -- the plumbing --------------------------------------------------------

    def call_in_session(
        self,
        session: RpcdSession,
        obj: str,
        fn: str,
        args: Mapping[str, Any] | None = None,
    ) -> Any:
        """One ubus call in an existing session.

        A spent session refuses every call: after an apply the change
        may still be staged in it, and an apply from there would
        re-apply it.
        """
        if session.spent:
            raise RpcdError(
                "this rpcd session is spent: it must not be used again"
            )
        return self.client.call(session, obj, fn, args)

    def _open(self, creds: RpcdCredentials, timeout_s: int) -> RpcdSession:
        return self.client.login(creds.username, creds.password, timeout_s)

    # -- the pending detector ------------------------------------------------

    def pending_entries(self, session: RpcdSession) -> list[Any]:
        """The entries of the snapshot directory, or an empty list.

        The detector is read-only: it lists the snapshot directory the
        router creates while a window is open.  A real window holds one
        file per changed config, so the directory has an entry.

        An EMPTY directory is not a window: a refused apply leaves the
        directory behind, empty, and it stays that way (measured on
        lab-r1).  A directory that is not there at all (the router
        answers ``[4]``) is not a window either.

        A failed listing raises: an unknown state is never "not
        pending".
        """
        try:
            answer = self.call_in_session(
                session, "file", "list", {"path": SNAPSHOT_DIR}
            )
        except RpcdCallFailed as exc:
            if exc.code == 4:
                # the directory is not there: there is no window
                return []
            raise
        entries = answer.get("entries") if isinstance(answer, Mapping) else None
        if not isinstance(entries, (list, tuple)):
            raise RpcdTxnError(
                "the pending state cannot be read: unknown is not 'not pending'"
            )
        return list(entries)

    def pending(self, session: RpcdSession) -> bool:
        """True while a rollback window is open on the router."""
        return bool(self.pending_entries(session))

    # -- apply ---------------------------------------------------------------

    def apply(
        self,
        ops: Sequence[Op],
        window_s: int,
        creds: RpcdCredentials | None = None,
    ) -> ApplyResult:
        """Stage the ops and open a rollback window.

        The window is the router's own undo timer: ``uci apply
        {rollback: true, timeout}``.  Newton confirms only later, and
        only when it can prove the pending change is its own.
        """
        ops = _require_ops(ops)
        if (
            isinstance(window_s, bool)
            or not isinstance(window_s, int)
            or not 1 <= window_s <= MAX_WINDOW_S
        ):
            raise RpcdTxnError(
                f"the window must be 1 to {MAX_WINDOW_S} seconds"
            )
        if creds is not None:
            self.credentials = creds
        creds = self.credentials
        session = self._open(creds, window_s + 60)
        try:
            if self.pending(session):
                return ApplyResult(
                    BUSY,
                    reason="an apply is already pending on the router",
                )
            try:
                held = self._changes(session)
            except RpcdTxnError as exc:
                # the router's change list cannot be read: nothing is
                # staged, nothing is applied
                return ApplyResult(REFUSED, reason=str(exc))
            if held:
                return ApplyResult(
                    REFUSED,
                    reason="the session already holds changes",
                )
            self._read_prior(session, ops)
            self._stage(session, ops)
            try:
                matched = self._changes_match(ops, self._changes(session))
            except RpcdTxnError as exc:
                # a change record Newton does not recognise: the apply
                # is refused, never guessed at
                return ApplyResult(REFUSED, reason=str(exc))
            if not matched:
                return ApplyResult(
                    REFUSED,
                    reason="the router staged something else than the change",
                )
            sent_at = self._now()
            deadline = sent_at + window_s
            try:
                self.call_in_session(
                    session,
                    "uci",
                    "apply",
                    {"rollback": True, "timeout": window_s},
                )
            except RpcdCallFailed as exc:
                if exc.code == 6:
                    return ApplyResult(
                        BUSY,
                        reason="another apply won the race",
                    )
                if exc.code == 5:
                    raise NothingStaged(
                        "the router has nothing staged to apply"
                    ) from None
                raise
            except RpcdTransportError as exc:
                if not exc.sent:
                    raise
                # The answer was lost.  The change may or may not have
                # been applied, so the values are read back in a fresh
                # session before anything is confirmed.
                try:
                    verdict = self.resolve(ops, deadline)
                except RpcdError as err:
                    # The router cannot be read any more: the change
                    # may be live and Newton cannot prove it either
                    # way.  That is UNKNOWN, and it is never an
                    # exception that leaves the approval reusable.
                    return ApplyResult(
                        LOST,
                        deadline=deadline,
                        reason=str(err),
                        resolve=UNKNOWN,
                    )
                return ApplyResult(
                    LOST,
                    deadline=deadline,
                    reason="the answer to the apply was lost",
                    resolve=verdict,
                )
            return ApplyResult(
                APPLIED_PENDING,
                deadline=deadline,
                session=session,
            )
        finally:
            # Whatever happened, the session is spent: a rollback puts
            # the change back into it as staged, and an apply from there
            # would re-apply it.
            session.mark_spent()

    # -- resolve -------------------------------------------------------------

    def resolve(
        self,
        ops: Sequence[Op],
        deadline: float,
        creds: RpcdCredentials | None = None,
    ) -> str:
        """Decide whether the pending change is ours: OWN, NOT_APPLIED or UNKNOWN."""
        ops = _require_ops(ops)
        session = self._open(creds or self.credentials, READ_TIMEOUT_S)
        try:
            return self._resolve_in_session(session, ops, deadline)
        finally:
            session.mark_spent()

    def _resolve_in_session(
        self, session: RpcdSession, ops: Sequence[Op], deadline: float
    ) -> str:
        pending = self.pending(session)
        values = self._read_values(session, ops)
        types = self._read_types(session, ops)
        staged = _staged_values(ops)
        staged_types = _staged_types(ops)
        if not _all_read(values) or not _all_read(types):
            # an answer Newton cannot read is never an answer: it is
            # never a value, and never a proven absence either
            return UNKNOWN
        if pending:
            if (
                _holds(values, types, staged, staged_types)
                and self._now() < deadline - RESOLVE_MARGIN_S
            ):
                return OWN
            return UNKNOWN
        if not _holds_any(values, types, staged, staged_types):
            return NOT_APPLIED
        return UNKNOWN

    # -- confirm -------------------------------------------------------------

    def confirm(
        self,
        ops: Sequence[Op],
        deadline: float,
        checks_passed: bool,
        creds: RpcdCredentials | None = None,
    ) -> ConfirmResult:
        """Confirm the change, but only when it is provably ours.

        The confirm runs in the same fresh session that read the values
        back, and only when every safety check passed.
        """
        ops = _require_ops(ops)
        if not checks_passed:
            return ConfirmResult(
                REFUSED,
                reason="the safety checks did not pass: nothing was confirmed",
            )
        try:
            session = self._open(creds or self.credentials, READ_TIMEOUT_S)
        except RpcdError as exc:
            # The router cannot be reached: nothing was confirmed, and
            # the caller settles the change by reading it back.
            return ConfirmResult(UNKNOWN, reason=str(exc))
        try:
            verdict = self._resolve_in_session(session, ops, deadline)
            if verdict != OWN:
                return ConfirmResult(
                    REFUSED,
                    reason=(
                        "the pending change is not provably ours "
                        f"({verdict}): nothing was confirmed"
                    ),
                )
            try:
                self.call_in_session(session, "uci", "confirm", {})
            except RpcdCallFailed as exc:
                if exc.code == 5:
                    return ConfirmResult(
                        NOTHING_PENDING,
                        reason="the router had nothing pending to confirm",
                    )
                raise
            return ConfirmResult(CONFIRMED)
        except RpcdError as exc:
            # A confirm that cannot be made is not a confirm: the
            # change is left for the read-back to judge.
            return ConfirmResult(UNKNOWN, reason=str(exc))
        finally:
            session.mark_spent()

    # -- settle --------------------------------------------------------------

    def settle(
        self,
        ops: Sequence[Op],
        creds: RpcdCredentials | None = None,
    ) -> str:
        """Say what happened after the window: REVERTED, KEPT or UNKNOWN.

        The values are read back and compared with the value before the
        change (read by ``apply``) and with the staged value.  A
        change that survived the window because the router rebooted is
        KEPT.
        """
        ops = _require_ops(ops)
        try:
            session = self._open(creds or self.credentials, READ_TIMEOUT_S)
        except RpcdError:
            # The router cannot be reached: an answer Newton could not
            # get is never an answer, so it is UNKNOWN.
            return UNKNOWN
        try:
            values = self._read_values(session, ops)
            types = self._read_types(session, ops)
        except RpcdError:
            return UNKNOWN
        finally:
            session.mark_spent()
        staged = _staged_values(ops)
        staged_types = _staged_types(ops)
        if not _all_read(values) or not _all_read(types):
            # an answer Newton cannot read is never a verdict
            return UNKNOWN
        if any(unit not in self._prior for unit in staged):
            return UNKNOWN
        if any(key not in self._prior_types for key in staged_types):
            return UNKNOWN
        before = {unit: self._prior[unit] for unit in staged}
        before_types = {key: self._prior_types[key] for key in staged_types}
        if not _all_read(before) or not _all_read(before_types):
            # the value before the change was never read
            return UNKNOWN
        if _holds(values, types, before, before_types):
            return REVERTED
        if _holds(values, types, staged, staged_types):
            return KEPT
        return UNKNOWN

    # -- the router's own view ------------------------------------------------

    def _changes(self, session: RpcdSession) -> dict[str, Any]:
        answer = self.call_in_session(session, "uci", "changes", {})
        changes = answer.get("changes") if isinstance(answer, Mapping) else None
        if not isinstance(changes, Mapping):
            raise RpcdTxnError("the router's change list cannot be read")
        return dict(changes)

    def _stage(self, session: RpcdSession, ops: Sequence[Op]) -> None:
        for op in ops:
            if op.kind == "set":
                self.call_in_session(
                    session,
                    "uci",
                    "set",
                    {
                        "config": op.config,
                        "section": op.section,
                        "values": dict(op.values),
                    },
                )
            elif op.kind == "add":
                self.call_in_session(
                    session,
                    "uci",
                    "add",
                    {
                        "config": op.config,
                        "type": op.type,
                        "name": op.name,
                        "values": dict(op.values),
                    },
                )
            elif op.kind == "delete":
                args: dict[str, Any] = {
                    "config": op.config,
                    "section": op.section,
                }
                if op.option is not None:
                    args["option"] = op.option
                self.call_in_session(session, "uci", "delete", args)

    def _changes_match(self, ops: Sequence[Op], changes: Mapping[str, Any]) -> bool:
        """True when the router staged exactly what we staged.

        The records are compared whole: the verb is part of the record,
        so a delete is only ever a ``remove`` record for that exact
        section (and option).
        """
        expected = _expected_records(ops)
        actual = self._actual_records(changes)
        if len(expected) != len(actual):
            return False
        remaining = list(actual)
        for record in expected:
            for index, candidate in enumerate(remaining):
                if candidate != record:
                    continue
                del remaining[index]
                break
            else:
                return False
        return not remaining

    def _actual_records(self, changes: Mapping[str, Any]) -> list[_Record]:
        """The router's change records, whole.

        Only the shapes the router lists are read: a value set
        (``["set", section, option, value]``), a new section
        (``["set", section, type]``), an option removed
        (``["remove", section, option]``) and a section removed
        (``["remove", section]``).  A record of any other shape is
        never a guess: it is an error, and the apply is refused.
        """
        records: list[_Record] = []
        for config, entries in changes.items():
            if not isinstance(config, str) or not isinstance(entries, (list, tuple)):
                raise RpcdTxnError("the router's change list cannot be read")
            for entry in entries:
                records.append(self._actual_record(config, entry))
        return records

    def _actual_record(self, config: str, entry: Any) -> _Record:
        """One change record of the router, read whole."""
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            raise RpcdTxnError("the router's change list cannot be read")
        verb = entry[0]
        if not isinstance(verb, str):
            raise RpcdTxnError("the router's change list cannot be read")
        if verb == "set" and len(entry) == 4:
            section, option, value = entry[1], entry[2], entry[3]
            if not all(isinstance(item, str) for item in (section, option, value)):
                raise RpcdTxnError("the router's change list cannot be read")
            return _Record("set", config, section, option, value)
        if verb == "set" and len(entry) == 3:
            section, section_type = entry[1], entry[2]
            if not all(isinstance(item, str) for item in (section, section_type)):
                raise RpcdTxnError("the router's change list cannot be read")
            return _Record("set", config, section, None, section_type)
        if verb == "remove" and len(entry) == 3:
            section, option = entry[1], entry[2]
            if not all(isinstance(item, str) for item in (section, option)):
                raise RpcdTxnError("the router's change list cannot be read")
            return _Record("remove", config, section, option, None)
        if verb == "remove" and len(entry) == 2:
            section = entry[1]
            if not isinstance(section, str):
                raise RpcdTxnError("the router's change list cannot be read")
            return _Record("remove", config, section, None, None)
        raise RpcdTxnError(
            "the router staged a change Newton does not recognise"
        )

    # -- the values ----------------------------------------------------------

    def _read_prior(
        self, session: RpcdSession, ops: Sequence[Op]
    ) -> dict[tuple[str, str, str | None], Any]:
        """Read the value of every touched option before staging."""
        prior: dict[tuple[str, str, str | None], Any] = {}
        for unit in _units(ops):
            value = self._read_unit(session, *unit)
            prior[unit] = value
            self._prior[unit] = value
        for key in _added_sections(ops):
            self._prior_types[key] = self._read_type(session, key[0], key[1])
        return prior

    def _read_values(
        self, session: RpcdSession, ops: Sequence[Op]
    ) -> dict[tuple[str, str, str | None], Any]:
        values: dict[tuple[str, str, str | None], Any] = {}
        for unit in _units(ops):
            values[unit] = self._read_unit(session, *unit)
        return values

    def _read_types(
        self, session: RpcdSession, ops: Sequence[Op]
    ) -> dict[tuple[str, str], Any]:
        """The type of every added section, as the router answers it."""
        return {
            key: self._read_type(session, key[0], key[1])
            for key in _added_sections(ops)
        }

    def _read_unit(
        self, session: RpcdSession, config: str, section: str, option: str | None
    ) -> Any:
        """One unit: the value of an option, or a whole section."""
        if option is None:
            return self._read_section(session, config, section)
        return self._read_option(session, config, section, option)

    def _read_option(
        self, session: RpcdSession, config: str, section: str, option: str
    ) -> Any:
        """The value of one option.

        Three outcomes, and they are not the same: the value itself,
        ``None`` when the router proved the option does not exist, and
        ``UNREADABLE`` when the answer cannot be read (malformed data,
        no value in it, or a value of the wrong type).  An unreadable
        answer is never a proven deletion.
        """
        answer = self._get(session, config, section, option)
        if answer is _NOT_FOUND:
            return None
        if not isinstance(answer, Mapping):
            return UNREADABLE
        value = answer.get("value")
        if not isinstance(value, str):
            return UNREADABLE
        return value

    def _read_section(
        self, session: RpcdSession, config: str, section: str
    ) -> Any:
        """A whole section.

        A ``_Section`` when the router answered with one, ``None``
        when it proved the section does not exist, and ``UNREADABLE``
        when the answer cannot be read.

        The type of a section is one of its options: rpcd answers a
        section dump with the type, the name and the anonymous flag
        inside ``values`` (rpcd's ``uci.c``), so the type is read from
        there.  There is no top-level ``.type``.
        """
        answer = self._get(session, config, section, None)
        if answer is _NOT_FOUND:
            return None
        if not isinstance(answer, Mapping):
            return UNREADABLE
        values = answer.get("values")
        if not isinstance(values, Mapping):
            return UNREADABLE
        section_type = values.get(".type")
        return _Section(
            type=section_type if isinstance(section_type, str) else None,
            values={str(key): str(value) for key, value in values.items()},
        )

    def _read_type(
        self, session: RpcdSession, config: str, section: str
    ) -> Any:
        """The type of a section.

        The type itself, ``None`` when the router proved the section
        does not exist, and ``UNREADABLE`` when it cannot be read: an
        added section whose type cannot be proven is never ours.
        """
        section = self._read_section(session, config, section)
        if section is None or section is UNREADABLE:
            return section
        if section.type is None:
            # the answer carries no type: the type cannot be proven
            return UNREADABLE
        return section.type

    def _get(
        self,
        session: RpcdSession,
        config: str,
        section: str,
        option: str | None,
    ) -> Any:
        """The raw answer of ``uci get``.

        ``_NOT_FOUND`` is the router's own "there is no such option".

        The router's measured answer for a unit that is not there is a
        status 0 with NO data at all (an empty answer), not a refusal:
        a missing section, an option of a missing section and a
        missing option of a section that is there all answer that way.
        So an empty answer is the router's proof of absence.  An answer
        with a body that is malformed stays unreadable: only an answer
        that says nothing proves that something is not there.
        """
        args: dict[str, Any] = {"config": config, "section": section}
        if option is not None:
            args["option"] = option
        try:
            answer = self.call_in_session(session, "uci", "get", args)
        except RpcdCallFailed as exc:
            if exc.code == 4:
                # not there: the option does not exist
                return _NOT_FOUND
            raise
        if isinstance(answer, Mapping) and not answer:
            # the measured answer of a unit that is not there
            return _NOT_FOUND
        return answer
