"""the read-back of an owner script, and the confirm.

ADR-021 point 5, point 6 and the design's rule 3: Newton
confirms a change only when every check passes.  There is no "applied
but not verified": a change that cannot be read back is not confirmed,
and the router's own timer puts it back.

The read-back runs in a FRESH limited session -- never the session the
script used, which was the router's root session and is not Newton's
to reuse.  Every check is mandatory:

  * the router is reachable (the fresh login works);
  * a rollback window is open (the change is waiting for confirmation);
  * the router still has the internet: the installed router program's
    own check (ping 1.1.1.1, and openwrt.org resolved by the router)
    passes.  The check waits for the router's own reload (the apply
    returns before netifd has taken the uplinks down) and retries
    until the router has the internet again;
  * every touched unit holds what the change was supposed to make it
    hold -- lists as lists, in order, and an absence as a proven
    absence;
  * NOTHING ELSE changed: every other section and option of every
    touched config still holds what the backup holds;
  * the mandatory checks of the change's classes pass;
  * Newton's own login still holds exactly the groups Newton asked for;
  * the claims that can be run, pass.

A change that exposes the router to the internet needs one more thing:
the owner types ``keep`` at the prompt, inside the window.  Newton
cannot see the live firewall rules, so it cannot tell whether the
exposure is what the owner wanted -- only the owner can say that.

The verdict and the audit line carry ids, the state and check names.
They never carry a value: a value can hold a secret, and a value that
came from the router is untrusted text.
"""

from __future__ import annotations

import select
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import envelope
from . import noinstall_checks
from . import noinstall_read
from . import owner_backup
from . import owner_ops
from . import rpcd_txn
from .adapters import openwrt_rpcd as rpcd


#: The states a run can end in.  These are the words the run prints.
CONFIRMED = "CONFIRMED"
ROLLED_BACK = "ROLLED BACK"
NOT_APPLIED = "NOT APPLIED"
KEPT = "KEPT"
UNKNOWN = "UNKNOWN"

STATES: tuple[str, ...] = (CONFIRMED, ROLLED_BACK, NOT_APPLIED, KEPT, UNKNOWN)

#: The policy reasons that mean the change can open the router to the
#: internet.  A change with one of them needs the owner's "keep".
EXPOSURE_REASONS: tuple[str, ...] = (
    "wan-zone",
    "zone-exposure",
    "wan-forwarding",
    "wan-redirect",
    "wan-rule",
    "defaults-accept",
)

#: The options that change by themselves on a quiet router.  Empty
#: until a lab measurement fills it.  A unit on this
#: list is not compared with the backup.
VOLATILE_OPTIONS: frozenset[str] = frozenset()

#: The prompt the owner reads when the change can open the router to
#: the internet.  The word "keep" is the only answer that keeps it.
KEEP_PROMPT = (
    "Checks passed. This change can open your router to the internet, and "
    "Newton cannot see the live firewall rules. Test it now. Type keep "
    "before {0} (host time) to keep it; anything else, or nothing, and the "
    "router undoes it."
)

#: The prompt the owner reads when the change only takes a rule away, or
#: only puts back the values the backup holds.  Such a change touches a
#: rule that controls access from the internet, and it does not open the
#: router: the words say what is true.  The gate is the same gate: only
#: "keep" keeps the change.
KEEP_PROMPT_RULE = (
    "Checks passed. This change touches a rule that controls access from "
    "the internet, and Newton cannot see the live firewall rules. Test it "
    "now. Type keep before {0} (host time) to keep it; anything else, or "
    "nothing, and the router undoes it."
)

#: The sentence a change that removes something adds to the prompt: what
#: silence does to a removal.  It is said only when the change removes
#: something: a change that only puts a value back takes nothing away,
#: so nothing comes back.
KEEP_PROMPT_REMOVAL = (
    "If you do not type keep, the router puts the old settings back, so a "
    "port forward or rule this change removes comes back."
)

#: The note the verdict carries when the owner did not type "keep".
DID_NOT_KEEP = "the owner did not keep it"

#: The session timeout the read-back asks for.
LOGIN_TIMEOUT_S = 30

#: The timeout of the session the checks run in.  The internet check
#: waits out the settle and its retries, and the class checks run
#: after it, so the session has to outlive that whole budget: a
#: session that is gone would answer every later probe with "could
#: not run".
CHECK_TIMEOUT_S = (
    LOGIN_TIMEOUT_S
    + noinstall_checks.INTERNET_SETTLE_S
    + noinstall_checks.INTERNET_WAIT_MAX_S
)

#: How long the settle waits past the window's own deadline before it
#: gives up.  The router undoes the change when ITS timer ends, which
#: is a little after the deadline Newton knows (measured on lab-r1: the
#: rollback landed at t+121 for a window that closed at t+120), so the
#: settle keeps polling until the host clock passes the deadline plus
#: this grace.
SETTLE_GRACE_S = 60

#: The timeout of the session object the confirm is sent with.  The
#: token is the session the script opened; the script's own timeout
#: (the window plus two minutes) is the one that counts on the router.
CONFIRM_TIMEOUT_S = 60

#: The note the verdict carries when there is no session to confirm
#: with.  The lane died before the script printed its session, so the
#: change is never confirmed and the router undoes it.
NO_TOKEN = (
    "there is no session to confirm with; the router puts the change "
    "back by itself"
)

#: The marker of an answer Newton cannot read.  It is not a value and
#: not an absence: a shape Newton does not know proves nothing.
UNREADABLE: Any = object()

#: The names of the checks, in the order they run.
CHECK_NAMES: tuple[str, ...] = (
    "reachable",
    "pending",
    "internet",
    "expected",
    "nothing-else",
    "class-checks",
    "acls",
    "claims",
)


class VerifyError(Exception):
    """A refusal of the read-back.

    The message names a check, a config, a section or an option.  It
    never echoes a value.
    """


@dataclass(frozen=True)
class Verdict:
    """What the read-back found.

    ``state`` is one of the states above.  ``checks`` names the checks
    that passed.  ``deadline`` is the host time the window closes.
    ``notes`` says why, in words that carry no value.
    """

    state: str
    checks: tuple[str, ...] = ()
    deadline: float = 0.0
    notes: tuple[str, ...] = ()
    not_verified: tuple[str, ...] = ()
    owner_keep: bool | None = None

    def sentence(self) -> str:
        """The state in one plain sentence."""
        if self.state == CONFIRMED:
            return "the change is applied and confirmed on the router."
        if self.state == ROLLED_BACK:
            return "the router put the change back; nothing was changed."
        if self.state == NOT_APPLIED:
            return "the change was never applied; the router is as it was."
        if self.state == KEPT:
            return "the change is on the router and stayed."
        return "Newton cannot tell what the router did with the change."


# ---- the helpers -----------------------------------------------------------


def _reason_code(reason: str) -> str:
    """The code of a policy reason: the word before the colon."""
    return str(reason).split(":", 1)[0].strip()


def is_exposure(record: Mapping[str, Any]) -> bool:
    """True when the record's reasons can open the router to the internet."""
    reasons = record.get("reasons")
    if not isinstance(reasons, list):
        return False
    return any(_reason_code(reason) in EXPOSURE_REASONS for reason in reasons)


def _restore_original(record: Mapping[str, Any], state: Any) -> Any:
    """The backup of the plan a restore undoes, or None.

    It is the state BEFORE the change: the values a restore puts back
    are the ones that backup holds.
    """
    if state is None:
        return None
    restore_of = record.get("restore_of")
    if not isinstance(restore_of, str) or not restore_of:
        return None
    try:
        return owner_backup.load(Path(state), restore_of)
    except owner_backup.BackupError:
        return None


def closes_only(
    record: Mapping[str, Any], backup: Any, state: Any = None
) -> bool:
    """True when the change can only take access away, never open it.

    A change that only deletes, or that only puts back the values the
    backup holds, leaves the router's access the way it was or takes it
    away: it can never open the router to the internet.  The gate stays
    the gate -- the owner still has to type "keep" -- only the words of
    the prompt change.

    A RESTORE is judged against the backup of the plan it undoes: a
    restore runs against the state the change made, so its own backup
    holds the changed values, and the values it puts back are the ones
    the original backup holds.

    A change that sets a value of its own is not one of these: it may
    open a way in, and the prompt says so.
    """
    try:
        ops = ops_of(record)
    except VerifyError:
        return False
    if not ops:
        return False
    original = _restore_original(record, state)
    if original is not None:
        backup = original
    configs = getattr(backup, "configs", {})
    for op in ops:
        if op.verb == "delete":
            # the change takes something away
            continue
        if op.verb != "set" or op.option is None:
            return False
        old = _value_of(configs, op.config, op.section, op.option)
        if not isinstance(old, str) or old != str(op.value):
            # the change writes a value that is not the one the backup
            # holds: it is a change of its own
            return False
    return True


def keep_prompt_text(
    record: Mapping[str, Any], backup: Any, state: Any = None
) -> str:
    """The prompt the owner reads: the wording depends on the change."""
    if not closes_only(record, backup, state):
        return KEEP_PROMPT
    if not removes_something(record):
        return KEEP_PROMPT_RULE
    return f"{KEEP_PROMPT_RULE} {KEEP_PROMPT_REMOVAL}"


def removes_something(record: Mapping[str, Any]) -> bool:
    """True when one of the ops of the record takes something away.

    A change that only sets values back removes nothing, so the prompt
    of such a change does not say that something comes back.
    """
    try:
        ops = ops_of(record)
    except VerifyError:
        return False
    return any(op.verb == "delete" for op in ops)


def _unit_name(unit: tuple[str, str, str | None]) -> str:
    config, section, option = unit
    if option is None:
        return f"{config}.{section}"
    return f"{config}.{section}.{option}"


def ops_of(record: Mapping[str, Any]) -> list[owner_ops.OwnerOp]:
    """The ops of a record, as the ops of the grammar.

    The record carries the ops of its script as ``(verb, key, value)``
    triples, so the read-back works from the record alone and never
    has to trust the script on disk.
    """
    try:
        return owner_ops.ops_of(record)
    except owner_ops.OwnerScriptError as exc:
        raise VerifyError(str(exc)) from None


def _units_of(configs: Mapping[str, Any]) -> dict[tuple[str, str, str | None], Any]:
    """Every unit of a set of configs, with its value.

    A list option is a tuple of its items, in the order the router
    answered them.  The metadata keys (``.name``, ``.index`` ...) are
    not units: they are not settings.
    """
    units: dict[tuple[str, str, str | None], Any] = {}
    for config, sections in configs.items():
        if not isinstance(sections, Mapping):
            continue
        for name, entry in sections.items():
            if not isinstance(entry, Mapping):
                # a section that is not a mapping proves nothing
                units[(str(config), str(name), None)] = UNREADABLE
                continue
            section_type = entry.get(".type")
            units[(str(config), str(name), None)] = (
                section_type if isinstance(section_type, str) else UNREADABLE
            )
            for key, value in entry.items():
                if str(key).startswith("."):
                    continue
                if isinstance(value, (list, tuple)):
                    if all(isinstance(item, str) for item in value):
                        units[(str(config), str(name), str(key))] = tuple(value)
                    else:
                        # An item that is not text proves nothing: the
                        # answer is a shape Newton does not know, so it
                        # is UNREADABLE and never a value.
                        units[(str(config), str(name), str(key))] = UNREADABLE
                elif isinstance(value, str):
                    units[(str(config), str(name), str(key))] = value
                else:
                    # A value uci does not answer: None, a dict, a
                    # number.  It proves nothing, so Newton cannot
                    # read it.
                    units[(str(config), str(name), str(key))] = UNREADABLE
    return units


def _value_of(
    configs: Mapping[str, Any], config: str, section: str, option: str | None
) -> Any:
    """The value of one unit in a set of configs, or None when it is absent.

    ``UNREADABLE`` when the answer is a shape Newton does not know: an
    answer Newton cannot read is never a proven absence, because a
    proven absence is what tells Newton that the change did not reach
    the router.
    """
    sections = configs.get(config)
    if not isinstance(sections, Mapping):
        return UNREADABLE
    if section not in sections:
        # the section is not there: a proven absence
        return None
    entry = sections[section]
    if not isinstance(entry, Mapping):
        return UNREADABLE
    if option is None:
        section_type = entry.get(".type")
        return section_type if isinstance(section_type, str) else UNREADABLE
    if option not in entry:
        return None
    value = entry[option]
    if isinstance(value, (list, tuple)):
        if all(isinstance(item, str) for item in value):
            return tuple(value)
        # An item that is not text proves nothing: the answer is a
        # shape Newton does not know, so it is UNREADABLE and never a
        # value.
        return UNREADABLE
    if isinstance(value, str):
        return value
    # a value uci does not answer proves nothing
    return UNREADABLE


def _same(left: Any, right: Any) -> bool:
    """True when two unit values are the same."""
    if isinstance(left, tuple) or isinstance(right, tuple):
        if not isinstance(left, tuple) or not isinstance(right, tuple):
            return False
        return list(left) == list(right)
    return left == right


# ---- the session -----------------------------------------------------------


class _ReadSession:
    """A session that may make the read calls the checks need."""

    def __init__(self, client: Any, session: Any) -> None:
        self._client = client
        self._session = session

    def call(
        self,
        obj: str,
        fn: str,
        args: Mapping[str, Any] | None = None,
    ) -> Any:
        return self._client.call(self._session, obj, fn, dict(args or {}))


def _password(device: Any) -> str:
    """The rpcd password, with the one rule the read path has."""
    return noinstall_read._password(device)


def _login(
    client_factory: Callable[[Any], Any],
    device: Any,
    timeout_s: int = LOGIN_TIMEOUT_S,
) -> tuple[Any, Any]:
    """A fresh limited session, or the reason there is none."""
    client = client_factory(device)
    password = _password(device)
    session = client.login(rpcd.RPCD_USER, password, timeout_s)
    return client, session


def _read_configs(
    session: Any,
    configs: Sequence[str],
    missing: Sequence[str] = (),
) -> tuple[dict[str, Any], str | None]:
    """The named configs, or the reason they could not be read.

    A config the backup says is missing, and that the router still
    refuses, is not a config Newton cannot read: it is a config that is
    still missing.  That is a state the router can be in, and it is
    what "the change did not reach the router" looks like.
    """
    values: dict[str, Any] = {}
    for config in configs:
        # the backup's own reader: one rule for what an answer may look
        # like.  An answer it refuses is an answer Newton cannot read,
        # and an answer Newton cannot read is never a proven absence.
        sections, problem = owner_backup.read_config(session, config)
        if problem == "missing" and config in missing:
            # still missing: an empty answer, not a failure
            values[config] = {}
            continue
        if problem is not None or sections is None:
            return {}, f"the {config} config cannot be read from the router"
        values[config] = sections
    return values, None


def _unreadable_config(
    configs: Sequence[str], current: Mapping[str, Any]
) -> str | None:
    """The name of the first config that holds an answer Newton cannot read.

    A unit that is unreadable is not a value and not an absence: it
    proves nothing, anywhere in the config.  A config that holds one
    cannot be read back at all.
    """
    for config in configs:
        sections = current.get(config)
        if not isinstance(sections, Mapping):
            continue
        for value in _units_of({config: sections}).values():
            if value is UNREADABLE:
                return config
    return None


# ---- the checks ------------------------------------------------------------


def _check_expected(
    current: Mapping[str, Any],
    expected: Mapping[tuple[str, str, str | None], Any],
) -> str | None:
    """Every touched unit holds what the change was to make it hold."""
    for unit, want in expected.items():
        config, section, option = unit
        got = _value_of(current, config, section, option)
        if got is UNREADABLE:
            return f"the {config} config cannot be read from the router"
        if want is None:
            # a proven absence: the answer said so, and the option is
            # not there
            if got is not None:
                return f"the change did not reach {config}.{section}" + (
                    f".{option}" if option else ""
                )
            continue
        if not _same(got, want):
            return f"the change did not reach {config}.{section}" + (
                f".{option}" if option else ""
            )
    return None


def _check_nothing_else(
    current: Mapping[str, Any],
    before: Mapping[str, Any],
    touched: set[tuple[str, str, str | None]],
) -> str | None:
    """Nothing else changed: every other unit still holds what it held."""
    current_units = _units_of(current)
    before_units = _units_of(before)
    for unit in sorted(
        set(current_units) | set(before_units),
        key=lambda item: (item[0], item[1], item[2] or ""),
    ):
        if unit in touched:
            continue
        if unit[2] is not None and unit[2] in VOLATILE_OPTIONS:
            continue
        if current_units.get(unit) is UNREADABLE:
            return f"the {unit[0]} config cannot be read from the router"
        if unit not in current_units:
            return f"UNAPPROVED_CHANGE: {_unit_name(unit)} is gone"
        if unit not in before_units:
            return f"UNAPPROVED_CHANGE: {_unit_name(unit)} is new"
        if not _same(current_units[unit], before_units[unit]):
            return f"UNAPPROVED_CHANGE: {_unit_name(unit)} changed"
    return None


def _section_types(backup: Any) -> dict[tuple[str, str], str]:
    """The type of every section the backup holds.

    The backup is the router's own answer, so it is where the type of
    a section the plan does not create comes from.
    """
    types: dict[tuple[str, str], str] = {}
    for config, sections in getattr(backup, "configs", {}).items():
        if not isinstance(sections, Mapping):
            continue
        for name, entry in sections.items():
            if not isinstance(entry, Mapping):
                continue
            section_type = entry.get(".type")
            if isinstance(section_type, str):
                types[(str(config), str(name))] = section_type
    return types


def _check_class_checks(
    session: Any, record: Mapping[str, Any], backup: Any
) -> str | None:
    """The mandatory checks of the change's classes.

    The batch that is checked is the RESOLVED one: the ops of the
    record, with the anonymous addresses (``@type[0]``) resolved to the
    names the script writes.  A probe that names an address the router
    does not know never answers.

    The types of the sections come from the backup: the change may
    touch an option of a section the plan does not create, and only the
    router knows what type that section is.
    """
    ops = ops_of(record)
    batch = "\n".join(owner_ops.batch_lines(ops))
    return noinstall_checks.check_class_checks(
        session, batch, _section_types(backup)
    )


def _check_claims(session: Any, probes: Any) -> str | None:
    """The claim probes of the record that can run."""
    return noinstall_checks.check_claims(session, probes)


# ---- the owner prompt ------------------------------------------------------


def _host_time(epoch: float) -> str:
    """The host time as HH:MM:SS."""
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def unknown_advice(device_name: str, session_id: str, deadline: float) -> str:
    """What the owner is told when Newton cannot tell what happened.

    The owner must not touch the router while the change may still be
    waiting for confirmation: the router's own timer undoes it.
    """
    return (
        "Do nothing. If the change was not confirmed, the router restores "
        f"itself at about {_host_time(deadline)} (host time). Run "
        f"`newton-router-setup {device_name} owner-finish {session_id}` "
        "after that to check."
    )


def tty_prompt(
    deadline: float, now: Callable[[], float] = time.time
) -> str | None:
    """One line from the TTY, or None when there is none to read.

    The line is read from the TTY, never from the ssh lane: the ssh
    lane carries the script, and a line of the script would be read as
    the owner's answer.

    The clock is the caller's: the deadline is counted from the same
    clock the rest of the read-back uses.
    """
    remaining = deadline - now() - rpcd_txn.RESOLVE_MARGIN_S
    if remaining <= 0:
        return None
    try:
        with open("/dev/tty", "r", encoding="utf-8") as tty:
            ready, _, _ = select.select([tty], [], [], remaining)
            if not ready:
                return None
            return tty.readline()
    except (OSError, ValueError):
        return None


# ---- the read-back ---------------------------------------------------------


def finish(
    device: Any,
    record: Mapping[str, Any],
    backup: Any,
    run: Mapping[str, Any],
    client_factory: Callable[[Any], Any],
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    keep_prompt: Callable[[float], str | None] | None = None,
    confirm_token: str | None = None,
    state: Any = None,
) -> Verdict:
    """Read the change back, and confirm it only when everything passes.

    Returns the verdict.  The verdict's state is ``CONFIRMED`` only when
    every check passed (and, for a change that can open the router to
    the internet, only when the owner typed ``keep``).

    The internet check runs right after the window is read: it waits
    for the router's own reload (the apply returns before netifd has
    taken the uplinks down, measured: the check ran about a second
    after the apply, while the uplinks were still up) and retries
    until the router has the internet again.  ``sleep`` is the caller's
    sleep, so a test never waits for real time.

    ``confirm_token`` is the session the script opened.  It is the only
    session rpcd lets confirm a root script's apply (measured: a fresh
    limited session gets ``[6]``), and the script gave it exactly one
    right: ``uci confirm``.  The token is used here and nowhere else,
    and it is never written down.
    """
    timeout_s = record.get("timeout_s")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int):
        raise VerifyError("the plan record carries no window")
    started_at = run.get("started_at")
    if isinstance(started_at, bool) or not isinstance(started_at, (int, float)):
        raise VerifyError("the run record carries no start time")
    deadline = float(started_at) + float(timeout_s)
    notes: list[str] = []
    not_verified = record.get("not_verified")
    not_verified = (
        tuple(str(item) for item in not_verified)
        if isinstance(not_verified, list)
        else ()
    )
    ops = ops_of(record)
    expected = owner_ops.expected_after(ops, backup)
    # The touched units are the ops' own units plus the options of every
    # section the change deletes: the change takes the whole section
    # away, so the options of that section change too.  Their EXPECTED
    # values are not in ``expected``: a section that is gone holds no
    # options.
    touched = owner_ops.touched_units(ops, backup)
    configs = sorted({config for config, _section, _option in touched})

    def verdict(
        state: str,
        checks: Sequence[str],
        extra: Sequence[str] = (),
        owner_keep: bool | None = None,
    ) -> Verdict:
        return Verdict(
            state=state,
            checks=tuple(checks),
            deadline=deadline,
            notes=tuple(notes) + tuple(extra),
            not_verified=not_verified,
            owner_keep=owner_keep,
        )

    # 1. the deadline: the host clock, and the margin
    if now() >= deadline - rpcd_txn.RESOLVE_MARGIN_S:
        notes.append("the window is nearly over; there is no time to confirm")
        return verdict(UNKNOWN, ())

    # 2. reachability: a fresh limited session.  The session outlives
    #    the internet check's whole budget, because the check waits and
    #    retries and the class checks run after it.
    try:
        client, session = _login(
            client_factory, device, timeout_s=CHECK_TIMEOUT_S
        )
    except rpcd.RpcdCallFailed:
        notes.append("the router refused the login; the change cannot be confirmed")
        return verdict(UNKNOWN, ())
    except rpcd.RpcdError:
        notes.append("the router could not be reached; the change cannot be confirmed")
        return verdict(UNKNOWN, ())
    except Exception:
        notes.append("the router could not be reached; the change cannot be confirmed")
        return verdict(UNKNOWN, ())
    checks: list[str] = ["reachable"]

    read_session = _ReadSession(client, session)
    try:
        # 3a. the pending detector: a window must be open
        transaction = rpcd_txn.RpcdTransaction(client)
        try:
            pending = transaction.pending(session)
        except rpcd.RpcdError:
            notes.append("the pending state of the router cannot be read")
            return verdict(UNKNOWN, checks)
        if not pending:
            # 7. the window was not open: the change was never applied
            state, extra = _classify(
                device,
                backup,
                expected,
                touched,
                client_factory,
                NOT_APPLIED,
            )
            return verdict(state, checks, extra)
        checks.append("pending")

        # 3b. the router still has the internet: the installed router
        # program's own check, run before every confirm there.  The
        # check waits for the router's own reload (the apply returns
        # before netifd has taken the uplinks down) and retries until
        # the router has the internet again or the budget is gone.  It
        # runs right after the pending check, so the class checks run
        # after the settle too.
        #
        # The settle is anchored at the apply: the pending check has
        # just proved that the change is on the router, so the wait for
        # the router's own reload starts here.  The start of the run is
        # NOT the anchor: an owner script asks the owner for the router
        # password before it applies the change, and on a
        # password-authenticated router that wait alone is often longer
        # than the settle, so a settle measured from the start of the run
        # is gone by the time the change is applied.
        applied_at = now()
        failure = noinstall_checks.wait_for_internet(
            read_session,
            applied_at=applied_at,
            deadline=deadline,
            now=now,
            sleep=sleep,
        )
        if failure is not None:
            notes.append(failure)
            return verdict(UNKNOWN, checks)
        checks.append("internet")

        # 3c. every touched unit holds what the change made it hold
        current, problem = _read_configs(
            read_session, configs, getattr(backup, "missing", ())
        )
        if problem is not None:
            notes.append(problem)
            return verdict(UNKNOWN, checks)
        unreadable = _unreadable_config(configs, current)
        if unreadable is not None:
            notes.append(f"the {unreadable} config cannot be read from the router")
            return verdict(UNKNOWN, checks)
        failure = _check_expected(current, expected)
        if failure is not None:
            notes.append(failure)
            return verdict(UNKNOWN, checks)
        checks.append("expected")

        # 3d. nothing else changed
        before = {
            config: sections
            for config, sections in getattr(backup, "configs", {}).items()
            if config in configs
        }
        failure = _check_nothing_else(current, before, touched)
        if failure is not None:
            notes.append(failure)
            return verdict(UNKNOWN, checks)
        checks.append("nothing-else")

        # 3e. the mandatory checks of the change's classes
        failure = _check_class_checks(read_session, record, backup)
        if failure is not None:
            notes.append(failure)
            return verdict(UNKNOWN, checks)
        checks.append("class-checks")

        # 3f. Newton's own login still holds exactly the groups it asked for
        differences = rpcd.check_acls(getattr(session, "acls", None))
        if differences:
            notes.append("the groups of Newton's own login changed")
            return verdict(UNKNOWN, checks)
        checks.append("acls")

        # 3g. the claims that can run
        failure = _check_claims(read_session, record.get("probes"))
        if failure is not None:
            notes.append(failure)
            return verdict(UNKNOWN, checks)
        checks.append("claims")

        # 4. the owner keeps an exposure
        owner_keep: bool | None = None
        if is_exposure(record):
            answer = _ask_keep(
                deadline,
                keep_prompt,
                now,
                keep_prompt_text(record, backup, state),
            )
            owner_keep = isinstance(answer, str) and answer.strip() == "keep"
            if not owner_keep:
                notes.append(DID_NOT_KEEP)
                return verdict(UNKNOWN, checks, owner_keep=False)
            checks.append("keep")

        # 5. the confirm.  The deadline is checked AGAIN here: the
        # checks and the prompt took time, and a confirm inside the
        # margin (or after the window) is a confirm the router cannot
        # undo any more.
        if now() >= deadline - rpcd_txn.RESOLVE_MARGIN_S:
            notes.append("the window is nearly over; there is no time to confirm")
            return verdict(UNKNOWN, checks, owner_keep=owner_keep)
        # The confirm goes out with the SESSION THE SCRIPT OPENED, over
        # the same pinned client.  A fresh limited session cannot
        # confirm a root script's apply: rpcd answers [6] (measured).
        # The token is the session id and nothing else, and it is never
        # written down.
        if not confirm_token:
            notes.append(NO_TOKEN)
            return verdict(UNKNOWN, checks, owner_keep=owner_keep)
        confirm_session = _ReadSession(client, _token_session(confirm_token))
        try:
            confirm_session.call("uci", "confirm", {})
        except rpcd.RpcdCallFailed:
            notes.append("the router refused the confirm")
            return verdict(UNKNOWN, checks, owner_keep=owner_keep)
        except rpcd.RpcdError:
            notes.append("the confirm could not be sent")
            return verdict(UNKNOWN, checks, owner_keep=owner_keep)
        checks.append("confirmed")

        # 5b. the re-read, in another fresh session
        note = _reread(device, expected, client_factory)
        extra = ("re-read failed",) if note else ()
        return verdict(CONFIRMED, checks, extra, owner_keep=owner_keep)
    finally:
        try:
            session.mark_spent()
        except Exception:
            pass


def _token_session(token: str) -> rpcd.RpcdSession:
    """The session object of the token the script printed.

    It is never logged, never stored and never shown: the repr of a
    session hides its id.
    """
    return rpcd.RpcdSession(
        id=token,
        expires_at=time.time() + CONFIRM_TIMEOUT_S,
        acls={},
        timeout_s=CONFIRM_TIMEOUT_S,
    )


def _ask_keep(
    deadline: float,
    keep_prompt: Callable[[float], str | None] | None,
    now: Callable[[], float] = time.time,
    text: str = KEEP_PROMPT,
) -> str | None:
    """Ask the owner to keep an exposure, and read the answer.

    The prompt is printed on the terminal the owner is sitting at; the
    answer is read from the TTY, never from the ssh lane.  The words
    are the ones the change deserves: a change that only takes a rule
    away does not open the router, and the prompt says so.
    """
    print(text.format(_host_time(deadline)))
    if keep_prompt is None:
        return tty_prompt(deadline, now)
    return keep_prompt(deadline)


def _reread(
    device: Any,
    expected: Mapping[tuple[str, str, str | None], Any],
    client_factory: Callable[[Any], Any],
) -> str | None:
    """Read the touched units back in another fresh session.

    Returns None when the re-read agreed, and "re-read failed" when it
    did not: the change was confirmed either way, so the state stays
    CONFIRMED.
    """
    configs = sorted({config for config, _section, _option in expected})
    try:
        client, session = _login(client_factory, device)
    except Exception:
        return "re-read failed"
    try:
        current, problem = _read_configs(_ReadSession(client, session), configs)
        if problem is not None:
            return "re-read failed"
        if _check_expected(current, expected) is not None:
            return "re-read failed"
    except Exception:
        return "re-read failed"
    finally:
        try:
            session.mark_spent()
        except Exception:
            pass
    return None


def _matches(
    current_units: Mapping[tuple[str, str, str | None], Any],
    wanted_units: Mapping[tuple[str, str, str | None], Any],
    touched: set[tuple[str, str, str | None]],
) -> bool:
    """True when every touched unit holds what the wanted units hold."""
    for unit in touched:
        got = current_units.get(unit)
        want = wanted_units.get(unit)
        if got is None and want is None:
            continue
        if not _same(got, want):
            return False
    return True


def _touched_state(
    current: Mapping[str, Any],
    backup: Any,
    expected: Mapping[tuple[str, str, str | None], Any],
    touched: set[tuple[str, str, str | None]],
) -> str:
    """Whether the touched units hold the old values, the new ones or neither."""
    current_units = _units_of(current)
    before_units = _units_of(getattr(backup, "configs", {}))
    if _matches(current_units, before_units, touched):
        return "before"
    if _matches(current_units, expected, touched):
        return "after"
    return "neither"


def _classify(
    device: Any,
    backup: Any,
    expected: Mapping[tuple[str, str, str | None], Any],
    touched: set[tuple[str, str, str | None]],
    client_factory: Callable[[Any], Any],
    absent_state: str,
) -> tuple[str, tuple[str, ...]]:
    """The state of the change, read from the router.

    ``absent_state`` is the word for "the router holds the old values":
    ``NOT APPLIED`` when no window was ever open, ``ROLLED BACK`` when
    the window closed without a confirm.
    """
    configs = sorted({config for config, _section, _option in touched})
    try:
        client, session = _login(client_factory, device)
    except Exception:
        return UNKNOWN, ("the router could not be reached",)
    try:
        current, problem = _read_configs(
            _ReadSession(client, session), configs,
            getattr(backup, "missing", ()),
        )
        if problem is not None:
            return UNKNOWN, (problem,)
        unreadable = _unreadable_config(configs, current)
        if unreadable is not None:
            return UNKNOWN, (
                f"the {unreadable} config cannot be read from the router",
            )
        state = _touched_state(current, backup, expected, touched)
        if state == "before":
            return absent_state, ()
        if state == "after":
            return KEPT, ("the router restarted or someone else confirmed",)
        return UNKNOWN, ("the router holds something Newton cannot explain",)
    except Exception:
        return UNKNOWN, ("the router could not be read",)
    finally:
        try:
            session.mark_spent()
        except Exception:
            pass


def settle(
    device: Any,
    record: Mapping[str, Any],
    backup: Any,
    run: Mapping[str, Any],
    client_factory: Callable[[Any], Any],
    sleep: Callable[[float], None] = time.sleep,
    poll_s: float = 5.0,
    now: Callable[[], float] = time.time,
    previous: Verdict | None = None,
) -> Verdict:
    """Wait for the window to close, and say what the router did.

    The pending detector is polled every ``poll_s`` seconds until the
    host clock passes the window's own deadline plus
    ``SETTLE_GRACE_S``.  The budget is counted from the DEADLINE, not
    from the moment the settle was called: a window that closes a
    little after the deadline is still a window that closed, and the
    router undoes the change a little after the deadline too.

    The state is then read from the router, never from the clock: a
    change that was rolled back, a change that stayed, and a change
    Newton cannot explain are three different answers.

    The notes of the read-back that came before are KEPT: the owner did
    not keep the change, and an unapproved change was seen, and both
    are still true whatever the router did with it.
    """
    timeout_s = record.get("timeout_s")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int):
        raise VerifyError("the plan record carries no window")
    ops = ops_of(record)
    expected = owner_ops.expected_after(ops, backup)
    # The touched units are the ops' own units plus the options of every
    # section the change deletes: the change takes the whole section
    # away, so the options of that section change too.  Their EXPECTED
    # values are not in ``expected``: a section that is gone holds no
    # options.
    touched = owner_ops.touched_units(ops, backup)
    configs = sorted({config for config, _section, _option in touched})
    started_at = run.get("started_at")
    if isinstance(started_at, bool) or not isinstance(started_at, (int, float)):
        raise VerifyError("the run record carries no start time")
    deadline = float(started_at) + float(timeout_s)
    notes: list[str] = []
    owner_keep: bool | None = None
    not_verified: tuple[str, ...] = ()
    if previous is not None:
        notes.extend(previous.notes)
        owner_keep = previous.owner_keep
        not_verified = previous.not_verified
    # The budget runs from the window's own deadline: the router undoes
    # the change when ITS timer ends, which is a little after the
    # deadline Newton knows.
    limit = deadline + SETTLE_GRACE_S
    # A host clock that stands still or was stepped back must not make
    # this poll for ever: the polls are bounded by the window too.
    polls_left = int((timeout_s + SETTLE_GRACE_S) / poll_s) + 1
    pending = True
    while True:
        polls_left -= 1
        try:
            client, session = _login(client_factory, device)
        except Exception:
            # The router cannot be reached: the state of the window is
            # unknown, and unknown is never "not pending".
            if now() >= limit or polls_left <= 0:
                break
            sleep(poll_s)
            continue
        try:
            transaction = rpcd_txn.RpcdTransaction(client)
            try:
                pending = transaction.pending(session)
            except rpcd.RpcdError:
                pending = True
        finally:
            try:
                session.mark_spent()
            except Exception:
                pass
        if not pending:
            break
        if now() >= limit or polls_left <= 0:
            break
        sleep(poll_s)
    if pending:
        # the window is still open: the router has not decided yet, and
        # it may still undo the change.  Nothing is said about it.
        notes.append("the change is still waiting for confirmation on the router")
        return Verdict(
            state=UNKNOWN,
            checks=(),
            deadline=deadline,
            notes=tuple(notes),
            not_verified=not_verified,
            owner_keep=owner_keep,
        )
    state, extra = _classify(
        device, backup, expected, touched, client_factory, ROLLED_BACK
    )
    return Verdict(
        state=state,
        checks=(),
        deadline=deadline,
        notes=tuple(notes) + tuple(extra),
        not_verified=not_verified,
        owner_keep=owner_keep,
    )
