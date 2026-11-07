"""The safety checks that can run over the stock ACL groups.

ADR-021 point 5: every allowlisted change class names its mandatory
safety checks, and a missing mandatory check makes the class ineligible
for auto-apply.  This module is the table of what the stock groups can
run, the probe runner that runs it, and the per-class answer.

The probes keep the router program's own meaning (design 4.3, the
``probe_*`` functions of ``newton-router``): the same pass, the same
fail, and "could not run" where the router program would have had no
answer at all.  A probe never passes on an error.

Three rules keep that promise over the stock groups:

* only the measured shapes count.  An answer of a shape Newton does not
  know is no answer at all: it ends as "could not run", never as a pass;
* a refusal is not an answer, except where the router's own meaning says
  it is (``uci get``'s ``[4]`` for ``uci-unset``: the config file is not
  there, so the option is not set either).  Every other refusal ends as
  "could not run";
* the arguments are checked with the installed path's own checker
  (``probes.validate_probes``), so a probe whose arguments do not fit
  never reaches the router, and a secret-looking option is refused
  before the call, exactly as it is on the installed path.  The one
  probe that exists only here (``uci-list``) keeps its own small rule
  and the same refusals.

Nothing here calls the router: a caller opens a session (one rpcd
login) and hands it over.  A caller that returns a detail must put it
in an untrusted-device-data envelope: a detail may hold the router's
own text.  A detail never holds a value the router has: a mismatch says
"mismatch", the way the router program's own probes say it.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, Sequence

from . import change_classes
from . import probes
from . import rpcd_txn
from . import touched
from .adapters.openwrt_rpcd import RpcdCallFailed, RpcdError
from .redact import _looks_like_secret_option


#: The rpcd call that runs each probe, or None when the stock groups
#: cannot run it.  Every name in ``probes.PROBE_TABLE`` has an entry, so
#: a new probe cannot be forgotten.
PROBE_SUPPORT: dict[str, str | None] = {
    # a local constant failure: it means "this check fails", so it needs
    # no call at all.
    "fail": None,
    "ping": "file exec /bin/ping",
    "resolve": "file exec /usr/bin/nslookup",
    "service-running": "service list",
    "uci-equals": "uci get",
    "uci-unset": "uci get",
    "listen": None,
    "nft-rule": None,
    "nft-rule-order": None,
    "nft-rule-near": None,
    "nft-set-has": None,
    "conf-has": None,
    "proc-args": None,
    "iface-field": "network.interface dump",
    "iface-absent": "network.interface dump",
    "sysctl-equals": "file read",
    "ra-absent": None,
    "log-has": "log read",
    "root-password-class": None,
}

#: The configs the rpcd user may write.  The ``system`` config is not
#: on the list: the router's own groups make it read-only.
WRITABLE_CONFIGS: tuple[str, ...] = ("dhcp", "firewall", "network", "wireless")

#: The ONE list of the change classes Newton may apply itself on a
#: no-install router (ADR-021 point 4).  A
#: change of any other class is an owner script, and a Wi-Fi change
#: never is: the wireless check is not measured yet, and a Wi-Fi key is
#: a secret the owner sets in LuCI.
AUTO_APPLY: tuple[str, ...] = ("dhcp-reservations", "dns")

#: The reason the plan shows when Newton applies the change itself.
AUTO_APPLY_REASON = "Newton applies this itself"

#: The start of the reason the plan shows when it does not.
OWNER_SCRIPT_REASON = "this needs an owner script because "

#: The internet probes every confirm runs first.  They are the ones the
#: installed router program runs before every confirm (``cmd_verify``
#: of ``newton-router``): ping 1.1.1.1, and openwrt.org resolved by the
#: router itself.  A router without the internet confirms nothing, in
#: the installed mode and here.
INTERNET_PROBES: tuple[tuple[str, ...], ...] = (
    ("ping", "1.1.1.1"),
    ("resolve", "openwrt.org", "127.0.0.1"),
)

#: The seconds the check waits after the apply before the first probe.
#: ``uci apply`` returns before the router's network reload is done:
#: measured on the real router, an owner script that took the uplinks
#: down was confirmed 2.8 s after the run started, and the internet
#: check ran about a second after the apply, while netifd had not
#: taken the uplinks down yet.  The check waits for the reload.
INTERNET_SETTLE_S = 10

#: The seconds between two internet probes.
INTERNET_RETRY_S = 5

#: The longest the check waits, after the settle, for the internet to
#: come back.
INTERNET_WAIT_MAX_S = 60

#: The seconds kept free before the deadline, for the rest of the
#: checks and the confirm.
INTERNET_RESERVE_S = 10

#: The most internet probes one check runs.  Every try waits
#: ``INTERNET_RETRY_S`` and the wait is at most ``INTERNET_WAIT_MAX_S``
#: long, so this many tries fit in the budget.  The bound holds even
#: when the clock does not move while the check waits.
INTERNET_MAX_TRIES = 1 + INTERNET_WAIT_MAX_S // INTERNET_RETRY_S

#: The number of log lines a log check reads.
LOG_LINES = 100

#: The probes that have an answer here without any rpcd call: a planted
#: failure is a local constant, so it runs (and fails) on its own.
LOCAL_PROBES: frozenset[str] = frozenset({"fail"})

#: The probes that exist only on the no-install path.  The installed
#: router program has no such probe, so ``probes.PROBE_TABLE`` does not
#: name it and ``PROBE_SUPPORT`` does not carry it: it runs here and
#: nowhere else, and it keeps its own small grammar.
NOINSTALL_PROBES: frozenset[str] = frozenset({"uci-list"})

#: The sysctl keys the stock groups may read: the per-interface ones.
#: The path is ``/proc/sys/net/<key>``.  A part is a plain name: no
#: leading dot and no ``..``, so a key can never walk out of the tree
#: it names (``/proc/sys/net/<key>``).
_SYSCTL_RE = re.compile(
    r"^(?:ipv4|ipv6)/conf/(?![.])[A-Za-z0-9_.-]+/(?![.])[A-Za-z0-9_.-]+$"
)


# ---- the session ------------------------------------------------------------


class RpcSession(Protocol):
    """What a probe needs: a session that can make one rpcd call."""

    def call(
        self,
        obj: str,
        fn: str,
        args: Mapping[str, Any] | None = None,
    ) -> Any:
        ...


class _CouldNotRun(Exception):
    """The probe could not run: the reason is in the message."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class _Refused(Exception):
    """The router refused the call; its code is kept, never shown."""

    def __init__(self, code: int) -> None:
        super().__init__("the router refused the call")
        self.code = code


# ---- the result ------------------------------------------------------------


@dataclass(frozen=True)
class ProbeResult:
    """What one probe ended in.

    ``passed`` is True, False, or None when the probe could not run at
    all.  ``detail`` is a fixed word, plus the router's own text where
    it helps: a caller that returns it must put it in an
    untrusted-device-data envelope.
    """

    passed: bool | None
    detail: str


# ---- the plumbing -----------------------------------------------------------


def _call(
    session: RpcSession,
    obj: str,
    fn: str,
    args: Mapping[str, Any] | None = None,
) -> Any:
    """One rpcd call, with the router's refusals turned into exceptions."""
    try:
        return session.call(obj, fn, dict(args or {}))
    except RpcdCallFailed as exc:
        raise _Refused(exc.code) from None
    except RpcdError:
        raise _CouldNotRun("the router could not be reached") from None


def _split_uci_path(path: str) -> tuple[str, str, str | None]:
    """A uci path as (config, section, option)."""
    parts = path.split(".")
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], None
    return parts[0], "", None


def _bare(value: Any) -> str:
    """A value as ``uci get`` prints it."""
    if isinstance(value, (list, tuple)):
        return " ".join(str(item) for item in value)
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _scalar(value: Any) -> str:
    """A value as the router's own tools print it (true/false)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _uci_get(
    session: RpcSession,
    config: str,
    section: str,
    option: str | None,
) -> tuple[str, Any]:
    """The answer of ``uci get``: ("value", v), ("unset", None) or ("section", v).

    Only the measured shapes count: a value, an empty answer (the entry
    is not set) and the values of a section.  A refusal is raised as
    ``_Refused`` so that the probe can give it its measured meaning (or
    not); an answer of a shape Newton does not know is "could not run".

    A config the stock groups may not read is refused before the router
    is asked: the router answers such a config with "permission denied"
    anyway.
    """
    # imported here, not at the top: the read module needs the server's
    # own read grammar, and the server may import this module one day.
    from .noinstall_read import READABLE_CONFIGS

    if config not in READABLE_CONFIGS:
        raise _CouldNotRun("this config is not readable in no-install access")
    args: dict[str, Any] = {"config": config}
    if section:
        args["section"] = section
    if option:
        args["option"] = option
    answer = _call(session, "uci", "get", args)
    if not isinstance(answer, Mapping):
        raise _CouldNotRun("the answer could not be read")
    if option is not None:
        if "value" in answer:
            if not _is_uci_value(answer["value"]):
                raise _CouldNotRun("the answer could not be read")
            return ("value", answer["value"])
        if not answer:
            # the measured "not set" answer: the call succeeded and
            # carried no data at all
            return ("unset", None)
        raise _CouldNotRun("the answer could not be read")
    values = answer.get("values")
    if isinstance(values, Mapping):
        if not values:
            # an empty values mapping is not a section: a real section
            # always carries its .name and its .type, so the answer is
            # one Newton does not understand
            raise _CouldNotRun("the answer could not be read")
        return ("section", values)
    if not answer:
        # the measured "not there" answer: the call succeeded and
        # carried no data at all
        return ("unset", None)
    raise _CouldNotRun("the answer could not be read")


def _is_uci_value(value: Any) -> bool:
    """Is this a value uci can hold? (a string, a number, a list of them)"""
    if isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, (list, tuple)):
        return all(isinstance(item, (str, bool, int)) for item in value)
    return False


def _dump_entries(answer: Any) -> list[Any]:
    """The interfaces of a dump, or "could not run".

    The measured shape of ``network.interface dump`` is a mapping with an
    ``interface`` list of mappings.  Anything else is an answer Newton
    does not understand, and an answer nobody understands is no answer.
    """
    if not isinstance(answer, Mapping):
        raise _CouldNotRun("the answer could not be read")
    entries = answer.get("interface")
    if not isinstance(entries, (list, tuple)):
        raise _CouldNotRun("the answer could not be read")
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise _CouldNotRun("the answer could not be read")
    return list(entries)


def _interface(entries: list[Any], name: str) -> Mapping[str, Any] | None:
    """The interface of a dump, by name."""
    for entry in entries:
        if entry.get("interface") == name:
            return entry
    return None


def _running(instance: Any) -> bool | None:
    """Is this service instance running?  None when the answer says nothing.

    The measured answer says ``running: true`` or ``running: false``; a
    missing or unreadable field is an answer nobody understands.
    """
    if not isinstance(instance, Mapping):
        return None
    running = instance.get("running")
    if isinstance(running, bool):
        return running
    return None


def _holds(line: str, texts: Sequence[str]) -> bool:
    """The router program's rule: the texts must appear in order.

    A text that starts with ``!`` must not appear at all; the others
    must appear in order, without overlap.  The match is a plain
    substring, never a regular expression.
    """
    rest = line
    for text in texts:
        if text.startswith("!"):
            if text[1:] in line:
                return False
            continue
        position = rest.find(text)
        if position < 0:
            return False
        rest = rest[position + len(text) :]
    return True


def _expect_ok(expect: str, count: int) -> bool:
    """The router program's expectation rule."""
    if expect == "present":
        return count >= 1
    if expect == "absent":
        return count == 0
    if expect.startswith("eq:"):
        return count == int(expect[3:])
    if expect.startswith("min:"):
        return count >= int(expect[4:])
    raise _CouldNotRun("the expectation could not be read")


# ---- the probes ------------------------------------------------------------


def _probe_fail(session: RpcSession, args: list[str]) -> ProbeResult:
    """``fail`` never passes: it means "this check fails"."""
    return ProbeResult(False, "planted")


def _probe_ping(session: RpcSession, args: list[str]) -> ProbeResult:
    """The exit of the ping is the answer."""
    host = args[0]
    count = args[1] if len(args) > 1 else "1"
    answer = _call(
        session,
        "file",
        "exec",
        {"command": "/bin/ping", "params": ["-c", count, "-W", "3", host]},
    )
    code = _exec_code(answer)
    if code is None:
        raise _CouldNotRun("the answer could not be read")
    return ProbeResult(code == 0, "ok" if code == 0 else "fail")


def _probe_resolve(session: RpcSession, args: list[str]) -> ProbeResult:
    """The exit of the nslookup is the answer."""
    host = args[0]
    server = args[1] if len(args) > 1 else "127.0.0.1"
    answer = _call(
        session,
        "file",
        "exec",
        {"command": "/usr/bin/nslookup", "params": [host, server]},
    )
    code = _exec_code(answer)
    if code is None:
        raise _CouldNotRun("the answer could not be read")
    return ProbeResult(code == 0, "ok" if code == 0 else "fail")


def _exec_code(answer: Any) -> int | None:
    if not isinstance(answer, Mapping):
        return None
    code = answer.get("code")
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    return code


def _probe_service_running(session: RpcSession, args: list[str]) -> ProbeResult:
    """Is the service (or one of its instances) running?"""
    service = args[0]
    instance = args[1]
    state = args[2] if len(args) > 2 else "present"
    answer = _call(session, "service", "list", {"name": service})
    if not isinstance(answer, Mapping):
        raise _CouldNotRun("the answer could not be read")
    if not answer:
        # the measured "no such service" answer: the call succeeded and
        # the mapping is empty (the measured answer of an unknown
        # service is ``[0]``)
        found = False
    elif service not in answer:
        # a mapping that is not empty and does not carry the service is
        # an answer nobody understands: it could name another service
        raise _CouldNotRun("the answer could not be read")
    else:
        entry = answer[service]
        if not isinstance(entry, Mapping):
            raise _CouldNotRun("the answer could not be read")
        instances = entry.get("instances")
        if not isinstance(instances, Mapping):
            raise _CouldNotRun("the answer could not be read")
        # every instance is read, not only the one that was asked for:
        # one unreadable entry makes the whole answer unreadable
        running_of: dict[str, bool] = {}
        for name, one in instances.items():
            running = _running(one)
            if running is None:
                raise _CouldNotRun("the answer could not be read")
            running_of[name] = running
        if instance == "any":
            found = any(running_of.values())
        else:
            # the measured answer of a service without that instance:
            # the service does not run it
            found = running_of.get(instance, False)
    if state == "present":
        return ProbeResult(found, "ok" if found else "absent")
    if state == "absent":
        return ProbeResult(not found, "ok" if not found else "present")
    raise _CouldNotRun("the expectation could not be read")


def _probe_uci_equals(session: RpcSession, args: list[str]) -> ProbeResult:
    """Does the option hold the expected value?"""
    path, expected = args[0], args[1]
    config, section, option = _split_uci_path(path)
    try:
        state, value = _uci_get(session, config, section, option)
    except _Refused:
        # a refusal has no measured meaning here: the option may or may
        # not hold the value, and Newton does not know
        raise _CouldNotRun("the router refused the call") from None
    if state == "unset":
        return ProbeResult(False, "unset")
    if state != "value":
        raise _CouldNotRun("the answer could not be read")
    text = _bare(value)
    if text != expected:
        # the router program's own word: the value stays on the router
        # and never travels back
        return ProbeResult(False, "mismatch")
    return ProbeResult(True, "ok")


def _probe_uci_unset(session: RpcSession, args: list[str]) -> ProbeResult:
    """Is the option (or the section) not set?"""
    path = args[0]
    config, section, option = _split_uci_path(path)
    try:
        state, _value = _uci_get(session, config, section, option)
    except _Refused as exc:
        if exc.code == 4:
            # no such config file: the option is not set either
            return ProbeResult(True, "ok")
        raise _CouldNotRun("the router refused the call") from None
    if state == "unset":
        return ProbeResult(True, "ok")
    if state in ("value", "section"):
        return ProbeResult(False, "present")
    raise _CouldNotRun("the answer could not be read")


def _probe_uci_list(session: RpcSession, args: list[str]) -> ProbeResult:
    """Does the option's list hold what the batch says it holds?

    This probe exists only on the no-install path.  The installed
    router program has no ``uci-list`` probe: it compares a list with
    the whole list it expects, and it cannot know the list the router
    held before the batch was applied.  The no-install path can say
    more: it reads the list as it is and checks the values the batch
    added (which must be in it) and the values the batch removed
    (which must not be in it).

    The list is read with the same ``_uci_get`` the other uci probes
    use: an option with one value is a one-item list, and the measured
    empty answer (the option is not set) is the empty list.  A bad
    answer, a refusal and an option name that looks like a secret
    never pass: the rules of the r2 review hold here too.
    """
    path = args[0]
    config, section, option = _split_uci_path(path)
    required = [item[1:] for item in args[1:] if item.startswith("+")]
    forbidden = [item[1:] for item in args[1:] if item.startswith("-")]
    try:
        state, value = _uci_get(session, config, section, option)
    except _Refused:
        # a refusal has no measured meaning here: the list may or may
        # not hold the values, and Newton does not know
        raise _CouldNotRun("the router refused the call") from None
    if state == "unset":
        items: list[str] = []
    elif state == "value":
        raw = value if isinstance(value, (list, tuple)) else [value]
        items = [_bare(item) for item in raw]
    else:
        raise _CouldNotRun("the answer could not be read")
    for want in required:
        if want not in items:
            # the router program's own word: the value stays on the
            # router and never travels back
            return ProbeResult(False, "mismatch")
    for unwanted in forbidden:
        if unwanted in items:
            return ProbeResult(False, "mismatch")
    return ProbeResult(True, "ok")


def _probe_iface_field(session: RpcSession, args: list[str]) -> ProbeResult:
    """Does the interface's field hold the expected value?"""
    iface, field, expected = args[0], args[1], args[2]
    answer = _call(session, "network.interface", "dump", {})
    entry = _interface(_dump_entries(answer), iface)
    if entry is None:
        # the router program's own word: the interface is not there
        return ProbeResult(False, "error")
    if field not in entry:
        return ProbeResult(False, "mismatch")
    text = _scalar(entry[field])
    if text != expected:
        # the router program's own word: the value stays on the router
        # and never travels back
        return ProbeResult(False, "mismatch")
    return ProbeResult(True, "ok")


def _probe_iface_absent(session: RpcSession, args: list[str]) -> ProbeResult:
    """Is the interface not there?"""
    iface = args[0]
    answer = _call(session, "network.interface", "dump", {})
    entry = _interface(_dump_entries(answer), iface)
    if entry is None:
        return ProbeResult(True, "ok")
    return ProbeResult(False, "present")


def _probe_sysctl_equals(session: RpcSession, args: list[str]) -> ProbeResult:
    """Does the sysctl key hold the expected value?"""
    key, expected = args[0], args[1]
    match = _SYSCTL_RE.fullmatch(key)
    if match is None:
        raise _CouldNotRun("the stock groups cannot read this key")
    path = f"/proc/sys/net/{key}"
    try:
        answer = _call(session, "file", "read", {"path": path})
    except _Refused:
        raise _CouldNotRun("the router refused the call") from None
    if not isinstance(answer, Mapping):
        raise _CouldNotRun("the answer could not be read")
    data = answer.get("data")
    if not isinstance(data, str):
        raise _CouldNotRun("the answer could not be read")
    lines = data.splitlines()
    value = lines[0] if lines else ""
    if value != expected:
        # the router program's own word: the value stays on the router
        # and never travels back
        return ProbeResult(False, "mismatch")
    return ProbeResult(True, "ok")


def _probe_log_has(session: RpcSession, args: list[str]) -> ProbeResult:
    """Do the log lines satisfy the expectation?"""
    expect = args[0]
    texts = list(args[1:])
    answer = _call(session, "log", "read", {"lines": LOG_LINES, "stream": False})
    if not isinstance(answer, Mapping):
        raise _CouldNotRun("the answer could not be read")
    entries = answer.get("log")
    if not isinstance(entries, (list, tuple)):
        raise _CouldNotRun("the answer could not be read")
    count = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise _CouldNotRun("the answer could not be read")
        message = entry.get("msg")
        if not isinstance(message, str):
            raise _CouldNotRun("the answer could not be read")
        if _holds(message, texts):
            count += 1
    ok = _expect_ok(expect, count)
    return ProbeResult(ok, "ok" if ok else f"count={count}")


_PROBES: dict[str, Any] = {
    "fail": _probe_fail,
    "ping": _probe_ping,
    "resolve": _probe_resolve,
    "service-running": _probe_service_running,
    "uci-equals": _probe_uci_equals,
    "uci-unset": _probe_uci_unset,
    "uci-list": _probe_uci_list,
    "iface-field": _probe_iface_field,
    "iface-absent": _probe_iface_absent,
    "sysctl-equals": _probe_sysctl_equals,
    "log-has": _probe_log_has,
}


def _noinstall_arguments_ok(name: str, args: Sequence[str]) -> bool:
    """Do these arguments fit the probe that exists only here?

    The installed path has no grammar for these probes (the router
    program does not have them), so the no-install path keeps its own
    small rule: a uci path of three parts and one membership per value
    (``+value`` must be in the list, ``-value`` must not be in it).
    The refusals of the installed path hold here too: a secret-looking
    option is refused before the router is asked, so the agent gets no
    yes/no oracle on a value it only ever sees redacted.

    The LIMITS of the installed path hold here as well (the router's
    own probe grammar, 3.6): a field is at most 128 bytes, a line is
    at most 512 bytes, every character is printable ASCII without a
    backslash, and a value cannot be in the list and out of it at the
    same time.
    """
    if name != "uci-list":
        return False
    if len(args) < 2:
        return False
    path = args[0]
    if not isinstance(path, str) or path.count(".") != 2:
        return False
    if not probes._is_ucipath(path):
        return False
    if _looks_like_secret_option(path.rsplit(".", 1)[1]):
        return False
    memberships: list[str] = []
    for membership in args[1:]:
        if not isinstance(membership, str) or len(membership) < 2:
            return False
        if membership[0] not in ("+", "-"):
            return False
        memberships.append(membership)
    fields = [name, *args]
    if any(len(field) > probes.MAX_PROBE_FIELD_BYTES for field in fields):
        return False
    if len("\t".join(fields)) > probes.MAX_PROBE_LINE_BYTES:
        return False
    if any(
        not field
        or any(ord(ch) < 0x20 or ord(ch) > 0x7E or ch == "\\" for ch in field)
        for field in fields
    ):
        return False
    # a value that has to be in the list and out of it at the same time
    # is not a check the router can answer
    required = {item[1:] for item in memberships if item[0] == "+"}
    forbidden = {item[1:] for item in memberships if item[0] == "-"}
    if required & forbidden:
        return False
    return True


def _arguments_ok(name: str, args: Sequence[str]) -> bool:
    """Do these arguments fit the probe the installed path accepts?

    The installed path's own checker is the only grammar there is: the
    same rule, the same refusals (a secret-looking option is refused
    there too, so the agent gets no yes/no oracle on a value it only
    ever sees redacted).  A probe whose arguments do not fit is refused
    here, before the router is asked.  The probe that exists only here
    keeps its own small rule (``_noinstall_arguments_ok``).
    """
    from .server import NewtonError

    if name in NOINSTALL_PROBES:
        return _noinstall_arguments_ok(name, args)
    fields = [name, *args]
    if not all(isinstance(field, str) for field in fields):
        return False
    try:
        probes.validate_probes([fields])
    except NewtonError:
        return False
    return True


def run_probe(session: RpcSession, name: str, args: Sequence[str]) -> ProbeResult:
    """Run one probe over the stock groups.

    ``passed`` is True, False, or None when the probe could not run.
    A probe never passes on an error, on a refusal or on an answer of a
    shape Newton does not know.
    """
    handler = _PROBES.get(name)
    if handler is None:
        if name in probes.PROBE_TABLE:
            return ProbeResult(None, "the stock groups cannot run this probe")
        return ProbeResult(None, "there is no such probe")
    if not _arguments_ok(name, args):
        return ProbeResult(None, "the probe's arguments are not valid")
    try:
        return handler(session, list(args))
    except _CouldNotRun as exc:
        return ProbeResult(None, exc.detail)
    except _Refused:
        # a refusal the probe gave no measured meaning to
        return ProbeResult(None, "the router refused the call")
    except IndexError:
        return ProbeResult(None, "the probe's arguments do not fit")
    except (ValueError, TypeError, KeyError, AttributeError):
        return ProbeResult(None, "the answer could not be read")


# ---- the class table -------------------------------------------------------


@dataclass(frozen=True)
class Check:
    """One safety check of a change class.

    ``kind`` says what the check does, ``probe`` names the probe that
    runs it (None for a check that has no probe yet) and ``args`` are
    the probe's own arguments.
    """

    kind: str
    probe: str | None
    args: tuple[str, ...] = ()
    mandatory: bool = True

    @property
    def runnable(self) -> bool:
        """Can this check run over the stock groups?"""
        if self.probe is None:
            return False
        if self.probe in LOCAL_PROBES:
            return True
        if self.probe in NOINSTALL_PROBES:
            # the probe exists only here, so it runs here
            return True
        return PROBE_SUPPORT.get(self.probe) is not None


@dataclass(frozen=True)
class ClassChecks:
    """The checks of one change class, and why it may not be eligible."""

    name: str
    config: str
    mandatory: tuple[Check, ...]
    optional: tuple[Check, ...] = ()
    measured: bool = True
    reason: str = ""


@dataclass(frozen=True)
class ClassCheck:
    """What one class of a staged change needs, and whether it may run."""

    name: str
    eligible: bool
    mandatory: tuple[Check, ...]
    optional: tuple[Check, ...] = ()
    reason: str = ""


#: The read-back of every staged option, and the service that must still
#: be running.
_DNSMASQ_RUNNING = Check(
    "service-running", "service-running", ("dnsmasq", "any", "present"), True
)
_READ_BACK = Check("read-back", "uci-equals", (), True)

CLASS_CHECKS: dict[str, ClassChecks] = {
    "dhcp-reservations": ClassChecks(
        name="dhcp-reservations",
        config="dhcp",
        mandatory=(_READ_BACK, _DNSMASQ_RUNNING),
    ),
    "dns": ClassChecks(
        name="dns",
        config="dhcp",
        mandatory=(_READ_BACK, _DNSMASQ_RUNNING),
        optional=(Check("resolve", "resolve", (), False),),
    ),
    "wifi-name-key": ClassChecks(
        name="wifi-name-key",
        config="wireless",
        mandatory=(
            _READ_BACK,
            Check("wifi-device-up", None, (), True),
        ),
        measured=False,
        reason="the wireless check's answer shape is not measured yet",
    ),
    "hostname": ClassChecks(
        name="hostname",
        config="system",
        mandatory=(_READ_BACK,),
        reason="the system config is read-only for the rpcd user",
    ),
}


def probe_supported(name: str) -> bool:
    """True when the no-install path can run this probe.

    A probe the stock groups cannot run was listed in ``not_verified``
    at plan time, and it is skipped at verify time.  A probe that can
    run must run: one that cannot run at that moment blocks the
    confirm, because an applied but not verified change is not a
    confirmed change.
    """
    if name in LOCAL_PROBES or name in NOINSTALL_PROBES:
        return True
    return PROBE_SUPPORT.get(name) is not None


def eligible(class_name: str) -> bool:
    """May this class be applied without asking, over the stock groups?

    A class is eligible when it was measured, when its config is one the
    rpcd user may write, and when every mandatory check of it can run.
    """
    spec = CLASS_CHECKS.get(class_name)
    if spec is None:
        return False
    if not spec.measured:
        return False
    if spec.config not in WRITABLE_CONFIGS:
        return False
    return all(check.runnable for check in spec.mandatory)


def _configs_of(uci_batch: Any) -> set[str]:
    """The configs every line of the batch touches.

    The line is read the way the router reads it (``shlex``), so a
    quoted value never becomes a config name and a line with junk in
    it contributes nothing.
    """
    configs: set[str] = set()
    if not isinstance(uci_batch, str):
        return configs
    for raw in uci_batch.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = touched._split_batch_words(line)
        if len(words) < 2:
            continue
        path = words[1].split("=", 1)[0]
        config = path.split(".", 1)[0]
        if config:
            configs.add(config)
    return configs


def _removes_a_setting(uci_batch: Any) -> bool:
    """True when the batch takes a setting away.

    The verbs come from the change lines of the batch, read the way
    ``change_classes`` reads them: a line that is not a change line is
    not a change, and a junk line is not a removal.
    """
    if not isinstance(uci_batch, str):
        return False
    return any(
        words[0] == "delete" and len(words) > 1
        for words in change_classes._change_lines(uci_batch)
    )


def auto_apply_decision(
    uci_batch: Any,
    types: Mapping[tuple[str, str], str] | None = None,
    *,
    risk: str | None = None,
) -> tuple[bool, str]:
    """May Newton apply this change itself on a no-install router?

    The answer is True only when EVERY rule of the allowlist holds
    (ADR-021 point 4):

    * the change classifies to one or more classes;
    * every class is in ``AUTO_APPLY`` and is eligible, i.e. every
      mandatory check of it can run over the stock groups;
    * the change is grantable and not high;
    * every config it touches is one the rpcd user may write;
    * the policy's own verdict is not critical.

    Anything else is an owner script, and the reason says why: the
    plan shows it to the owner.

    ``risk`` is the policy's risk word for the change (``low`` or
    ``critical``).  The policy reads the router's diff, so the caller
    passes the verdict in; a change the policy has not judged is never
    applied by itself, so a change without a verdict is refused here.
    """
    if not isinstance(uci_batch, str) or not uci_batch.strip():
        return False, OWNER_SCRIPT_REASON + "the change is empty"
    classification = change_classes.classify(uci_batch, types=types)
    if classification.high:
        return False, (
            OWNER_SCRIPT_REASON
            + "the change is high risk ("
            + ", ".join(classification.high_reasons)
            + ")"
        )
    if not classification.grantable:
        if _removes_a_setting(uci_batch):
            return False, (
                OWNER_SCRIPT_REASON
                + "it removes a setting, and Newton never removes settings by itself"
            )
        return False, (
            OWNER_SCRIPT_REASON
            + "it holds a change that is not on the list Newton applies by itself"
        )
    class_checks = checks_for(uci_batch, types)
    if not class_checks:
        return False, (
            OWNER_SCRIPT_REASON
            + "the change is not one of the classes Newton applies itself"
        )
    for check in class_checks:
        if check.name not in AUTO_APPLY:
            return False, (
                OWNER_SCRIPT_REASON
                + "the change is a "
                + check.name
                + " change, and Newton applies only "
                + " and ".join(AUTO_APPLY)
                + " itself"
            )
        if not check.eligible:
            return False, OWNER_SCRIPT_REASON + (
                check.reason or "a mandatory check cannot run over the stock groups"
            )
    for config in sorted(_configs_of(uci_batch)):
        if config not in WRITABLE_CONFIGS:
            return False, (
                OWNER_SCRIPT_REASON
                + "the change touches "
                + config
                + ", and Newton may not write that config here"
            )
    if risk is None:
        return False, (
            OWNER_SCRIPT_REASON + "the policy has not judged the change yet"
        )
    if str(risk).strip().lower() == "critical":
        return False, OWNER_SCRIPT_REASON + "the policy calls the change critical"
    return True, AUTO_APPLY_REASON


def _classes_of_fact(
    fact: Any,
    types: Mapping[tuple[str, str], str],
) -> set[str]:
    """The classes that explain one staged line."""
    return change_classes._explaining_classes(
        fact.cfg,
        fact.option,
        fact.value,
        types.get((fact.cfg, fact.section)),
    )


#: The operations a batch stages for one option.
_OP_SET = "set"
_OP_ADD = "add"
_OP_DEL = "del"
_OP_DELETE = "delete"

#: The option name of the marker a whole-section delete leaves behind.
#: The section itself is gone, so the check says the section is not
#: set: the options of the section are not named by the batch.
_SECTION_GONE = ""


def _option_ops(
    uci_batch: str,
) -> dict[tuple[str, str, str], list[tuple[str, str]]]:
    """The operations the batch stages for every option, in batch order.

    The rules are uci's own, and the ones ``touched`` applies:

    * ``set cfg.sec.opt='v'`` rebuilds the list: it holds ``v`` (an
      empty value rebuilds it as nothing);
    * ``add_list cfg.sec.opt='v'`` and ``set cfg.sec.opt+='v'`` append
      to the list;
    * ``del_list cfg.sec.opt='v'`` and ``set cfg.sec.opt-='v'`` remove
      every equal item, the way uci does;
    * ``delete cfg.sec.opt`` takes the option away.

    A section-level line (``cfg.sec=type`` or a list verb without an
    option) is not an operation on an option's values: it never changes
    them.  ``touched._parse_batch_facts`` keeps the option facts of a
    section a section-level ``set`` touches (it pops only the section's
    own fact), and the rule here is the same one.
    """
    ops: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for raw in uci_batch.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = touched._split_batch_words(line)
        if not words:
            continue
        verb = words[0]
        rest = words[1:]
        if not rest:
            continue
        if verb == "set":
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = touched._parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, marker = parsed
            if opt is None:
                # a section-level line: it never changes the values of
                # an option
                continue
            value = touched._unquote(raw_value)
            key = (cfg, sec, opt)
            if marker == "+":
                ops.setdefault(key, []).append((_OP_ADD, value))
            elif marker == "-":
                ops.setdefault(key, []).append((_OP_DEL, value))
            else:
                ops.setdefault(key, []).append((_OP_SET, value))
            continue
        if verb in ("add_list", "del_list"):
            text = rest[0]
            if "=" not in text:
                continue
            path, _, raw_value = text.partition("=")
            parsed = touched._parse_batch_path_with_marker(path)
            if parsed is None:
                continue
            cfg, sec, opt, _marker = parsed
            if opt is None:
                # a list verb without an option: it never changes the
                # values of an option
                continue
            value = touched._unquote(raw_value)
            key = (cfg, sec, opt)
            if verb == "add_list":
                ops.setdefault(key, []).append((_OP_ADD, value))
            else:
                ops.setdefault(key, []).append((_OP_DEL, value))
            continue
        if verb == "delete":
            parsed = touched._parse_batch_path(rest[0])
            if parsed is None:
                continue
            cfg, sec, opt = parsed
            if opt is None:
                # a whole section: every option of it is gone
                for key in [k for k in ops if k[0] == cfg and k[1] == sec]:
                    ops[key].append((_OP_DELETE, ""))
                # and the section itself is gone: the batch names no
                # option of it, so the check that proves the change is
                # the check of the section
                ops.setdefault((cfg, sec, _SECTION_GONE), []).append(
                    (_OP_DELETE, "")
                )
                continue
            ops.setdefault((cfg, sec, opt), []).append((_OP_DELETE, ""))
            continue
    return ops


def _expected_list(ops: Sequence[tuple[str, str]]) -> list[str] | None:
    """The list the router will hold, or None when it is not known.

    The list is known as soon as one operation rebuilds it (a plain
    ``set`` or a ``delete`` of the option): everything before it is
    irrelevant, because uci resets the list there, and everything after
    it applies to the rebuilt list.  A batch of only ``add_list`` and
    ``del_list`` operations leaves the list dependent on what the
    router holds already, so it is not known.
    """
    items: list[str] = []
    known = False
    for verb, value in ops:
        if verb == _OP_SET:
            # a plain set resets the list to one value; an empty value
            # resets it to nothing
            items = [] if value == "" else [value]
            known = True
        elif verb == _OP_ADD:
            items.append(value)
        elif verb == _OP_DEL:
            # uci removes every equal item, not only the first one
            items = [item for item in items if item != value]
        elif verb == _OP_DELETE:
            items = []
            known = True
    return items if known else None


def _list_membership(
    ops: Sequence[tuple[str, str]],
) -> tuple[list[str], list[str]]:
    """The values the list must hold, and the values it must not hold.

    The last operation on a value wins: a value that is added and
    removed later is not in the list (uci removes every equal item),
    and a value that is removed and added again is in it.
    """
    net: dict[str, str] = {}
    for verb, value in ops:
        if verb == _OP_ADD:
            net[value] = _OP_ADD
        elif verb == _OP_DEL:
            net[value] = _OP_DEL
    required = [value for value, verb in net.items() if verb == _OP_ADD]
    forbidden = [value for value, verb in net.items() if verb == _OP_DEL]
    return required, forbidden


def _option_classes(
    uci_batch: str,
    section_types: Mapping[tuple[str, str], str],
) -> dict[tuple[str, str, str], set[str]]:
    """The classes that explain every option the batch stages.

    The classes come from the option and from the type of the section
    it sits in, and not from the facts of the batch: a fact is dropped
    when a later section-level line touches the same section, and the
    option the batch stages is still staged.  An option that only
    loses a value has no fact at all, and its class is named here too.
    """
    classes: dict[tuple[str, str, str], set[str]] = {}
    for key in _option_ops(uci_batch):
        config, section, option = key
        section_type = change_classes._section_type_of(
            section_types, config, section
        )
        if option == _SECTION_GONE:
            # a whole section: the class is the class of the section
            # itself, by the type the router holds
            classes.setdefault(key, set()).update(
                change_classes._explaining_classes(
                    config, None, section_type, None
                )
            )
            continue
        classes.setdefault(key, set()).update(
            change_classes._explaining_classes(config, option, None, section_type)
        )
    return classes


def _read_back_checks(
    uci_batch: str,
    option_classes: Mapping[tuple[str, str, str], set[str]],
    class_name: str,
) -> list[Check]:
    """One read-back check per staged option of the class.

    The options come from the batch itself (``_option_ops``), and not
    from its facts: a section-level line drops the facts of the options
    of its section, and an option that only loses a value has no fact
    at all, and both are staged all the same.

    The check says what the router must hold after the batch:

    * a batch that rebuilds the list (a plain ``set`` or a ``delete``
      of the option) leaves the whole list known, so the check compares
      the list the router holds with the list the batch stages: an
      empty list is an ``uci-unset`` check, a list is an ``uci-equals``
      check;
    * a batch that only adds to the list and takes from it leaves the
      list dependent on what the router holds already, so the check
      says which values must be in the list and which must not: the
      no-install-only ``uci-list`` check.

    A list option is one check, not one per value: the router program
    reads a list option as the whole space-separated list.
    """
    ops_of = _option_ops(uci_batch)
    checks: list[Check] = []
    for key in sorted(option_classes):
        config, section, option = key
        if class_name not in option_classes[key]:
            continue
        ops = ops_of.get(key, [])
        if not ops:
            continue
        if option == _SECTION_GONE:
            # the whole section: the check says the section is not set
            path = f"{config}.{section}"
        else:
            path = f"{config}.{section}.{option}"
        items = _expected_list(ops)
        if items is None:
            # the list the router holds is not known: the check says
            # what must be in it and what must not
            required, forbidden = _list_membership(ops)
            args = [path]
            args.extend(f"+{value}" for value in required)
            args.extend(f"-{value}" for value in forbidden)
            checks.append(Check("read-back", "uci-list", tuple(args), True))
            continue
        if not items:
            checks.append(Check("read-back", "uci-unset", (path,), True))
        else:
            checks.append(
                Check("read-back", "uci-equals", (path, " ".join(items)), True)
            )
    return checks


def _staged_domains(
    facts: Any,
    types: Mapping[tuple[str, str], str],
    class_name: str,
) -> list[str]:
    """The domain names the batch stages."""
    names: list[str] = []
    for fact in sorted(
        facts, key=lambda f: (f.cfg, f.section, f.option or "", f.value)
    ):
        if fact.option != "name":
            continue
        if types.get((fact.cfg, fact.section)) != "domain":
            continue
        if class_name not in _classes_of_fact(fact, types):
            continue
        if fact.value and fact.value not in names:
            names.append(fact.value)
    return names


def checks_for(
    uci_batch: Any, types: Mapping[tuple[str, str], str] | None = None
) -> list[ClassCheck]:
    """What the staged change needs, class by class.

    The batch is classified by ``change_classes``: Newton decides what a
    change is, never the agent.  One entry comes back per class the
    change touches, with the mandatory and optional checks of that class
    and whether the class may be applied over the stock groups.

    ``types`` is the type of the sections the router holds now: a
    change of an option of an existing section has no class without it.

    A batch that only TAKES settings away has classes too: a delete is
    a change of the setting it takes away, so the mandatory checks of
    that class run on it as well.
    """
    classification = change_classes.classify(uci_batch, types=types)
    classes = set(classification.classes)
    classes |= set(change_classes.classes_of_deletes(uci_batch, types))
    facts = touched._parse_batch_facts(uci_batch) if isinstance(uci_batch, str) else set()
    section_types = change_classes.types_of(facts, types)
    # the classes of the options the batch stages: the facts of the
    # batch do not name them all (a section-level line drops the facts
    # of its section, and an option that only loses a value has no fact
    # at all), and a staged option always needs its read-back.
    option_classes = (
        _option_classes(uci_batch, section_types)
        if isinstance(uci_batch, str)
        else {}
    )
    for names in option_classes.values():
        classes |= names
    if not classes:
        return []
    results: list[ClassCheck] = []
    for name in sorted(classes):
        spec = CLASS_CHECKS.get(name)
        if spec is None:
            results.append(
                ClassCheck(
                    name=name,
                    eligible=False,
                    mandatory=(),
                    optional=(),
                    reason="this class is not in the table",
                )
            )
            continue
        mandatory: list[Check] = []
        optional: list[Check] = []
        for check in spec.mandatory:
            if check.kind == "read-back":
                mandatory.extend(
                    _read_back_checks(uci_batch, option_classes, name)
                )
            else:
                mandatory.append(check)
        for check in spec.optional:
            if check.kind == "resolve":
                for domain in _staged_domains(facts, section_types, name):
                    optional.append(
                        Check("resolve", "resolve", (domain,), False)
                    )
            else:
                optional.append(check)
        may = eligible(name)
        reason = ""
        if not may:
            reason = spec.reason or "a mandatory check cannot run over the stock groups"
        if not classification.grantable or classification.high:
            # the batch as a whole is not something the stock groups may
            # apply on their own, whatever class it touches
            may = False
            reason = "the batch also holds a change outside the allowlist"
        results.append(
            ClassCheck(
                name=name,
                eligible=may,
                mandatory=tuple(mandatory),
                optional=tuple(optional),
                reason=reason,
            )
        )
    return results


# ---- the runners -----------------------------------------------------------


def check_class_checks(
    session: RpcSession,
    batch: str,
    types: Mapping[tuple[str, str], str] | None = None,
) -> str | None:
    """The mandatory checks of the change's classes.

    The batch that is checked is the RESOLVED one: the ops of the
    change, with the anonymous addresses (``@type[0]``) resolved to the
    names the change writes.  A probe that names an address the router
    does not know never answers.

    The types of the sections come from the router's own read: the
    change may touch an option of a section the plan does not create,
    and only the router knows what type that section is.

    None when every check passed.  Otherwise the reason, which names
    the check and never a value: a check that could not run is not the
    same as a check that failed, and the words say which one it was.
    """
    for class_check in checks_for(batch, types=types):
        for check in class_check.mandatory:
            if check.probe is None:
                return f"the {class_check.name} check cannot run"
            result = run_probe(session, check.probe, check.args)
            if result.passed is None:
                return f"the {class_check.name} check could not run"
            if not result.passed:
                return f"the {class_check.name} check failed"
    return None


def check_internet(session: RpcSession) -> str | None:
    """The internet check every confirm runs first.

    The probes are the ones the installed router program runs before
    every confirm (``cmd_verify`` of ``newton-router``), so a router
    without the internet confirms nothing here either.

    None when every probe passed.  Otherwise the reason, which says
    whether the check could not run or did not hold: a check that could
    not run is not a failed check, and the words say which one it was.
    """
    for probe in INTERNET_PROBES:
        name, *args = probe
        result = run_probe(session, name, args)
        if result.passed is None:
            return "the internet check could not run"
        if not result.passed:
            return "the internet check failed"
    return None


def wait_for_internet(
    session: RpcSession,
    *,
    applied_at: float,
    deadline: float,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> str | None:
    """The internet check, once the router's own reload has finished.

    ``uci apply`` returns before the router's network reload is done:
    measured on the real router, an owner script that took the uplinks
    down was confirmed 2.8 s after the run started, and the internet
    check ran about a second after the apply, while netifd had not
    taken the uplinks down yet -- the ping still passed.  So the check
    waits ``INTERNET_SETTLE_S`` for the reload to finish, and then
    retries every ``INTERNET_RETRY_S`` until the router has the
    internet again.

    The budget is the clock's, not the schedule's: it is counted from
    the moment the check starts, and it ends before the deadline, and
    it keeps ``INTERNET_RESERVE_S`` free for the rest of the checks and
    the confirm.  The sleep never runs past that budget, and a check
    that starts after the budget is gone runs no probe at all.

    The tries are spaced ``INTERNET_RETRY_S`` from the END of the last
    try, so a slow probe cannot make the tries fire back-to-back, and
    no try starts after the budget is gone.  The number of tries is
    bounded too, so a wait that does not move the clock cannot make
    the check probe for ever.

    None when the router has the internet.  Otherwise the reason of the
    LAST try: a check that could not run is retried like a check that
    failed, and the last word is the one that counts.  When the budget
    is gone before the first try, no probe runs at all.
    """
    first_try = applied_at + INTERNET_SETTLE_S
    start = now()
    budget_end = min(
        start + INTERNET_SETTLE_S + INTERNET_WAIT_MAX_S,
        deadline - rpcd_txn.RESOLVE_MARGIN_S - INTERNET_RESERVE_S,
    )
    try_at = max(first_try, start)
    if try_at > budget_end:
        # the budget is gone before the first try: no probe runs at all
        return "the internet check could not run"
    tries_left = INTERNET_MAX_TRIES
    while True:
        gap = try_at - now()
        if gap > 0:
            sleep(gap)
        reason = check_internet(session)
        if reason is None:
            return None
        tries_left -= 1
        if tries_left <= 0:
            # the budget allows no more tries: the last word is the one
            # that counts
            return reason
        # the next try is INTERNET_RETRY_S after the END of this one,
        # not on a fixed grid: a slow probe cannot squeeze the tries
        # together, and the tries that are left still fit the budget
        try_at = now() + INTERNET_RETRY_S
        if try_at > budget_end:
            return reason


def check_claims(session: RpcSession, probes: Any) -> str | None:
    """The claim probes of a record that can run.

    A claim whose probe the no-install path cannot run at all was
    listed in ``not_verified`` at plan time: it does not block the
    confirm.  A claim that can run and could not run NOW is not a
    verified claim, and a claim that ran and did not hold is a failed
    one: neither is a confirmed change.
    """
    if not isinstance(probes, list):
        return None
    for probe in probes:
        if not isinstance(probe, (list, tuple)) or not probe:
            continue
        name = str(probe[0])
        if not probe_supported(name):
            # a claim that cannot run was listed in not_verified at plan
            # time: it does not block the confirm
            continue
        result = run_probe(session, name, list(probe[1:]))
        if result.passed is None:
            # the claim can run, and it could not run NOW: an applied
            # but not verified change is not a confirmed change
            return "a claim of the plan could not run"
        if not result.passed:
            return "a claim of the plan did not hold"
    return None
