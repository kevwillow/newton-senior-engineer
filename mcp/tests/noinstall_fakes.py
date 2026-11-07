"""Fakes for the no-install tests: a fake rpcd and a fake device.

The fake router answers like the router's own ``/ubus``: an answer is
either a data object (what the call returns), an integer (the ubus
refusal code, raised as ``RpcdCallFailed``) or a callable (the answer
depends on the call's arguments).  Every call and every login is
recorded, so a test can prove that a read made no write call and that
every read opened its own session.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from newton_mcp.adapters import openwrt_rpcd as rpcd


class FakeRouter:
    """A fake rpcd client."""

    def __init__(self, answers: dict[tuple[str, str], Any] | None = None) -> None:
        self.answers: dict[tuple[str, str], Any] = dict(answers or {})
        self.calls: list[tuple[str, str, str, dict[str, Any]]] = []
        self.logins: list[tuple[str, str, int]] = []
        self._counter = 0

    def answer(self, obj: str, fn: str, args: dict[str, Any]) -> Any:
        value = self.answers.get((obj, fn), self.answers.get(("*", "*"), {}))
        if callable(value):
            value = value(obj, fn, args)
        if isinstance(value, bool):
            raise AssertionError("a refusal code must be an int, not a bool")
        if isinstance(value, int):
            raise rpcd.RpcdCallFailed(value)
        if isinstance(value, BaseException):
            raise value
        return value

    # -- the client interface ------------------------------------------------

    def login(self, username: str, password: str, timeout_s: int) -> rpcd.RpcdSession:
        self.logins.append((username, password, timeout_s))
        self._counter += 1
        return rpcd.RpcdSession(
            id=f"{self._counter:032x}",
            expires_at=time.time() + timeout_s,
            acls={},
            timeout_s=timeout_s,
        )

    def call(
        self,
        session: rpcd.RpcdSession,
        obj: str,
        fn: str,
        args: dict[str, Any] | None = None,
    ) -> Any:
        call_args = dict(args or {})
        self.calls.append((session.id, obj, fn, call_args))
        return self.answer(obj, fn, call_args)

    # -- helpers for the tests ----------------------------------------------

    def calls_of(self, obj: str, fn: str) -> list[dict[str, Any]]:
        """The arguments of every call of one kind."""
        return [args for _sid, o, f, args in self.calls if o == obj and f == fn]


@dataclass
class FakeDevice:
    """The fields of a no-install device that the read path uses."""

    name: str = "lab-r1"
    https_host: str = "192.0.2.1"
    https_port: int = 443
    https_spki: str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    rpcd_password_file: Path | None = None


def password_file(tmp_path: Path, secret: str = "synthetic-password") -> Path:
    """A password file with the mode the inventory requires (0600)."""
    path = tmp_path / "rpcd-password"
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(secret + "\n")
    os.chmod(path, 0o600)
    return path


def exec_answers_by_command(
    answers: dict[str, Any],
) -> Callable[[str, str, dict[str, Any]], Any]:
    """The answers of the exec calls: one body per command.

    A router that answers the ping and the nslookup in different ways
    is the case the internet check has to catch.  The fake takes the
    command from the arguments and answers with the body that command
    has, so the test says which probe fails and the order of the calls
    does not matter.  Every other command answers with a success.
    """

    def answer(obj: str, fn: str, args: dict[str, Any]) -> Any:
        command = str(args.get("command", ""))
        if command in answers:
            return answers[command]
        return {"code": 0}

    return answer


def factory(router: FakeRouter) -> Callable[[Any], FakeRouter]:
    """A client factory that hands out the fake router."""

    def build(_device: Any) -> FakeRouter:
        return router

    return build


class FakeSession:
    """A session-shaped caller: ``call(obj, fn, args)`` like the read path.

    The probes take a session, not a client: the session is what holds
    the logged-in router.  The fake answers from a table, exactly like
    ``FakeRouter``, and records every call.
    """

    def __init__(self, answers: dict[tuple[str, str], Any] | None = None) -> None:
        self.answers: dict[tuple[str, str], Any] = dict(answers or {})
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def call(
        self,
        obj: str,
        fn: str,
        args: dict[str, Any] | None = None,
    ) -> Any:
        call_args = dict(args or {})
        self.calls.append((obj, fn, call_args))
        value = self.answers.get((obj, fn), self.answers.get(("*", "*"), {}))
        if callable(value):
            value = value(obj, fn, call_args)
        if isinstance(value, bool):
            raise AssertionError("a refusal code must be an int, not a bool")
        if isinstance(value, int):
            raise rpcd.RpcdCallFailed(value)
        if isinstance(value, BaseException):
            raise value
        return value


class ApplyRouter:
    """A fake rpcd router that can apply a change and be read back.

    It answers the calls the no-install apply makes: the config dumps,
    the change list of a session, the stage (set, add, delete), the
    apply, the confirm, the pending detector and the service list.

    A test can make the apply be refused (the code the router answers
    with), make the answer to the apply be lost, make dnsmasq look
    stopped, or keep the rollback window open for ever.

    The clock is the test's: ``now`` is a callable, so a test that
    drives the window shut does it without waiting for real time.
    """

    def __init__(
        self, configs: dict[str, dict[str, dict[str, Any]]] | None = None
    ) -> None:
        #: (config, section) -> (type, {option: value})
        self.sections: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        for config, entries in (configs or {}).items():
            for name, entry in entries.items():
                options = {
                    str(key): value
                    for key, value in entry.items()
                    if not str(key).startswith(".")
                }
                self.sections[(str(config), str(name))] = (
                    str(entry.get(".type", "")),
                    options,
                )
        self.calls: list[tuple[str, str, str, dict[str, Any]]] = []
        self.logins: list[tuple[str, str, int]] = []
        #: session id -> the staged records of that session
        self.staged: dict[str, list[tuple[str, str, str | None, str | None]]] = {}
        self.pending = False
        #: the code the router answers an apply with (0 is a success)
        self.apply_code = 0
        #: the code the router answers a confirm with (0 is a success)
        self.confirm_code = 0
        #: the answer to the apply never comes back
        self.lose_apply_answer = False
        #: a lost answer that still applied the change
        self.lose_apply_answer_applies = True
        #: dnsmasq looks stopped
        self.service_running = True
        #: dnsmasq is not there at all
        self.service_missing = False
        #: the router refuses the service list
        self.service_refused = False
        #: the commands the router runs answer with a failure
        self.exec_fails = False
        #: the answer of one command, by its path: a per-command
        #: failure, so a test can make the ping work and the nslookup
        #: fail
        self.exec_answers: dict[str, Any] = {}
        #: the rollback window never closes
        self.never_close = False
        #: the router answers a missing unit with [0] and no data (measured)
        self.absence_answers_empty = False
        #: after the apply the router cannot be reached any more
        self.unreachable_after_apply = False
        #: after the apply the router refuses every login
        self.login_fails_after_apply = False
        #: after the apply the router cannot be read
        self.reads_fail_after_apply = False
        #: the confirm answers with a lost answer
        self.confirm_fails = False
        #: the host time the window closes at
        self.window_closes_at = 0.0
        #: the clock of the router and of the settle
        self.now: Callable[[], float] = time.time
        self._counter = 0
        self._prior: dict[str, Any] | None = None
        #: the apply happened: the change may be live on the router
        self._applied = False
        #: the router stops answering after this many calls (0 is no
        #: limit): a test that must not spin for ever sets it
        self.call_limit = 0
        #: called with every call, before the answer: a test that makes
        #: the router answer by the clock uses it
        self.on_call: Callable[[str, str, dict[str, Any]], None] | None = None

    # -- the client interface ------------------------------------------------

    def login(
        self, username: str, password: str, timeout_s: int
    ) -> rpcd.RpcdSession:
        self.logins.append((username, password, timeout_s))
        self._counter += 1
        if self.login_fails_after_apply and self._applied:
            raise rpcd.RpcdTransportError("the router is gone", sent=False)
        session = rpcd.RpcdSession(
            id=f"{self._counter:032x}",
            expires_at=time.time() + timeout_s,
            acls={},
            timeout_s=timeout_s,
        )
        self.staged[session.id] = []
        return session

    def call(
        self,
        session: rpcd.RpcdSession,
        obj: str,
        fn: str,
        args: dict[str, Any] | None = None,
    ) -> Any:
        call_args = dict(args or {})
        self.calls.append((session.id, obj, fn, call_args))
        if self.call_limit and len(self.calls) > self.call_limit:
            raise AssertionError(
                f"the router was called {len(self.calls)} times: the test's "
                "call limit was reached"
            )
        if self.on_call is not None:
            self.on_call(obj, fn, call_args)
        if self.unreachable_after_apply and self._applied:
            raise rpcd.RpcdTransportError("the router is gone", sent=False)
        if (
            self.reads_fail_after_apply
            and self._applied
            and obj == "uci"
            and fn == "get"
        ):
            raise rpcd.RpcdTransportError(
                "the router cannot be read", sent=False
            )
        if obj == "system" and fn == "board":
            return {"board_name": "lab-r1"}
        if obj == "file" and fn == "list":
            return {"entries": self._window_entries()}
        if obj == "file" and fn == "exec":
            command = str(call_args.get("command", ""))
            if command in self.exec_answers:
                return self.exec_answers[command]
            return {"code": 1 if self.exec_fails else 0, "stdout": ""}
        if obj == "uci" and fn == "get":
            return self._get(call_args)
        if obj == "uci" and fn == "changes":
            return {"changes": self._changes(session.id)}
        if obj == "uci" and fn == "set":
            config = str(call_args["config"])
            section = str(call_args["section"])
            for option, value in dict(call_args.get("values", {})).items():
                self.staged[session.id].append(
                    ("set", config, section, str(option), str(value))
                )
            return {}
        if obj == "uci" and fn == "add":
            config = str(call_args["config"])
            name = str(call_args["name"])
            self.staged[session.id].append(
                ("set", config, name, None, str(call_args["type"]))
            )
            for option, value in dict(call_args.get("values", {})).items():
                self.staged[session.id].append(
                    ("set", config, name, str(option), str(value))
                )
            return {"section": name}
        if obj == "uci" and fn == "delete":
            config = str(call_args["config"])
            section = str(call_args["section"])
            option = call_args.get("option")
            self.staged[session.id].append(
                (
                    "remove",
                    config,
                    section,
                    None if option is None else str(option),
                    None,
                )
            )
            return {}
        if obj == "uci" and fn == "apply":
            return self._apply(session.id, call_args)
        if obj == "uci" and fn == "confirm":
            if self.confirm_fails:
                raise rpcd.RpcdTransportError(
                    "the confirm answer was lost", sent=False
                )
            if self.confirm_code:
                raise rpcd.RpcdCallFailed(self.confirm_code)
            self.pending = False
            self._prior = None
            return {}
        if obj == "service" and fn == "list":
            if self.service_refused:
                raise rpcd.RpcdCallFailed(6)
            if self.service_missing:
                return {}
            return {
                "dnsmasq": {
                    "instances": {
                        "instance1": {"running": self.service_running, "pid": 1}
                    }
                }
            }
        raise AssertionError(f"unexpected call {obj}.{fn}")

    # -- the answers ---------------------------------------------------------

    def _window_entries(self) -> list[dict[str, str]]:
        """The snapshot files of an open rollback window."""
        if not self.pending:
            return []
        if self.never_close:
            return [{"name": "dhcp", "type": "file"}]
        if self.now() >= self.window_closes_at:
            # the router's own timer ended: the change is put back
            self._revert()
            self.pending = False
            return []
        return [{"name": "dhcp", "type": "file"}]

    def _get(self, args: dict[str, Any]) -> Any:
        config = str(args.get("config", ""))
        section = args.get("section")
        option = args.get("option")
        if section is None:
            return {"values": self._config_values(config)}
        key = (config, str(section))
        if key not in self.sections:
            if self.absence_answers_empty:
                # the measured answer: [0] with no data at all
                return {}
            raise rpcd.RpcdCallFailed(4)
        section_type, options = self.sections[key]
        if option is None:
            return {
                "values": {
                    ".type": section_type,
                    ".name": str(section),
                    ".anonymous": "false",
                    **options,
                }
            }
        if str(option) not in options:
            if self.absence_answers_empty:
                # the measured answer: [0] with no data at all
                return {}
            raise rpcd.RpcdCallFailed(4)
        return {"value": options[str(option)]}

    def _config_values(self, config: str) -> dict[str, dict[str, Any]]:
        values: dict[str, dict[str, Any]] = {}
        for (cfg, name), (section_type, options) in self.sections.items():
            if cfg != config:
                continue
            values[name] = {
                ".type": section_type,
                ".name": name,
                ".anonymous": "false",
                **options,
            }
        return values

    def _changes(self, session_id: str) -> dict[str, list[list[str]]]:
        changes: dict[str, list[list[str]]] = {}
        for verb, config, section, option, value in self.staged[session_id]:
            if verb == "set":
                entry = (
                    ["set", section, str(value)]
                    if option is None
                    else ["set", section, option, str(value)]
                )
            elif option is None:
                entry = ["remove", section]
            else:
                entry = ["remove", section, option]
            changes.setdefault(config, []).append(entry)
        return changes

    def _apply(self, session_id: str, args: dict[str, Any]) -> Any:
        if self.lose_apply_answer:
            if self.lose_apply_answer_applies:
                self._commit(session_id, args)
            raise rpcd.RpcdTransportError("the answer was lost", sent=True)
        if self.apply_code:
            raise rpcd.RpcdCallFailed(self.apply_code)
        self._commit(session_id, args)
        return {}

    def _commit(self, session_id: str, args: dict[str, Any]) -> None:
        """The staged changes become the live ones, and a window opens."""
        self._prior = {
            "sections": {
                key: (section_type, dict(options))
                for key, (section_type, options) in self.sections.items()
            }
        }
        for verb, config, section, option, value in self.staged[session_id]:
            key = (config, section)
            if verb == "set" and option is None:
                self.sections[key] = (str(value), {})
            elif verb == "set":
                if key not in self.sections:
                    self.sections[key] = ("", {})
                self.sections[key][1][str(option)] = value
            elif option is None:
                self.sections.pop(key, None)
            else:
                if key in self.sections:
                    self.sections[key][1].pop(str(option), None)
        self.pending = True
        self._applied = True
        timeout = args.get("timeout")
        window = int(timeout) if isinstance(timeout, int) else 0
        self.window_closes_at = self.now() + window

    def _revert(self) -> None:
        """The router puts the change back: the prior values are live."""
        if self._prior is None:
            return
        self.sections = {
            key: (section_type, dict(options))
            for key, (section_type, options) in self._prior["sections"].items()
        }

    # -- the helpers ---------------------------------------------------------

    def calls_of(self, obj: str, fn: str) -> list[dict[str, Any]]:
        """The arguments of every call of one kind."""
        return [args for _sid, o, f, args in self.calls if o == obj and f == fn]

    def count(self, obj: str, fn: str) -> int:
        """How many calls of one kind the router got."""
        return len(self.calls_of(obj, fn))
