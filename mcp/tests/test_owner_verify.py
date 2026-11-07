"""the read-back of an owner script, and the confirm.

ADR-021 point 5, point 6 and the design's rule 3: Newton
confirms a change only when every check passes.  There is no "applied
but not verified".

What is proved here:

  * every check is mandatory: each one that fails, or that cannot run,
    gives no confirm;
  * a change that opens the router to the internet needs the owner to
    type ``keep`` inside the window;
  * the confirm runs in a fresh session, never the applying one, and
    exactly once;
  * the deadline comes from the run's start time, not from the clock
    when the change was applied;
  * a change that changed something else is never confirmed;
  * an unreadable answer is never a confirmation and never a "not
    applied".
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import owner_backup
from newton_mcp import owner_flow
from newton_mcp import owner_verify
from newton_mcp import rpcd_txn
from newton_mcp.adapters import openwrt_rpcd as rpcd
from newton_mcp.owner_verify import Verdict

from test_owner_flow import (  # noqa: E402  (tests dir is on sys.path)
    BATCH,
    FakeClient,
    FakeService,
    _answers,
    _explanation_for,
    _factory as _owner_factory,
    _measured,
    _state as _owner_state,
)


# ---- the fake router -------------------------------------------------------


def _acls() -> dict[str, Any]:
    """The groups Newton asked for, as a login answer carries them."""
    groups: dict[str, Any] = {}
    for group, permissions in rpcd.expected_groups().items():
        groups[group] = sorted(permissions)
    return {"access-group": groups}


class FakeSession:
    def __init__(self, router: "FakeRouter", index: int) -> None:
        self.router = router
        self.id = f"{index:032x}"
        self.acls = dict(router.acls)
        self.expires_at = time.time() + 30
        self.timeout_s = 30
        self.spent = False

    def mark_spent(self) -> None:
        self.spent = True


class FakeRouter:
    """A router whose UCI answers the test tells it to answer."""

    def __init__(
        self,
        configs: dict[str, dict[str, dict[str, Any]]],
        *,
        pending: bool = True,
        acls: dict[str, Any] | None = None,
        refuse_login: bool = False,
        unreadable: tuple[str, ...] = (),
        missing: tuple[str, ...] = (),
        service_running: bool = True,
        service_unreadable: bool = False,
        internet: bool = True,
        internet_unreadable: bool = False,
        exec_answers: dict[str, Any] | None = None,
        on_call=None,
    ) -> None:
        self.configs = configs
        self.pending = pending
        self.acls = acls if acls is not None else _acls()
        self.refuse_login = refuse_login
        self.unreadable = unreadable
        self.missing = missing
        self.service_running = service_running
        self.service_unreadable = service_unreadable
        #: the router has the internet (the installed program's check)
        self.internet = internet
        #: the answer to the internet check cannot be read
        self.internet_unreadable = internet_unreadable
        #: the answer of one command, by its path: a per-command
        #: failure, so a test can make the ping work and the nslookup
        #: fail
        self.exec_answers: dict[str, Any] = dict(exec_answers or {})
        self.on_call = on_call
        self.logins = 0
        self.sessions: list[FakeSession] = []
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.confirms = 0
        #: the session every confirm was sent with
        self.confirm_sessions: list[str] = []
        #: the code the router answers a confirm with (0 is a success)
        self.confirm_code = 0

    def login(self, username: str, password: str, timeout_s: int) -> FakeSession:
        if self.refuse_login:
            raise rpcd.RpcdCallFailed(6)
        self.logins += 1
        session = FakeSession(self, self.logins)
        self.sessions.append(session)
        return session

    def call(self, session: FakeSession, obj: str, fn: str, args=None) -> Any:
        call_args = dict(args or {})
        self.calls.append((obj, fn, call_args))
        if self.on_call is not None:
            self.on_call(obj, fn, call_args)
        if obj == "file" and fn == "list":
            entries = [{"name": "dhcp", "type": "file"}] if self.pending else []
            return {"entries": entries}
        if obj == "file" and fn == "exec":
            command = str(call_args.get("command", ""))
            if command in self.exec_answers:
                return self.exec_answers[command]
            # the internet check of the installed router program: the
            # exit of the command is the answer
            if self.internet_unreadable:
                # an answer Newton cannot read: no code at all
                return {}
            return {"code": 0 if self.internet else 1}
        if obj == "uci" and fn == "get":
            config = str(call_args.get("config", ""))
            if config in self.unreadable:
                raise rpcd.RpcdCallFailed(6)
            if config in self.missing:
                # the router has no such config
                raise rpcd.RpcdCallFailed(4)
            section = call_args.get("section")
            option = call_args.get("option")
            if section and option:
                value = self._option(config, str(section), str(option))
                return {"value": value} if value is not None else {}
            if section:
                # a section that is not there answers with an empty
                # body (the measured shape), and a section that is
                # there answers with its own values
                entry = self.configs.get(config, {}).get(str(section))
                if not isinstance(entry, dict):
                    return {}
                return {"values": entry}
            return {"values": self.configs.get(config, {})}
        if obj == "uci" and fn == "confirm":
            self.confirms += 1
            self.confirm_sessions.append(str(getattr(session, "id", "")))
            if self.confirm_code:
                raise rpcd.RpcdCallFailed(self.confirm_code)
            return {}
        if obj == "service" and fn == "list":
            if self.service_unreadable:
                raise rpcd.RpcdCallFailed(6)
            return {
                "dnsmasq": {
                    "instances": {
                        "instance1": {"running": self.service_running, "pid": 1}
                    }
                }
            }
        return {}

    def _option(self, config: str, section: str, option: str) -> Any:
        sections = self.configs.get(config, {})
        entry = sections.get(section)
        if not isinstance(entry, dict):
            return None
        value = entry.get(option)
        if isinstance(value, list):
            return " ".join(str(item) for item in value)
        return value


def _factory(router: FakeRouter):
    def build(_device: Any) -> FakeRouter:
        return router

    return build


# ---- the fixtures ----------------------------------------------------------


def _no_sleep(_seconds: float) -> None:
    """A sleep that does not sleep: the test's clock is the only clock."""


def _device(tmp_path: Path, **overrides: Any):
    from newton_mcp.server import Device

    password = tmp_path / "rpcd-password"
    handle = os.open(str(password), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write("synthetic-password\n")
    fields = {
        "name": "lab-r1",
        "platform": "openwrt",
        "host": "192.0.2.1",
        "user": "root",
        "profile": "lab",
        "access": "no-install",
        "https_host": "192.0.2.1",
        "https_port": 443,
        "https_spki": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "rpcd_password_file": password,
    }
    fields.update(overrides)
    return Device(**fields)


BEFORE = {
    "dhcp": {
        "cfg01411c": {
            ".anonymous": True,
            ".index": 0,
            ".name": "cfg01411c",
            ".type": "dnsmasq",
            "domain": "lan",
        },
        "lan": {
            ".anonymous": False,
            ".index": 1,
            ".name": "lan",
            ".type": "dhcp",
            "limit": "150",
        },
    }
}

AFTER = {
    "dhcp": {
        "cfg01411c": {
            ".anonymous": True,
            ".index": 0,
            ".name": "cfg01411c",
            ".type": "dnsmasq",
            "domain": "lan",
        },
        "lan": {
            ".anonymous": False,
            ".index": 1,
            ".name": "lan",
            ".type": "dhcp",
            "limit": "250",
        },
    }
}


#: The system section of the lab router: the one an anonymous address
#: resolves to.
SYSTEM = {
    "system": {
        "cfg01e48a": {
            ".anonymous": True,
            ".index": 0,
            ".name": "cfg01e48a",
            ".type": "system",
            "hostname": "router1",
        }
    }
}


def _backup(configs=None):
    return owner_backup.Backup(
        configs=BEFORE if configs is None else configs, board="lab-r1"
    )


def _measured_dhcp() -> dict[str, Any]:
    """The measured dhcp config: the router as lab-r1 holds it."""
    values = _measured("uci.get.dhcp")[1]["values"]
    return {"dhcp": json.loads(json.dumps(values))}


def _owner_record(state: Path, sid: str) -> dict[str, Any]:
    """The plan record of a plan the flow wrote."""
    return json.loads((state / "plans" / f"{sid}.json").read_text(encoding="utf-8"))


def _record(**overrides: Any) -> dict[str, Any]:
    record = {
        "device": "lab-r1",
        "host": "192.0.2.1",
        "session_id": "a" * 32,
        "uci_batch": "set dhcp.lan.limit='250'",
        "diff": "dhcp.lan.limit='250'",
        "probes": [],
        "timeout_s": 180,
        "base_hash": "b" * 64,
        "requires_approval": True,
        "router_digest": "c" * 64,
        "explanation": {
            "intent": "x",
            "steps": ["y"],
            "expect": [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}],
            "risk": "z",
        },
        "owner_confirmed_in_chat": True,
        "staged_at": None,
        "reasons": [],
        "router_leash": "owner-script",
        "router_profile": "no-install",
        "router_sections": ["dhcp.lan"],
        "router_requires_approval": True,
        "staged_check": {"fw4": "not-checked", "reason": "no-install", "not_checked": []},
        "ops": [["set", "dhcp.lan.limit", "250"]],
        "not_verified": ["Newton cannot read the rpcd config"],
    }
    record.update(overrides)
    return record


def _run(started_at: float | None = None) -> dict[str, Any]:
    return {"started_at": time.time() - 10 if started_at is None else started_at}


#: The session the script printed: the token the confirm goes out with.
TOKEN = "0123456789abcdef0123456789abcdef"


def _finish(
    tmp_path: Path,
    router: FakeRouter,
    record: dict[str, Any] | None = None,
    run: dict[str, Any] | None = None,
    now: Any = None,
    keep_prompt=None,
    confirm_token: str | None = TOKEN,
    backup: Any = None,
) -> Verdict:
    if now is None:
        clock: Any = time.time
    elif callable(now):
        clock = now
    else:
        clock = lambda: now
    # the test never really waits: the sleep of the check moves the
    # test's own clock, and a clock that cannot move does not sleep
    advance = getattr(clock, "advance", None)
    sleep = advance if callable(advance) else _no_sleep
    return owner_verify.finish(
        _device(tmp_path),
        record if record is not None else _record(),
        _backup() if backup is None else backup,
        run if run is not None else _run(),
        _factory(router),
        now=clock,
        sleep=sleep,
        keep_prompt=keep_prompt,
        confirm_token=confirm_token,
    )


# ---- the happy path --------------------------------------------------------


def test_every_check_passing_confirms_the_change(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.CONFIRMED
    assert router.confirms == 1
    for name in ("reachable", "pending", "expected", "nothing-else", "acls"):
        assert name in verdict.checks


def test_the_confirm_runs_in_a_fresh_session(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    _finish(tmp_path, router)
    confirms = [
        args
        for obj, fn, args in router.calls
        if obj == "uci" and fn == "confirm"
    ]
    assert len(confirms) == 1
    # the session that confirmed is a fresh one: the router was asked
    # to log in again for the re-read
    assert router.logins >= 2


def test_the_confirm_goes_out_with_the_script_session(tmp_path: Path) -> None:
    """Only the script's own session may confirm its change.

    A fresh limited session cannot: rpcd answers [6] (measured).  The
    session the script opened is the one that carries the right, and
    the confirm goes out with it.
    """
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router, confirm_token=TOKEN)
    assert verdict.state == owner_verify.CONFIRMED
    assert router.confirms == 1
    assert router.confirm_sessions == [TOKEN]
    # and it is not the session of the fresh limited login
    assert router.sessions[0].id != TOKEN


def test_without_a_token_there_is_no_confirm(tmp_path: Path) -> None:
    """The lane died before the script printed its session.

    Then there is no session that may confirm, and the change is never
    confirmed: the router puts it back by itself.
    """
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router, confirm_token=None)
    assert verdict.state != owner_verify.CONFIRMED
    assert router.confirms == 0
    assert owner_verify.NO_TOKEN in verdict.notes


def test_a_confirm_the_router_refuses_is_not_a_confirm(tmp_path: Path) -> None:
    """An answer other than [0] is not a confirm.

    The router answers [5] when there is nothing pending to confirm.
    The change is then never confirmed, and the state is decided after
    the window.
    """
    router = FakeRouter(AFTER)
    router.confirm_code = 5
    verdict = _finish(tmp_path, router, confirm_token=TOKEN)
    assert verdict.state != owner_verify.CONFIRMED
    assert router.confirms == 1
    assert "the router refused the confirm" in verdict.notes


def test_the_token_is_never_in_the_verdict(tmp_path: Path) -> None:
    """The token is used and forgotten: it is never shown."""
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router, confirm_token=TOKEN)
    said = " ".join(
        [verdict.sentence(), *verdict.notes, *verdict.checks, *verdict.not_verified]
    )
    assert TOKEN not in said


def test_the_verdict_carries_no_value(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router)
    assert "250" not in " ".join(verdict.notes)
    assert "150" not in " ".join(verdict.notes)


def test_the_verdict_carries_what_newton_could_not_check(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router)
    assert verdict.not_verified == ("Newton cannot read the rpcd config",)


# ---- the failing checks ----------------------------------------------------


def test_a_window_that_is_not_open_gives_not_applied(tmp_path: Path) -> None:
    router = FakeRouter(BEFORE, pending=False)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.NOT_APPLIED
    assert router.confirms == 0


def test_a_change_that_never_happened_is_not_applied(tmp_path: Path) -> None:
    router = FakeRouter(AFTER, pending=False)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.KEPT
    assert router.confirms == 0


def test_a_touched_unit_that_does_not_hold_gives_no_confirm(tmp_path: Path) -> None:
    router = FakeRouter(BEFORE)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert "did not reach dhcp.lan.limit" in " ".join(verdict.notes)


def test_an_unapproved_change_gives_no_confirm(tmp_path: Path) -> None:
    changed = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], limit="250", extra="1"),
        }
    }
    router = FakeRouter(changed)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert any("UNAPPROVED_CHANGE" in note for note in verdict.notes)
    assert any("dhcp.lan.extra" in note for note in verdict.notes)


def test_an_unapproved_change_never_echoes_a_value(tmp_path: Path) -> None:
    changed = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], limit="250", extra="s3cret"),
        }
    }
    router = FakeRouter(changed)
    verdict = _finish(tmp_path, router)
    assert "s3cret" not in " ".join(verdict.notes)


def test_a_widened_acl_gives_no_confirm(tmp_path: Path) -> None:
    acls = _acls()
    acls["access-group"]["luci-mod-network-config"] = ["read", "write", "exec"]
    router = FakeRouter(AFTER, acls=acls)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_an_unreadable_answer_gives_no_confirm(tmp_path: Path) -> None:
    router = FakeRouter(AFTER, unreadable=("dhcp",))
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_a_login_that_fails_gives_no_confirm(tmp_path: Path) -> None:
    router = FakeRouter(AFTER, refuse_login=True)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_inside_the_margin_there_is_no_confirm(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    started = time.time()
    verdict = _finish(
        tmp_path,
        router,
        run={"started_at": started},
        now=started + 180 - rpcd_txn.RESOLVE_MARGIN_S / 2,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_the_deadline_uses_the_start_time_not_the_clock(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    started = time.time() - 100
    verdict = _finish(tmp_path, router, run={"started_at": started})
    assert verdict.deadline == pytest.approx(started + 180)


def test_a_class_check_that_cannot_run_gives_no_confirm(tmp_path: Path) -> None:
    """A change in a class with a mandatory check, whose check cannot
    run: no confirm at all.

    The batch adds a dnsmasq section with a server in it, so the
    change is in the dns class, and the dns class has a mandatory check
    (the dnsmasq service must be running).  The router cannot answer
    that call, so the check cannot run, and a check that cannot run
    never confirms.
    """
    record = _record(
        uci_batch=(
            "set dhcp.newdnsmasq=dnsmasq\n"
            "set dhcp.newdnsmasq.server='1.1.1.1'"
        ),
        ops=[
            ["set", "dhcp.newdnsmasq", "dnsmasq"],
            ["set", "dhcp.newdnsmasq.server", "1.1.1.1"],
        ],
    )
    after = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": BEFORE["dhcp"]["lan"],
            "newdnsmasq": {
                ".anonymous": False,
                ".index": 2,
                ".name": "newdnsmasq",
                ".type": "dnsmasq",
                "server": "1.1.1.1",
            },
        }
    }
    router = FakeRouter(after, service_unreadable=True)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state != owner_verify.CONFIRMED
    assert router.confirms == 0
    assert any("check could not run" in note for note in verdict.notes)


def test_a_claim_that_fails_gives_no_confirm(tmp_path: Path) -> None:
    record = _record(probes=[["uci-equals", "dhcp.lan.limit", "999"]])
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_a_claim_that_cannot_run_does_not_block(tmp_path: Path) -> None:
    record = _record(probes=[["nft-rule", "something"]])
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state == owner_verify.CONFIRMED
    assert router.confirms == 1


# ---- the class checks of the resolved change --------------------------------


def test_a_dns_change_of_an_existing_section_needs_the_dnsmasq_check(
    tmp_path: Path,
) -> None:
    """The type of a section the plan does not create comes from the backup.

    The plan changes an option of the dnsmasq section of the router, and
    the batch never names the type.  The router does: without it the
    change has no class, and the mandatory check of the dns class (the
    dnsmasq service must be running) never runs.
    """
    record = _record(
        uci_batch="set dhcp.cfg01411c.server='1.1.1.1'",
        ops=[["set", "dhcp.cfg01411c.server", "1.1.1.1"]],
    )
    after = {
        "dhcp": {
            "cfg01411c": dict(BEFORE["dhcp"]["cfg01411c"], server="1.1.1.1"),
            "lan": BEFORE["dhcp"]["lan"],
        }
    }
    router = FakeRouter(after, service_running=False)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state != owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 0
    assert any("dns check failed" in note for note in verdict.notes), verdict.notes


def test_a_dns_change_of_an_existing_section_confirms_with_the_dnsmasq_up(
    tmp_path: Path,
) -> None:
    """The same change, with the service running: it is confirmed."""
    record = _record(
        uci_batch="set dhcp.cfg01411c.server='1.1.1.1'",
        ops=[["set", "dhcp.cfg01411c.server", "1.1.1.1"]],
    )
    after = {
        "dhcp": {
            "cfg01411c": dict(BEFORE["dhcp"]["cfg01411c"], server="1.1.1.1"),
            "lan": BEFORE["dhcp"]["lan"],
        }
    }
    router = FakeRouter(after)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 1


def test_a_hostname_change_is_read_back_under_the_resolved_name(
    tmp_path: Path,
) -> None:
    """The probe names the section the script writes, not the address.

    ``system.@system[0]`` is resolved to the name the router holds
    before the change is staged, so the read-back asks the router about
    that name: an address the router does not know never answers.
    """
    record = _record(
        uci_batch="set system.@system[0].hostname='router2'",
        ops=[["set", "system.cfg01e48a.hostname", "router2"]],
    )
    after = {
        "system": {
            "cfg01e48a": dict(SYSTEM["system"]["cfg01e48a"], hostname="router2")
        }
    }
    router = FakeRouter(after)
    backup = _backup({**BEFORE, **SYSTEM})
    verdict = _finish(tmp_path, router, record=record, backup=backup)
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 1
    asked = [
        args for obj, fn, args in router.calls if obj == "uci" and fn == "get"
    ]
    sections = {
        str(args.get("section")) for args in asked if args.get("section")
    }
    assert "cfg01e48a" in sections, asked
    assert "@system[0]" not in sections, asked


# ---- the exposure ----------------------------------------------------------


def _exposure_record(**overrides: Any) -> dict[str, Any]:
    record = _record(reasons=["wan-rule: a rule opens a port to the internet"])
    record.update(overrides)
    return record


def test_an_exposure_needs_the_owner_to_keep_it(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path, router, record=_exposure_record(), keep_prompt=lambda _deadline: "keep\n"
    )
    assert verdict.state == owner_verify.CONFIRMED
    assert verdict.owner_keep is True
    assert router.confirms == 1


def test_an_exposure_the_owner_does_not_keep_is_not_confirmed(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path, router, record=_exposure_record(), keep_prompt=lambda _deadline: "yes\n"
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert verdict.owner_keep is False
    assert router.confirms == 0
    assert owner_verify.DID_NOT_KEEP in verdict.notes


def test_an_empty_answer_is_not_keep(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path, router, record=_exposure_record(), keep_prompt=lambda _deadline: ""
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_an_end_of_file_is_not_keep(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path, router, record=_exposure_record(), keep_prompt=lambda _deadline: None
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_a_capitalised_keep_is_not_keep(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path, router, record=_exposure_record(), keep_prompt=lambda _deadline: "Keep\n"
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_a_non_exposure_never_asks(tmp_path: Path) -> None:
    router = FakeRouter(AFTER)
    asked: list[float] = []

    def prompt(deadline: float) -> str:
        asked.append(deadline)
        return "no"

    verdict = _finish(tmp_path, router, keep_prompt=prompt)
    assert asked == []
    assert verdict.state == owner_verify.CONFIRMED


#: The router after a change that only took an option away.
DELETED = {
    "dhcp": {
        "cfg01411c": {
            ".anonymous": True,
            ".index": 0,
            ".name": "cfg01411c",
            ".type": "dnsmasq",
            "domain": "lan",
        },
        "lan": {
            ".anonymous": False,
            ".index": 1,
            ".name": "lan",
            ".type": "dhcp",
        },
    }
}


def test_the_keep_prompt_of_a_change_that_only_deletes_names_the_rule(
    tmp_path: Path, capsys
) -> None:
    """A change that only takes a rule away does not open the router.

    The words of the prompt change: the change touches a rule that
    controls access from the internet, and it does not say the change
    opens the router.  The gate does not change: the owner still has
    to type "keep".
    """
    record = _exposure_record(ops=[["delete", "dhcp.lan.limit", None]])
    router = FakeRouter(DELETED)
    verdict = _finish(
        tmp_path, router, record=record, keep_prompt=lambda _deadline: "keep\n"
    )
    out = capsys.readouterr().out
    assert "touches a rule that controls access from the internet" in out, out
    assert "can open your router to the internet" not in out, out
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 1


def test_the_keep_prompt_of_a_change_that_only_deletes_still_gates(
    tmp_path: Path, capsys
) -> None:
    """The gate stays: only "keep" keeps the change."""
    record = _exposure_record(ops=[["delete", "dhcp.lan.limit", None]])
    router = FakeRouter(DELETED)
    verdict = _finish(
        tmp_path, router, record=record, keep_prompt=lambda _deadline: "no\n"
    )
    out = capsys.readouterr().out
    assert "touches a rule that controls access from the internet" in out, out
    assert verdict.state == owner_verify.UNKNOWN
    assert verdict.owner_keep is False
    assert owner_verify.DID_NOT_KEEP in verdict.notes
    assert router.confirms == 0


def test_the_keep_prompt_of_a_restore_that_puts_the_values_back_names_the_rule(
    tmp_path: Path, capsys
) -> None:
    """A restore that puts the original values back opens nothing.

    A restore plan runs against the state the change made, so its own
    backup holds the CHANGED values.  It is judged against the backup
    of the plan it undoes: the values before the change.

    A restore removes nothing, so the prompt does not say that
    something comes back: the words have to be true.
    """
    state = _owner_state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    planned = owner_flow.plan(
        service,
        "lab-r1",
        BATCH,
        explanation=_explanation_for(BATCH),
        owner_confirmed_in_chat=True,
        client_factory=_owner_factory(FakeClient(_answers())),
    )
    restore_sid = planned["restore_session_id"]
    record = _owner_record(state, restore_sid)
    # the change is an exposure, so the owner is asked to keep it
    record["reasons"] = ["wan-rule: a rule opens a port to the internet"]
    # the restore runs against the state the change made
    backup = owner_backup.load(state, restore_sid)
    # the router holds the values the restore put back
    router = FakeRouter(_measured_dhcp())
    verdict = owner_verify.finish(
        _device(tmp_path),
        record,
        backup,
        _run(),
        _factory(router),
        now=time.time,
        sleep=_no_sleep,
        keep_prompt=lambda _deadline: "keep\n",
        confirm_token=TOKEN,
        state=state,
    )
    out = capsys.readouterr().out
    assert "touches a rule that controls access from the internet" in out, out
    assert "can open your router to the internet" not in out, out
    assert "comes back" not in out, out
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes


def test_the_keep_prompt_of_a_change_that_only_puts_a_value_back_is_silent() -> None:
    """A change that removes nothing does not say that something comes back.

    The words of the prompt have to be true of the change they are
    read for: a change that only sets a value the backup already holds
    removes nothing, so nothing comes back when the owner types
    nothing.
    """
    record = _record(ops=[["set", "dhcp.lan.limit", "150"]])
    text = owner_verify.keep_prompt_text(record, _backup())
    assert "touches a rule that controls access from the internet" in text, text
    assert "comes back" not in text, text


def test_the_keep_prompt_of_a_change_that_removes_something_says_it() -> None:
    """A change that removes something says what silence does.

    The sentence names the removal, so it is only said when there is a
    removal to name.
    """
    record = _record(ops=[["delete", "dhcp.lan.limit", None]])
    text = owner_verify.keep_prompt_text(record, _backup())
    assert "comes back" in text, text


def test_the_keep_prompt_of_a_change_that_opens_the_router_says_so(
    tmp_path: Path, capsys
) -> None:
    """A change that sets a value of its own still says what it does."""
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path,
        router,
        record=_exposure_record(),
        keep_prompt=lambda _deadline: "keep\n",
    )
    out = capsys.readouterr().out
    assert "can open your router to the internet" in out, out
    assert "touches a rule that controls access from the internet" not in out, out
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes


def test_the_keep_prompt_of_an_opening_change_is_unchanged(
    tmp_path: Path, capsys
) -> None:
    """A change that opens the router keeps the words it had.

    The new sentence says what silence does to a removal.  It says
    nothing of a change that opens the router: that prompt still says
    the change can open the router, and it still undoes on silence.
    """
    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path,
        router,
        record=_exposure_record(),
        keep_prompt=lambda _deadline: "keep\n",
    )
    out = capsys.readouterr().out
    assert "comes back" not in out, out
    assert "can open your router to the internet" in out, out
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes


def test_the_prompt_names_the_time_it_closes(tmp_path: Path, capsys) -> None:
    router = FakeRouter(AFTER)
    started = time.time()
    _finish(
        tmp_path,
        router,
        record=_exposure_record(),
        run={"started_at": started},
        keep_prompt=lambda _deadline: "keep\n",
    )
    out = capsys.readouterr().out
    assert "Type keep before" in out
    assert "the router undoes it" in out


# ---- a config that is still missing ----------------------------------------


#: The plan that creates the first section of a config the router does
#: not have.
CREATE_WIRELESS = _record(
    uci_batch=(
        "set wireless.newradio=wifi-iface\n"
        "set wireless.newradio.ssid='lab'"
    ),
    diff="+wireless.newradio",
    ops=[
        ["set", "wireless.newradio", "wifi-iface"],
        ["set", "wireless.newradio.ssid", "lab"],
    ],
)


def _missing_backup() -> owner_backup.Backup:
    """The backup of a router whose wireless config does not exist."""
    return owner_backup.Backup(
        configs=BEFORE, board="lab-r1", missing=("wireless",)
    )


def test_a_config_that_is_still_missing_is_not_applied(tmp_path: Path) -> None:
    """A config the backup says is missing, and the router still refuses.

    The change creates the first section of a config the router does not
    have.  A router that still answers "no such config" means the
    change never reached it: NOT APPLIED, not "Newton cannot read it".
    """
    router = FakeRouter(BEFORE, pending=False, missing=("wireless",))
    verdict = _finish(
        tmp_path, router, record=CREATE_WIRELESS, backup=_missing_backup()
    )
    assert verdict.state == owner_verify.NOT_APPLIED, verdict.notes


def test_a_config_that_is_still_missing_is_rolled_back(tmp_path: Path) -> None:
    """The same after the window: the router put the change back."""
    router = FakeRouter(BEFORE, pending=False, missing=("wireless",))
    verdict = owner_verify.settle(
        _device(tmp_path),
        CREATE_WIRELESS,
        _missing_backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.ROLLED_BACK, verdict.notes


# ---- an answer Newton cannot read ------------------------------------------


def test_an_unreadable_unit_anywhere_is_unknown_after_the_window(
    tmp_path: Path,
) -> None:
    """A unit Newton cannot read is never a proven absence.

    The type of the section comes back as a number: that is not a shape
    uci answers.  The change did not reach the router, but Newton cannot
    prove it, so the state is UNKNOWN.
    """
    changed = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], **{".type": 7}),
        }
    }
    router = FakeRouter(changed, pending=False)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.UNKNOWN, verdict.notes


def test_a_value_that_is_not_text_is_never_confirmed(tmp_path: Path) -> None:
    """An option value that is not text proves nothing.

    The router answers the number 250 where the plan staged the text
    "250".  A number is not a shape uci answers: Newton cannot read
    it, so the change is neither confirmed nor kept.
    """
    changed = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], limit=250),
        }
    }
    router = FakeRouter(changed)
    verdict = _finish(tmp_path, router)
    assert verdict.state != owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 0


def test_a_value_that_is_not_text_is_never_kept(tmp_path: Path) -> None:
    """The same after the window: UNKNOWN, never KEPT."""
    changed = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], limit=250),
        }
    }
    router = FakeRouter(changed, pending=False)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.UNKNOWN, verdict.notes


def test_a_value_that_is_not_text_is_unreadable(tmp_path: Path) -> None:
    """None, a dict and a number are all shapes uci does not answer."""
    for value in (None, {"a": "b"}, 7, 1.5, True):
        changed = {
            "dhcp": {
                "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
                "lan": dict(BEFORE["dhcp"]["lan"], limit=value),
            }
        }
        router = FakeRouter(changed)
        verdict = _finish(tmp_path, router)
        assert verdict.state != owner_verify.CONFIRMED, (value, verdict.notes)
        assert router.confirms == 0, value


# ---- the settling ----------------------------------------------------------


def test_the_settle_says_the_router_put_it_back(tmp_path: Path) -> None:
    router = FakeRouter(BEFORE, pending=False)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.ROLLED_BACK


def test_the_settle_says_the_change_stayed(tmp_path: Path) -> None:
    router = FakeRouter(AFTER, pending=False)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.KEPT


def test_the_settle_says_unknown_when_it_cannot_tell(tmp_path: Path) -> None:
    other = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], limit="300"),
        }
    }
    router = FakeRouter(other, pending=False)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.UNKNOWN


# ---- the clock the test moves ----------------------------------------------


class Clock:
    """A clock the test moves by hand."""

    def __init__(self, start: float) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_the_deadline_is_checked_again_before_the_confirm(tmp_path: Path) -> None:
    """A clock that runs past the margin while the checks run: the change
    is not confirmed."""
    started = time.time()
    clock = Clock(started)
    router = FakeRouter(AFTER, on_call=lambda obj, fn, args: clock.advance(200))
    verdict = _finish(
        tmp_path,
        router,
        run={"started_at": started},
        now=clock,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_the_deadline_is_checked_again_after_the_keep_prompt(tmp_path: Path) -> None:
    """A clock that runs past the margin while the owner is asked: the
    change is not confirmed."""
    started = time.time()
    clock = Clock(started)

    def prompt(deadline: float) -> str:
        clock.advance(200)
        return "keep\n"

    router = FakeRouter(AFTER)
    verdict = _finish(
        tmp_path,
        router,
        record=_exposure_record(),
        run={"started_at": started},
        now=clock,
        keep_prompt=prompt,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert owner_verify.DID_NOT_KEEP not in verdict.notes


def test_the_prompt_gets_the_injected_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prompt's own timeout is counted from the clock the caller
    injected, not from the wall clock."""
    seen: dict[str, Any] = {}

    def fake_prompt(deadline: float, now: Any = time.time) -> str | None:
        seen["now"] = now
        return None

    monkeypatch.setattr(owner_verify, "tty_prompt", fake_prompt)
    clock = Clock(time.time())
    router = FakeRouter(AFTER)
    _finish(
        tmp_path,
        router,
        record=_exposure_record(),
        now=clock,
        keep_prompt=None,
    )
    assert seen["now"] is clock


# ---- the claims ------------------------------------------------------------


def test_a_claim_that_cannot_run_blocks_the_confirm(tmp_path: Path) -> None:
    """A claim that can run but cannot run NOW blocks the confirm: an
    applied-but-not-verified change is not a confirmed change."""
    record = _record(probes=[["service-running", "dnsmasq", "any", "present"]])
    router = FakeRouter(AFTER, service_unreadable=True)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert any("claim" in note for note in verdict.notes)


def test_a_claim_that_is_not_supported_does_not_block(tmp_path: Path) -> None:
    """A claim the stock groups cannot run was listed in not_verified at
    plan time: it does not block the confirm."""
    record = _record(probes=[["nft-rule", "something"]])
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state == owner_verify.CONFIRMED
    assert router.confirms == 1


# ---- the malformed read-back -----------------------------------------------


#: A read-back whose section is not a mapping at all.
MALFORMED = {
    "dhcp": {
        "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
        "lan": "corrupt",
    }
}

#: The plan that deletes the section the malformed answer carries.
DELETE_LAN = _record(
    uci_batch="delete dhcp.lan",
    diff="-dhcp.lan",
    ops=[["delete", "dhcp.lan", None]],
)


def test_a_malformed_read_back_is_never_a_proven_absence(tmp_path: Path) -> None:
    """A section that comes back as something else is unreadable: the
    change is not confirmed."""
    router = FakeRouter(MALFORMED)
    verdict = _finish(tmp_path, router, record=DELETE_LAN)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert any("cannot be read" in note for note in verdict.notes)


def test_a_malformed_read_back_after_the_window_is_unknown(tmp_path: Path) -> None:
    """The same malformed answer after the window: UNKNOWN, never KEPT."""
    router = FakeRouter(MALFORMED, pending=False)
    verdict = owner_verify.settle(
        _device(tmp_path),
        DELETE_LAN,
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
    )
    assert verdict.state == owner_verify.UNKNOWN


def test_a_section_without_a_type_is_unreadable(tmp_path: Path) -> None:
    """A section whose type is not text is unreadable, not an absence."""
    changed = {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": dict(BEFORE["dhcp"]["lan"], limit="250", **{".type": 7}),
        }
    }
    router = FakeRouter(changed)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert any("cannot be read" in note for note in verdict.notes)


def test_the_settle_keeps_the_notes_of_the_read_back(tmp_path: Path) -> None:
    """The settle merges the notes of the read-back: what the owner did
    not keep, and what changed that it did not approve, are still true."""
    router = FakeRouter(BEFORE, pending=False)
    before = Verdict(
        state=owner_verify.UNKNOWN,
        checks=("reachable",),
        deadline=0.0,
        notes=("the owner did not keep it", "UNAPPROVED_CHANGE: dhcp.lan.extra changed"),
        not_verified=("Newton cannot read the rpcd config",),
        owner_keep=False,
    )
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        _run(),
        _factory(router),
        sleep=lambda _seconds: None,
        previous=before,
    )
    assert verdict.state == owner_verify.ROLLED_BACK
    assert owner_verify.DID_NOT_KEEP in verdict.notes
    assert any("UNAPPROVED_CHANGE" in note for note in verdict.notes)
    assert verdict.owner_keep is False
    assert verdict.not_verified == ("Newton cannot read the rpcd config",)


def test_the_settle_does_not_decide_while_the_window_is_open(tmp_path: Path) -> None:
    """A window that is still open has not decided anything yet: the
    settle says so instead of guessing."""
    started = time.time()
    clock = SettleClock(started)
    router = FakeRouter(BEFORE, pending=True)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        {"started_at": started},
        _factory(router),
        now=clock,
        sleep=clock.sleep,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert any("waiting for confirmation" in note for note in verdict.notes)


# ---- the third review, defect 1: a deleted section's options ---------------


#: A section the apply added, with the options it carries.
ADDED_HOST = {
    ".anonymous": False,
    ".index": 2,
    ".name": "newhost",
    ".type": "host",
    "mac": "00:11:22:33:44:55",
    "ip": "10.109.0.55",
}

#: The backup the restore of that section runs against.
RESTORE_BACKUP = _backup(
    {
        "dhcp": {
            "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
            "lan": BEFORE["dhcp"]["lan"],
            "newhost": ADDED_HOST,
        }
    }
)

#: The restore that takes that added section away again.
DELETE_NEWHOST = _record(
    uci_batch="delete dhcp.newhost",
    diff="-dhcp.newhost",
    ops=[["delete", "dhcp.newhost", None]],
)


def test_a_deleted_section_and_its_options_are_touched(tmp_path: Path) -> None:
    """The options of a deleted section are touched too.

    The change deletes a section that had options.  The router took the
    section and its options away, which is exactly what the change
    asked for, so the read-back must not call it an unapproved change.
    """
    router = FakeRouter({"dhcp": {"cfg01411c": BEFORE["dhcp"]["cfg01411c"]}})
    verdict = _finish(tmp_path, router, record=DELETE_LAN)
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 1


def test_the_restore_of_an_added_section_is_confirmed(tmp_path: Path) -> None:
    """The restore takes away a section the apply added.

    The backup the restore runs against holds that section with its
    options, so those options are touched too: the restore is not an
    unapproved change either.
    """
    router = FakeRouter(
        {
            "dhcp": {
                "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
                "lan": BEFORE["dhcp"]["lan"],
            }
        }
    )
    verdict = _finish(
        tmp_path, router, record=DELETE_NEWHOST, backup=RESTORE_BACKUP
    )
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 1


def test_a_change_that_took_another_options_away_is_not_confirmed(
    tmp_path: Path,
) -> None:
    """The same restore, but the router also took an option of ANOTHER
    section away: that is not what the change asked for."""
    router = FakeRouter(
        {
            "dhcp": {
                "cfg01411c": BEFORE["dhcp"]["cfg01411c"],
                "lan": {
                    ".anonymous": False,
                    ".index": 1,
                    ".name": "lan",
                    ".type": "dhcp",
                },
            }
        }
    )
    verdict = _finish(
        tmp_path, router, record=DELETE_NEWHOST, backup=RESTORE_BACKUP
    )
    assert verdict.state == owner_verify.UNKNOWN, verdict.notes
    assert router.confirms == 0
    assert any(
        "UNAPPROVED_CHANGE: dhcp.lan.limit is gone" in note
        for note in verdict.notes
    ), verdict.notes


# ---- the third review, defect 2: a batch that only takes settings away ----


def test_a_dns_change_that_only_deletes_needs_the_dnsmasq_check(
    tmp_path: Path,
) -> None:
    """A batch that only takes a DNS setting away is still a DNS change.

    A delete stages no value, so the batch holds no fact: without the
    class the mandatory check of the dns class (the dnsmasq service
    must be running) never ran, and a change that stopped dnsmasq was
    confirmed.
    """
    record = _record(
        uci_batch="delete dhcp.cfg01411c.domain",
        diff="-dhcp.cfg01411c.domain",
        ops=[["delete", "dhcp.cfg01411c.domain", None]],
    )
    after = {
        "dhcp": {
            "cfg01411c": {
                key: value
                for key, value in BEFORE["dhcp"]["cfg01411c"].items()
                if key != "domain"
            },
            "lan": BEFORE["dhcp"]["lan"],
        }
    }
    router = FakeRouter(after, service_running=False)
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state != owner_verify.CONFIRMED, verdict.notes
    assert router.confirms == 0
    assert any("dns check failed" in note for note in verdict.notes), verdict.notes


# ---- the third review, defect 5: an item of a list that is not text -------


def test_a_list_option_with_something_that_is_not_text_cannot_be_read() -> None:
    """A list option with an item that is not text proves nothing.

    The items were coerced into text, so a malformed answer read as a
    value.  An answer Newton cannot read is never a value and never a
    proven absence: it is UNKNOWN.
    """
    for value in ([150], ["1.1.1.1", None]):
        configs = {"dhcp": {"lan": {"server": value}}}
        units = owner_verify._units_of(configs)
        assert units[("dhcp", "lan", "server")] is owner_verify.UNREADABLE, value
        got = owner_verify._value_of(configs, "dhcp", "lan", "server")
        assert got is owner_verify.UNREADABLE, value


# ---- the settle after a real rollback (the lab-r1 end-to-end finding) -----


class SettleClock:
    """A clock the settle's own sleeps move."""

    def __init__(self, start: float) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class ClosingRouter(FakeRouter):
    """A router whose undo window closes at a given time."""

    def __init__(self, configs, clock, closes_at, **kwargs) -> None:
        super().__init__(configs, **kwargs)
        self.clock = clock
        self.closes_at = float(closes_at)

    def call(self, session, obj, fn, args=None):
        if obj == "file" and fn == "list":
            self.pending = self.clock.now < self.closes_at
        return super().call(session, obj, fn, args)


def test_the_settle_waits_for_the_window_to_close(tmp_path: Path) -> None:
    """The window closes after the deadline: the settle waits for it.

    The poll budget counted from the moment the settle was CALLED, so
    a window that closed at deadline+2 was never seen: the settle gave
    up while the router was still rolling back, and said UNKNOWN.
    """
    started = time.time()
    clock = SettleClock(started)
    deadline = started + 180
    router = ClosingRouter(BEFORE, clock, deadline + 2)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        {"started_at": started},
        _factory(router),
        now=clock,
        sleep=clock.sleep,
    )
    assert verdict.state == owner_verify.ROLLED_BACK, verdict.notes
    assert clock.now >= deadline + 2


def test_the_settle_ends_when_the_clock_stands_still(tmp_path: Path) -> None:
    """A host clock that never moves (or was stepped back) cannot make
    the settle poll for ever: the number of polls is bounded too."""
    started = time.time()
    sleeps: list[float] = []
    router = FakeRouter(BEFORE, pending=True)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        {"started_at": started},
        _factory(router),
        now=lambda: started - 1000.0,
        sleep=sleeps.append,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert sum(sleeps) <= 180 + owner_verify.SETTLE_GRACE_S + 5


def test_the_settle_gives_up_only_after_the_grace(tmp_path: Path) -> None:
    """A window that never closes: UNKNOWN, and only after the grace.

    The grace is counted from the window's own deadline, not from the
    moment the settle was called.
    """
    started = time.time()
    clock = SettleClock(started)
    deadline = started + 180
    router = FakeRouter(BEFORE, pending=True)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        {"started_at": started},
        _factory(router),
        now=clock,
        sleep=clock.sleep,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert any("waiting for confirmation" in note for note in verdict.notes)
    assert clock.now >= deadline + owner_verify.SETTLE_GRACE_S


def test_the_settle_survives_a_login_that_always_fails(tmp_path: Path) -> None:
    """A router Newton cannot log into: UNKNOWN, and no exception."""
    started = time.time()
    clock = SettleClock(started)
    router = FakeRouter(BEFORE, refuse_login=True)
    verdict = owner_verify.settle(
        _device(tmp_path),
        _record(),
        _backup(),
        {"started_at": started},
        _factory(router),
        now=clock,
        sleep=clock.sleep,
    )
    assert verdict.state == owner_verify.UNKNOWN
    assert clock.now >= started + 180 + owner_verify.SETTLE_GRACE_S


# ---- the internet check (the installed program's own check) ----------------


def test_a_router_without_the_internet_is_never_confirmed(tmp_path: Path) -> None:
    """The router's own internet check comes before the confirm.

    A router without the internet cannot have applied a change that
    works, so it confirms nothing: the change is left to the router's
    own timer.
    """
    router = FakeRouter(AFTER, internet=False)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert "the internet check failed" in verdict.notes, verdict.notes


def test_an_internet_check_that_cannot_run_is_never_confirmed(
    tmp_path: Path,
) -> None:
    """An internet check that could not run is not a verified check."""
    router = FakeRouter(AFTER, internet_unreadable=True)
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert "the internet check could not run" in verdict.notes, verdict.notes


def test_the_internet_check_runs_the_probes_of_the_router_program(
    tmp_path: Path,
) -> None:
    """The probes are the ones the installed router program runs."""
    router = FakeRouter(AFTER)
    verdict = _finish(tmp_path, router)
    assert "internet" in verdict.checks
    execs = [
        args for obj, fn, args in router.calls if obj == "file" and fn == "exec"
    ]
    assert execs == [
        {
            "command": "/bin/ping",
            "params": ["-c", "1", "-W", "3", "1.1.1.1"],
        },
        {
            "command": "/usr/bin/nslookup",
            "params": ["openwrt.org", "127.0.0.1"],
        },
    ], execs


def test_a_router_that_pings_but_cannot_resolve_is_never_confirmed(
    tmp_path: Path,
) -> None:
    """The ping is not the internet check: the name has to resolve too.

    The installed router program runs a ping and a lookup before every
    confirm, so a router that answers the ping and cannot resolve a
    name has no working internet: it confirms nothing.
    """
    router = FakeRouter(
        AFTER, exec_answers={"/usr/bin/nslookup": {"code": 1}}
    )
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert "the internet check failed" in verdict.notes, verdict.notes


def test_a_router_whose_dns_answer_cannot_be_read_is_never_confirmed(
    tmp_path: Path,
) -> None:
    """An answer Newton cannot read is not a check that passed.

    The ping answers, the lookup answers with a body that holds no
    exit code: the lookup could not run, so the check could not run
    either.
    """
    router = FakeRouter(
        AFTER, exec_answers={"/usr/bin/nslookup": {}}
    )
    verdict = _finish(tmp_path, router)
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
    assert "the internet check could not run" in verdict.notes, verdict.notes


# ---- the internet check waits for the router's own reload ------------------


def test_a_router_whose_ping_fails_twice_and_then_works_is_confirmed(
    tmp_path: Path,
) -> None:
    """The restore case: the internet comes back, and the change is kept.

    The router's own network reload finishes after the apply returns,
    so the first probes can fail while the uplinks are still down.  The
    check retries, and a router that has the internet again confirms
    the change.
    """
    started = 1_000.0
    clock = Clock(started)
    router = FakeRouter(AFTER)
    pings = {"count": 0}

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        if obj == "file" and fn == "exec" and args.get("command") == "/bin/ping":
            pings["count"] += 1
            router.internet = pings["count"] > 2

    router.on_call = on_call
    verdict = _finish(
        tmp_path,
        router,
        run={"started_at": started},
        now=clock,
    )
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert "internet" in verdict.checks
    assert router.confirms == 1, router.calls


def test_a_router_whose_ping_works_only_in_the_first_second_is_not_confirmed(
    tmp_path: Path,
) -> None:
    """The measured case: the check ran before the uplinks were down.

    On the real router an owner script that took the uplinks down was
    confirmed 2.8 s after the run started, and the internet check ran
    about a second after the apply, while netifd had not taken the
    uplinks down yet.  The check waits for the reload, so the ping
    that still works in the first second is not the answer.
    """
    started = 1_000.0
    clock = Clock(started)
    router = FakeRouter(AFTER)

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        # the router has the internet only in the first second
        router.internet = (clock() - started) <= 1

    router.on_call = on_call
    verdict = _finish(
        tmp_path,
        router,
        run={"started_at": started},
        now=clock,
    )
    assert verdict.state == owner_verify.UNKNOWN, verdict.notes
    assert "the internet check failed" in verdict.notes, verdict.notes
    assert router.confirms == 0, router.calls


def test_a_router_whose_internet_dies_after_the_apply_is_not_confirmed(
    tmp_path: Path,
) -> None:
    """The settle is anchored at the apply, not at the start of the run.

    An owner script asks the owner for the router password before it
    applies the change, so the apply lands much later than the start
    of the run: on a password-authenticated router the wait for the
    password alone is often longer than the settle.  A settle measured
    from the start of the run is gone by then, and the check probes
    while the uplinks are still up and confirms a change that took the
    internet down.
    """
    started = 1_000.0
    clock = Clock(started)
    router = FakeRouter(AFTER)
    state: dict[str, float] = {}
    probes: list[float] = []

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        if obj == "file" and fn == "list":
            # the read-back: the owner has typed the password and the
            # change is on the router, 30 s after the run started
            clock.advance(30)
            state["applied_at"] = clock.now
        elif obj == "file" and fn == "exec":
            probes.append(clock.now)
            # the router's internet dies 1 s after the apply
            router.internet = clock.now < state["applied_at"] + 1

    router.on_call = on_call
    verdict = _finish(
        tmp_path,
        router,
        run={"started_at": started},
        now=clock,
    )
    assert verdict.state == owner_verify.UNKNOWN, verdict.notes
    assert "the internet check failed" in verdict.notes, verdict.notes
    assert router.confirms == 0, router.calls
    # the first probe runs 10 s after the read-back, which is after the
    # apply, and not 10 s after the start of the run
    assert probes[0] == started + 30 + 10, probes


def test_a_read_back_that_starts_after_the_budget_runs_no_probe(
    tmp_path: Path,
) -> None:
    """A read-back that starts too late has no budget: no probe runs.

    The window is nearly over, so there is no time for the check: the
    reason says the check could not run, and nothing is confirmed.
    """
    started = 1_000.0
    clock = Clock(started)
    router = FakeRouter(AFTER)

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        if obj == "file" and fn == "list":
            # the read-back: the owner took 20 s to type the password
            clock.advance(20)

    router.on_call = on_call
    verdict = _finish(
        tmp_path,
        router,
        record=_record(timeout_s=30),
        run={"started_at": started},
        now=clock,
    )
    assert verdict.state == owner_verify.UNKNOWN, verdict.notes
    assert "the internet check could not run" in verdict.notes, verdict.notes
    assert router.confirms == 0, router.calls
    execs = [
        args for obj, fn, args in router.calls if obj == "file" and fn == "exec"
    ]
    assert execs == [], execs


def test_the_class_checks_run_after_the_settle(tmp_path: Path) -> None:
    """The class checks run after the internet check, so after the settle.

    A router whose dnsmasq stopped is caught by the class check, and
    that check has to run when the router's own reload is over.
    """
    started = 1_000.0
    clock = Clock(started)
    after = {
        "dhcp": {
            "cfg01411c": {
                key: value
                for key, value in BEFORE["dhcp"]["cfg01411c"].items()
                if key != "domain"
            },
            "lan": BEFORE["dhcp"]["lan"],
        }
    }
    router = FakeRouter(after)
    seen: dict[str, float] = {}

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        if obj == "service" and fn == "list":
            seen["service"] = clock()

    router.on_call = on_call
    verdict = _finish(
        tmp_path,
        router,
        record=_record(
            uci_batch="delete dhcp.cfg01411c.domain",
            diff="-dhcp.cfg01411c.domain",
            ops=[["delete", "dhcp.cfg01411c.domain", None]],
        ),
        run={"started_at": started},
        now=clock,
    )
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    assert "class-checks" in verdict.checks
    assert seen["service"] >= started + 10, seen


def test_the_check_names_name_the_order_of_the_checks() -> None:
    """The names of the checks, in the order the checks run.

    A constant that names an order does not prove that order: the
    order of the CALLS is proved by the test below.
    """
    assert owner_verify.CHECK_NAMES == (
        "reachable",
        "pending",
        "internet",
        "expected",
        "nothing-else",
        "class-checks",
        "acls",
        "claims",
    ), owner_verify.CHECK_NAMES


def test_the_router_is_asked_for_the_internet_right_after_the_pending_check(
    tmp_path: Path,
) -> None:
    """The order of the CALLS: the internet comes right after the window.

    The check waits for the router's own reload, so it runs first, and
    the class checks (the dnsmasq service) run after it.  This is the
    order the router is asked in: moving the internet check after the
    class checks has to make this test fail.
    """
    after = {
        "dhcp": {
            "cfg01411c": {
                key: value
                for key, value in BEFORE["dhcp"]["cfg01411c"].items()
                if key != "domain"
            },
            "lan": BEFORE["dhcp"]["lan"],
        }
    }
    record = _record(
        uci_batch="delete dhcp.cfg01411c.domain",
        diff="-dhcp.cfg01411c.domain",
        ops=[["delete", "dhcp.cfg01411c.domain", None]],
    )
    asked: list[str] = []

    def on_call(obj: str, fn: str, args: dict[str, Any]) -> None:
        if obj == "file" and fn == "list":
            if args.get("path") == rpcd_txn.SNAPSHOT_DIR:
                asked.append("pending")
        elif obj == "file" and fn == "exec":
            if args.get("command") in ("/bin/ping", "/usr/bin/nslookup"):
                asked.append("internet")
        elif obj == "uci" and fn == "get":
            asked.append("configs")
        elif obj == "service" and fn == "list":
            asked.append("class-checks")

    router = FakeRouter(after)
    router.on_call = on_call
    verdict = _finish(tmp_path, router, record=record)
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes
    for name in ("pending", "internet", "configs", "class-checks"):
        assert name in asked, asked
    # the window is read first, the internet check comes right after
    # it, and the read of the configs and the class checks come after
    # the internet check
    assert asked.index("pending") < asked.index("internet"), asked
    assert asked.index("internet") < asked.index("configs"), asked
    assert asked.index("internet") < asked.index("class-checks"), asked


# ---- a removal that takes a way in away ------------------------------------


#: The firewall of lab-r1: a DNAT forward, an ACCEPT rule and a zone.
FIREWALL_BEFORE: dict[str, dict[str, dict[str, Any]]] = {
    "firewall": {
        "redirect1": {
            ".anonymous": False,
            ".index": 1,
            ".name": "redirect1",
            ".type": "redirect",
            "dest_port": "443",
            "target": "DNAT",
        },
        "rule1": {
            ".anonymous": False,
            ".index": 2,
            ".name": "rule1",
            ".type": "rule",
            "src": "wan",
            "dest_port": "22",
            "target": "ACCEPT",
        },
        "rule2": {
            ".anonymous": False,
            ".index": 3,
            ".name": "rule2",
            ".type": "rule",
            "src": "wan",
            "dest_port": "23",
            "target": "DROP",
        },
        "wan": {
            ".anonymous": False,
            ".index": 4,
            ".name": "wan",
            ".type": "zone",
            "name": "wan",
        },
    }
}

#: The same firewall without the forward.
FIREWALL_AFTER: dict[str, dict[str, dict[str, Any]]] = {
    "firewall": {
        key: entry
        for key, entry in FIREWALL_BEFORE["firewall"].items()
        if key != "redirect1"
    }
}


def _forward_record(**overrides: Any) -> dict[str, Any]:
    """A record of a change that opens a port to the internet."""
    record = _record(
        reasons=["wan-redirect: a port forward opens a port to the internet"]
    )
    record.update(overrides)
    return record


def _prompt_that_is_never_asked(asked: list[float]):
    def prompt(deadline: float) -> str:
        asked.append(deadline)
        return None

    return prompt


def test_the_keep_prompt_of_a_removal_says_that_the_forward_comes_back(
    tmp_path: Path, capsys
) -> None:
    """The gate stays, and the words say what silence does.

    Newton cannot see the live firewall, so a removal of a port
    forward is asked for like every other exposure.  The prompt says
    what happens when the owner types nothing: the router puts the
    old settings back, so the forward this change removes comes back.
    """
    record = _forward_record(ops=[["delete", "firewall.redirect1", None]])
    router = FakeRouter(FIREWALL_AFTER)
    verdict = _finish(
        tmp_path,
        router,
        record=record,
        backup=_backup(FIREWALL_BEFORE),
        keep_prompt=lambda _deadline: "keep\n",
    )
    out = capsys.readouterr().out
    assert "comes back" in out, out
    assert verdict.state == owner_verify.CONFIRMED, verdict.notes


def test_the_removal_of_a_drop_rule_still_asks(tmp_path: Path) -> None:
    """A rule that is not an ACCEPT rule is not a way in that goes away."""
    record = _forward_record(ops=[["delete", "firewall.rule2", None]])
    router = FakeRouter(
        {
            "firewall": {
                key: entry
                for key, entry in FIREWALL_BEFORE["firewall"].items()
                if key != "rule2"
            }
        }
    )
    asked: list[float] = []
    verdict = _finish(
        tmp_path,
        router,
        record=record,
        backup=_backup(FIREWALL_BEFORE),
        keep_prompt=_prompt_that_is_never_asked(asked),
    )
    assert asked, "the owner is still asked to keep it"
    assert verdict.state == owner_verify.UNKNOWN
    assert verdict.owner_keep is False
    assert router.confirms == 0


def test_the_removal_of_an_option_of_a_forward_still_asks(tmp_path: Path) -> None:
    """Only the whole forward goes away: an option is not a way in."""
    after = {
        "firewall": {
            "redirect1": {
                ".anonymous": False,
                ".index": 1,
                ".name": "redirect1",
                ".type": "redirect",
                "dest_port": "443",
            },
            "rule1": FIREWALL_BEFORE["firewall"]["rule1"],
            "rule2": FIREWALL_BEFORE["firewall"]["rule2"],
            "wan": FIREWALL_BEFORE["firewall"]["wan"],
        }
    }
    record = _forward_record(
        ops=[["delete", "firewall.redirect1.target", None]]
    )
    router = FakeRouter(after)
    asked: list[float] = []
    verdict = _finish(
        tmp_path,
        router,
        record=record,
        backup=_backup(FIREWALL_BEFORE),
        keep_prompt=_prompt_that_is_never_asked(asked),
    )
    assert asked, "the owner is still asked to keep it"
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0


def test_a_batch_that_also_sets_something_still_asks(tmp_path: Path) -> None:
    """A batch that holds more than the removal is not a removal."""
    before = {
        "dhcp": BEFORE["dhcp"],
        "firewall": FIREWALL_BEFORE["firewall"],
    }
    after = {
        "dhcp": AFTER["dhcp"],
        "firewall": FIREWALL_AFTER["firewall"],
    }
    record = _forward_record(
        ops=[
            ["delete", "firewall.redirect1", None],
            ["set", "dhcp.lan.limit", "250"],
        ]
    )
    router = FakeRouter(after)
    asked: list[float] = []
    verdict = _finish(
        tmp_path,
        router,
        record=record,
        backup=_backup(before),
        keep_prompt=_prompt_that_is_never_asked(asked),
    )
    assert asked, "the owner is still asked to keep it"
    assert verdict.state == owner_verify.UNKNOWN
    assert router.confirms == 0
