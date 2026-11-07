"""the plan of a no-install device.

The allowlist of part 1 decides what Newton may do by itself: a change
of an allowlisted class becomes an auto plan (mode ``auto``), and every
other change becomes an owner script (the flow).

What is proved here:

  * a DHCP reservation is an auto plan: one record, no script, the
    record verifies with the plan hash, and the router is only read;
  * a Wi-Fi change is an owner script, and a Wi-Fi key is refused with
    the LuCI hint;
  * a live grant waives the owner's chat yes for an auto plan and
    never for an owner script;
  * the window is the window (120..600, default 180) and the reboot
    line is in the result;
  * the plan of a no-install device never reaches ssh.

No router is contacted: the backup comes from the measured answers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import grants
from newton_mcp import noinstall_flow
from newton_mcp import owner_flow
from newton_mcp import plan as _plan
from newton_mcp import server as _server
from newton_mcp.server import NewtonError

import noinstall_answers
import noinstall_fakes
from noinstall_fakes import FakeRouter

from test_owner_flow import FakeService, _device


# ---- the fakes -------------------------------------------------------------


#: The measured dhcp config of lab-r1.
DHCP = noinstall_answers.data("uci.get.dhcp")["values"]

#: A wireless config with one interface (the measured router's wireless
#: config is not readable, so this one is synthetic).
WIRELESS = {
    "default_radio0": {
        ".anonymous": False,
        ".index": 1,
        ".name": "default_radio0",
        ".type": "wifi-iface",
        "device": "radio0",
        "ifname": "wlan0",
        "network": "lan",
        "ssid": "labnet",
    }
}


def _answers(configs: dict[str, Any]) -> dict[tuple[str, str], Any]:
    """The answers of a router that holds the given configs."""
    def uci_get(_obj: str, _fn: str, args: dict[str, Any]) -> Any:
        return {"values": configs.get(str(args.get("config", "")), {})}

    return {
        ("file", "list"): {"entries": []},
        ("system", "board"): {"board_name": "lab-r1"},
        ("uci", "get"): uci_get,
    }


def _state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    return state


def _explanation_for(batch: str) -> dict[str, Any]:
    """A valid explanation for one batch: one step per change line."""
    lines = [line for line in batch.splitlines() if line.strip()]
    return {
        "intent": "change one setting of the router",
        "steps": ["one change for the owner to read"] * len(lines),
        "expect": [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}],
        "risk": "the router's own settings change",
    }


#: A DHCP reservation: the class Newton may apply itself.
RESERVATION = (
    "set dhcp.laptop=host\n"
    "set dhcp.laptop.mac='02:00:00:00:10:01'\n"
    "set dhcp.laptop.ip='10.109.0.55'\n"
)

#: A value added to a list: the transaction engine has no shape for a
#: list verb, so Newton cannot apply this one itself.
LIST_VALUE = "add_list dhcp.cfg01411c.server='1.1.1.1'\n"

#: A section with no setting of its own: the engine creates a section
#: and its settings in one call, so there is nothing to create.
EMPTY_SECTION = "set dhcp.newthing=host\n"

#: A Wi-Fi name: never auto-applied on a no-install router.
WIFI_NAME = "set wireless.default_radio0.ssid='newname'\n"

#: A Wi-Fi key: a secret, so the owner sets it in LuCI.
WIFI_KEY = "set wireless.default_radio0.key='synthetic-secret'\n"


def _run_plan(
    tmp_path: Path,
    batch: str = RESERVATION,
    *,
    window_s: int = 180,
    owner_confirmed: Any = True,
    configs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The plan of a no-install device, over the fake router."""
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(
        _answers(configs if configs is not None else {"dhcp": DHCP})
    )
    result = noinstall_flow.plan(
        service,
        "lab-r1",
        batch,
        window_s,
        explanation=_explanation_for(batch),
        owner_confirmed_in_chat=owner_confirmed,
        client_factory=noinstall_fakes.factory(router),
    )
    result["_service"] = service
    result["_router"] = router
    return result


def _record(state: Path, sid: str) -> dict[str, Any]:
    return json.loads(
        (state / "plans" / f"{sid}.json").read_text(encoding="utf-8")
    )


# ---- the auto plan ---------------------------------------------------------


def test_a_dhcp_reservation_is_an_auto_plan(tmp_path: Path) -> None:
    """The allowlisted class is planned as an auto plan: one record, no
    script, the fields the installed record has and the ones the
    no-install plan adds."""
    result = _run_plan(tmp_path)
    assert result["mode"] == "auto"
    assert result["auto_apply_reason"] == "Newton applies this itself"
    state = result["_service"].state
    record = _record(state, result["session_id"])
    assert record["mode"] == "auto"
    assert record["router_leash"] == "rpcd"
    assert record["router_profile"] == "no-install"
    assert record["requires_approval"] is True
    assert record["timeout_s"] == 180
    assert record["base_hash"]
    assert record["ops"]
    assert record["checks"]
    assert record["not_verified"]
    assert record["device"] == "lab-r1"
    assert record["uci_batch"] == RESERVATION
    # an auto plan is applied by Newton itself: there is no script
    assert "script" not in result


def test_the_auto_plan_record_verifies_with_the_plan_hash(tmp_path: Path) -> None:
    result = _run_plan(tmp_path)
    record = _record(result["_service"].state, result["session_id"])
    assert _plan.compute_plan_hash(record) == record["plan_hash"]


def test_the_auto_plan_only_reads_the_router(tmp_path: Path) -> None:
    """The plan reads the settings it touches and writes nothing."""
    result = _run_plan(tmp_path)
    router = result["_router"]
    assert router.logins, "the plan reads the router"
    verbs = {(obj, fn) for _sid, obj, fn, _args in router.calls}
    assert ("uci", "get") in verbs
    for obj, fn in verbs:
        assert fn not in {
            "set", "delete", "commit", "apply", "confirm", "revert",
            "rollback", "destroy",
        }, (obj, fn)


def test_the_auto_plan_needs_the_owners_yes(tmp_path: Path) -> None:
    """Without a yes in the chat and without a grant, the plan is
    refused before the router is read."""
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(_answers({"dhcp": DHCP}))
    with pytest.raises(NewtonError) as caught:
        noinstall_flow.plan(
            service,
            "lab-r1",
            RESERVATION,
            180,
            explanation=_explanation_for(RESERVATION),
            owner_confirmed_in_chat=False,
            client_factory=noinstall_fakes.factory(router),
        )
    assert "owner_confirmed_in_chat" in str(caught.value)
    assert router.calls == []


def test_a_change_the_transaction_engine_cannot_carry_is_an_owner_script(
    tmp_path: Path,
) -> None:
    """A list verb has no shape in the transaction engine.

    The plan promises an auto-apply only when Newton can apply the
    change itself: a change the engine cannot carry is an owner
    script, and the plan says why.
    """
    result = _run_plan(tmp_path, LIST_VALUE)
    assert result["mode"] == "owner-script"
    assert "add_list" in result["auto_apply_reason"]
    assert result["script"]


def test_a_section_with_no_setting_of_its_own_is_an_owner_script(
    tmp_path: Path,
) -> None:
    """The engine creates a section and its settings in one call."""
    result = _run_plan(tmp_path, EMPTY_SECTION)
    assert result["mode"] == "owner-script"
    assert "no settings of its own" in result["auto_apply_reason"]
    assert result["script"]


def test_a_batch_that_re_types_an_existing_section_is_refused(
    tmp_path: Path,
) -> None:
    """A batch that changes the type of a section the router holds is refused.

    ``dhcp.lan`` is the router's DHCP pool: a batch that says it is a
    host would change what the section is, and the allowlist would then
    see a host.  Nothing is planned: no auto plan and no owner script.
    """
    batch = "set dhcp.lan=host\nset dhcp.lan.leasetime='1m'\n"
    with pytest.raises(NewtonError) as excinfo:
        _run_plan(tmp_path, batch)
    assert "changes the type of dhcp.lan" in str(excinfo.value)
    state = _state(tmp_path)
    assert not list((state / "plans").glob("*.json"))


def test_the_transaction_engine_refuses_a_section_line_that_re_types() -> None:
    """The engine never drops a section line that changes the type.

    A section the router holds is what it is: a line that says another
    type is refused, not carried as "nothing to do".
    """
    from newton_mcp import owner_ops

    ops = [owner_ops.OwnerOp("set", "dhcp", "lan", None, None, "host")]
    carried, why = noinstall_flow.txn_ops(
        ops,
        {("dhcp", "lan")},
        {("dhcp", "lan"): "dhcp"},
    )
    assert carried == []
    assert why == (
        "the batch changes the type of dhcp.lan from dhcp to host; "
        "Newton does not do that"
    ), why


# ---- the owner script ------------------------------------------------------


def test_a_wifi_change_is_an_owner_script(tmp_path: Path) -> None:
    """a Wi-Fi change is an owner script, and the plan says why."""
    result = _run_plan(tmp_path, WIFI_NAME, configs={"wireless": WIRELESS})
    assert result["mode"] == "owner-script"
    assert result["auto_apply_reason"].startswith(
        "this needs an owner script because "
    )
    assert "wifi-name-key" in result["auto_apply_reason"]
    assert result["script"]
    # the owner script keeps the A3 records: the apply one and the
    # restore one
    state = result["_service"].state
    assert _record(state, result["session_id"])["kind"] == "owner-script"
    assert _record(state, result["restore_session_id"])["kind"] == "owner-script"


def test_a_wifi_key_is_refused_with_the_luci_hint(tmp_path: Path) -> None:
    """A key is a secret: the owner sets it in LuCI."""
    with pytest.raises(NewtonError) as caught:
        _run_plan(tmp_path, WIFI_KEY, configs={"wireless": WIRELESS})
    assert "set it yourself in LuCI" in str(caught.value)


# ---- the grants -------------------------------------------------------


def test_a_grant_covers_an_auto_plan(tmp_path: Path, monkeypatch) -> None:
    """A live grant is the owner's consent: the auto plan needs no
    second yes in the chat."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32
    )
    result = _run_plan(tmp_path, owner_confirmed=False)
    assert result["mode"] == "auto"
    assert result["consent_basis"] == "grant"
    record = _record(result["_service"].state, result["session_id"])
    assert record["consent_basis"] == "grant"
    assert record["owner_confirmed_in_chat"] is False


def test_a_grant_never_covers_an_owner_script(
    tmp_path: Path, monkeypatch
) -> None:
    """An owner script always needs the owner's own yes: a grant is the
    consent of a change Newton applies itself, not of a script the
    owner runs."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["wifi-name-key"], 1, "ab" * 32, "0" * 32
    )
    with pytest.raises(NewtonError) as caught:
        _run_plan(
            tmp_path,
            WIFI_NAME,
            owner_confirmed=False,
            configs={"wireless": WIRELESS},
        )
    assert "owner_confirmed_in_chat" in str(caught.value)


# ---- the grant may not read the router -----------------------


def test_a_grant_that_cannot_cover_the_change_never_reads_the_router(
    tmp_path: Path, monkeypatch
) -> None:
    """The router is read before the owner's yes ONLY for a live grant
    that could cover the change.

    A grant for DHCP reservations says nothing about a firewall
    change, so the change needs the owner's yes in the chat, and the
    router is not read for it.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32
    )
    batch = "set firewall.wan.input='ACCEPT'\n"
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(_answers({"dhcp": DHCP}))
    with pytest.raises(NewtonError) as caught:
        noinstall_flow.plan(
            service,
            "lab-r1",
            batch,
            180,
            explanation=_explanation_for(batch),
            owner_confirmed_in_chat=False,
            client_factory=noinstall_fakes.factory(router),
        )
    assert "owner_confirmed_in_chat" in str(caught.value)
    assert router.calls == [], "the router must not be contacted at all"
    assert not list((state / "plans").glob("*.json"))


def test_a_grant_that_cannot_carry_the_change_never_reads_the_router(
    tmp_path: Path, monkeypatch
) -> None:
    """A grant covers the changes Newton applies itself.

    A list verb has no shape in the transaction engine, so the change
    is an owner script, and an owner script always needs the owner's
    yes in the chat: the router is not read for it.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant("lab-r1", ["dns"], 1, "ab" * 32, "0" * 32)
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(_answers({"dhcp": DHCP}))
    with pytest.raises(NewtonError) as caught:
        noinstall_flow.plan(
            service,
            "lab-r1",
            LIST_VALUE,
            180,
            explanation=_explanation_for(LIST_VALUE),
            owner_confirmed_in_chat=False,
            client_factory=noinstall_fakes.factory(router),
        )
    assert "owner_confirmed_in_chat" in str(caught.value)
    assert router.calls == [], "the router must not be contacted at all"
    assert not list((state / "plans").glob("*.json"))


def test_a_grant_that_covers_a_list_verb_never_reads_the_router(
    tmp_path: Path, monkeypatch
) -> None:
    """A grant covers the changes Newton applies itself, and a list verb
    is not one of them.

    The batch says the type of its own section, so the grant covers the
    change and the owner's yes in the chat is not needed.  But the
    change carries a list verb, which the transaction engine cannot
    carry: it is an owner script, and an owner script always needs the
    owner's own yes.  The router is not read for it.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32
    )
    batch = "set dhcp.h1=host\nadd_list dhcp.h1.tag='iot'\n"
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(_answers({"dhcp": DHCP}))
    with pytest.raises(NewtonError) as caught:
        noinstall_flow.plan(
            service,
            "lab-r1",
            batch,
            180,
            explanation=_explanation_for(batch),
            owner_confirmed_in_chat=False,
            client_factory=noinstall_fakes.factory(router),
        )
    assert "owner_confirmed_in_chat" in str(caught.value)
    assert router.calls == [], "the router must not be contacted at all"
    assert not list((state / "plans").glob("*.json"))


def test_a_grant_of_the_router_name_never_reads_the_router(
    tmp_path: Path, monkeypatch
) -> None:
    """Newton applies only the allowlisted classes on a no-install
    router.

    A grant for the router name covers that change on an installed
    device, but here the change is an owner script: Newton never
    applies it by itself, so the router is not read for it.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant("lab-r1", ["hostname"], 1, "ab" * 32, "0" * 32)
    batch = "set system.main.hostname='newname'\n"
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(_answers({"system": {}}))
    with pytest.raises(NewtonError) as caught:
        noinstall_flow.plan(
            service,
            "lab-r1",
            batch,
            180,
            explanation=_explanation_for(batch),
            owner_confirmed_in_chat=False,
            client_factory=noinstall_fakes.factory(router),
        )
    assert "owner_confirmed_in_chat" in str(caught.value)
    assert router.calls == [], "the router must not be contacted at all"
    assert not list((state / "plans").glob("*.json"))


def test_a_grant_of_the_wifi_class_never_reads_the_router(
    tmp_path: Path, monkeypatch
) -> None:
    """A Wi-Fi change is an owner script on a no-install router.

    A grant for the Wi-Fi class changes nothing here: the change needs
    the owner's own yes, so the router is not read for it.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["wifi-name-key"], 1, "ab" * 32, "0" * 32
    )
    state = _state(tmp_path)
    service = FakeService(state, {"lab-r1": _device(tmp_path)})
    router = FakeRouter(_answers({"wireless": WIRELESS}))
    with pytest.raises(NewtonError) as caught:
        noinstall_flow.plan(
            service,
            "lab-r1",
            WIFI_NAME,
            180,
            explanation=_explanation_for(WIFI_NAME),
            owner_confirmed_in_chat=False,
            client_factory=noinstall_fakes.factory(router),
        )
    assert "owner_confirmed_in_chat" in str(caught.value)
    assert router.calls == [], "the router must not be contacted at all"
    assert not list((state / "plans").glob("*.json"))


def test_a_grant_could_cover_a_change_of_a_section_the_router_holds(
    tmp_path: Path, monkeypatch
) -> None:
    """The optimistic map says the grant could cover the change.

    The type of the section is not known before the router is read, so
    the map says what it would have to be: a host for a DHCP
    reservation.  The router is read, the type is the one the map
    said, and the grant is honoured.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32
    )
    configs = {
        "dhcp": dict(
            DHCP,
            laptop={
                ".anonymous": False,
                ".index": 6,
                ".name": "laptop",
                ".type": "host",
                "mac": "02:00:00:00:10:01",
                "ip": "10.109.0.55",
            },
        )
    }
    result = _run_plan(
        tmp_path,
        "set dhcp.laptop.ip='10.109.0.56'\n",
        owner_confirmed=False,
        configs=configs,
    )
    assert result["mode"] == "auto", result
    assert result["consent_basis"] == "grant", result


# ---- the window and the reboot line ----------------------------------------


def test_the_window_is_the_a3_window(tmp_path: Path) -> None:
    """120..600 seconds, as the owner script's window."""
    for window in (0, 119, 601, 3600):
        with pytest.raises(NewtonError) as caught:
            _run_plan(tmp_path, window_s=window)
        assert "window" in str(caught.value)
    result = _run_plan(tmp_path, window_s=120)
    assert result["timeout_s"] == 120


def test_the_reboot_line_is_in_the_result(tmp_path: Path) -> None:
    """The owner reads the reboot line once, in the plan result."""
    result = _run_plan(tmp_path)
    assert result["reboot_line"] == owner_flow.REBOOT_LINE.format(180)
    assert result["reboot_line"].count("reboots") == 1


def test_the_record_carries_the_reboot_line(tmp_path: Path) -> None:
    """The record carries the reboot line too, so the approval shows it."""
    result = _run_plan(tmp_path)
    record = _record(result["_service"].state, result["session_id"])
    assert record["reboot_line"] == owner_flow.REBOOT_LINE.format(180)


def test_the_returned_reasons_carry_no_device_text(tmp_path: Path) -> None:
    """The reasons the model sees are cut the way the installed plan cuts
    them: a reason is only ever shortened, never invented, and no line of
    the device's own diff rides along outside the envelope."""
    result = _run_plan(tmp_path)
    record = _record(result["_service"].state, result["session_id"])
    assert result["approval_reasons"] == _server.returned_approval_reasons(
        record["reasons"], record["uci_batch"], record["diff"]
    )
    for reason in result["approval_reasons"]:
        assert any(
            reason == kept or kept.startswith(reason)
            for kept in record["reasons"]
        )


def test_a_grant_covers_a_change_of_a_section_the_router_holds(
    tmp_path: Path, monkeypatch
) -> None:
    """A grant covers a change of a section the router already holds.

    The class of such a change needs the type the router holds: the
    plan reads the router before it answers, so the grant is honoured
    and the owner is not asked a second time.
    """
    monkeypatch.setenv("NEWTON_STATE_DIR", str(_state(tmp_path)))
    grants.open_grant(
        "lab-r1", ["dhcp-reservations"], 1, "ab" * 32, "0" * 32
    )
    configs = {
        "dhcp": dict(
            DHCP,
            laptop={
                ".anonymous": False,
                ".index": 6,
                ".name": "laptop",
                ".type": "host",
                "mac": "02:00:00:00:10:01",
                "ip": "10.109.0.55",
            },
        )
    }
    result = _run_plan(
        tmp_path,
        "set dhcp.laptop.ip='10.109.0.56'\n",
        owner_confirmed=False,
        configs=configs,
    )
    assert result["mode"] == "auto", result
    assert result["consent_basis"] == "grant", result
    record = _record(result["_service"].state, result["session_id"])
    assert record["section_types"]["dhcp.laptop"] == "host", record


def test_the_probes_are_the_probe_and_its_arguments(tmp_path: Path) -> None:
    """The record's probes are the probe and its arguments.

    The installed records carry a probe the same way, so the approval
    shows the same shape in both cases: the probe first, then what it
    is given.  The list is built from the RESOLVED batch, so a section
    the router holds is checked by its real name, and the probes of the
    explanation are in it too.
    """
    result = _run_plan(tmp_path)
    record = _record(result["_service"].state, result["session_id"])
    assert record["probes"] == [
        ["uci-equals", "dhcp.laptop.ip", "10.109.0.55"],
        ["uci-equals", "dhcp.laptop.mac", "02:00:00:00:10:01"],
        ["service-running", "dnsmasq", "any", "present"],
        ["ping", "127.0.0.1"],
    ], record["probes"]


# ---- a list fact survives a later section set -------------------


#: A section the router holds, with a type the grantable classes know.
HOST_SECTION = {
    ".anonymous": False,
    ".index": 6,
    ".name": "h1",
    ".type": "host",
    "mac": "02:00:00:00:10:02",
    "ip": "10.109.0.56",
}


def test_a_list_fact_survives_a_later_section_set_on_the_no_install_path(
    tmp_path: Path,
) -> None:
    """A section-level set does not clear the options of the section.

    The batch adds a value to a list and then sets the type of the
    section: uci keeps the option, so the change is HIGH (it runs a
    command) and Newton does not apply it by itself.
    """
    batch = (
        "add_list dhcp.h1.dhcp_script='/tmp/evil.sh'\n"
        "set dhcp.h1=host\n"
    )
    configs = {"dhcp": dict(DHCP, h1=HOST_SECTION)}
    result = _run_plan(tmp_path, batch, configs=configs)

    assert result["mode"] == "owner-script", result
    assert "high risk" in result["auto_apply_reason"], result
    assert "runs-commands" in result["auto_apply_reason"], result


# ---- a repeated section line ----------------------------------


def test_a_repeated_section_line_for_the_same_new_section_is_one_add() -> None:
    """The same section line twice is one section.

    The transaction engine creates a section and its settings in one
    call, so a batch that says the same thing twice creates it once.
    """
    from newton_mcp import owner_ops

    ops = [
        owner_ops.OwnerOp("set", "dhcp", "laptop", None, None, "host"),
        owner_ops.OwnerOp("set", "dhcp", "laptop", None, None, "host"),
        owner_ops.OwnerOp("set", "dhcp", "laptop", "ip", "10.109.0.55", None),
    ]

    carried, why = noinstall_flow.txn_ops(ops, set(), {})

    assert why == "", why
    assert len(carried) == 1, carried
    assert carried[0].kind == "add", carried
    assert carried[0].values == (("ip", "10.109.0.55"),), carried


def test_a_repeated_section_line_with_another_type_is_refused() -> None:
    """A batch that says two types for one new section is refused.

    The engine creates the section with one type, so a batch that names
    another one is a change Newton does not apply by itself.
    """
    from newton_mcp import owner_ops

    ops = [
        owner_ops.OwnerOp("set", "dhcp", "laptop", None, None, "host"),
        owner_ops.OwnerOp("set", "dhcp", "laptop", None, None, "domain"),
        owner_ops.OwnerOp("set", "dhcp", "laptop", "ip", "10.109.0.55", None),
    ]

    carried, why = noinstall_flow.txn_ops(ops, set(), {})

    assert carried == [], carried
    assert "dhcp.laptop" in why, why
    assert "host" in why and "domain" in why, why


def test_a_repeated_section_line_is_an_auto_plan(tmp_path: Path) -> None:
    """The plan of a batch that says the same section twice is an auto plan.

    The change itself is a DHCP reservation, so Newton applies it; the
    engine creates the section once.
    """
    batch = (
        "set dhcp.laptop=host\n"
        "set dhcp.laptop=host\n"
        "set dhcp.laptop.ip='10.109.0.55'\n"
    )
    result = _run_plan(tmp_path, batch)
    assert result["mode"] == "auto", result
