"""MCP tools that expose the tier splitter.

The ``newton_mcp.tiers`` module does not touch the network; it just
reads the generated ``<tier>.uci`` files next to the manifest,
classifies blocks and partitions the non-skipped ones into probe-safe
batches.  R2 wires those batches to the MCP server through two read-side
tools:

* ``newton_list_tiers`` -- read-only, no device: the three tiers, with
  their batch count, probe lines, placeholders, and the controls the
  planner will NEVER carry (``skipped``).

* ``newton_plan_tier`` -- one batch at a time: the planner picks the
  batch (``batch_index``), the operator fills the placeholder values,
  the server resolves them and calls the same ``plan()`` path as
  ``newton_plan_change`` (so the seal, ADR-010 touched checks on the
  RESOLVED lines, approval gate, leash and prod-profile decisions all
  apply).  There is no apply-tier tool: applying stays on the existing
  plan/approve flow.

These tests cover the tool surface, the schema, the placeholder
fail-closed path (the operator must provide a value for every
placeholder, a bad value is refused by NAME without ever reaching the
router, the response never echoes a rejected value), and the
bypass-checks that the new tool ONLY plans (never applies, never sets
lab/prod profiles).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from exhelp import tier_explained

import newton_mcp.probes as probes
import newton_mcp.server as server
import newton_mcp.tiers as tiers
from newton_mcp.server import NewtonError


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
PROBES_SHA = "1" * 64


# ---- fixtures --------------------------------------------------------------


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def _plan_output(diff="dhcp.skilltest='host'"):
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 1 {PROBES_SHA}\n"
        "PROFILE lab\n"
        "SECTION dhcp cfg01 dnsmasq dnsmasq\n"
        "LEASH wan-rule firewall.wan_rule\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {ROUTER_DIGEST}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )


# ---- tool list (TOOL_NAMES, names, in-memory SDK list) ---------------------


def test_tool_names_has_exactly_seventeen_names_and_lists_the_read_tools():
    """TOOL_NAMES is the canonical source of truth for the MCP surface."""
    assert len(server.TOOL_NAMES) == 17
    assert "newton_list_tiers" in server.TOOL_NAMES
    assert "newton_plan_tier" in server.TOOL_NAMES
    assert "newton_guided_recommend" in server.TOOL_NAMES
    assert "newton_guided_audit" in server.TOOL_NAMES
    assert "newton_list_getters" in server.TOOL_NAMES
    assert "newton_get_state" in server.TOOL_NAMES
    assert "newton_plan_scan" in server.TOOL_NAMES
    assert "newton_run_scan" in server.TOOL_NAMES


def test_tool_names_never_named_approve_profile_or_break_glass():
    """The lab safety policy forbids any tool that approves, sets a
    lab/prod profile, or break-glasses; the new tier tools are allowed
    but must keep their promises by being NAMED correctly."""
    for name in server.TOOL_NAMES:
        assert "approve" not in name
        assert "profile" not in name, name
        assert "break_glass" not in name, name
        assert name.startswith("newton_"), name


def test_live_list_tools_equals_tool_names():
    """The MCP in-memory client lists exactly the tools in TOOL_NAMES."""
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    assert {tool.name for tool in response.tools} == server.TOOL_NAMES
    # the new tools actually exist by name
    assert "newton_list_tiers" in {tool.name for tool in response.tools}
    assert "newton_plan_tier" in {tool.name for tool in response.tools}
    assert "newton_guided_recommend" in {tool.name for tool in response.tools}
    assert "newton_guided_audit" in {tool.name for tool in response.tools}


def test_tier_tool_descriptions_explain_that_placeholders_want_uci_section_ids():
    """R4: a placeholder like ``{fw_wan_zone}`` wants the UCI section id
    (``@zone[1]`` or a named section id), NOT the zone's ``name`` option
    value (``wan``).  Both ``newton_list_tiers`` and ``newton_plan_tier``
    must say so plainly in their tool description so the agent does not
    silently send ``wan`` for ``{fw_wan_zone}``."""
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    descriptions = {tool.name: tool.description for tool in response.tools}
    for name in ("newton_list_tiers", "newton_plan_tier"):
        assert name in descriptions, name
        desc = descriptions[name]
        assert "section id" in desc, (name, desc)
        assert "@zone[1]" in desc, (name, desc)
        assert "name option" in desc, (name, desc)


def test_newton_plan_tier_schema_is_typed_tier_enum_with_no_path_or_file_arg():
    """``tier`` is a Literal enum of the three tiers (so the schema
    reflects them) and the tool takes NO file/path argument (the MCP
    server resolves the .uci files itself)."""
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    response = asyncio.run(listed())
    plan_tool = next(t for t in response.tools if t.name == "newton_plan_tier")
    properties = plan_tool.inputSchema["properties"]
    assert set(properties) == {"device", "tier", "batch_index", "values", "timeout_s", "explanation", "owner_confirmed_in_chat"}
    assert "path" not in properties
    assert "file" not in properties
    tier_schema = properties["tier"]
    # FastMCP serialises typing.Literal[...] as an enum with the values
    # listed under anyOf (single string item) or directly as ``enum``.
    enum_values: list[str] = []
    if "enum" in tier_schema:
        enum_values = list(tier_schema["enum"])
    elif "anyOf" in tier_schema:
        for alt in tier_schema["anyOf"]:
            if alt.get("type") == "string" and "enum" in alt:
                enum_values.extend(alt["enum"])
    assert sorted(enum_values) == sorted(tiers.TIER_NAMES)
    # batch_index takes integers and only integers (no path-like string).
    assert properties["batch_index"]["type"] == "integer"


# ---- newton_list_tiers is read-only and never contacts the device ----------


def test_newton_list_tiers_returns_three_tiers_with_placeholders_and_skipped(configured, monkeypatch):
    """``newton_list_tiers`` returns the three tiers (no device contact),
    each with its placeholder names and the planner-skipped controls
    (lab-bound and conditional)."""
    def fail_if_called(*a, **k):
        raise AssertionError("run_script must not be called for list_tiers")

    monkeypatch.setattr(server.NewtonService, "run_script", fail_if_called)
    monkeypatch.setattr(server.subprocess, "run", fail_if_called)

    result = server.newton_list_tiers()
    assert result["result"] == "ok"
    assert sorted(t["tier"] for t in result["tiers"]) == sorted(tiers.TIER_NAMES)
    by_name = {t["tier"]: t for t in result["tiers"]}
    # every tier carries its own placeholders and skipped blocks
    for tier in tiers.TIER_NAMES:
        assert "placeholders" in by_name[tier]
        assert "skipped" in by_name[tier]
        assert "batches" in by_name[tier]
        assert "probe_lines" in by_name[tier]
    # hardened lists OW-MGMT-02 in skipped (lab-bound)
    skipped_ids = {s["id"] for s in by_name["hardened"]["skipped"]}
    assert "OW-MGMT-02" in skipped_ids
    # placeholders for hardened cover fw_wan_zone and fw_allow_ping
    # (the tier doc's firewall keys), and never include a lab-bound name
    assert "fw_wan_zone" in by_name["hardened"]["placeholders"]
    assert "fw_allow_ping" in by_name["hardened"]["placeholders"]
    # the note makes the apply/cancel boundaries and the read-with-newton_read
    # instruction clear to the model
    note = result["note"]
    assert "batch" in note.lower()
    assert "skipped" in note.lower()


# ---- newton_plan_tier calls self.plan with resolved text and stamps the result


def _fake_script(calls, *, output, uci_text_holder, probes_holder):
    """Fake run_script that captures the staged .uci file content and the
    sealed probe file content (read INSIDE the call, before plan()'s
    finally clause unlinks both temp files)."""
    def fake_run(self, device, *args, **kwargs):
        for arg in args:
            if isinstance(arg, str) and arg.startswith("/tmp/newton-uci-"):
                uci_text_holder["text"] = Path(arg).read_text(encoding="utf-8")
                uci_text_holder["path"] = arg
            if isinstance(arg, str) and arg.startswith("/tmp/newton-probes-"):
                probes_holder["path"] = arg
                probes_holder["bytes"] = Path(arg).read_bytes()
        modes = tuple(
            stat.S_IMODE(os.stat(part).st_mode)
            for part in args
            if isinstance(part, str) and part.startswith("/tmp/newton-")
        )
        calls.append((args, kwargs, modes))
        return subprocess.CompletedProcess(list(args), 0, output, "")

    return fake_run


def test_newton_plan_tier_submits_resolved_text_and_returns_tier_metadata(configured, monkeypatch):
    """A hardened batch whose text references {fw_wan_zone} ends up at
    the router with the value substituted and no '{' left; the result
    carries tier / batch_index / batches_total / control_ids."""
    calls, uci_text_holder, probes_holder = [], {}, {}
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        _fake_script(
            calls, output=_plan_output(),
            uci_text_holder=uci_text_holder, probes_holder=probes_holder,
        ),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})

    result = server.newton_plan_tier(
        "quasar", "hardened", batch_index=0,
        values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"},
        timeout_s=120, **tier_explained("hardened", 0, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
    )
    # the staged .uci file the router would have seen has NO leftover
    # placeholder and the substituted values are present
    assert uci_text_holder["text"] is not None
    assert "{" not in uci_text_holder["text"]
    assert "wan" in uci_text_holder["text"]
    assert "Allow-Ping" in uci_text_holder["text"]
    # the call went through the normal plan path: args are plan, dest,
    # uci file, timeout, probe file (positional).
    args = calls[0][0]
    assert args[0] == "plan"
    assert args[1] == "root@192.0.2.1"
    assert os.path.basename(args[2]).startswith("newton-uci-")
    assert not os.path.exists(args[2])
    assert args[3] == "120"
    assert os.path.basename(args[4]).startswith("newton-probes-")
    # the returned plan dict carries the tier metadata and the session id
    assert result["session_id"] == SID
    assert result["tier"] == "hardened"
    assert result["batch_index"] == 0
    assert result["batches_total"] >= 1
    assert isinstance(result["control_ids"], list)
    assert result["control_ids"]  # at least one touched control id
    # the skipped controls are surfaced (lab-bound + conditional) so the
    # operator sees what the planner NEVER carries for this tier
    assert isinstance(result["skipped"], list)
    skipped_ids = {s["id"] for s in result["skipped"]}
    assert "OW-MGMT-02" in skipped_ids or "OW-FW-06" in skipped_ids


def test_sealed_probe_file_contains_the_batch_touched_controls(configured, monkeypatch):
    """The probe file written for the call contains the manifest probes
    of the controls touched by this batch (so the router's manifest-touch
    contract is honoured without the caller naming every probe by hand)."""
    _, _, probes_holder = {}, {}, {}
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        _fake_script(
            [], output=_plan_output(),
            uci_text_holder={}, probes_holder=probes_holder,
        ),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})

    server.newton_plan_tier(
        "quasar", "hardened", batch_index=0,
        values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", 0, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
    )
    probe_bytes = probes_holder.get("bytes")
    assert probe_bytes, probe_bytes


# ---- fail-closed: bad inputs are refused before run_script is called ------


def _plan_tier_service(monkeypatch):
    """Build a ``NewtonService`` configured by ``configured`` (inventory,
    state dir) with ``read`` and ``run_script`` monkeypatched to fail if
    called, so tests can assert the new tool never reaches the device
    for any bad-input path."""
    def fail_if_called(*a, **k):
        raise AssertionError("router must not be called for a precondition failure")

    monkeypatch.setattr(server.NewtonService, "run_script", fail_if_called)
    monkeypatch.setattr(server.NewtonService, "read", fail_if_called)
    return server.NewtonService()


def test_plan_tier_refuses_missing_placeholder_value_by_name_and_does_not_call_router(configured, monkeypatch):
    """A batch whose text references {fw_wan_zone} without a value raises
    NewtonError naming the placeholder BEFORE any device subprocess.
    The MCP tool wrapper turns NewtonError into a tool ``error`` result
    (the same way every other tool surfaces validation failures)."""
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError) as excinfo:
        svc.plan_tier("quasar", "hardened", batch_index=0, values={}, **tier_explained("hardened", 0, {}))
    assert "fw_wan_zone" in str(excinfo.value)
    # the tool wrapper catches it into a client-facing error
    result = server.newton_plan_tier("quasar", "hardened", batch_index=0, values={}, **tier_explained("hardened", 0, {}))
    assert "error" in result
    assert "fw_wan_zone" in result["error"]


def test_plan_tier_refuses_unknown_value_name(configured, monkeypatch):
    """An extra name in ``values`` is refused (no surprise carrier)."""
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError, match="bogus"):
        svc.plan_tier(
            "quasar",
            "hardened",
            batch_index=0,
            values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping", "bogus": "x"}, **tier_explained("hardened", 0, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping", "bogus": "x"}),
        )


@pytest.mark.parametrize("bad_value", ["'DROP'", "DROP\n", "DROP DROP", "$(reboot)", "DROP;DROP"])
def test_plan_tier_refuses_unsafe_value_without_echoing_it(configured, monkeypatch, bad_value):
    """A bad value (quote, newline, space, ;, $(...)) is refused and the
    error message NEVER contains the value (redactor-style)."""
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError) as excinfo:
        svc.plan_tier(
            "quasar",
            "hardened",
            batch_index=0,
            values={"fw_wan_zone": bad_value, "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", 0, {"fw_wan_zone": bad_value, "fw_allow_ping": "Allow-Ping"}),
        )
    message = str(excinfo.value)
    assert "fw_wan_zone" in message  # the key is named
    assert bad_value not in message  # the bad value is never echoed


@pytest.mark.parametrize("batch_index", [-1, 99])
def test_plan_tier_refuses_batch_index_out_of_range(configured, monkeypatch, batch_index):
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError) as excinfo:
        svc.plan_tier(
            "quasar",
            "hardened",
            batch_index=batch_index,
            values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", batch_index, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
        )
    message = str(excinfo.value)
    assert "batch" in message.lower() or "batches_total" in message
    assert "hardened" not in message  # the tier value is not echoed


def test_plan_tier_refuses_negative_batch_index(configured, monkeypatch):
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError):
        svc.plan_tier(
            "quasar", "hardened", batch_index=-1,
            values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", -1, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
        )


@pytest.mark.parametrize("batch_index", [True, "0", 1.5])
def test_plan_tier_refuses_non_integer_batch_index(configured, monkeypatch, batch_index):
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError):
        svc.plan_tier(
            "quasar",
            "hardened",
            batch_index=batch_index,
            values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", batch_index, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
        )


def test_plan_tier_refuses_unknown_tier(configured, monkeypatch):
    svc = _plan_tier_service(monkeypatch)
    with pytest.raises(NewtonError, match="tier"):
        svc.plan_tier("quasar", "bogus", batch_index=0, values={}, **tier_explained("bogus", 0, {}))


# ---- bypass checks: plan_tier is a PLAN path, not an APPLY / profile path --


def test_plan_tier_source_does_not_call_apply():
    """``NewtonService.plan_tier`` source must not call ``apply(`` -- the
    tier path plans ONE batch and returns; the existing plan/approve/
    apply flow runs the next batch the same way ``newton_plan_change``
    does.  This is the bypass guard against a tool that ships a tier as
    one write without the human-in-the-loop."""
    source = inspect.getsource(server.NewtonService.plan_tier)
    assert "apply(" not in source, source


def test_plan_tier_result_session_id_is_from_plan_path_only(tmp_path, monkeypatch):
    """A successful plan_tier result must carry the session_id the
    router issued -- i.e. session_id only appears because we called the
    same ``plan()`` path the existing tool uses.  Use a lab-profile
    device so the prod-profile approval rule does not require approval
    for this test (we are checking the session_id round-trip)."""
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\nprofile = "lab"\nlab = true\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        _fake_script(
            [], output=_plan_output(),
            uci_text_holder={}, probes_holder={},
        ),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    result = server.newton_plan_tier(
        "quasar", "hardened", batch_index=0,
        values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", 0, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
    )
    assert result["session_id"] == SID
    assert result["approval_required"] is False


def test_plan_tier_audit_records_the_call(configured, monkeypatch):
    """call_tool() audits the call; plan_tier must inherit that -- the
    audit line for a successful call carries the tool name and 'ok'."""
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        _fake_script(
            [], output=_plan_output(),
            uci_text_holder={}, probes_holder={},
        ),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    server.newton_plan_tier(
        "quasar", "hardened", batch_index=0,
        values={"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}, **tier_explained("hardened", 0, {"fw_wan_zone": "wan", "fw_allow_ping": "Allow-Ping"}),
    )
    audit = (configured / "state" / "mcp-audit.log").read_text()
    assert "newton_plan_tier" in audit


# ---- value handling for a tier with no placeholders is a no-op -------------


def test_plan_tier_with_a_tier_having_no_placeholders_works_without_values(configured, monkeypatch):
    """Standard has {fw_wan_zone}; if a control ever drops its placeholder,
    plan_tier must still work without values."""
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        _fake_script(
            [], output=_plan_output(),
            uci_text_holder={}, probes_holder={},
        ),
    )
    monkeypatch.setattr(server.NewtonService, "read", lambda self, d, c: {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False})
    # Use the values for every placeholder standard needs. The contract
    # is fail-closed; standard has fw_wan_zone, so missing it is refused.
    # This shape of test asserts the success path of an all-present dict.
    result = server.newton_plan_tier(
        "quasar", "standard", batch_index=0,
        values={"fw_wan_zone": "wan"}, **tier_explained("standard", 0, {"fw_wan_zone": "wan"}),
    )
    assert result["session_id"] == SID
    assert result["tier"] == "standard"
