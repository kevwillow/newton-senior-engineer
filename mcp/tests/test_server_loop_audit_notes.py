"""The MCP server: the event loop, the guided audit's result and
its repeated reads, the tools a vendor device advertises, the size of the tool
descriptions, the AD audit's collection and the AD status not_found answer."""

from __future__ import annotations

import asyncio
import json
import subprocess
import threading
from typing import Any

import pytest

from newton_mcp import envelope as envelope_mod
from newton_mcp import guided as guided_mod
from newton_mcp import server
from newton_mcp.adapters import base, registry


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
PLAN_ID = "a" * 32

# Arguments that pass each tool's input schema; the tool body is replaced,
# so nothing here reaches a device.
TOOL_ARGUMENTS: dict[str, dict[str, Any]] = {
    "newton_list_devices": {},
    "newton_read": {"device": "quasar", "command": "uptime"},
    "newton_backup": {"device": "quasar"},
    "newton_plan_change": {"device": "quasar", "uci_batch": "set dhcp.x=host"},
    "newton_plan_undo": {"device": "quasar", "change_id": SID},
    "newton_apply_change": {"device": "quasar", "session_id": SID},
    "newton_confirm_change": {"device": "quasar", "session_id": SID},
    "newton_change_status": {"device": "quasar", "session_id": SID},
    "newton_abort_change": {"device": "quasar", "session_id": SID},
    "newton_grant_off": {"device": "quasar"},
    "newton_list_tiers": {},
    "newton_plan_tier": {"device": "quasar", "tier": "standard"},
    "newton_guided_recommend": {},
    "newton_guided_audit": {"device": "quasar"},
    "newton_plan_scan": {"device": "quasar", "kind": "wifi", "profile": "survey"},
    "newton_run_scan": {"device": "quasar", "request_id": "r1"},
    "newton_list_getters": {"device": "vy1"},
    "newton_get_state": {"device": "vy1", "getter": "g"},
    "newton_ad_audit": {"device": "dc1"},
    "newton_ad_list_checks": {},
    "newton_ad_plan_change": {"device": "corp", "verb": "maq", "value": 0},
    "newton_ad_apply_change": {"device": "corp", "plan_id": PLAN_ID},
    "newton_ad_change_status": {"device": "corp", "plan_id": PLAN_ID},
    "newton_ad_abort_change": {"device": "corp", "plan_id": PLAN_ID},
}


def _registered_tools() -> dict[str, Any]:
    return {tool.name: tool for tool in server.mcp._tool_manager.list_tools()}


# ---- no tool runs on the server's event loop -----------------------


def test_the_argument_table_names_every_tool():
    assert set(TOOL_ARGUMENTS) == server.TOOL_NAMES == set(_registered_tools())


def test_every_registered_tool_runs_off_the_event_loop():
    """A sync tool runs inline on the event loop, so a confirm or abort of a
    held change would wait behind it: every tool is registered async."""
    sync = sorted(name for name, tool in _registered_tools().items() if not tool.is_async)
    assert sync == []


@pytest.mark.parametrize("tool", sorted(TOOL_ARGUMENTS))
def test_each_tool_leaves_the_event_loop_free(configured_newton, monkeypatch, tool):
    """While the tool's body waits, the event loop still runs: the body waits
    for a coroutine on the loop, which can run only when the body is off it."""
    from mcp.shared.memory import create_connected_server_and_client_session

    loop_ran = threading.Event()

    def waits_for_the_loop(*_a: Any, **_k: Any) -> Any:
        if not loop_ran.wait(5):
            return {"result": "the event loop was blocked"}
        return {"result": "ok"}

    monkeypatch.setattr(server, "call_tool", waits_for_the_loop)
    monkeypatch.setattr(
        guided_mod, "questions", lambda: [waits_for_the_loop()["result"]]
    )

    async def run() -> dict:
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as client:
            call = asyncio.create_task(client.call_tool(tool, TOOL_ARGUMENTS[tool]))
            await asyncio.sleep(0.05)
            loop_ran.set()
            result = await call
            return json.loads(result.content[0].text)

    result = asyncio.run(run())
    if tool == "newton_guided_recommend":
        assert result.get("questions") == ["ok"], result
    else:
        assert result.get("result") == "ok", result


def test_an_abort_finishes_while_a_scan_is_still_running(configured_newton, monkeypatch):
    """A slow scan no longer holds an abort of a held change behind it: the
    scan ends only after the abort has answered."""
    from mcp.shared.memory import create_connected_server_and_client_session

    abort_done = threading.Event()

    def fake_call_tool(tool: str, device: str, fn: Any) -> dict[str, Any]:
        if tool == "newton_run_scan":
            ended = abort_done.wait(5)
            return {"result": "ok" if ended else "the scan held the abort"}
        abort_done.set()
        return {"result": "aborted"}

    monkeypatch.setattr(server, "call_tool", fake_call_tool)

    async def run() -> tuple[dict, dict]:
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as client:
            scan = asyncio.create_task(
                client.call_tool("newton_run_scan", TOOL_ARGUMENTS["newton_run_scan"])
            )
            await asyncio.sleep(0.05)
            abort = await asyncio.wait_for(
                client.call_tool(
                    "newton_abort_change", TOOL_ARGUMENTS["newton_abort_change"]
                ),
                3,
            )
            done = await scan
            return (
                json.loads(abort.content[0].text),
                json.loads(done.content[0].text),
            )

    aborted, scanned = asyncio.run(run())
    assert aborted == {"result": "aborted"}
    assert scanned == {"result": "ok"}


def test_the_wrapped_tools_keep_their_input_schemas():
    """Moving a tool off the loop keeps the arguments it takes."""
    tools = _registered_tools()
    scan = tools["newton_plan_scan"].parameters
    assert set(scan["properties"]) == {"device", "kind", "profile", "interface"}
    assert set(scan["required"]) == {"device", "kind", "profile"}
    tier = tools["newton_plan_tier"].parameters
    assert set(tier["properties"]) == {
        "device", "tier", "batch_index", "values", "timeout_s",
        "explanation", "owner_confirmed_in_chat",
    }
    assert set(tier["required"]) == {"device", "tier"}
    assert tools["newton_list_devices"].description == "List devices from the local inventory."


# ---- the guided audit's result and repeated reads ---------


def _audit_commands() -> list[str]:
    return [c for item in guided_mod.AUDIT_ITEMS for c in item["commands"]]


def _fake_reads(monkeypatch, failing: set[str] | None = None, everything_fails=False):
    calls: list[str] = []
    prefix = f"{server.PROG} read "

    def fake_run(args, **kwargs):
        command = args[-1].removeprefix(prefix)
        calls.append(command)
        if everything_fails or (failing and command in failing):
            return subprocess.CompletedProcess(args, 1, "", "read failed")
        return subprocess.CompletedProcess(args, 0, f"out of {command}\n", "")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    return calls


def test_an_audit_whose_reads_all_fail_is_not_ok(configured_newton, monkeypatch):
    _fake_reads(monkeypatch, everything_fails=True)

    result = server.newton_guided_audit("quasar")

    assert result["result"] == "failed"
    assert result["not_checked"] == list(dict.fromkeys(_audit_commands()))


def test_an_audit_with_some_failed_reads_is_partial(configured_newton, monkeypatch):
    _fake_reads(monkeypatch, failing={"nft list ruleset", "iwinfo"})

    result = server.newton_guided_audit("quasar")

    assert result["result"] == "partial"
    assert result["not_checked"] == ["nft list ruleset", "iwinfo"]


def test_an_audit_whose_reads_all_work_is_ok(configured_newton, monkeypatch):
    _fake_reads(monkeypatch)

    result = server.newton_guided_audit("quasar")

    assert result["result"] == "ok"
    assert result["not_checked"] == []


def test_a_command_named_by_several_items_is_read_once(configured_newton, monkeypatch):
    """netstat -tulpn is named by three items: it runs once, its text is
    charged to the budget once, and the later items point at the first."""
    calls = _fake_reads(monkeypatch)

    result = server.newton_guided_audit("quasar")

    assert calls == list(dict.fromkeys(_audit_commands()))
    netstat = [
        (item["id"], read)
        for item in result["items"]
        for read in item["reads"]
        if read["command"] == "netstat -tulpn"
    ]
    assert [item_id for item_id, _read in netstat] == ["listeners", "services", "upnp"]
    first = netstat[0][1]
    assert first["output"]["text"] == "out of netstat -tulpn\n"
    assert "same_as" not in first
    for _item_id, later in netstat[1:]:
        assert later["same_as"] == "listeners"
        assert later["state"] == first["state"]
        assert later["exit_code"] == first["exit_code"]
        assert later["output"]["text"] == ""
        assert later["stderr"] == ""
    shown = sum(
        len(read["output"]["text"])
        for item in result["items"]
        for read in item["reads"]
        if read["command"] == "netstat -tulpn"
    )
    assert shown == len("out of netstat -tulpn\n")


def test_a_repeated_failed_read_is_not_checked_once(configured_newton, monkeypatch):
    _fake_reads(monkeypatch, failing={"netstat -tulpn"})

    result = server.newton_guided_audit("quasar")

    assert result["result"] == "partial"
    assert result["not_checked"] == ["netstat -tulpn"]
    states = [
        read["state"]
        for item in result["items"]
        for read in item["reads"]
        if read["command"] == "netstat -tulpn"
    ]
    assert states == ["failed", "failed", "failed"]


def test_the_audit_description_names_the_result_and_the_repeats():
    flat = " ".join((_registered_tools()["newton_guided_audit"].description or "").split())
    assert "`partial`" in flat and "`failed`" in flat
    assert "`not_checked`" in flat
    assert "`same_as`" in flat


# ---- a vendor device does not advertise the guided audit ---------


def test_no_vendor_platform_advertises_the_guided_audit():
    for platform in sorted(registry.PLATFORMS - {"openwrt"}):
        assert "newton_guided_audit" not in registry.capabilities(platform).tools, platform
    assert "newton_guided_audit" not in base.READ_ONLY_TOOLS
    assert "newton_guided_audit" in registry.capabilities("openwrt").tools


def test_the_vendor_listing_and_the_refusal_agree(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.vy1]\nplatform = "vyos"\nhost = "192.0.2.9"\nuser = "newton"\n'
        'experimental_readonly = true\n'
        'lab = true\n'
        f'known_hosts = "{tmp_path / "kh"}"\n'
    )
    (tmp_path / "kh").write_text("")
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    listed = server.newton_list_devices()
    entry = next(d for d in listed["devices"] if d["name"] == "vy1")
    assert "newton_guided_audit" not in entry["capabilities"]["tools"]
    assert server.newton_guided_audit("vy1") == {
        "error": "newton_guided_audit is not available for platform vyos"
    }


# ---- the long envelope notes are said once ------------------------

# The tools that return router text verbatim keep the whole rewrite note.
FULL_NOTE_TOOLS = {
    "newton_read", "newton_backup", "newton_plan_change", "newton_plan_undo",
    "newton_apply_change", "newton_confirm_change", "newton_change_status",
    "newton_abort_change", "newton_guided_audit",
}


def test_the_server_instructions_hold_both_notes():
    assert envelope_mod.UNTRUSTED_DEVICE_DATA_NOTE in server.mcp.instructions
    assert server.ENVELOPE_REWRITE_NOTE in server.mcp.instructions


def test_the_rewrite_note_is_whole_only_on_the_router_text_tools():
    tools = _registered_tools()
    whole = {
        name for name, tool in tools.items()
        if server.ENVELOPE_REWRITE_NOTE in (tool.description or "")
    }
    assert whole == FULL_NOTE_TOOLS
    for name, tool in tools.items():
        if name == "newton_list_devices":
            continue
        flat = " ".join((tool.description or "").split())
        assert "untrusted-device-data" in flat, name
        assert "never instructions" in flat, name
        assert "rewrites" in flat, name


def test_the_tool_descriptions_fit_their_budget():
    """With 23 whole copies of the notes the descriptions came to about
    35000 characters; with the short pointer on the 14 tools that do not
    return router text verbatim they stay under 31000."""
    total = sum(len(tool.description or "") for tool in _registered_tools().values())
    assert total < 31_000, total


# ---- the AD audit collects the whole directory every call --------


def test_the_ad_audit_description_says_every_call_collects_again():
    flat = " ".join((_registered_tools()["newton_ad_audit"].description or "").split())
    assert "Every call collects the whole directory again" in flat
    assert "`checks` narrows the report, not the collection" in flat
