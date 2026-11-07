"""The dialog over the real MCP wire: SDK client, in-memory streams, the registered tool.

The fake-context tests in test_elicit_approval.py cannot show that the
registered tool really sends an elicitation, that the client's answer comes
back through the SDK's own types, or that ``ctx`` stays out of the tool's input
schema.  This one drives ``newton_apply_change`` through ``ClientSession``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import ElicitResult

import newton_mcp.elicit_approval as elicit_approval
import newton_mcp.server as server
from test_elicit_approval import (  # noqa: E402  (tests dir is on sys.path)
    DEVICE,
    PASSPHRASE,
    SID,
    WRONG_PASSPHRASE,
    _approval_path,
    _audit_text,
    _plan,
    _write_fingerprint,
    _write_plan,
)


def _call(callback):
    async def run():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server, elicitation_callback=callback
        ) as client:
            tools = await client.list_tools()
            tool = next(t for t in tools.tools if t.name == "newton_apply_change")
            result = await client.call_tool(
                "newton_apply_change", {"device": DEVICE, "session_id": SID}
            )
            return tool, result

    return asyncio.run(run())


@pytest.fixture(autouse=True)
def _slow_dialog(monkeypatch):
    """A person takes more than the 1.5 s dwell; the stub answers 'later'."""
    import newton_mcp.elicit_approval as ea

    ticks = iter(float(i) * 10.0 for i in range(1000))
    # the module's own clock is replaced, not the clock of the whole
    # process: patching time.monotonic itself would move the event
    # loop's clock too, and the loop's timers would fire at once
    monkeypatch.setattr(
        ea, "time", SimpleNamespace(monotonic=lambda: next(ticks))
    )


def test_tool_schema_has_no_approval_or_ctx_parameter(configured_newton):
    async def never(context, params):
        return ElicitResult(action="cancel")

    tool, _ = _call(never)
    assert set(tool.inputSchema["properties"]) == {"device", "session_id"}
    assert "grant_hours" not in json.dumps(tool.inputSchema).lower()
    assert "grant" not in json.dumps(tool.inputSchema).lower()


def test_dialog_travels_over_the_wire_and_writes_the_approval(configured_newton):
    _write_plan(_plan())
    _write_fingerprint()
    seen = {}

    async def answer(context, params):
        seen["message"] = params.message
        seen["schema"] = params.requestedSchema
        return ElicitResult(
            action="accept", content={"secret": PASSPHRASE, "device_name": DEVICE}
        )

    _, result = _call(answer)
    assert seen["message"].startswith("NEWTON  APPROVAL")
    assert "secret" in seen["schema"]["properties"]
    assert _approval_path().exists()
    saved = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert saved["approved_by"] == "elicit:passphrase"
    assert PASSPHRASE not in json.dumps(result.model_dump(), default=str)


def test_wrong_secret_over_the_wire_writes_nothing_and_does_not_leak_it(configured_newton):
    _write_plan(_plan())
    _write_fingerprint()

    async def answer(context, params):
        return ElicitResult(
            action="accept", content={"secret": WRONG_PASSPHRASE, "device_name": DEVICE}
        )

    _, result = _call(answer)
    assert not _approval_path().exists()
    text = "".join(
        part.text for part in result.content if getattr(part, "type", "") == "text"
    )
    assert "wrong approval answer" in text
    assert "newton-approve" in text
    assert WRONG_PASSPHRASE not in text


def test_the_wire_result_carries_the_clear_notice(configured_newton):
    """The owner has to be told to clear the screen they typed on."""
    _write_plan(_plan())
    _write_fingerprint()

    async def answer(context, params):
        return ElicitResult(
            action="accept", content={"secret": PASSPHRASE, "device_name": DEVICE}
        )

    _, result = _call(answer)

    payload = json.loads(
        "".join(
            part.text for part in result.content if getattr(part, "type", "") == "text"
        )
    )
    assert payload["approval_notice"] == elicit_approval.CLEAR_NOTICE
    assert "approval_notice" in json.dumps(result.model_dump(), default=str)


def test_the_wire_result_never_carries_the_passphrase(configured_newton, caplog):
    """The whole wire result is checked, not just the fields read here."""
    _write_plan(_plan())
    _write_fingerprint()
    caplog.set_level(logging.DEBUG)

    async def answer(context, params):
        return ElicitResult(
            action="accept", content={"secret": PASSPHRASE, "device_name": DEVICE}
        )

    _, result = _call(answer)

    assert PASSPHRASE not in json.dumps(result.model_dump(), default=str)
    assert PASSPHRASE not in _audit_text()
    assert PASSPHRASE not in caplog.text


def test_the_wire_result_never_carries_a_wrong_passphrase(configured_newton, caplog):
    """A wrong answer is a secret as well."""
    _write_plan(_plan())
    _write_fingerprint()
    caplog.set_level(logging.DEBUG)

    async def answer(context, params):
        return ElicitResult(
            action="accept", content={"secret": WRONG_PASSPHRASE, "device_name": DEVICE}
        )

    _, result = _call(answer)

    assert WRONG_PASSPHRASE not in json.dumps(result.model_dump(), default=str)
    assert WRONG_PASSPHRASE not in _audit_text()
    assert WRONG_PASSPHRASE not in caplog.text
