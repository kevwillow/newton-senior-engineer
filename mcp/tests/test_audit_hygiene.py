"""Triage #3 and #26: device-name validation at the MCP boundary and
one-line, size-capped audit fields, so no caller or device text can forge
or flood a log line."""

import json
import re

import pytest

from exhelp import explained

import newton_mcp.server as server

SID = "fd595e20f2cd6c2b928fe3156f82d5db"
FORGED = "x\n2026-01-01T00:00:00+00:00 tool=newton_apply_change device=lab result=ok"
TOOLS = [
    ("newton_read", lambda d: server.newton_read(d, "uci show")),
    ("newton_backup", server.newton_backup),
    ("newton_plan_change", lambda d: server.newton_plan_change(d, "set dhcp.x=y", **explained("set dhcp.x=y"))),
    ("newton_apply_change", lambda d: server.newton_apply_change(d, SID)),
    ("newton_change_status", lambda d: server.newton_change_status(d, SID)),
    ("newton_abort_change", lambda d: server.newton_abort_change(d, SID)),
]


@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.lab]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def audit_lines(configured):
    log = configured / "state" / "mcp-audit.log"
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("tool,call", TOOLS, ids=[t for t, _ in TOOLS])
def test_every_tool_refuses_a_bad_device_name_in_one_new_line(
    configured, monkeypatch, tool, call
):
    monkeypatch.setattr(
        server.NewtonService, "run_script",
        lambda *a, **k: pytest.fail("must not run anything for a bad device name"),
    )
    bad = "lab" + FORGED  # a newline plus a forged audit line after it
    before = audit_lines(configured)
    assert call(bad) == {"error": "invalid device name"}
    after = audit_lines(configured)
    assert len(after) == len(before) + 1, (before, after)
    assert FORGED not in "\n".join(after)
    forged_ok = re.search(r"tool=newton_apply_change device=lab result=ok", "\n".join(after))
    assert not forged_ok
    assert after[-1].endswith(f"tool={tool} device=- result=error invalid device name")


@pytest.mark.parametrize("bad", [
    "lab" + FORGED,
    "a" * 10000,
    "lab\u2028router",
    "lab\u0085router",
    "lab\rrouter",
    "",
    "Lab",
    "lab_r1",
    "1lab",
], ids=["newline-forged", "10000-chars", "u2028", "u0085", "cr", "empty",
        "uppercase", "underscore", "leading-digit"])
def test_read_refuses_each_bad_name_without_logging_it(configured, monkeypatch, bad):
    monkeypatch.setattr(
        server.subprocess, "run",
        lambda *a, **k: pytest.fail("must not reach ssh for a bad device name"),
    )
    before = audit_lines(configured)
    assert server.newton_read(bad, "uci show") == {"error": "invalid device name"}
    after = audit_lines(configured)
    assert len(after) == len(before) + 1
    joined = "\n".join(after)
    for needle in (FORGED, "lab\u2028router", "lab\u0085router", "lab\rrouter"):
        assert needle not in joined
    assert "a" * 300 not in joined  # the 10 000 character name is capped


def test_valid_but_unknown_device_is_logged_as_given(configured):
    before = audit_lines(configured)
    result = server.newton_read("other-router", "uci show")
    assert result["error"] == "unknown device: other-router"
    after = audit_lines(configured)
    assert len(after) == len(before) + 1
    assert after[-1].endswith("tool=newton_read device=other-router result=error")


def test_oneline_replaces_every_control_character():
    assert server.oneline("a\nb\tc\rd\x00e\x7ff\u0085g\u2028h\u2029i") == "a b c d e f g h i"


def test_oneline_caps_the_field():
    assert server.oneline("x" * 500) == "x" * server.ONELINE_LIMIT
    assert len(server.oneline("x" * 500)) < 500


def test_write_audit_fields_all_go_through_oneline(configured):
    server.write_audit("tool\ninjected", "dev\u2028ice", "res\rult")
    line = audit_lines(configured)[-1]
    assert line.count("\n") == 0
    assert "tool=tool injected" in line and "device=dev ice" in line and "result=res ult" in line


def test_audit_line_keeps_the_key_value_shape(configured):
    server.write_audit("newton_read", "lab", "ok")
    line = audit_lines(configured)[-1]
    assert re.fullmatch(
        r"\S+ tool=\S+ device=\S+ result=.*", line)
    json.dumps(line)  # still one plain line
