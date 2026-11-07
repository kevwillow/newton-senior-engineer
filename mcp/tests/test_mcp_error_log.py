"""mcp-errors.log: tracebacks for the generic ``except Exception`` branch.

The branch in :func:`newton_mcp.server.call_tool` deliberately hides the
real cause from the model (``{"error": "internal server error"}``) so an
installed server can keep running, but operators still need the original
traceback to diagnose what went wrong.  These tests pin the on-disk shape.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

import newton_mcp.server as server


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """A throwaway inventory so ``NewtonService()`` can be built; the
    autouse ``_isolate_state_dir`` fixture has already pointed
    ``NEWTON_STATE_DIR`` at ``tmp_path / "state"``.
    """
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return tmp_path


def _raise_runtime(_service):
    raise RuntimeError("boom-marker")


def test_unexpected_exception_writes_traceback_and_returns_generic_error(configured):
    state = configured / "state"
    log = state / "mcp-errors.log"
    audit = state / "mcp-audit.log"
    result = server.call_tool("newton_read", "quasar", _raise_runtime)

    assert result == {"error": "internal server error"}
    assert "boom-marker" not in str(result)

    assert log.exists(), "mcp-errors.log should be created on the first unexpected error"
    assert stat.S_IMODE(log.stat().st_mode) == 0o600

    text = log.read_text(encoding="utf-8")
    assert "RuntimeError" in text
    assert "boom-marker" in text
    assert "newton_read" in text

    headers = [line for line in text.splitlines() if "tool=newton_read" in line]
    assert len(headers) == 1, text
    assert "device=quasar" in headers[0]

    assert audit.exists()
    audit_lines = audit.read_text(encoding="utf-8").splitlines()
    assert any(
        line.endswith("tool=newton_read device=quasar result=error")
        for line in audit_lines
    ), audit_lines


def test_second_unexpected_exception_appends_a_second_entry(configured):
    log = configured / "state" / "mcp-errors.log"

    server.call_tool("newton_read", "quasar", _raise_runtime)
    server.call_tool("newton_list_devices", "-", _raise_runtime)

    text = log.read_text(encoding="utf-8")
    headers = [
        line
        for line in text.splitlines()
        if "tool=newton_read" in line or "tool=newton_list_devices" in line
    ]
    assert len(headers) == 2, text
    seen = {line.split("tool=")[1].split(" ")[0] for line in headers}
    assert seen == {"newton_read", "newton_list_devices"}, seen


def test_unwritable_state_dir_still_returns_generic_error(configured, tmp_path, monkeypatch):
    """When ``NEWTON_STATE_DIR`` cannot be a directory the helper is allowed
    to fail silently; the tool still returns the standard error.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a regular file, not a directory\n")
    monkeypatch.setenv("NEWTON_STATE_DIR", str(blocker))

    result = server.call_tool("newton_read", "quasar", _raise_runtime)
    assert result == {"error": "internal server error"}


def test_newton_error_does_not_write_mcp_errors_log(configured):
    def raise_newton(_service):
        raise server.NewtonError("some validation error")

    state = configured / "state"
    server.call_tool("newton_read", "quasar", raise_newton)

    assert not (state / "mcp-errors.log").exists()


def test_device_text_error_does_not_write_mcp_errors_log(configured):
    def raise_device_text(_service):
        raise server.DeviceTextError("device output unparseable")

    state = configured / "state"
    result = server.call_tool("newton_read", "quasar", raise_device_text)

    assert "error" in result
    assert not (state / "mcp-errors.log").exists()
