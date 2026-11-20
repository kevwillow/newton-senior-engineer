"""An unsafe state directory is named in the answer, never a crash.

Every model-bound answer is redacted with a key that lives in the state
directory.  When that directory is a symlink (or otherwise unsafe) the key
cannot be loaded: a failed call raised that RuntimeError out of call_tool and
a call that worked answered "internal server error".  Now each answers a
fixed refusal that names the state directory and returns none of the output
it could not redact.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import newton_mcp.redact as _redact
import newton_mcp.server as server

SID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def symlinked_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "state").symlink_to(real)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    _redact.reset_key_cache()
    yield real
    _redact.reset_key_cache()


REFUSAL = "state directory unsafe: state directory must not be a symlink"


def test_a_call_that_worked_names_the_unsafe_state_directory(symlinked_state):
    assert server.newton_list_devices() == {"error": REFUSAL}


def test_a_refused_call_names_the_unsafe_state_directory(symlinked_state):
    assert server.newton_read("nosuch", "uptime") == {"error": REFUSAL}


def test_a_device_text_error_names_the_unsafe_state_directory(
    symlinked_state, monkeypatch
):
    def fail(self, device, command):
        raise server.DeviceTextError("synthetic-call-text")

    monkeypatch.setattr(server.NewtonService, "read", fail)
    assert server.newton_read("quasar", "uptime") == {"error": REFUSAL}


def test_output_that_cannot_be_redacted_is_never_returned(symlinked_state, monkeypatch):
    def fail(self, device, command):
        raise server.NewtonError("synthetic-call-text")

    monkeypatch.setattr(server.NewtonService, "read", fail)
    result = server.newton_read("quasar", "uptime")
    assert result == {"error": REFUSAL}
    assert "synthetic-call-text" not in str(result)
