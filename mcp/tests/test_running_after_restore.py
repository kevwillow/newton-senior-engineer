"""The running field of a status: what the router runs now, after the
guard put a session's settings back on its own (design 6.5).

The host script prints the router's status line through `oneline`, which
cuts it at 120 characters.  The running field stands at the very end of
that line, so a line with a quarantined count in it loses the field and
the MCP never sees it.  The host therefore prints the value as a machine
line of its own, `RUNNING session=<sid> <value>`, and the MCP reads that
line only: it trusts the host's line, not the router's.

The MCP returns the value as its own `running` key, and when the running
network does not match the settings that are back it adds the next step as
well: the warning must not live in the untrusted envelope only.  A status
without such a line changes nothing.
"""

from __future__ import annotations

import subprocess

import pytest

from newton_mcp import server
from test_server import SID, configured_lab  # noqa: F401


STATUS = f"rolled-back sid={SID} guard=restored:deadline rpcd=- config=- boot=-"
NEXT_STEP = (
    "the router put the old settings back on its own, but Newton cannot show the running "
    "network matches them; on the router run: reload_config; /etc/init.d/firewall restart; "
    "wifi reload"
)


@pytest.fixture(autouse=True)
def _own_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))


def _fake(stdout: str, rc: int = 0):
    def run(self, device, *args, **kwargs):
        return subprocess.CompletedProcess(list(args), rc, stdout, "")
    return run


def _status(monkeypatch, stdout: str) -> dict:
    monkeypatch.setattr(server.NewtonService, "run_script", _fake(stdout))
    return server.newton_change_status("quasar", SID)


@pytest.mark.parametrize("running", ["differs", "unproven"], ids=["differs", "unproven"])
def test_a_running_network_that_does_not_match_names_the_next_step(
        configured_lab, monkeypatch, running):
    """The guard put the settings back on its own and the running network
    does not match them: the result says which, and names the next step."""
    result = _status(monkeypatch, f"RUNNING session={SID} {running}")
    assert result["running"] == running, result
    assert result["next_step"] == NEXT_STEP, result


@pytest.mark.parametrize("running", ["match", "boot"], ids=["match", "boot"])
def test_a_matching_or_rebooted_running_network_names_no_next_step(
        configured_lab, monkeypatch, running):
    """`match` (the running network matches) and `boot` (the router rebooted,
    so the services started from the restored files) need no next step."""
    result = _status(monkeypatch, f"RUNNING session={SID} {running}")
    assert result["running"] == running, result
    assert "next_step" not in result, result


def test_a_status_line_without_the_running_field_adds_no_key(
        configured_lab, monkeypatch):
    """A status without the running field (the guard did not restore this
    session on its own) is the result of today: no new key."""
    result = _status(monkeypatch, STATUS)
    assert "running" not in result, result
    assert "next_step" not in result, result
    assert result["exit_code"] == 0, result


def test_a_hostile_running_line_cannot_forge_the_running_field(
        configured_lab, monkeypatch):
    """A line that only looks like the host's line (the value is not at the
    end of the line) is not one: nothing is taken from it."""
    result = _status(monkeypatch, f"RUNNING session={SID} match; rm -rf /")
    assert "running" not in result, result
    assert "next_step" not in result, result


def test_a_running_line_of_another_session_is_not_taken(
        configured_lab, monkeypatch):
    """The line belongs to the session the status names; another session's
    line says nothing about this one."""
    other = "f" * 32
    result = _status(monkeypatch, f"RUNNING session={other} differs")
    assert "running" not in result, result
    assert "next_step" not in result, result


def test_the_routers_own_running_field_is_not_taken(
        configured_lab, monkeypatch):
    """The router's status line ends in the running field, but the MCP
    trusts the host's line only.

    The host cuts the router's line at 120 characters, so the field can be
    lost on the way.  A router line that still carries it says nothing to
    the MCP: without the host's line there is no answer.
    """
    result = _status(monkeypatch, f"{STATUS} running=differs")
    assert "running" not in result, result
    assert "next_step" not in result, result
