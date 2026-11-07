from __future__ import annotations

import json
import subprocess

import pytest

from newton_mcp import server


SECRET = "ObviousFakeReadSecret987"


def _run_read(monkeypatch, *, command, stdout="", stderr="", returncode=0, timeout=False):
    def fake_run(args, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(args, 30, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    return server.newton_read("quasar", command)


@pytest.mark.parametrize("name", ["pass", "pwd", "pw", "pincode", "pin_code", "uuid", "ro_community", "auth_pass"])
def test_uci_get_new_secret_names_redact_bare_stdout(configured_newton, monkeypatch, name):
    result = _run_read(monkeypatch, command=f"uci get network.wan.{name}", stdout=SECRET + "\n")
    assert SECRET not in json.dumps(result)
    assert result["stdout"]["text"].startswith("<redacted:")


def test_uci_get_nonempty_stdout_redacts_even_on_failure(configured_newton, monkeypatch):
    result = _run_read(
        monkeypatch, command="uci get wireless.x.key", stdout=SECRET + "\n", returncode=1
    )
    assert result["exit_code"] == 1
    assert SECRET not in json.dumps(result)


def test_uci_get_empty_stdout_stays_empty(configured_newton, monkeypatch):
    result = _run_read(
        monkeypatch, command="uci get wireless.x.key", stdout="", stderr="entry not found", returncode=1
    )
    assert result["stdout"]["text"] == ""
    assert result["stderr"]["text"] == "entry not found"


def test_timeout_uses_bare_value_redaction_and_fallback(configured_newton, monkeypatch):
    result = _run_read(
        monkeypatch, command="uci get wireless.x.key", stdout=SECRET + "\n", timeout=True
    )
    assert result["exit_code"] == 124
    assert SECRET not in json.dumps(result)
    assert result["stdout"]["text"].startswith("<redacted:")
    assert result["stderr"]["text"] == "read command timed out"


def test_timeout_partial_json_is_redacted(configured_newton, monkeypatch):
    result = _run_read(
        monkeypatch,
        command="ubus call network.wireless status",
        stdout=f'{{"key": "{SECRET}',
        timeout=True,
    )
    assert SECRET not in json.dumps(result)
    assert '<redacted:' in result["stdout"]["text"]


def test_redaction_precedes_large_output_truncation(configured_newton, monkeypatch):
    prefix = "x" * (64 * 1024 - len("wireless.x.key='ObviousFakeRead") - 2)
    raw = prefix + f"\nwireless.x.key='{SECRET}'\n"
    result = _run_read(monkeypatch, command="uci show wireless", stdout=raw)
    assert result["truncated"] is True
    assert SECRET not in json.dumps(result)
    assert "ObviousFakeRead" not in result["stdout"]["text"]


def test_timeout_redacts_stderr_before_truncation(configured_newton, monkeypatch):
    result = _run_read(
        monkeypatch,
        command="uci show wireless",
        stderr="x" * 65520 + f" password={SECRET}",
        timeout=True,
    )
    assert SECRET not in json.dumps(result)


def test_autouse_fixture_blocks_unpatched_real_ssh():
    with pytest.raises(AssertionError, match="test attempted a real ssh call"):
        subprocess.run(["ssh", "root@192.0.2.1", "true"])
