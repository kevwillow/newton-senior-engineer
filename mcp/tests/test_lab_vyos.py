"""Recorded VyOS getter fixtures and lab receipts."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp.adapters.getters import load_getters


RECORDED = Path(__file__).parent / "fixtures" / "vendors" / "vyos" / "recorded"
OS_RANGE = "2026.10.01-0035-rolling"
LAB_RECEIPT = f"lab:vyos:{OS_RANGE}:2026-10-18"
ENABLED_IDS = (
    "version",
    "interfaces",
    "routes",
    "firewall_policy",
    "nat",
    "ntp",
    "vpn",
)
MARKER_RE = re.compile(
    r"^# recorded lab:vyos:2026\.10\.01-0035-rolling:(?P<date>\d{4}-\d{2}-\d{2})$"
)

# The fake writes the recorded body to stdout, or to stderr when asked, and
# exits with the recorded code: a real VyOS bad command printed only to stderr.
FAKE_SSH = r'''#!/usr/bin/env python3
import os
from pathlib import Path

payload = Path(os.environ["NEWTON_RECORDED_FIXTURE"]).read_bytes()
_marker, separator, body = payload.partition(b"\n")
if not separator:
    raise SystemExit("recorded fixture has no marker line")
os.write(int(os.environ.get("NEWTON_RECORDED_FD", "1")), body)
raise SystemExit(int(os.environ.get("NEWTON_RECORDED_EXIT", "0")))
'''


def _marker(path: Path) -> str:
    return path.read_bytes().split(b"\n", 1)[0].decode("utf-8")


@pytest.fixture
def run_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., dict[str, Any]]:
    """Run one marker-stripped recorded body through the real getter tool path."""
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
    fake_ssh.chmod(0o755)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.31 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    device = server.Device(
        name="lab-vyos",
        platform="vyos",
        host="192.0.2.31",
        user="newton",
        experimental_readonly=True,
        lab=True,
        known_hosts=known_hosts,
    )
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(server, "SSH_BINARY", str(fake_ssh))
    monkeypatch.setattr(server, "_RUNNERS", {})
    monkeypatch.setattr(server, "_SEEN_IFACES", {})
    monkeypatch.setattr(server, "load_inventory", lambda: {device.name: device})

    def run(
        getter_id: str, fixture: Path, exit_code: int = 0, fd: int = 1
    ) -> dict[str, Any]:
        monkeypatch.setenv("NEWTON_RECORDED_FIXTURE", str(fixture))
        monkeypatch.setenv("NEWTON_RECORDED_EXIT", str(exit_code))
        monkeypatch.setenv("NEWTON_RECORDED_FD", str(fd))
        server._RUNNERS.clear()
        return server.newton_get_state(device=device.name, getter=getter_id)

    return run


def test_mv1_11b_03_enabled_getters_have_date_matched_recordings() -> None:
    """Every enabled receipt has a recording with the same lab date."""
    for getter_id, getter in load_getters("vyos").items():
        if not getter.enabled:
            continue
        fixture = RECORDED / f"{getter_id}.txt"
        assert fixture.is_file(), fixture
        match = MARKER_RE.fullmatch(_marker(fixture))
        assert match is not None, fixture
        assert match.group("date") == getter.verified.rsplit(":", 1)[1], getter_id


def test_mv1_11b_04_loader_pins_lab_receipts_and_disabled_rows() -> None:
    """Enabled rows pin the lab VyOS build; running_config stays off."""
    getters = load_getters("vyos")
    for getter_id in ENABLED_IDS:
        assert getters[getter_id].enabled is True, getter_id
        assert getters[getter_id].verified == LAB_RECEIPT, getter_id
        assert getters[getter_id].os_range == OS_RANGE, getter_id
    assert getters["running_config"].enabled is False
    assert getters["running_config"].verified == "unverified"


def test_mv1_11b_05_recorded_getters_pass_get_state_pipeline(
    run_recorded: Callable[..., dict[str, Any]],
) -> None:
    """Recorded bodies classify as ok, shape matched, through newton_get_state.

    VyOS prints a sentence for an empty table ("NAT is not configured",
    "IPsec not initialized"), so even the empty-table captures are ok.
    """
    for getter_id in ENABLED_IDS:
        result = run_recorded(getter_id, RECORDED / f"{getter_id}.txt")
        assert result["status"] == "ok", getter_id
        assert result["truncated"] is False, getter_id
        assert result["shape"] == "matched", getter_id


def test_mv1_11b_06_recorded_invalid_command_is_device_error(
    run_recorded: Callable[..., dict[str, Any]],
) -> None:
    """The lab bad command (stderr only, exit 1) is a device error."""
    fixture = RECORDED / "error-invalid-command.txt"
    result = run_recorded("version", fixture, exit_code=1, fd=2)
    assert result["status"] == "device_error"


def test_mv1_11b_07_invalid_command_text_alone_is_a_device_error(
    run_recorded: Callable[..., dict[str, Any]],
) -> None:
    """The wrapper can exit 0 on a bad command; the text still classifies."""
    fixture = RECORDED / "error-invalid-command.txt"
    for fd in (1, 2):
        result = run_recorded("version", fixture, exit_code=0, fd=fd)
        assert result["status"] == "device_error", fd


def test_mv1_11b_08_recorded_directory_holds_only_known_captures() -> None:
    """No stray capture (e.g. running_config output) in recorded/."""
    allowed = {f"{getter_id}.txt" for getter_id in ENABLED_IDS} | {
        "error-invalid-command.txt"
    }
    assert {path.name for path in RECORDED.iterdir()} == allowed
