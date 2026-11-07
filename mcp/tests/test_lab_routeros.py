"""Recorded RouterOS CHR getter fixtures and lab receipts."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp.adapters.getters import Getter, load_getters


RECORDED = Path(__file__).parent / "fixtures" / "vendors" / "routeros" / "recorded"
LAB_RECEIPT = "lab:chr:7.24.5:2026-10-18"
OS_RANGE = "7.24.5"
ENABLED_IDS = (
    "version",
    "interfaces",
    "routes",
    "firewall_policy",
    "nat",
    "mgmt_services",
    "logging",
    "ntp",
    "vpn",
)
DISABLED_IDS = ("admins", "running_config")
MARKER_RE = re.compile(
    r"^# recorded lab:chr:7\.24\.5:(?P<date>\d{4}-\d{2}-\d{2})$"
)

FAKE_SSH = r'''#!/usr/bin/env python3
import os
from pathlib import Path

payload = Path(os.environ["NEWTON_RECORDED_FIXTURE"]).read_bytes()
_marker, separator, body = payload.partition(b"\n")
if not separator:
    raise SystemExit("recorded fixture has no marker line")
os.write(1, body)
raise SystemExit(int(os.environ.get("NEWTON_RECORDED_EXIT", "0")))
'''


def _marker(path: Path) -> str:
    return path.read_bytes().split(b"\n", 1)[0].decode("utf-8")


def _assert_recorded_receipts(
    getters: dict[str, Getter], recorded: Path = RECORDED
) -> None:
    for getter_id, getter in getters.items():
        if not getter.enabled:
            continue
        fixture = recorded / f"{getter_id}.txt"
        assert fixture.is_file(), fixture
        match = MARKER_RE.fullmatch(_marker(fixture))
        assert match is not None, fixture
        assert getter.verified.startswith("lab:chr:7.24.5:"), getter_id
        assert match.group("date") == getter.verified.rsplit(":", 1)[1], getter_id


def _assert_paging_capture(path: Path) -> None:
    payload = path.read_bytes()
    marker, separator, body = payload.partition(b"\n")
    assert separator == b"\n"
    assert MARKER_RE.fullmatch(marker.decode("utf-8")) is not None
    assert len(body.splitlines()) >= 80
    assert b"\x1b" not in body
    assert b"-- [Q quit" not in body
    assert b"-- [" not in body


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
        "192.0.2.24 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    device = server.Device(
        name="lab-chr",
        platform="routeros",
        host="192.0.2.24",
        user="newton-ro",
        experimental_readonly=True,
        lab=True,
        known_hosts=known_hosts,
    )
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(server, "SSH_BINARY", str(fake_ssh))
    monkeypatch.setattr(server, "_RUNNERS", {})
    monkeypatch.setattr(server, "_SEEN_IFACES", {})
    monkeypatch.setattr(server, "load_inventory", lambda: {device.name: device})

    def run(getter_id: str, fixture: Path, exit_code: int = 0) -> dict[str, Any]:
        monkeypatch.setenv("NEWTON_RECORDED_FIXTURE", str(fixture))
        monkeypatch.setenv("NEWTON_RECORDED_EXIT", str(exit_code))
        server._RUNNERS.clear()
        return server.newton_get_state(device=device.name, getter=getter_id)

    return run


def test_mv1_11_01_enabled_getters_have_date_matched_recordings() -> None:
    """Every enabled receipt has a recording with the same lab date."""
    _assert_recorded_receipts(load_getters("routeros"))


def test_mv1_11_02_recorded_getters_pass_get_state_pipeline(
    run_recorded: Callable[..., dict[str, Any]],
) -> None:
    """Recorded bodies classify correctly through newton_get_state."""
    for getter_id in ENABLED_IDS:
        fixture = RECORDED / f"{getter_id}.txt"
        assert fixture.is_file(), fixture
        result = run_recorded(getter_id, fixture)
        expected = "empty" if getter_id == "vpn" else "ok"
        assert result["status"] == expected, getter_id
        assert result["status"] != "device_error", getter_id
        assert result["truncated"] is False, getter_id


def test_mv1_11_03_loader_pins_lab_receipts_and_disabled_rows() -> None:
    """Enabled rows pin CHR 7.24.5; disabled rows remain unverified."""
    getters = load_getters("routeros")
    for getter_id in ENABLED_IDS:
        assert getters[getter_id].enabled is True, getter_id
        assert getters[getter_id].verified == LAB_RECEIPT, getter_id
        assert getters[getter_id].os_range == OS_RANGE, getter_id
    for getter_id in DISABLED_IDS:
        assert getters[getter_id].enabled is False, getter_id
        assert getters[getter_id].verified == "unverified", getter_id


def test_mv1_11_04_recorded_bad_command_is_device_error(
    run_recorded: Callable[..., dict[str, Any]],
) -> None:
    """The recorded RouterOS command error survives the full pipeline."""
    fixture = RECORDED / "error-bad-command.txt"
    assert fixture.is_file(), fixture
    # The lab capture exited 1; the marker alone must not be what this relies on.
    result = run_recorded("version", fixture, exit_code=1)
    assert result["status"] == "device_error"
    assert result["truncated"] is False


def test_mv1_11_05_recorded_long_print_has_no_pager_artifacts() -> None:
    """A long no-PTY print is complete and contains no pager bytes."""
    _assert_paging_capture(RECORDED / "paging-long-print.txt")


def test_mv1_11_06_recorded_directory_holds_only_known_captures() -> None:
    """No stray capture (e.g. a disabled getter's output) in recorded/."""
    allowed = {f"{getter_id}.txt" for getter_id in ENABLED_IDS} | {
        "error-bad-command.txt",
        "paging-long-print.txt",
    }
    found = {path.name for path in RECORDED.iterdir()}
    assert found == allowed
