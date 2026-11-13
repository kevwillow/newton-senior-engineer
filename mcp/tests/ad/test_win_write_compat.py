"""Windows PowerShell 5.1 compatibility probes for the write helper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pwsh_path import PWSH


AD_DIR = Path(__file__).resolve().parent
PROBE = AD_DIR / "win_write_compat_probe.ps1"
HELPER = AD_DIR.parents[1] / "newton_mcp" / "ad" / "collector" / "write.ps1"


def test_hex_parser_accepts_bytes_and_rejects_bad_text() -> None:
    if not PWSH.is_file():
        pytest.skip(f"PowerShell 7.4 is not installed at {PWSH}")
    finished = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(PROBE), str(HELPER)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    answer = json.loads(finished.stdout)
    assert answer["valid_length"] == 32
    assert answer["valid_first"] == 0x11
    assert answer["odd"] == "rejected"
    assert answer["non_hex"] == "rejected"


def test_only_the_write_rights_make_an_ace_unsafe() -> None:
    """A read right never makes the install unsafe (SPEC section 8)."""
    if not PWSH.is_file():
        pytest.skip(f"PowerShell 7.4 is not installed at {PWSH}")
    finished = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(PROBE), str(HELPER)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    answer = json.loads(finished.stdout)
    for right in (
        "read_writable",
        "read_execute_writable",
        "read_permissions_writable",
        "synchronize_writable",
    ):
        assert answer[right] is False, right
    for right in (
        "write_data_writable",
        "append_data_writable",
        "write_attributes_writable",
        "write_extended_writable",
        "delete_writable",
        "delete_children_writable",
        "change_permissions_writable",
        "take_ownership_writable",
        "modify_writable",
        "full_control_writable",
    ):
        assert answer[right] is True, right

