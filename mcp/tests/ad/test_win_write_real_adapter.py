"""The REAL LDAP adapter of the Windows write helper, run under pwsh.

The fake of the directory (``win_write_fake.ps1``) replaces the adapter of the
helper entirely, so no test of the fake ever runs the real ``Modify`` and
``Add`` methods.  On a real Windows Server 2025 domain controller it
was measured that the answer of an apply was a JSON list:

    [0,1,{"v":1,"code":"ok","live":{"uac":512},"undo_at":1794247873}]

The cause is the return value of the collection methods of
``System.DirectoryServices.Protocols``: ``DirectoryAttributeModificationCollection``
``.Add`` and ``DirectoryAttributeCollection.Add`` return the index of the entry
they added, and the real adapter did not discard it.

These tests run the real adapter methods with the connection of the adapter
replaced by an object that records the request and answers nothing.  No host
is contacted: nothing is ever sent over a socket.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pwsh_path import PWSH


AD_DIR = Path(__file__).resolve().parent
PROBE = AD_DIR / "win_write_real_adapter_probe.ps1"
SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "newton_mcp"
    / "ad"
    / "collector"
    / "write.ps1"
)


def _pwsh() -> str:
    """The shell of the tests, or a skip."""
    if not PWSH.is_file():
        pytest.skip(
            f"PowerShell 7.4 is not installed at {PWSH}: the real LDAP "
            "adapter of the helper cannot be exercised"
        )
    return str(PWSH)


def _protocols_load() -> tuple[bool, str]:
    """Whether the protocols assembly loads in pwsh, and what it said."""
    finished = subprocess.run(
        [
            _pwsh(),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Add-Type -AssemblyName System.DirectoryServices.Protocols; "
            "'loaded'",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return finished.returncode == 0, (finished.stdout + finished.stderr).strip()


@pytest.fixture(scope="module")
def protocols() -> str:
    """The protocols assembly, or a skip that says it does not load."""
    loaded, output = _protocols_load()
    if not loaded:
        pytest.skip(
            "System.DirectoryServices.Protocols does not load in "
            f"{PWSH}: {output}"
        )
    return output


@pytest.fixture(scope="module")
def probe(protocols: str) -> dict[str, object]:
    """What the real adapter of the helper puts into the pipeline."""
    finished = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(PROBE)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if finished.returncode != 0:
        # the probe could not run: the answer of every test below is a
        # failure with the reason of the probe.
        return {
            "error": finished.stderr.strip()[:2000],
            "modify_output_count": -1,
            "modify_output_types": [],
            "add_output_count": -1,
            "add_output_types": [],
            "request_count": -1,
            "modify_modifications": -1,
            "add_attributes": -1,
        }
    return json.loads(finished.stdout)


def test_the_protocols_assembly_loads_in_powershell() -> None:
    """The protocols assembly ships with PowerShell 7 on Linux."""
    loaded, output = _protocols_load()
    assert loaded, output


def test_the_probe_of_the_real_adapter_runs(probe: dict[str, object]) -> None:
    """The probe ran the real adapter of the helper."""
    assert "error" not in probe, probe.get("error")


def test_the_real_modify_puts_nothing_into_the_pipeline(probe: dict[str, object]) -> None:
    """The real Modify answers nothing (the index is discarded)."""
    assert probe["modify_output_count"] == 0, probe["modify_output_types"]
    assert probe["modify_output_types"] == []


def test_the_real_add_puts_nothing_into_the_pipeline(probe: dict[str, object]) -> None:
    """The real Add answers nothing (the index is discarded)."""
    assert probe["add_output_count"] == 0, probe["add_output_types"]
    assert probe["add_output_types"] == []


def test_the_real_adapter_still_builds_its_requests(probe: dict[str, object]) -> None:
    """The probe ran the real adapter: the requests carry the values."""
    assert probe["request_count"] == 2
    assert probe["modify_modifications"] == 2
    assert probe["add_attributes"] == 5
