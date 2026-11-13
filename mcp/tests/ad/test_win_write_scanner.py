"""The JSON scanner of the Windows write helper.

The helper has its own scanner over the raw text of the request: it refuses
a duplicate key, two keys that differ only in case and every number that is
not written in the int form of the contract.  The scan must also stay linear
in the size of the input: a text of 64 KiB of brackets is answered at once,
and a request that is nested too deep is a schema.

The tests are skipped, with a reason, when PowerShell 7.4 is not installed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pwsh_path import PWSH


AD_DIR = Path(__file__).resolve().parent
PROBE = AD_DIR / "win_write_scanner_probe.ps1"
HELPER = AD_DIR.parents[1] / "newton_mcp" / "ad" / "collector" / "write.ps1"


def _probe() -> dict[str, object]:
    if not PWSH.is_file():
        pytest.skip(
            f"PowerShell 7.4 is not installed at {PWSH}: the scanner of the "
            "Windows write helper cannot be exercised"
        )
    finished = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(PROBE), str(HELPER)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    return json.loads(finished.stdout)


def test_the_scanner_caps_the_nesting_at_thirty_two() -> None:
    """A nesting of 31 is accepted and a nesting of 32 is refused."""
    measured = _probe()
    assert measured["depth_31_accepted"] is True
    assert measured["depth_32_refused"] is True


def test_the_scan_of_64_kib_of_brackets_is_linear() -> None:
    """64 KiB of brackets are answered at once, not one stack frame at a time."""
    measured = _probe()
    assert measured["brackets_accepted"] is False
    assert int(measured["brackets_ms"]) < 5000
    assert measured["nested_accepted"] is False
    assert int(measured["nested_ms"]) < 5000


def test_a_request_that_is_nested_too_deep_is_a_schema() -> None:
    """A request of 64 KiB of brackets never reaches the parser."""
    measured = _probe()
    assert measured["deep_request_code"] == "schema"
