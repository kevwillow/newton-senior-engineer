"""The helper's wait for the directory after a boot (DESIGN-1.5 "The build
account after promotion": after every reboot the helper waits until
``Get-ADDomain`` answers).

MEASURED on BUILD1, 2026-11-18 (MEASURED-1.5 "Stage 8 on BUILD1,
2026-11-18"): the status after stage 2's second boot stopped the stage
``error`` with "Attempting to perform the InitializeDefaultDrives operation
on the 'ActiveDirectory' provider failed.": ``Import-Module ActiveDirectory``
ran once, before the wait, and the module's AD: drive cannot be mounted
while ADWS does not serve yet.  The import is part of what the wait
retries.

The real ``Wait-NewtonDirectory`` is cut out of ``build.ps1`` and run under
pwsh with fakes of ``Import-Module``, ``Get-ADDomain`` and ``Start-Sleep``.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from newton_mcp.ad.build import bootstrap

from pwsh_path import PWSH

DRIVE_ERROR = "Attempting to perform the InitializeDefaultDrives operation on the 'ActiveDirectory' provider failed."


def _function(name: str) -> str:
    source = bootstrap.HELPER_PATH.read_text(encoding="utf-8")
    found = re.search(r"(?ms)^function " + re.escape(name) + r" \{\n.*?^\}\n", source)
    assert found is not None
    return found.group(0)


def _wait(tmp_path: Path, *, import_failures: int, domain_failures: int, seconds: int = 30, warn: bool = False) -> dict:
    if not PWSH.is_file():
        pytest.fail("the AD 1.5 gate requires the pwsh tests to run")
    script = tmp_path / "wait.ps1"
    script.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$script:DirectoryWaitSeconds = {seconds}\n"
        f"$script:ImportLeft = {import_failures}\n"
        f"$script:DomainLeft = {domain_failures}\n"
        "$script:Imports = 0\n$script:Domains = 0\n"
        "function Import-Module { [CmdletBinding()] param([string]$Name)\n"
        "    $script:Imports++\n"
        + ("    Write-Warning \"Error initializing default drive: 'Unable to contact the server.'\"\n" if warn else "")
        + 
        f"    if ($script:ImportLeft -gt 0) {{ $script:ImportLeft--; throw \"{DRIVE_ERROR}\" }} }}\n"
        "function Get-ADDomain { [CmdletBinding()] param()\n"
        "    $script:Domains++\n"
        "    if ($script:DomainLeft -gt 0) { $script:DomainLeft--; throw 'Unable to contact the server.' }\n"
        "    return 'build.newton.test' }\n"
        "function Start-Sleep { param($Seconds) }\n"
        + _function("Wait-NewtonDirectory")
        + "$ok = $false\n"
        "try { $ok = Wait-NewtonDirectory; $err = '' } catch { $err = $_.Exception.Message }\n"
        "[Console]::Out.Write((@{ ok = [bool]$ok; err = $err; imports = $script:Imports; domains = $script:Domains } | ConvertTo-Json -Compress))\n",
        encoding="utf-8",
    )
    done = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_an_import_that_fails_while_adws_is_not_serving_is_retried(tmp_path: Path) -> None:
    result = _wait(tmp_path, import_failures=3, domain_failures=2)
    assert result == {"ok": True, "err": "", "imports": 6, "domains": 3}


def test_the_directory_that_answers_at_once_needs_one_import(tmp_path: Path) -> None:
    result = _wait(tmp_path, import_failures=0, domain_failures=0)
    assert result["ok"] is True and result["err"] == "" and result["domains"] == 1


def test_a_module_that_never_imports_is_not_ready(tmp_path: Path) -> None:
    result = _wait(tmp_path, import_failures=10**9, domain_failures=0, seconds=1)
    assert result["ok"] is False
    assert result["err"] == ""
    assert result["domains"] == 0


def test_the_import_warning_while_adws_is_down_never_reaches_the_answer(tmp_path: Path) -> None:
    # Measured on BUILD2, 2026-11-18, ADWS stopped: `Import-Module
    # ActiveDirectory` succeeds and writes "WARNING: Error initializing
    # default drive: 'Unable to contact the server. ...'" to stdout, and
    # DC2's status after the promotion's boot answered more than one JSON
    # object (the runner stopped answer_invalid).  The answer is the
    # helper's whole stdout, so the wait imports without warnings.
    if not PWSH.is_file():
        pytest.fail("the AD 1.5 gate requires the pwsh tests to run")
    result = _wait(tmp_path, import_failures=0, domain_failures=1, warn=True)
    assert result["ok"] is True


def test_every_import_in_the_helpers_own_session_hides_its_warnings() -> None:
    # The helper's stdout is its answer: an Import-Module the helper runs
    # in its own process (outside the op bodies, which run in their own
    # processes with their output in files) imports without warnings.
    source = bootstrap.HELPER_PATH.read_text(encoding="utf-8")
    own = re.sub(r"(?ms)^\$script:OpBodies\[[^\]]+\] = @'\n.*?^'@", "", source)
    own = re.sub(r"(?ms)@'\n.*?^'@", "", own)
    imports = [line for line in own.splitlines() if "Import-Module ActiveDirectory" in line and not line.lstrip().startswith("#")]
    assert len(imports) >= 2
    for line in imports:
        assert "-WarningAction SilentlyContinue" in line, line


def test_an_op_still_running_in_its_task_is_answered_without_reading_its_output(tmp_path: Path) -> None:
    # Measured on BUILD1, 2026-11-18: DC1's stage 7 read-back (the s7-read
    # poll, up to 30 minutes) outlived the 600 s wait of its password task,
    # and the helper then read C:\NewtonBuild\out\s7-read.txt, which the
    # running task holds open: "The process cannot access the file ...
    # because it is being used by another process.", and the stage stopped
    # error instead of answering started for the status record path.
    if not PWSH.is_file():
        pytest.fail("the AD 1.5 gate requires the pwsh tests to run")
    script = tmp_path / "op.ps1"
    build = tmp_path / "nb"
    script.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$script:BuildDir = '{build}'\n"
        "$script:TaskWaitSeconds = 600\n"
        "$script:Held = $null\n"
        "function Invoke-NewtonPasswordTask { param([string]$Op, [string]$OpPath, [int]$WaitSeconds)\n"
        "    $path = Get-NewtonOutPath $Op\n"
        # A file the running task holds open cannot be read on Windows; a
        # directory at its path stands in for it under pwsh on Linux, where
        # FileShare is not enforced inside one process.
        "    $null = New-Item -ItemType Directory -Path $path -Force\n"
        "    return [ordered]@{ outcome = 'running'; result = -1; found = 'still running after 600 s; it is left to finish' } }\n"
        + "".join(_function(name) for name in ("Get-NewtonOutPath", "Get-NewtonResultPath", "Get-NewtonOpPath", "Clear-NewtonOpResult", "Invoke-NewtonStageOp"))
        + "try { $ran = Invoke-NewtonStageOp -Op 's7-read' -Script 'x' -AsTask $true; $err = '' } catch { $err = $_.Exception.Message; $ran = @{} }\n"
        "[Console]::Out.Write((@{ err = $err; outcome = [string]$ran['outcome']; output = [string]$ran['output'] } | ConvertTo-Json -Compress))\n",
        encoding="utf-8",
    )
    done = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"err": "", "outcome": "running", "output": ""}
