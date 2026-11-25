"""Stage 9 of the helper: the cleanup (PLAN-1.5 task 8 part B9; DESIGN-1.5
"Stage graphs"; MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2, 2026-11-15",
"Stage 9 on BUILD2, then BUILD1").

Measured: a one-shot SYSTEM task, registered from the key login, restores
the sshd configuration from its backup, restarts sshd and deletes the keys
file, the helper, K and pw.bin; on DC1 it then deletes the domain account
``newton-build`` (SYSTEM on a DC deleted it, in and out of Domain Admins).
The removal from Domain Admins in the key login was never made (the
group read before it threw on both DCs), and DC2 runs no password task
after its promotion, so DC2's stage 9 makes no removal; DC1's runs in its
password task (unmeasured; DESIGN-1.5 open point 18 of task 8).

The account is deleted last: a pwsh test runs the rendered cleanup script
with every cmdlet it calls replaced by a recorder, and reads the order.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import plan
from test_build_stages_0_4 import (  # type: ignore[import-not-found]
    PLAN_INPUTS,
    Server,
    _call,
    _ok,
    _ops_called,
    _pwsh,
    _states,
    server,  # noqa: F401
)

#: The removal's output: the shape of the op's own lines, NOT measured (the
#: removal never ran in the lab; DESIGN-1.5 open point 18 of task 8).
DA_OUT = (
    "task identity: nbuild\\newton-build | auth Kerberos\n"
    "task start 2026-11-15T19:54:39.4628992Z\n"
    "member before: 1\n"
    "Remove-ADGroupMember Domain Admins newton-build: ok\n"
    "member after: 0\n"
    "task end 2026-11-15T19:54:39.7900195Z\n"
)

#: The measured lines of the registration (MEASURED-1.5, stage 9).
REGISTER_OUT = (
    "task identity: nbuild\\newton-build | auth Kerberos\n"
    "task start 2026-11-15T19:54:40.8896994Z\n"
    "cleanup script: C:\\ProgramData\\Newton\\ad-build-cleanup.ps1, bytes 2505\n"
    "registered NewtonBuild-cleanup as SYSTEM LogonType ServiceAccount\n"
    "state Running\n"
    "task end 2026-11-15T19:54:43.4683810Z\n"
)


def _two_plan() -> dict[str, Any]:
    inputs = copy.deepcopy(PLAN_INPUTS)
    dc2 = dict(inputs["servers"][0], device="build2", role="dc2", hostname="BDC2", ip="192.0.2.42",
               vmgenid="0f5c9a44-3c51-4b6e-9d0a-6a1b2c3d4e5f")
    inputs["servers"].append(dc2)
    return plan.plan_build(inputs)


def _seed_to_9(server: Server, the_plan: dict[str, Any], role: str) -> None:  # noqa: F811
    digest = plan.digest(the_plan)
    the_server = next(s for s in the_plan["servers"] if s["role"] == role)
    records: list[dict[str, Any]] = []
    for stage in plan.stage_graph(the_plan, the_server):
        if stage == "9":
            break
        records.append({"stage": stage, "state": "started", "digest": digest})
        records.append({"stage": stage, "state": "done", "digest": digest})
    server.seed(records)
    (server.root / "device.txt").write_text(the_server["device"] + "\n", encoding="ascii")


def _cleanup_text(result: dict[str, Any]) -> str:
    scripts = [c["script"] for c in result["calls"] if c["kind"] == "op" and c["op"] == "s9-register"]
    assert len(scripts) == 1, result
    match = re.search(r"^\$CleanupB64 = '([A-Za-z0-9+/=]+)'$", scripts[0], re.MULTILINE)
    assert match, scripts[0]
    return base64.b64decode(match.group(1)).decode("utf-8-sig")


# --------------------------------------------------------------------------
# the run of stage 9
# --------------------------------------------------------------------------


def test_dc1s_stage_9_removes_domain_admins_in_its_task_then_registers_the_cleanup(server: Server) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)})
    assert result["answer"]["ok"] is True, result
    assert result["answer"]["status"] == "done"
    assert _ops_called(result) == ["s9-da", "s9-register"]
    ops = {c["op"]: c for c in result["calls"] if c["kind"] == "op"}
    assert ops["s9-da"]["task"] is True
    assert ops["s9-register"]["task"] is False
    assert _states(server, "9") == ["started", "done"]
    names = [c["name"] for c in result["answer"]["checks"]]
    assert names == ["domain_admins", "cleanup_task"]


def test_dc2s_stage_9_makes_no_removal_and_its_cleanup_keeps_the_account(server: Server) -> None:  # noqa: F811
    the_plan = _two_plan()
    _seed_to_9(server, the_plan, "dc2")
    result = _call(server, the_plan, "9", ops={"s9-register": _ok(REGISTER_OUT)})
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == ["s9-register"]
    assert "Remove-ADUser" not in _cleanup_text(result)


def test_a_removal_that_leaves_the_account_in_domain_admins_stops_before_the_cleanup(server: Server) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    out = DA_OUT.replace("member after: 0", "member after: 1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(out), "s9-register": _ok(REGISTER_OUT)})
    assert result["answer"]["status"] == "stopped", result
    assert result["answer"]["code"] == "readback_failed"
    assert _ops_called(result) == ["s9-da"]
    assert _states(server, "9") == ["started", "stopped"]


@pytest.mark.parametrize("drop", ["member after: 0\n", "member before: 1\n"])
def test_a_removal_read_that_is_missing_stops_before_the_cleanup(server: Server, drop: str) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT.replace(drop, "")), "s9-register": _ok(REGISTER_OUT)})
    assert result["answer"]["code"] == "readback_failed", result
    assert _ops_called(result) == ["s9-da"]


def test_a_failed_removal_op_stops_before_the_cleanup(server: Server) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    failed = {"result": 1, "output": "FAIL: Microsoft.ActiveDirectory.Management.ADException: An unspecified error has occurred\n"}
    result = _call(server, the_plan, "9", ops={"s9-da": failed, "s9-register": _ok(REGISTER_OUT)})
    assert result["answer"]["status"] == "stopped", result
    assert _ops_called(result) == ["s9-da"]


@pytest.mark.parametrize(
    "old, new",
    [
        ("registered NewtonBuild-cleanup as SYSTEM LogonType ServiceAccount", "registered NewtonBuild-cleanup as newton-build LogonType Password"),
        ("state Running", "state Ready"),
        ("state Running\n", ""),
    ],
    ids=["not-system", "not-running", "no-state"],
)
def test_a_cleanup_task_that_is_not_a_running_system_task_stops(server: Server, old: str, new: str) -> None:  # noqa: F811
    the_plan = _two_plan()
    _seed_to_9(server, the_plan, "dc2")
    result = _call(server, the_plan, "9", ops={"s9-register": _ok(REGISTER_OUT.replace(old, new))})
    assert result["answer"]["status"] == "stopped", result
    assert result["answer"]["code"] == "op_failed"
    assert _states(server, "9") == ["started", "stopped"]


def test_stage_9_takes_the_plan_token_and_never_a_checkpoint(server: Server) -> None:  # noqa: F811
    """Stage 9 takes no checkpoint, and a run under a token over a stage
    digest (what a stage token of 9 would be) is ``bad_token`` with no op;
    the same run under the plan token goes (the maintainer, 2026-11-13)."""
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", "checkpoint", ops={})
    assert result["answer"]["ok"] is False
    assert _ops_called(result) == []
    ops = {"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)}
    staged = _call(server, the_plan, "9", ops=ops, checkpoint="newton-cp-9")
    assert (staged["answer"]["ok"], staged["answer"]["code"]) == (False, "bad_token"), staged
    assert _ops_called(staged) == []
    assert _states(server, "9") == []
    planned = _call(server, the_plan, "9", ops=ops)
    assert planned["answer"]["status"] == "done", planned
    assert _ops_called(planned) == ["s9-da", "s9-register"]


# --------------------------------------------------------------------------
# the cleanup script, run under pwsh with every cmdlet it calls recorded
# --------------------------------------------------------------------------

RECORDER = r"""
param([string]$ScriptPath, [string]$OutPath, [string]$ConfigPath, [int]$SshdExit)
$script:Calls = New-Object System.Collections.ArrayList
function Rec([string]$What) { [void]$script:Calls.Add($What) }
function Fake-Sshd { Rec ('sshd ' + ($args -join ' ')); $global:LASTEXITCODE = $SshdExit }
function Start-Sleep { [CmdletBinding()] param([int]$Seconds) Rec ('sleep ' + $Seconds) }
function whoami { 'nt authority\system' }
function Copy-Item { [CmdletBinding()] param([string]$LiteralPath, [string]$Destination, [switch]$Force) Rec ('copy ' + $LiteralPath + ' -> ' + $Destination) }
function Get-FileHash { [CmdletBinding()] param([string]$LiteralPath) [pscustomobject]@{ Hash = 'AA' } }
function Restart-Service { [CmdletBinding()] param([string]$Name, [switch]$Force) Rec ('restart ' + $Name) }
function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Status = 'Running' } }
function Remove-Item { [CmdletBinding()] param([string]$LiteralPath, [switch]$Force) Rec ('delete ' + $LiteralPath) }
function Test-Path { [CmdletBinding()] param([string]$LiteralPath) $false }
function Import-Module { [CmdletBinding()] param([string]$Name) }
function Get-ADUser { [CmdletBinding()] param([string]$Identity) Rec ('read-account ' + $Identity); [pscustomobject]@{ DistinguishedName = 'CN=' + $Identity } }
function Remove-ADUser { [CmdletBinding()] param([string]$Identity, [switch]$Confirm) Rec ('delete-account ' + $Identity) }
function Unregister-ScheduledTask { [CmdletBinding()] param([string]$TaskName, [switch]$Confirm) Rec ('unregister ' + $TaskName) }
$text = [System.IO.File]::ReadAllText($ScriptPath)
$text = $text.Replace('C:\ProgramData\Newton\ad-build-cleanup.txt', (Join-Path ([IO.Path]::GetTempPath()) ('cleanup-' + [guid]::NewGuid().ToString() + '.txt')))
# The sshd configuration is a file of the test, and sshd.exe a recorder.
$configLine = '$SshdConfig = ''C:\ProgramData\ssh\sshd_config'''
$sshdPath = 'Join-Path $env:SystemRoot ''System32\OpenSSH\sshd.exe'''
if ((-not $text.Contains($configLine)) -or (-not $text.Contains($sshdPath))) { throw 'the cleanup names no sshd configuration or sshd.exe' }
$text = $text.Replace($configLine, ('$SshdConfig = ''' + $ConfigPath + ''''))
$text = $text.Replace($sshdPath, '''Fake-Sshd''')
. ([scriptblock]::Create($text))
[System.IO.File]::WriteAllText($OutPath, (@($script:Calls) | ConvertTo-Json -Compress))
"""


#: The sshd configuration of DC1 after stage 8: the bootstrap's settings and
#: the build account's block ahead of the administrators' block, then the
#: 1.3 collector block and the 1.4 write block the two setups append.  It is
#: constructed from the generators' text, not measured: MEASURED-1.5 "Stage 8
#: and 9 on BUILD1" records that the lab did not run.
SSHD_BEFORE_BUILD = (
    "# This is the sshd server system-wide configuration file.\n"
    "PasswordAuthentication no\n"
    "KbdInteractiveAuthentication no\n"
    "AuthorizedKeysFile\t.ssh/authorized_keys\n"
    "Subsystem\tsftp\tsftp-server.exe\n"
)
BUILD_BLOCK = (
    "# newton-ad build\n"
    "Match User newton-build,NBUILD\\newton-build\n"
    "    AuthorizedKeysFile C:/NewtonBuild/authorized_keys\n"
    "    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad-build\\build.ps1\n"
    "    PermitTTY no\n"
    "    AllowTcpForwarding no\n"
    "    PermitTunnel no\n"
    "    X11Forwarding no\n"
    "    AllowAgentForwarding no\n"
)
SSHD_AFTER_BUILD = (
    "Match Group administrators\n"
    "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n"
    "# newton-ad collector\n"
    "Match User nbuild\\newton-audit\n"
    "    AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/authorized_keys\n"
    "    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad\\collector.ps1\n"
    "    PermitTTY no\n"
    "    AllowTcpForwarding no\n"
    "    X11Forwarding no\n"
    "# newton-ad write\n"
    "Match User nbuild\\newton-ops\n"
    "    AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/write_authorized_keys\n"
    "    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad\\write.ps1\n"
    "    PermitTTY no\n"
    "    AllowTcpForwarding no\n"
    "    PermitTunnel no\n"
    "    X11Forwarding no\n"
    "    AllowAgentForwarding no\n"
)
SSHD_AFTER_STAGE_8 = SSHD_BEFORE_BUILD + BUILD_BLOCK + SSHD_AFTER_BUILD


def _run_cleanup(tmp_path: Path, text: str, *, config: str = SSHD_AFTER_STAGE_8, sshd_exit: int = 0) -> list[str]:
    config_path = tmp_path / "sshd_config"
    config_path.write_bytes(config.encode("utf-8"))
    # the bootstrap's backup, which holds no Newton block at all: restoring
    # it would take the newton-ops and newton-audit blocks away
    (tmp_path / "sshd_config.bak-newton-build").write_bytes((SSHD_BEFORE_BUILD + SSHD_AFTER_BUILD.split("# newton-ad collector")[0]).encode("utf-8"))
    script = tmp_path / "cleanup.ps1"
    script.write_text(text, encoding="utf-8")
    recorder = tmp_path / "recorder.ps1"
    recorder.write_text(RECORDER, encoding="utf-8")
    out = tmp_path / "calls.json"
    run = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(recorder), "-ScriptPath", str(script), "-OutPath", str(out),
         "-ConfigPath", str(config_path), "-SshdExit", str(sshd_exit)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert out.is_file(), run.stdout + run.stderr
    return list(json.loads(out.read_text(encoding="utf-8-sig")))


def test_the_cleanup_deletes_the_account_last(server: Server, tmp_path: Path) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)})
    calls = _run_cleanup(tmp_path, _cleanup_text(result))
    # it waits for the helper's answer to leave first
    assert calls[0].startswith("sleep ") and int(calls[0].split()[1]) >= 10
    restore = calls.index("sshd -t")
    restart = calls.index("restart sshd")
    account = calls.index("delete-account newton-build")
    deletes = [i for i, c in enumerate(calls) if c.startswith("delete ")]
    deleted = [calls[i][len("delete "):] for i in deletes]
    for path in (r"C:\NewtonBuild\authorized_keys", r"C:\NewtonBuild\pw.bin"):
        assert path in deleted, calls
    # The helper, K and the device name are where the bootstrap installs
    # them: the helper's install root (DESIGN-1.5 open point 23 of task 8).
    for name in ("build.ps1", "key.hex", "device.txt"):
        assert str(server.root / name) in deleted, calls
    assert not [c for c in calls if "k.hex" in c or "NewtonBuild\\build.ps1" in c], calls
    assert restore < restart < account
    # every access file goes before the account; after it only the task
    # and the script itself go
    assert all(i < account for i in deletes if not calls[i].endswith("ad-build-cleanup.ps1"))
    assert [c.split()[0] for c in calls[account + 1:]] in (
        ["read-account", "unregister", "delete"],
        ["unregister", "delete"],
    ), calls[account:]
    assert calls[-1].endswith(r"ad-build-cleanup.ps1")


def test_dc2s_cleanup_never_touches_the_account(server: Server, tmp_path: Path) -> None:  # noqa: F811
    the_plan = _two_plan()
    _seed_to_9(server, the_plan, "dc2")
    result = _call(server, the_plan, "9", ops={"s9-register": _ok(REGISTER_OUT)})
    calls = _run_cleanup(tmp_path, _cleanup_text(result))
    assert not [c for c in calls if "account" in c]
    assert "restart sshd" in calls
    assert r"delete C:\NewtonBuild\authorized_keys" in calls


# --------------------------------------------------------------------------
# the sshd configuration after the cleanup (the maintainer's decision on DESIGN-1.5 open
# point 37, 2026-11-16): only the build account's block goes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["dc1", "dc2"])
def test_the_cleanup_removes_only_the_build_block_and_keeps_stage_8s(server: Server, tmp_path: Path, role: str) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS)) if role == "dc1" else _two_plan()
    _seed_to_9(server, the_plan, role)
    ops = {"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)} if role == "dc1" else {"s9-register": _ok(REGISTER_OUT)}
    result = _call(server, the_plan, "9", ops=ops)
    calls = _run_cleanup(tmp_path, _cleanup_text(result))
    after = (tmp_path / "sshd_config").read_bytes().decode("utf-8")
    assert after == SSHD_BEFORE_BUILD + SSHD_AFTER_BUILD
    assert "# newton-ad collector\nMatch User nbuild\\newton-audit\n" in after
    assert "# newton-ad write\nMatch User nbuild\\newton-ops\n" in after
    assert calls.index("sshd -t") < calls.index("restart sshd")


def test_the_cleanup_never_restores_the_bootstrap_backup(server: Server, tmp_path: Path) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)})
    text = _cleanup_text(result)
    assert "bak-newton-build" not in text
    assert "Copy-Item" not in text
    calls = _run_cleanup(tmp_path, text)
    assert not [c for c in calls if c.startswith("copy ")], calls
    after = (tmp_path / "sshd_config").read_bytes()
    assert after != (tmp_path / "sshd_config.bak-newton-build").read_bytes()


def test_a_configuration_sshd_refuses_after_the_removal_is_put_back(server: Server, tmp_path: Path) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)})
    calls = _run_cleanup(tmp_path, _cleanup_text(result), sshd_exit=1)
    assert (tmp_path / "sshd_config").read_bytes().decode("utf-8") == SSHD_AFTER_STAGE_8
    # the build account's access goes anyway: its keys file is deleted
    assert r"delete C:\NewtonBuild\authorized_keys" in calls
    assert "restart sshd" in calls


def test_a_configuration_with_no_build_block_is_kept_as_it_is(server: Server, tmp_path: Path) -> None:  # noqa: F811
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)})
    _run_cleanup(tmp_path, _cleanup_text(result), config=SSHD_BEFORE_BUILD + SSHD_AFTER_BUILD)
    assert (tmp_path / "sshd_config").read_bytes().decode("utf-8") == SSHD_BEFORE_BUILD + SSHD_AFTER_BUILD


def test_the_cleanup_deletes_the_stage_8_templates_and_the_installed_write_helper(server: Server, tmp_path: Path) -> None:  # noqa: F811
    """The templates and the write helper the bootstrap installed for stage
    8 (the maintainer's decision of 2026-11-19 on the stage 8 transport) leave with the
    build helper."""
    the_plan = plan.plan_build(copy.deepcopy(PLAN_INPUTS))
    _seed_to_9(server, the_plan, "dc1")
    result = _call(server, the_plan, "9", ops={"s9-da": _ok(DA_OUT), "s9-register": _ok(REGISTER_OUT)})
    calls = _run_cleanup(tmp_path, _cleanup_text(result))
    for name in ("s8-ops.tmpl.ps1", "s8-audit.tmpl.ps1", "s8-write.ps1"):
        assert "delete " + str(server.root / name) in calls, calls
