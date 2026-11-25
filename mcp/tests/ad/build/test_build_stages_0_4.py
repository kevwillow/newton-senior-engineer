"""The stage templates 0 to 4 of the build helper (PLAN-1.5 task 5).

The templates are compiled into ``helper/build.ps1`` (DESIGN-1.5 "The
property": the helper runs only the templates it holds, with the
parameters it reads out of the approved plan's own bytes).  Each stage
renders one or more *ops*: a PowerShell script written to
``C:\\NewtonBuild\\ops`` and run either in the helper's own session
(stages 0 and 1, before the promotion) or in the one-shot scheduled task
registered with newton-build's password (every op from stage 2 on;
DESIGN-1.5 "The build account after promotion").  An op writes its own
output to ``C:\\NewtonBuild\\out``, and the helper parses that output
into the checks of the stage.

THE FIXTURES ARE MEASURED.  ``fixtures/stages_0_4/<op>.txt`` is the
output file of that op as rendered by this helper and run on BUILD1
(MEASURED-1.5 "The ops of stages 0 to 4 on BUILD1, second run"): the
wrapper's identity, start and end lines included, the BOM and the CRLF
dropped, masked: 10.111.0.41 is 192.0.2.41, 10.111.0.1 is 192.0.2.1,
and the domain SID and the domain GUID are replaced.  Stages 0 and 1 ran
as the local Administrator (a stand-in for the helper's own session),
every op from stage 2 on in the password task as newton-build.
``s2-genid-absent.txt`` is the read after the first boot, and
``s2-genid-present.txt`` the read after the second.
``s4-laps-newton-servers.txt`` is the first forest's stage 4 output
(MEASURED-1.5 "Stage 4"), whose self-permission was on a test OU; it is
kept because its LAPS schemaIDGUIDs differ from the second forest's.
``s0-dns-probes.txt`` holds the DNS probes of the first run.

THE TESTS DRIVE THE REAL HELPER.  A driver dot-sources ``build.ps1``
under pwsh and replaces only the functions that touch Windows (the op
runner, the restart, the wait for the directory, the token groups of
the session and the DPAPI file of the DSRM secret).  The token check,
the journal, the order and the parsers are the helper's own.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import baseline, plan
from newton_mcp.approve import approval_token
from ops_fixture import OPS  # type: ignore[import-not-found]
from pwsh_path import PWSH
from test_build_bootstrap import (
    HOSTILE_VALUES,
    _command_names,
    _every_occurrence_is_in_a_literal,
    _parse_errors,
    _single_quoted_spans,
)


HELPER = (
    Path(__file__).resolve().parents[3]
    / "newton_mcp"
    / "ad"
    / "build"
    / "helper"
    / "build.ps1"
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "stages_0_4"
GOLDEN = FIXTURES / "golden"

#: The key of the server: synthetic.
KEY_HEX = "c3" * 32

#: The clock of the tests: 2026-11-13T13:56:00Z, the minute of the
#: measured stage 0 reads.
BASE = 1794578160
NBF = BASE - 60
EXP = BASE + 1800

RUN = "d4" * 16

#: The boot times of the measured run (MEASURED-1.5, stages 1 and 2).
BOOT_0 = "2026-11-13T13:55:41.5000000Z"
BOOT_1 = "2026-11-13T13:59:23.5000000Z"
BOOT_2 = "2026-11-13T14:03:25.5000000Z"
BOOT_3 = "2026-11-13T14:10:05.5000000Z"
BOOT_4 = "2026-11-13T14:20:05.5000000Z"
BOOT_5 = "2026-11-13T14:30:05.5000000Z"

#: The plan of the measured run: BUILD1 becomes BDC1 of
#: build.newton.test (NBUILD) on Proxmox, the addresses masked.
PLAN_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "build.newton.test",
        "netbios": "NBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers"],
        "groups": ["IT Admins"],
        "owner_admin": "owner-admin",
    },
    "servers": [
        {
            "device": "build1",
            "role": "dc1",
            "hostname": "BDC1",
            "ip": "192.0.2.41",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.1"],
            "checkpoint": "proxmox",
            "vmgenid": "5781ffdf-9551-49ab-b94c-1d189c4fe1cc",
            "agent": 1,
        }
    ],
    "baseline": {"version": "2026.11", "options": {"administrator": "random-password"}},
    "accepted_findings": [],
    "ops": dict(OPS),
}

#: Every op of stages 0 to 4, in the order the stages run them.
OPS = [
    "s0-read",
    "s1-base",
    "s1-read",
    "s2-role",
    "s2-promote",
    "s2-groups",
    "s2-genid",
    "s2-read",
    "s3-recyclebin",
    "s4-laps",
    "s4-groups",
]

#: The ops that run in the password task: every op after the promotion
#: starts, and the promotion itself (MEASURED-1.5, stage 2).
TASK_OPS = {"s2-promote", "s2-groups", "s2-genid", "s2-read", "s3-recyclebin", "s4-laps"}

#: The cmdlets and programs that change an address, a route or DHCP.
IP_WRITERS = {
    "new-netipaddress",
    "set-netipaddress",
    "remove-netipaddress",
    "new-netroute",
    "set-netroute",
    "remove-netroute",
    "set-netipinterface",
    "netsh",
    "invoke-cimmethod",
    "invoke-wmimethod",
    "wmic",
    "wmic.exe",
    "netsh.exe",
    "ipconfig",
    "ipconfig.exe",
}


# ---------------------------------------------------------------------------
# the driver
# ---------------------------------------------------------------------------

DRIVER = r"""
param([string]$Helper, [string]$InstallRoot, [string]$Now, [string]$BootTime,
    [string]$InPath, [string]$OutPath)
$ErrorActionPreference = 'Stop'
. $Helper -InstallRoot $InstallRoot -Now $Now -BootTime $BootTime
$script:DriverIn = [System.IO.File]::ReadAllText($InPath) | ConvertFrom-Json
$script:DriverCalls = New-Object System.Collections.ArrayList

function ConvertTo-DriverTable {
    param($Object)
    $table = @{}
    foreach ($property in $Object.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [System.Array]) { $value = [string[]]@($value) }
        $table[$property.Name] = $value
    }
    return $table
}

function Test-NewtonWindowsHost { return $true }

function Invoke-NewtonStageOp {
    param([string]$Op, [string]$Script, [bool]$AsTask, [int]$WaitSeconds = -1, [switch]$AsSystem)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'op'; op = $Op; task = $AsTask; system = [bool]$AsSystem; script = $Script; wait = $WaitSeconds })
    if ($AsTask -and (@($script:DriverIn.fake.running) -contains $Op)) {
        # The real task runner (the password task or the SYSTEM task): a
        # task of that name from an earlier request still runs, and it is
        # not replaced.
        throw ('the task NewtonBuild-' + $Op + ' of an earlier request is still running')
    }
    $fake = Get-NewtonField $script:DriverIn.fake.ops $Op
    if ($null -eq $fake) { throw ('the fake holds no output for ' + $Op) }
    $advance = Get-NewtonField $fake 'advance'
    if ($null -ne $advance) {
        # The op took this many seconds: the helper's clock moves on.
        $script:NowOverride = [string]([int64]$script:NowOverride + [int64]$advance)
    }
    if ([bool](Get-NewtonField $fake 'drop')) {
        # The SSH session drops while the op runs in its task: the helper
        # process dies here, before it reads the task's outcome, and
        # writes nothing more.
        $dropped = [ordered]@{ dropped = $true; calls = @($script:DriverCalls) }
        [System.IO.File]::WriteAllText($OutPath, ($dropped | ConvertTo-Json -Depth 10 -Compress))
        exit 3
    }
    $outcome = [string](Get-NewtonField $fake 'outcome')
    if ([string]::IsNullOrEmpty($outcome)) { $outcome = 'ended' }
    return @{ outcome = $outcome; result = [int]$fake.result; output = [string]$fake.output;
        found = [string](Get-NewtonField $fake 'found') }
}

function Clear-NewtonOpResult {
    param([string]$Op)
    $entries = Get-NewtonJournalEntries ''
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'clear'; op = $Op; journal = $entries.Count })
}

function Read-NewtonOpResult {
    param([string]$Op)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'read-result'; op = $Op })
    $fake = Get-NewtonField $script:DriverIn.fake.results $Op
    if ($null -eq $fake) { return $null }
    return @{ result = [int]$fake.result; output = [string]$fake.output }
}

function Test-NewtonPasswordTaskRunning {
    param([string]$Op)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'task-state'; op = $Op })
    return (@($script:DriverIn.fake.running) -contains $Op)
}

function Remove-NewtonPasswordTask {
    param([string]$Op)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'task-removed'; op = $Op })
}

function Invoke-NewtonRestart {
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'restart' })
    return [bool]$script:DriverIn.fake.restart
}

function Wait-NewtonDirectory {
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'wait' })
    return [bool]$script:DriverIn.fake.directory
}

function Get-NewtonOwnGroups {
    return @($script:DriverIn.fake.groups)
}

function Write-NewtonSecretFile {
    param([string]$Path, [string]$Secret)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'secret'; path = $Path; secret = $Secret })
}

function Remove-NewtonSecretFile {
    param([string]$Path)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'secret-removed'; path = $Path })
}

# The fakes of the Task Scheduler and of the clock, for the tests of
# Invoke-NewtonPasswordTask itself (mode 'task').  The fake task starts
# start_at seconds after Start-ScheduledTask (never when it is null),
# runs for run_for seconds (for ever when it is null) and ends with
# result.  existing is the state of a task of that name registered
# before the request (null: none).
$script:FakeClock = 0.0
$script:FakeRegistered = $false
$script:FakeUnregistered = $false
$script:FakeStartedAt = $null

function Get-NewtonClockSeconds { return $script:FakeClock }

function Get-NewtonSessionUser { return 'NBUILD\newton-build' }

function Start-Sleep {
    param([int]$Seconds)
    $script:FakeClock = $script:FakeClock + $Seconds
}

function Get-NewtonBuildPassword {
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'password' })
    return 'fake-build-password'
}

function Get-FakeTaskPhase {
    $task = $script:DriverIn.fake.task
    if ($null -eq $script:FakeStartedAt) { return 'not-run' }
    if ($null -eq $task.start_at) { return 'not-run' }
    $began = $script:FakeStartedAt + [double]$task.start_at
    if ($script:FakeClock -lt $began) { return 'not-run' }
    if ($null -eq $task.run_for) { return 'running' }
    if ($script:FakeClock -lt ($began + [double]$task.run_for)) { return 'running' }
    return 'ended'
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    if ($script:FakeUnregistered) {
        if ($ErrorActionPreference -eq 'SilentlyContinue') { return $null }
        throw ('no task ' + $TaskName)
    }
    if (-not $script:FakeRegistered) {
        $existing = $script:DriverIn.fake.task.existing
        if ($null -eq $existing) {
            if ($ErrorActionPreference -eq 'SilentlyContinue') { return $null }
            throw ('no task ' + $TaskName)
        }
        return [pscustomobject]@{ TaskName = $TaskName; State = [string]$existing }
    }
    $state = 'Ready'
    if ((Get-FakeTaskPhase) -eq 'running') { $state = 'Running' }
    return [pscustomobject]@{ TaskName = $TaskName; State = $state }
}

function Get-ScheduledTaskInfo {
    [CmdletBinding()]
    param([string]$TaskName)
    $result = 267011
    switch (Get-FakeTaskPhase) {
        'running' { $result = 267009 }
        'ended' {
            $result = [int64]$script:DriverIn.fake.task.result
            # result_lag: the measured race (lab run 7, 2026-11-24): State is Ready while LastTaskResult
            # still reads 267009 for a moment after the task ended.
            $lag = $null
            if ($script:DriverIn.fake.task.PSObject.Properties.Name -contains 'result_lag') { $lag = $script:DriverIn.fake.task.result_lag }
            if ($null -ne $lag) {
                $task = $script:DriverIn.fake.task
                $ended = $script:FakeStartedAt + [double]$task.start_at + [double]$task.run_for
                if ($script:FakeClock -lt ($ended + [double]$lag)) { $result = 267009 }
            }
        }
    }
    return [pscustomobject]@{ TaskName = $TaskName; LastTaskResult = $result }
}

function New-ScheduledTaskAction {
    param([string]$Execute, [string]$Argument)
    return [pscustomobject]@{ Execute = $Execute; Argument = $Argument }
}

function New-ScheduledTaskSettingsSet {
    param($ExecutionTimeLimit)
    return [pscustomobject]@{ ExecutionTimeLimit = $ExecutionTimeLimit }
}

function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, $Action, $Settings, [string]$User, [string]$Password, [string]$RunLevel, $Principal)
    # The SYSTEM task is registered with a principal and with no password;
    # the password task with the user and the password of the build account.
    $principalUser = ''
    $principalLogon = ''
    $principalLevel = ''
    if ($null -ne $Principal) {
        $principalUser = [string]$Principal.UserId
        $principalLogon = [string]$Principal.LogonType
        $principalLevel = [string]$Principal.RunLevel
    }
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'register'; name = $TaskName; user = $User; run_level = $RunLevel; argument = [string]$Action.Argument
        principal_user = $principalUser; principal_logon_type = $principalLogon; principal_run_level = $principalLevel
        has_password = (-not [string]::IsNullOrEmpty($Password)) })
    $script:FakeRegistered = $true
    $script:FakeUnregistered = $false
    return [pscustomobject]@{ TaskName = $TaskName }
}

function New-ScheduledTaskPrincipal {
    param([string]$UserId, [string]$LogonType, [string]$RunLevel)
    return [pscustomobject]@{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel }
}

function Start-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'start'; name = $TaskName; at = $script:FakeClock })
    $script:FakeStartedAt = $script:FakeClock
}

function Stop-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'stop'; name = $TaskName; at = $script:FakeClock })
}

function Unregister-ScheduledTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$TaskName)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'unregister'; name = $TaskName; at = $script:FakeClock; registered = $script:FakeRegistered })
    if ($script:FakeRegistered) { $script:FakeUnregistered = $true }
}

# A disabled task does not start.  start_on_disable is the race of the
# give-up: the task starts in the moment between the helper's last poll
# and the Disable-ScheduledTask call that would have kept it from it.
function Disable-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'disable'; name = $TaskName; at = $script:FakeClock })
    $task = $script:DriverIn.fake.task
    if ([bool](Get-NewtonField $task 'start_on_disable') -and ($null -ne $script:FakeStartedAt)) {
        $task.start_at = $script:FakeClock - $script:FakeStartedAt
    }
    return [pscustomobject]@{ TaskName = $TaskName; State = 'Disabled' }
}

$result = [ordered]@{}
switch ([string]$script:DriverIn.mode) {
    'task' {
        try {
            $taskArgs = @{
                Op = [string]$script:DriverIn.op
                OpPath = ('C:\NewtonBuild\ops\' + [string]$script:DriverIn.op + '.ps1')
            }
            $wait = Get-NewtonField $script:DriverIn 'wait'
            if ($null -ne $wait) { $taskArgs['WaitSeconds'] = [int]$wait }
            $result.task = Invoke-NewtonPasswordTask @taskArgs
        } catch {
            $result.error = [string]$_.Exception.Message
        }
        $result.clock = $script:FakeClock
        $result.calls = @($script:DriverCalls)
    }
    'system-task' {
        # The same task runner, registered as NT AUTHORITY\SYSTEM: the
        # DESIGN-1.5 point 83, DC2's own read.
        try {
            $taskArgs = @{
                Op = [string]$script:DriverIn.op
                OpPath = ('C:\NewtonBuild\ops\' + [string]$script:DriverIn.op + '.ps1')
            }
            $wait = Get-NewtonField $script:DriverIn 'wait'
            if ($null -ne $wait) { $taskArgs['WaitSeconds'] = [int]$wait }
            $result.task = Invoke-NewtonSystemTask @taskArgs
        } catch {
            $result.error = [string]$_.Exception.Message
        }
        $result.clock = $script:FakeClock
        $result.calls = @($script:DriverCalls)
    }
    'request' {
        try {
            $request = ConvertFrom-NewtonRequest ([string]$script:DriverIn.request)
            $result.answer = Invoke-NewtonAction -Request $request
        } catch {
            $result.answer = New-NewtonAnswer -Ok $false -Status 'refused' `
                -Code (Get-NewtonRefusalCode $_) -Checks @()
            $result.error = [string]$_.Exception.Message
        } finally {
            Exit-NewtonJournalLock
        }
        $result.calls = @($script:DriverCalls)
    }
    'render' {
        $values = ConvertTo-DriverTable $script:DriverIn.values
        $scripts = [ordered]@{}
        foreach ($op in $script:DriverIn.ops) {
            $scripts[[string]$op] = Get-NewtonOpScript -Op ([string]$op) -Values $values
        }
        $result.scripts = $scripts
    }
    'values' {
        try {
            $plan = ConvertFrom-NewtonPlanBytes ([Convert]::FromBase64String([string]$script:DriverIn.plan))
            $result.values = Get-NewtonStageValues -Plan $plan -Role ([string]$script:DriverIn.role)
        } catch {
            $result.error = Get-NewtonRefusalCode $_
        }
    }
    'secret' {
        $key = New-Object byte[] 32
        $hex = [string]$script:DriverIn.key
        for ($i = 0; $i -lt 32; $i++) { $key[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        $result.secret = Get-NewtonDerivedSecret -Key $key -Digest ([string]$script:DriverIn.digest) `
            -Info ([string]$script:DriverIn.info)
    }
    'verdict' {
        $values = ConvertTo-DriverTable $script:DriverIn.values
        $verdict = Get-NewtonOpVerdict -Op ([string]$script:DriverIn.op) `
            -Output ([string]$script:DriverIn.output) -Values $values `
            -Now ([int64]$script:DriverIn.now) -NotBefore ([int64]$script:DriverIn.nbf) `
            -Groups @($script:DriverIn.groups)
        $result.verdict = $verdict
    }
}
[System.IO.File]::WriteAllText($OutPath, ($result | ConvertTo-Json -Depth 10 -Compress))
"""


def _pwsh() -> str:
    if not PWSH.is_file():
        pytest.fail("the gate of AD 1.5 task 5 requires the pwsh tests to run")
    return str(PWSH)


class Server:
    """The install root of BUILD1 under the tests, with its journal."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        (root / "key.hex").write_text(KEY_HEX + "\n", encoding="ascii")
        (root / "device.txt").write_text("build1\n", encoding="ascii")
        self.driver = root.parent / "driver.ps1"
        self.driver.write_text(DRIVER, encoding="utf-8")
        self.count = 0

    def drive(self, payload: dict[str, Any], *, now: int = BASE, boot: str = BOOT_0) -> dict[str, Any]:
        self.count += 1
        in_path = self.root.parent / f"in-{self.count}.json"
        out_path = self.root.parent / f"out-{self.count}.json"
        in_path.write_text(json.dumps(payload), encoding="utf-8")
        result = subprocess.run(
            [
                _pwsh(),
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.driver),
                "-Helper",
                str(HELPER),
                "-InstallRoot",
                str(self.root),
                "-Now",
                str(now),
                "-BootTime",
                boot,
                "-InPath",
                str(in_path),
                "-OutPath",
                str(out_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert out_path.is_file(), result.stdout + result.stderr
        return json.loads(out_path.read_text(encoding="utf-8-sig"))

    def seed(self, records: list[dict[str, Any]]) -> None:
        """Journal entries written before the request, as the helper writes them."""
        directory = self.root / "journal"
        directory.mkdir(exist_ok=True)
        for seq, record in enumerate(records):
            entry = {
                "run": RUN,
                "seq": seq,
                "stage": record["stage"],
                "state": record["state"],
                "reason": "",
                "digest": record["digest"],
                "checkpoint": record.get("checkpoint", ""),
                "boot": record.get("boot", BOOT_0),
                "time": BASE - 100,
                "checks": [],
            }
            if "secrets" in record:
                entry["secrets"] = record["secrets"]
            (directory / f"{RUN}.{seq}.json").write_text(json.dumps(entry), encoding="utf-8")

    def append(self, record: dict[str, Any]) -> None:
        """One more journal entry, at the next seq, as the helper writes it."""
        seq = len(self.journal())
        entry = {
            "run": RUN,
            "seq": seq,
            "stage": record["stage"],
            "state": record["state"],
            "reason": "",
            "digest": record["digest"],
            "checkpoint": record.get("checkpoint", ""),
            "boot": record.get("boot", BOOT_0),
            "time": BASE - 50,
            "checks": [],
        }
        if "secrets" in record:
            entry["secrets"] = record["secrets"]
        (self.root / "journal" / f"{RUN}.{seq}.json").write_text(json.dumps(entry), encoding="utf-8")

    def journal(self) -> list[dict[str, Any]]:
        directory = self.root / "journal"
        if not directory.is_dir():
            return []
        entries = [json.loads(p.read_text(encoding="utf-8")) for p in directory.glob("*.json")]
        return sorted(entries, key=lambda e: e["seq"])


@pytest.fixture
def server(tmp_path: Path) -> Server:
    return Server(tmp_path / "install")


def _plan(inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return plan.plan_build(copy.deepcopy(PLAN_INPUTS if inputs is None else inputs))


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="ascii")


def _ok(output: str) -> dict[str, Any]:
    return {"result": 0, "output": output}


def _role(name: str = "s2-role-workgroup.txt") -> dict[str, dict[str, Any]]:
    """The fake of the s2-role read, from its measured output."""
    return {"s2-role": _ok(_fixture(name))}


def _s4u_groups() -> list[str]:
    return [line for line in _fixture("s2-s4u-groups.txt").splitlines() if line]


def _request(the_plan: dict[str, Any], stage: str, action: str = "run", *, checkpoint: str = "") -> str:
    digest = plan.digest(the_plan)
    signed = digest
    if checkpoint:
        signed = plan.stage_digest(digest, stage, checkpoint)
    return json.dumps(
        {
            "run": RUN,
            "plan": base64.b64encode(plan.canonical_bytes(the_plan)).decode("ascii"),
            "stage": stage,
            "action": action,
            "token": approval_token(KEY_HEX, signed, NBF, EXP),
            "nbf": NBF,
            "exp": EXP,
        }
    )


def _call(
    server: Server,
    the_plan: dict[str, Any],
    stage: str,
    action: str = "run",
    *,
    ops: dict[str, dict[str, Any]] | None = None,
    groups: list[str] | None = None,
    directory: bool = True,
    restart: bool = True,
    checkpoint: str = "",
    now: int = BASE,
    boot: str = BOOT_0,
    results: dict[str, dict[str, Any]] | None = None,
    running: list[str] | None = None,
) -> dict[str, Any]:
    payload = {
        "mode": "request",
        "request": _request(the_plan, stage, action, checkpoint=checkpoint),
        "fake": {
            "ops": ops or {},
            "groups": groups or [],
            "directory": directory,
            "restart": restart,
            "results": results or {},
            "running": running or [],
        },
    }
    return server.drive(payload, now=now, boot=boot)


def _values(the_plan: dict[str, Any] | None = None, role: str = "dc1") -> dict[str, Any]:
    the_plan = _plan() if the_plan is None else the_plan
    raw = base64.b64encode(plan.canonical_bytes(the_plan)).decode("ascii")
    return {"plan": raw, "role": role}


#: The calls that only read or tidy the state of the password task (its
#: state, its result file, the clearing of the result files).
BOOKKEEPING = {"task-state", "clear", "read-result"}


def _calls(result: dict[str, Any]) -> list[dict[str, Any]]:
    """The calls of a request without the bookkeeping of the password task."""
    return [c for c in result["calls"] if c["kind"] not in BOOKKEEPING]


def _kinds(result: dict[str, Any], *kinds: str) -> list[str]:
    return [c["kind"] for c in result["calls"] if c["kind"] in kinds]


def _ops_called(result: dict[str, Any]) -> list[str]:
    return [c["op"] for c in result["calls"] if c["kind"] == "op"]


def _restarts(result: dict[str, Any]) -> int:
    return sum(1 for c in result["calls"] if c["kind"] == "restart")


def _states(server: Server, stage: str) -> list[str]:
    return [e["state"] for e in server.journal() if e["stage"] == stage]


def _seed_before(server: Server, the_plan: dict[str, Any], stage: str, checkpoint: str) -> None:
    """The journal of a run whose earlier stages are done and whose stage
    holds its checkpoint (the checkpoint adapter is task 7)."""
    digest = plan.digest(the_plan)
    records: list[dict[str, Any]] = []
    for earlier in ["0", "1", "2", "3", "4"]:
        if earlier == stage:
            break
        records.append({"stage": earlier, "state": "started", "digest": digest})
        records.append({"stage": earlier, "state": "done", "digest": digest})
    records.append({"stage": stage, "state": "checkpointed", "digest": digest, "checkpoint": checkpoint})
    server.seed(records)


# ---------------------------------------------------------------------------
# the values and the golden renders
# ---------------------------------------------------------------------------


def _stage_values(server: Server, the_plan: dict[str, Any] | None = None) -> dict[str, Any]:
    out = server.drive({"mode": "values", **_values(the_plan)})
    assert "values" in out, out
    return out["values"]


def test_the_values_of_a_stage_come_out_of_the_plan_bytes(server: Server) -> None:
    values = _stage_values(server)
    assert values == {
        "DnsName": "build.newton.test",
        "Netbios": "NBUILD",
        "Level": "Win2025",
        "HostName": "BDC1",
        "Ip": "192.0.2.41",
        "Prefix": "24",
        "Gateway": "192.0.2.1",
        "TimePeer": "192.0.2.1",
        "Forwarders": ["192.0.2.1"],
        "Checkpoint": "proxmox",
        "BuildUser": "newton-build",
        "SecretFile": "C:\\NewtonBuild\\dsrm.bin",
        # The values of stages 5 and 6 (task 6): the plan's names and
        # option, then the baseline compiled into the helper.
        "OuTree": ["IT/Servers"],
        "Groups": ["IT Admins"],
        "OwnerAdmin": "owner-admin",
        "AdministratorOption": "random-password",
        "AdminSecretFile": "C:\\NewtonBuild\\admin.bin",
        **baseline.load_baseline("2026.11").helper_values(),
    }


#: Addresses that are IPv4 addresses and that plan.py still refuses (the
#: nit of a review: the helper's re-checks were only the dotted-quad
#: grammar), as the server fields that change: an unusable address
#: (unspecified, loopback, multicast, link-local, reserved), an address
#: of the network, a gateway outside the network or equal to the
#: address, a forwarder that is unusable, the server's own, or twice.
#: Each case changes only what its check needs: the others hold.
PLAN_IP_REFUSALS: dict[str, dict[str, Any]] = {
    "ip-unspecified": {"ip": "0.0.0.0", "prefix": 1, "gateway": "0.0.0.1"},
    "ip-loopback": {"ip": "127.0.0.1", "gateway": "127.0.0.2"},
    "ip-multicast": {"ip": "224.0.0.10", "gateway": "224.0.0.1"},
    "ip-link-local": {"ip": "169.254.0.41", "gateway": "169.254.0.1"},
    "ip-reserved": {"ip": "240.0.2.41", "gateway": "240.0.2.1"},
    "ip-network": {"ip": "192.0.2.0"},
    "ip-broadcast": {"ip": "192.0.2.255"},
    "gateway-unspecified": {"ip": "0.0.0.1", "prefix": 1, "gateway": "0.0.0.0"},
    "gateway-network": {"gateway": "192.0.2.0"},
    "gateway-broadcast": {"gateway": "192.0.2.255"},
    "gateway-is-ip": {"gateway": "192.0.2.41"},
    "gateway-outside": {"gateway": "198.51.100.1"},
    "forwarder-loopback": {"forwarders": ["127.0.0.1"]},
    "forwarder-unspecified": {"forwarders": ["0.0.0.0"]},
    "forwarder-multicast": {"forwarders": ["224.0.0.251"]},
    "forwarder-link-local": {"forwarders": ["169.254.169.254"]},
    "forwarder-reserved": {"forwarders": ["255.255.255.255"]},
    "forwarder-is-ip": {"forwarders": ["192.0.2.41"]},
    "forwarder-twice": {"forwarders": ["192.0.2.1", "192.0.2.1"]},
    # The review's minors (T2): a usable address with an unusable gateway
    # inside its network, and the reverse, so the usable check of the
    # gateway and the one of the address each stop a plan on their own
    # (every other check of these plans passes).
    "gateway-loopback-ip-usable": {"ip": "10.0.0.5", "prefix": 1, "gateway": "127.0.0.1"},
    "gateway-link-local-ip-usable": {"ip": "169.0.0.5", "prefix": 8, "gateway": "169.254.0.1"},
    "gateway-multicast-ip-usable": {"ip": "200.0.0.5", "prefix": 1, "gateway": "224.0.0.1"},
    "gateway-reserved-ip-usable": {"ip": "200.0.0.5", "prefix": 1, "gateway": "240.0.0.1"},
    "ip-loopback-gateway-usable": {"ip": "127.0.0.5", "prefix": 1, "gateway": "10.0.0.1"},
    "ip-link-local-gateway-usable": {"ip": "169.254.0.5", "prefix": 8, "gateway": "169.0.0.1"},
    "ip-multicast-gateway-usable": {"ip": "224.0.0.5", "prefix": 1, "gateway": "200.0.0.1"},
    "ip-reserved-gateway-usable": {"ip": "240.0.0.5", "prefix": 1, "gateway": "200.0.0.1"},
}

#: The address edges plan.py accepts: a /30 whose two hosts are the
#: address and the gateway, a /1, a forwarder outside the network.
PLAN_IP_ACCEPTED: dict[str, dict[str, Any]] = {
    "slash-30": {"ip": "192.0.2.41", "prefix": 30, "gateway": "192.0.2.42"},
    "slash-1": {"ip": "100.64.0.5", "prefix": 1, "gateway": "64.0.0.1", "forwarders": ["64.0.0.1"]},
    "forwarder-outside": {"forwarders": ["198.51.100.53", "192.0.2.1"]},
}


def _plan_bytes_with(server_change: dict[str, Any]) -> str:
    """The canonical bytes of the golden plan with server fields changed
    in place (base64): the token is not the helper's concern here."""
    text = plan.canonical_bytes(_plan()).decode("ascii")
    for field, value in server_change.items():
        rendered = ",".join(value) if isinstance(value, list) else str(value)
        key = f"servers.0.{field}"
        changed = re.sub(rf"(?m)^{re.escape(key)}=.*$", lambda _: f"{key}={rendered}", text)
        assert changed != text or f"{key}={rendered}\n" in text
        text = changed
    return base64.b64encode(text.encode("ascii")).decode("ascii")


@pytest.mark.parametrize("case", sorted(PLAN_IP_REFUSALS))
def test_plan_py_refuses_each_address_case(case: str) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["servers"][0].update(PLAN_IP_REFUSALS[case])
    with pytest.raises(plan.BuildPlanRefused):
        plan.plan_build(inputs)


@pytest.mark.parametrize("case", sorted(PLAN_IP_REFUSALS))
def test_the_values_refuse_each_address_plan_py_refuses(server: Server, case: str) -> None:
    """The helper's address re-checks are exactly as strict as plan.py's."""
    out = server.drive({"mode": "values", "plan": _plan_bytes_with(PLAN_IP_REFUSALS[case]), "role": "dc1"})
    assert out.get("error") == "schema", out


@pytest.mark.parametrize("case", sorted(PLAN_IP_ACCEPTED))
def test_the_values_accept_each_address_plan_py_accepts(server: Server, case: str) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["servers"][0].update(PLAN_IP_ACCEPTED[case])
    plan.plan_build(inputs)
    out = server.drive({"mode": "values", "plan": _plan_bytes_with(PLAN_IP_ACCEPTED[case]), "role": "dc1"})
    assert "values" in out, out


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("servers.0.hostname", "BDC1'; Remove-Item C:\\ -Recurse #"),
        ("servers.0.ip", "192.0.2.300"),
        ("servers.0.gateway", "192.0.2.1;whoami"),
        ("servers.0.forwarders", "192.0.2.1,$(whoami)"),
        ("servers.0.prefix", "33"),
        # plan.py allows a prefix of 1 to 30 and no host, NetBIOS or
        # last DNS label that is all digits: the helper is as strict.
        ("servers.0.prefix", "31"),
        ("servers.0.prefix", "32"),
        ("servers.0.hostname", "12345"),
        ("domain.netbios", "12345"),
        ("domain.dns_name", "build.newton.123"),
        ("domain.dns_name", "build.newton.test'"),
        ("domain.netbios", "NBUILD-TOO-LONG-NAME"),
        ("domain.functional_level", "Win2016"),
    ],
)
def test_the_values_refuse_a_plan_value_outside_its_grammar(
    server: Server, key: str, value: str
) -> None:
    """The helper checks every value it renders, even inside signed bytes."""
    # The unchanged plan renders: the refusal below is the value's own.
    assert "values" in server.drive({"mode": "values", **_values()})
    text = plan.canonical_bytes(_plan()).decode("ascii")
    changed = re.sub(rf"(?m)^{re.escape(key)}=.*$", lambda _: f"{key}={value}", text)
    assert changed != text
    raw = base64.b64encode(changed.encode("ascii")).decode("ascii")
    out = server.drive({"mode": "values", "plan": raw, "role": "dc1"})
    assert out.get("error") == "schema", out


def _render(server: Server, values: dict[str, Any], ops: list[str] | None = None) -> dict[str, str]:
    out = server.drive({"mode": "render", "ops": ops or OPS, "values": values})
    return out["scripts"]


@pytest.mark.parametrize("op", OPS)
def test_the_golden_render_of_each_op(server: Server, op: str) -> None:
    scripts = _render(server, _stage_values(server), [op])
    golden = (GOLDEN / f"{op}.ps1").read_text(encoding="utf-8")
    assert scripts[op] == golden


def test_every_op_parses_and_writes_its_output_where_the_helper_reads_it(server: Server) -> None:
    scripts = _render(server, _stage_values(server))
    for op, script in scripts.items():
        assert _parse_errors(script) == [], op
        assert f"$OutFile = 'C:\\NewtonBuild\\out\\{op}.txt'" in script, op
        assert "Out-File -FilePath $OutFile" in script, op


def test_no_op_restarts_the_server_itself(server: Server) -> None:
    """The helper records rebooting before it restarts; an op never restarts."""
    scripts = _render(server, _stage_values(server))
    for op, script in scripts.items():
        names = {name.lower() for name in _command_names(script)}
        assert "restart-computer" not in names, op
        assert "shutdown" not in names and "shutdown.exe" not in names, op


@pytest.mark.parametrize("hostile", HOSTILE_VALUES)
def test_a_hostile_value_stays_inside_its_literal(server: Server, hostile: str) -> None:
    """Raw hostile values fed to the renderer directly stay in their strings."""
    golden = _render(server, _stage_values(server))
    values = _stage_values(server)
    for key in ["DnsName", "Netbios", "HostName", "Ip", "TimePeer", "BuildUser", "SecretFile"]:
        values[key] = hostile
    values["Forwarders"] = [hostile, "192.0.2.1"]
    scripts = _render(server, values)
    escaped = "'" + re.sub("['\u2018\u2019\u201a\u201b]", lambda m: m.group(0) * 2, hostile) + "'"
    for op, script in scripts.items():
        assert _parse_errors(script) == [], op
        assert _command_names(script) == _command_names(golden[op]), op
        spans = _single_quoted_spans(script)
        assert _every_occurrence_is_in_a_literal(script, hostile, spans), op
    assert f"$HostName = {escaped}" in scripts["s1-base"]
    assert f"$Forwarders = @({escaped}, '192.0.2.1')" in scripts["s1-base"]
    assert f"$DnsName = {escaped}" in scripts["s2-promote"]


# ---------------------------------------------------------------------------
# stage 0
# ---------------------------------------------------------------------------


DNS_FREE = (
    "Resolve-DnsName build.newton.test -DnsOnly True FAIL in 55 ms: System.ComponentModel.Win32Exception"
    " | NativeErrorCode 9003 | build.newton.test : DNS name does not exist"
    " | DNS_ERROR_RCODE_NAME_ERROR,Microsoft.DnsClient.Commands.ResolveDnsName"
)


def _stage0_output(dns_line: str = DNS_FREE) -> str:
    """The measured stage 0 output, with a resolver that answers NXDOMAIN.

    The fresh BUILD1 had no resolver (1460); the 9003 line is the shape
    measured against a resolver that answers (s0-dns-probes.txt).
    """
    lines = _fixture("s0-read.txt").splitlines()
    return "\n".join(dns_line if line.startswith("Resolve-DnsName ") else line for line in lines) + "\n"


def test_the_dns_lines_of_stage_0_are_the_measured_ones() -> None:
    """DNS_FREE is the measured 9003 line, with only the name changed.

    The measured line was a probe with ``-Server 127.0.0.1``; the template
    prints ``-DnsOnly True`` in that place (the s0-read op), so the text
    from ``FAIL in`` on is compared, with the probed name replaced by the
    plan's.
    """
    probes = _fixture("s0-dns-probes.txt").splitlines()
    measured = [line for line in probes if "NativeErrorCode 9003" in line]
    assert len(measured) == 1
    probe_name = "nothere-7f3a.build.newton.test"
    head, tail = measured[0].split(" FAIL in ", 1)
    assert head == f"Resolve-DnsName {probe_name} -Server 127.0.0.1"
    assert DNS_FREE == (
        "Resolve-DnsName build.newton.test -DnsOnly True FAIL in " + tail.replace(probe_name, "build.newton.test")
    )
    assert "NativeErrorCode 1460" in _fixture("s0-read.txt")


def test_stage_0_passes_on_the_measured_server_with_a_resolver(server: Server) -> None:
    the_plan = _plan()
    result = _call(server, the_plan, "0", ops={"s0-read": _ok(_stage0_output())})
    assert result["answer"]["ok"] is True, result
    assert result["answer"]["status"] == "done"
    assert _ops_called(result) == ["s0-read"]
    assert result["calls"][0]["task"] is False
    assert _states(server, "0") == ["started", "done"]
    names = [c["name"] for c in result["answer"]["checks"]]
    assert names == ["os", "workgroup", "adds", "ip", "clock", "disk", "domain", "agent"]
    assert all(c["ok"] for c in result["answer"]["checks"])


def _stopped(server: Server, result: dict[str, Any], stage: str, code: str) -> None:
    answer = result["answer"]
    assert answer["ok"] is False, result
    assert answer["status"] == "stopped"
    assert answer["code"] == code
    last = [e for e in server.journal() if e["stage"] == stage][-1]
    assert last["state"] == "stopped"
    assert last["reason"] == code


def test_stage_0_refuses_ip_mismatch(server: Server) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["servers"][0]["ip"] = "192.0.2.42"
    the_plan = _plan(inputs)
    result = _call(server, the_plan, "0", ops={"s0-read": _ok(_stage0_output())})
    _stopped(server, result, "0", "ip_mismatch")


def test_stage_0_refuses_ip_mismatch_on_the_gateway_and_the_prefix(server: Server) -> None:
    for field, value in [("gateway", "192.0.2.254"), ("prefix", 25)]:
        inputs = copy.deepcopy(PLAN_INPUTS)
        inputs["servers"][0][field] = value
        one = Server(server.root.parent / f"install-{field}")
        result = _call(one, _plan(inputs), "0", ops={"s0-read": _ok(_stage0_output())})
        _stopped(one, result, "0", "ip_mismatch")


def test_stage_0_refuses_clock_skew(server: Server) -> None:
    """The clock must be within 5 minutes of the request's NBF."""
    the_plan = _plan()
    result = _call(server, the_plan, "0", ops={"s0-read": _ok(_stage0_output())}, now=NBF + 301)
    _stopped(server, result, "0", "clock_skew")


def test_stage_0_accepts_a_clock_within_five_minutes(server: Server) -> None:
    the_plan = _plan()
    result = _call(server, the_plan, "0", ops={"s0-read": _ok(_stage0_output())}, now=NBF + 300)
    assert result["answer"]["status"] == "done", result


def test_stage_0_refuses_domain_exists(server: Server) -> None:
    """An answer for the plan's DNS name: the measured OK line shape."""
    line = "Resolve-DnsName build.newton.test -DnsOnly True OK in 10 ms: A 192.0.2.41"
    the_plan = _plan()
    result = _call(server, the_plan, "0", ops={"s0-read": _ok(_stage0_output(line))})
    _stopped(server, result, "0", "domain_exists")


@pytest.mark.parametrize("code", ["1460", "9002"])
def test_stage_0_stops_when_the_dns_check_cannot_be_made(server: Server, code: str) -> None:
    """No resolver (1460) or a server failure (9002) is not a free name."""
    measured = {
        "1460": _fixture("s0-read.txt"),
        "9002": _stage0_output(
            "Resolve-DnsName build.newton.test -DnsOnly True FAIL in 11087 ms: "
            "System.ComponentModel.Win32Exception | NativeErrorCode 9002 | build.newton.test : "
            "DNS server failure | RCODE_SERVER_FAILURE,Microsoft.DnsClient.Commands.ResolveDnsName"
        ),
    }[code]
    result = _call(server, _plan(), "0", ops={"s0-read": _ok(measured)})
    _stopped(server, result, "0", "dns_unchecked")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("QEMU-GA: Running, Automatic", "QEMU-GA: Stopped, Automatic"),
        ("QEMU-GA: Running, Automatic", "QEMU-GA: absent"),
        ("VirtIO Serial Driver: OK, System,", "VirtIO Serial Driver: Error, System,"),
    ],
)
def test_stage_0_refuses_agent_missing(server: Server, old: str, new: str) -> None:
    output = _stage0_output().replace(old, new)
    assert output != _stage0_output()
    result = _call(server, _plan(), "0", ops={"s0-read": _ok(output)})
    _stopped(server, result, "0", "agent_missing")


def test_stage_0_refuses_agent_missing_when_the_serial_device_is_absent(server: Server) -> None:
    output = "\n".join(
        line for line in _stage0_output().splitlines() if not line.startswith("VirtIO Serial Driver:")
    ) + "\nVirtIO Serial Driver: absent\n"
    result = _call(server, _plan(), "0", ops={"s0-read": _ok(output)})
    _stopped(server, result, "0", "agent_missing")


def test_stage_0_does_not_ask_for_the_agent_off_proxmox(server: Server) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["servers"][0]["checkpoint"] = "wbadmin"
    del inputs["servers"][0]["vmgenid"]
    del inputs["servers"][0]["agent"]
    output = _stage0_output().replace("QEMU-GA: Running, Automatic", "QEMU-GA: absent")
    result = _call(server, _plan(inputs), "0", ops={"s0-read": _ok(output)})
    assert result["answer"]["status"] == "done", result


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        ("Windows Server 2025 Standard Evaluation", "Windows Server 2022 Standard", "os_mismatch"),
        ("PartOfDomain False", "PartOfDomain True", "not_workgroup"),
        ("AD-Domain-Services Available", "AD-Domain-Services Installed", "adds_present"),
        ("C: free bytes 26017886208", "C: free bytes 21474836479", "disk_low"),
        ("PrefixOrigin Manual", "PrefixOrigin Dhcp", "ip_mismatch"),
    ],
)
def test_stage_0_refuses_every_other_precondition(server: Server, old: str, new: str, code: str) -> None:
    output = _stage0_output().replace(old, new)
    assert output != _stage0_output()
    result = _call(server, _plan(), "0", ops={"s0-read": _ok(output)})
    _stopped(server, result, "0", code)


def test_stage_0_stops_when_the_op_fails(server: Server) -> None:
    result = _call(server, _plan(), "0", ops={"s0-read": {"result": 1, "output": "FAIL: x: y\n"}})
    _stopped(server, result, "0", "op_failed")


# ---------------------------------------------------------------------------
# stage 1
# ---------------------------------------------------------------------------


def test_stage_1_never_touches_the_ip(server: Server) -> None:
    scripts = _render(server, _stage_values(server), ["s1-base", "s1-read"])
    for op, script in scripts.items():
        names = {name.lower() for name in _command_names(script)}
        assert not names & IP_WRITERS, (op, names & IP_WRITERS)
    base = scripts["s1-base"]
    assert "Rename-Computer -NewName $HostName -Force" in base
    assert "Install-WindowsFeature AD-Domain-Services, RSAT-AD-Tools, Windows-Server-Backup" in base
    assert "Set-DnsClientServerAddress -InterfaceIndex" in base
    assert "-ServerAddresses $Forwarders" in base


def _seed_done(server: Server, the_plan: dict[str, Any], stages: list[str]) -> None:
    digest = plan.digest(the_plan)
    records: list[dict[str, Any]] = []
    for stage in stages:
        records.append({"stage": stage, "state": "started", "digest": digest})
        records.append({"stage": stage, "state": "done", "digest": digest})
    server.seed(records)


def test_stage_1_runs_reboots_and_reads_back(server: Server) -> None:
    the_plan = _plan()
    _seed_done(server, the_plan, ["0"])
    result = _call(server, the_plan, "1", ops={"s1-base": _ok(_fixture("s1-base.txt"))}, boot=BOOT_0)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s1-base"]
    assert result["calls"][0]["task"] is False
    assert _restarts(result) == 1
    assert _states(server, "1") == ["started", "rebooting"]

    # The status before the boot time advances runs nothing.
    result = _call(server, the_plan, "1", "status", boot=BOOT_0)
    assert result["answer"]["status"] == "rebooting"
    assert _ops_called(result) == []

    result = _call(server, the_plan, "1", "status", ops={"s1-read": _ok(_fixture("s1-read.txt"))}, boot=BOOT_1)
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == ["s1-read"]
    assert _restarts(result) == 0
    assert all(c["ok"] for c in result["answer"]["checks"])
    assert {c["name"] for c in result["answer"]["checks"]} >= {"name", "features", "ip", "dns_client", "time"}


def test_stage_1_stops_when_the_ip_changed(server: Server) -> None:
    the_plan = _plan()
    _seed_done(server, the_plan, ["0"])
    output = _fixture("s1-base.txt").replace("after ip: 192.0.2.41/24 Manual", "after ip: 192.0.2.99/24 Manual")
    result = _call(server, the_plan, "1", ops={"s1-base": _ok(output)})
    _stopped(server, result, "1", "ip_mismatch")
    assert _restarts(result) == 0


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("cs: Name BDC1", "cs: Name BUILD1"),
        ("AD-Domain-Services       Installed", "AD-Domain-Services       Available"),
        ("NtpServer: 192.0.2.1,0x8 (Local)", "NtpServer: time.windows.com,0x9 (Local)"),
        ("dns client: 192.0.2.1", "dns client: "),
    ],
)
def test_stage_1_read_back_stops_on_a_deviation(server: Server, old: str, new: str) -> None:
    the_plan = _plan()
    _seed_done(server, the_plan, ["0"])
    _call(server, the_plan, "1", ops={"s1-base": _ok(_fixture("s1-base.txt"))})
    output = _fixture("s1-read.txt").replace(old, new)
    assert output != _fixture("s1-read.txt")
    result = _call(server, the_plan, "1", "status", ops={"s1-read": _ok(output)}, boot=BOOT_1)
    _stopped(server, result, "1", "readback_failed")


# ---------------------------------------------------------------------------
# stage 2
# ---------------------------------------------------------------------------


def test_stage_2_promotes_with_no_reboot_on_completion(server: Server) -> None:
    script = _render(server, _stage_values(server), ["s2-promote"])["s2-promote"]
    assert (
        "Install-ADDSForest -DomainName $DnsName -DomainNetbiosName $Netbios -ForestMode $Level"
        " -DomainMode $Level -InstallDns -SafeModeAdministratorPassword $sec -NoRebootOnCompletion -Force"
    ) in script
    assert "Remove-Item -LiteralPath $SecretFile" in script
    scripts = _render(server, _stage_values(server), ["s2-promote", "s2-groups", "s2-genid", "s2-read"])
    adders = [op for op, text in scripts.items() if "Add-ADGroupMember" in text]
    assert adders == ["s2-groups"]
    assert "foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') {" in scripts["s2-groups"]


CP = "pve:731:nb-stage2-20261113"


def test_stage_2_runs_through_both_reboots_until_the_generation_id(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    digest = plan.digest(the_plan)
    dsrm = plan.derive_secret(KEY_HEX, digest, plan.DSRM_INFO)

    # The run: the DSRM secret to its DPAPI file, the promotion in the
    # password task, the rebooting entry, the restart.  No group yet.
    result = _call(
        server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))}, checkpoint=CP, boot=BOOT_1
    )
    assert result["answer"]["status"] == "rebooting", result
    kinds = [c["kind"] for c in _calls(result)]
    assert kinds == ["op", "secret", "op", "secret-removed", "restart"]
    role = _calls(result)[0]
    assert role["op"] == "s2-role" and role["task"] is False
    assert _calls(result)[1]["secret"] == dsrm
    assert _calls(result)[1]["path"] == "C:\\NewtonBuild\\dsrm.bin"
    promote = _calls(result)[2]
    assert promote["op"] == "s2-promote" and promote["task"] is True
    assert dsrm not in promote["script"]
    assert _states(server, "2") == ["checkpointed", "started", "rebooting"]
    assert all(e["checkpoint"] == CP for e in server.journal() if e["stage"] == "2")

    # The first boot: the directory answers, the three groups are added
    # in the password task, then the second reboot.
    result = _call(
        server, the_plan, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))},
        checkpoint=CP, boot=BOOT_2,
    )
    assert result["answer"]["status"] == "rebooting", result
    assert [c["kind"] for c in _calls(result)] == ["wait", "op", "restart"]
    assert _ops_called(result) == ["s2-groups"]
    assert _calls(result)[1]["task"] is True
    assert _states(server, "2")[-1] == "rebooting"

    # The status before the second boot advances runs nothing.
    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_2)
    assert result["answer"]["status"] == "rebooting"
    assert result["calls"] == []

    # The second boot: msDS-GenerationId is absent, so one more reboot.
    result = _call(
        server, the_plan, "2", "status", ops={"s2-genid": _ok(_fixture("s2-genid-absent.txt"))},
        checkpoint=CP, boot=BOOT_3,
    )
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s2-genid"]
    assert _restarts(result) == 1

    # The third boot: present, then the read-back, then done.
    result = _call(
        server, the_plan, "2", "status",
        ops={"s2-genid": _ok(_fixture("s2-genid-present.txt")), "s2-read": _ok(_fixture("s2-read.txt"))},
        groups=_s4u_groups(), checkpoint=CP, boot=BOOT_4,
    )
    assert result["answer"]["status"] == "done", result
    assert result["answer"]["ok"] is True
    assert _ops_called(result) == ["s2-genid", "s2-read"]
    assert _restarts(result) == 0
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert set(checks) >= {
        "generation_id", "dcdiag", "sysvol", "netlogon", "srv", "levels", "forwarders",
        "memberships", "s4u_token",
    }
    assert all(c["ok"] for c in checks.values()), checks
    assert _states(server, "2")[-1] == "done"


def test_a_refused_restart_stops_the_stage(server: Server) -> None:
    """A restart that does not start leaves no stage waiting for a boot."""
    the_plan = _plan()
    _seed_done(server, the_plan, ["0"])
    result = _call(server, the_plan, "1", ops={"s1-base": _ok(_fixture("s1-base.txt"))}, restart=False)
    _stopped(server, result, "1", "error")
    assert _states(server, "1") == ["started", "rebooting", "stopped"]


def _stage2_at_second_boot(server: Server) -> dict[str, Any]:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))}, checkpoint=CP, boot=BOOT_1)
    _call(server, the_plan, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))}, checkpoint=CP, boot=BOOT_2)
    return the_plan


def test_stage_2_is_not_done_while_the_generation_id_is_absent(server: Server) -> None:
    """The stage reboots until msDS-GenerationId is there, then stops."""
    the_plan = _stage2_at_second_boot(server)
    absent = {"s2-genid": _ok(_fixture("s2-genid-absent.txt"))}
    boots = [BOOT_3, BOOT_4, BOOT_5]
    answers = []
    for boot in boots:
        result = _call(server, the_plan, "2", "status", ops=absent, checkpoint=CP, boot=boot)
        answers.append(result["answer"]["status"])
        assert "s2-read" not in _ops_called(result)
    assert answers[:-1] == ["rebooting", "rebooting"]
    assert answers[-1] == "stopped"
    _stopped(server, result, "2", "generation_id_missing")
    assert "done" not in _states(server, "2")


def test_stage_2_stops_when_the_s4u_token_lacks_a_group(server: Server) -> None:
    the_plan = _stage2_at_second_boot(server)
    groups = [g for g in _s4u_groups() if not g.endswith('-519","Mandatory group, Enabled by default, Enabled group"')]
    assert len(groups) == len(_s4u_groups()) - 1
    result = _call(
        server, the_plan, "2", "status",
        ops={"s2-genid": _ok(_fixture("s2-genid-present.txt")), "s2-read": _ok(_fixture("s2-read.txt"))},
        groups=groups, checkpoint=CP, boot=BOOT_3,
    )
    _stopped(server, result, "2", "readback_failed")


def test_stage_2_stops_when_the_directory_never_answers(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))}, checkpoint=CP, boot=BOOT_1)
    result = _call(server, the_plan, "2", "status", directory=False, checkpoint=CP, boot=BOOT_2)
    _stopped(server, result, "2", "directory_unready")
    assert _ops_called(result) == []


def test_stage_2_stops_when_the_promotion_fails(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    output = _fixture("s2-promote.txt").replace("Status         : Success", "Status         : Error")
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(output)}, checkpoint=CP, boot=BOOT_1)
    _stopped(server, result, "2", "op_failed")
    assert _restarts(result) == 0
    assert [c["kind"] for c in result["calls"]][-1] == "secret-removed"


def test_stage_2_stops_when_the_promotion_needs_no_reboot(server: Server) -> None:
    """Status Success without RebootRequired True is not the measured promotion.

    MEASURED-1.5 stage 2: -NoRebootOnCompletion returns Status Success and
    RebootRequired True.  A promotion that says no reboot is needed did
    not do what was measured, so the stage stops before any restart.
    """
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    measured = _fixture("s2-promote.txt")
    assert measured.count("RebootRequired : True\n") == 1
    output = measured.replace("RebootRequired : True\n", "RebootRequired : False\n")
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(output)}, checkpoint=CP, boot=BOOT_1)
    _stopped(server, result, "2", "op_failed")
    failed = [c for c in result["answer"]["checks"] if not c["ok"]]
    assert [c["name"] for c in failed] == ["promotion"]
    assert _restarts(result) == 0
    assert [c["kind"] for c in result["calls"]][-1] == "secret-removed"


def test_stage_2_stops_when_a_group_add_fails(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))}, checkpoint=CP, boot=BOOT_1)
    output = _fixture("s2-groups.txt").replace(", Schema Admins", "")
    result = _call(server, the_plan, "2", "status", ops={"s2-groups": _ok(output)}, checkpoint=CP, boot=BOOT_2)
    _stopped(server, result, "2", "op_failed")
    assert _restarts(result) == 0


def _verdict(server: Server, op: str, output: str, groups: list[str] | None = None) -> dict[str, Any]:
    out = server.drive(
        {
            "mode": "verdict",
            "op": op,
            "output": output,
            "values": _stage_values(server),
            "now": BASE,
            "nbf": NBF,
            "groups": groups or [],
        }
    )
    return out["verdict"]


def test_the_dcdiag_read_back_accepts_the_measured_fresh_forest(server: Server) -> None:
    """dcdiag exits 0 with DFSREvent and SystemLog failed: those two are accepted."""
    verdict = _verdict(server, "s2-read", _fixture("s2-read.txt"), _s4u_groups())
    dcdiag = [c for c in verdict["checks"] if c["name"] == "dcdiag"][0]
    assert dcdiag["ok"] is True, verdict
    assert verdict["code"] == ""


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("BDC1 passed test Replications", "BDC1 failed test Replications"),
        ("BDC1 passed test Advertising", ""),
        ("Schema passed test CheckSDRefDom", "Schema failed test CheckSDRefDom"),
    ],
)
def test_the_dcdiag_read_back_refuses_a_failed_or_missing_test(server: Server, old: str, new: str) -> None:
    output = _fixture("s2-read.txt").replace(old, new)
    assert output != _fixture("s2-read.txt")
    verdict = _verdict(server, "s2-read", output, _s4u_groups())
    dcdiag = [c for c in verdict["checks"] if c["name"] == "dcdiag"][0]
    assert dcdiag["ok"] is False
    assert verdict["code"] == "readback_failed"


@pytest.mark.parametrize(
    ("old", "new", "check"),
    [
        ("SYSVOLReady: 1", "SYSVOLReady: 0", "sysvol"),
        ("NETLOGON C:\\WINDOWS", "NOTNETLOGON C:\\WINDOWS", "netlogon"),
        ("_gc._tcp.build.newton.test -> bdc1.build.newton.test:3268", "_gc._tcp.build.newton.test -> other.build.newton.test:3268", "srv"),
        ("ForestMode Windows2025Forest", "ForestMode Windows2016Forest", "levels"),
        ("DNS forwarders: 192.0.2.1", "DNS forwarders: 192.0.2.53", "forwarders"),
        ("Domain Users, Enterprise Admins, Schema Admins", "Domain Users, Schema Admins", "memberships"),
    ],
)
def test_the_stage_2_read_back_refuses_each_deviation(server: Server, old: str, new: str, check: str) -> None:
    output = _fixture("s2-read.txt").replace(old, new)
    assert output != _fixture("s2-read.txt")
    verdict = _verdict(server, "s2-read", output, _s4u_groups())
    one = [c for c in verdict["checks"] if c["name"] == check][0]
    assert one["ok"] is False
    assert verdict["code"] == "readback_failed"


# ---------------------------------------------------------------------------
# stages 3 and 4
# ---------------------------------------------------------------------------


def test_stage_3_enables_the_recycle_bin_and_reads_its_scope(server: Server) -> None:
    script = _render(server, _stage_values(server), ["s3-recyclebin"])["s3-recyclebin"]
    assert (
        "Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet"
        " -Target $DnsName -Confirm:$false"
    ) in script
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    result = _call(
        server, the_plan, "3", ops={"s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))}, checkpoint="cp-3"
    )
    assert result["answer"]["status"] == "done", result
    assert _calls(result)[0]["task"] is True
    assert all(c["ok"] for c in result["answer"]["checks"])


def test_stage_3_stops_when_the_scope_is_not_there(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    output = _fixture("s3-recyclebin.txt").replace(
        "  CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test\n", ""
    )
    result = _call(server, the_plan, "3", ops={"s3-recyclebin": _ok(output)}, checkpoint="cp-3")
    _stopped(server, result, "3", "readback_failed")


def _s4_output() -> str:
    """The output of the s4-laps op itself, run on BDC1 (MEASURED-1.5,
    "Stage 4 on the Domain Controllers OU"): the self-permission set on
    ``OU=Domain Controllers`` and its SELF ACEs read back there."""
    return _fixture("s4-laps.txt")


#: The schemaIDGUIDs of two LAPS attributes in the two measured forests
#: (MEASURED-1.5): Update-LapsADSchema leaves the schemaIDGUID to the
#: directory, so each forest has its own.  The extended right's
#: rightsGuid is the same in both.
GUIDS_FIRST_FOREST = {
    "msLAPS-Password": "c2669bb2-4ab3-468b-87cd-ceb5b1de5011",
    "msLAPS-PasswordExpirationTime": "a2e8a763-9d06-46ae-addc-67f929ea585f",
}
GUIDS_SECOND_FOREST = {
    "msLAPS-Password": "e95aa6f5-1f87-4e83-a213-ff09e5941996",
    "msLAPS-PasswordExpirationTime": "9b5c1e57-ff56-4f14-9bd2-aa657d0390a9",
}
LAPS_RIGHT_GUID = "f3531ec6-6330-4f8e-8d39-7a671fbac605"


def test_the_two_measured_forests_have_their_own_laps_schema_guids() -> None:
    first = _fixture("s4-laps-newton-servers.txt")
    second = _fixture("s4-laps.txt")
    for name in GUIDS_FIRST_FOREST:
        assert f"lDAPDisplayName {name}, schemaIDGUID {GUIDS_FIRST_FOREST[name]}" in first
        assert f"lDAPDisplayName {name}, schemaIDGUID {GUIDS_SECOND_FOREST[name]}" in second
        assert GUIDS_FIRST_FOREST[name] != GUIDS_SECOND_FOREST[name]
    for text in (first, second):
        assert f"ObjectType {LAPS_RIGHT_GUID} ()" in text


def test_stage_4_reads_the_laps_guids_of_the_forest_it_built(server: Server) -> None:
    """The first forest's output passes the schema checks with its own GUIDs.

    Its self-permission was on a test OU, so its ACE check still fails:
    the ACEs are read only on the Domain Controllers OU.
    """
    verdict = _verdict(server, "s4-laps", _fixture("s4-laps-newton-servers.txt"))
    checks = {c["name"]: c["ok"] for c in verdict["checks"]}
    assert checks["laps_schema_before"] and checks["laps_schema"] and checks["laps_maycontain"], verdict
    assert checks["laps_ace"] is False
    assert verdict["code"] == "readback_failed"


def test_stage_4_holds_an_ace_to_the_schema_guid_the_same_output_read(server: Server) -> None:
    """An ACE whose ObjectType is another forest's GUID for the attribute is not the one set here."""
    measured = _s4_output()
    own = GUIDS_SECOND_FOREST["msLAPS-Password"]
    ace = f"ObjectType {own} (msLAPS-Password)"
    assert measured.count(ace) == 1
    output = measured.replace(ace, f"ObjectType {GUIDS_FIRST_FOREST['msLAPS-Password']} (msLAPS-Password)")
    verdict = _verdict(server, "s4-laps", output)
    one = [c for c in verdict["checks"] if c["name"] == "laps_ace"][0]
    assert one["ok"] is False
    assert verdict["code"] == "readback_failed"


def test_stage_4_refuses_a_laps_schema_read_without_a_guid(server: Server) -> None:
    output = _s4_output().replace(
        f"lDAPDisplayName msLAPS-Password, schemaIDGUID {GUIDS_SECOND_FOREST['msLAPS-Password']}",
        "lDAPDisplayName msLAPS-Password, schemaIDGUID ",
    )
    assert output != _s4_output()
    verdict = _verdict(server, "s4-laps", output)
    one = [c for c in verdict["checks"] if c["name"] == "laps_schema"][0]
    assert one["ok"] is False


def test_stage_4_refuses_two_laps_attributes_with_one_guid(server: Server) -> None:
    exp = GUIDS_SECOND_FOREST["msLAPS-PasswordExpirationTime"]
    output = _s4_output().replace(exp, GUIDS_SECOND_FOREST["msLAPS-Password"])
    assert output != _s4_output()
    verdict = _verdict(server, "s4-laps", output)
    one = [c for c in verdict["checks"] if c["name"] == "laps_schema"][0]
    assert one["ok"] is False


def test_stage_3_stops_when_the_recycle_bin_was_already_enabled(server: Server) -> None:
    """The read-back of the stage holds the state before it: none enabled."""
    output = _fixture("s3-recyclebin.txt").replace("before: EnabledScopes count 0 |", "before: EnabledScopes count 1 |")
    assert output != _fixture("s3-recyclebin.txt")
    verdict = _verdict(server, "s3-recyclebin", output)
    one = [c for c in verdict["checks"] if c["name"] == "recycle_bin_before"][0]
    assert one["ok"] is False
    assert verdict["code"] == "readback_failed"


def test_stage_4_removes_enterprise_and_schema_admins(server: Server) -> None:
    script = _render(server, _stage_values(server), ["s4-laps"])["s4-laps"]
    assert "Update-LapsADSchema -Confirm:$false -Verbose" in script
    assert "Set-LapsADComputerSelfPermission -Identity $ou" in script
    assert "foreach ($g in 'Enterprise Admins', 'Schema Admins') {" in script
    assert "Remove-ADGroupMember -Identity $g -Members $BuildUser -Confirm:$false" in script
    # Domain Admins stays: stage 9 removes it.
    removes = [line for line in script.splitlines() if "Remove-ADGroupMember" in line]
    assert len(removes) == 1 and "'Domain Admins'" not in removes[0]


def test_stage_4_reads_back_the_measured_schema_ace_and_memberships(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", "cp-4")
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint="cp-4")
    # The maintainer's decision, 2026-11-13: stage 4 ends with a reboot.
    assert result["answer"]["status"] == "rebooting", result
    assert _calls(result)[0]["task"] is True
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert set(checks) >= {"laps_schema", "laps_maycontain", "laps_legacy_absent", "laps_ace", "memberships"}
    assert all(c["ok"] for c in checks.values()), checks


@pytest.mark.parametrize(
    ("old", "new", "check"),
    [
        (
            "ms-LAPS-Password : present, lDAPDisplayName msLAPS-Password, schemaIDGUID e95aa6f5-1f87-4e83-a213-ff09e5941996",
            "ms-LAPS-Password : absent",
            "laps_schema",
        ),
        ("msLAPS-Password, msLAPS-PasswordExpirationTime\n", "msLAPS-Password\n", "laps_maycontain"),
        ("  ms-Mcs-AdmPwd : absent\n  computer mayContain msLAPS-*: msLAPS", "  ms-Mcs-AdmPwd : present, lDAPDisplayName ms-Mcs-AdmPwd, schemaIDGUID 00000000-0000-0000-0000-000000000001\n  computer mayContain msLAPS-*: msLAPS", "laps_legacy_absent"),
        (
            "NT AUTHORITY\\SELF | WriteProperty | Allow | ObjectType e95aa6f5-1f87-4e83-a213-ff09e5941996 (msLAPS-Password) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False",
            "NT AUTHORITY\\SELF | WriteProperty | Allow | ObjectType e95aa6f5-1f87-4e83-a213-ff09e5941996 (msLAPS-Password) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited True",
            "laps_ace",
        ),
        ("Get-ADPrincipalGroupMembership after: Administrators, Domain Admins, Domain Users", "Get-ADPrincipalGroupMembership after: Administrators, Domain Admins, Domain Users, Schema Admins", "memberships"),
        ("  Enterprise Admins members: Administrator\n", "  Enterprise Admins members: Administrator, newton-build\n", "memberships"),
        ("  Domain Admins members: Administrator, newton-build\n", "  Domain Admins members: Administrator\n", "memberships"),
        ("  ms-LAPS-EncryptedDSRMPassword : absent\n", "  ms-LAPS-EncryptedDSRMPassword : present, lDAPDisplayName msLAPS-EncryptedDSRMPassword, schemaIDGUID 9b06beb0-7501-4261-b3c2-a2c88c2e93c7\n", "laps_schema_before"),
        ("Set-LapsADComputerSelfPermission: OU=Domain Controllers,DC=build", "Set-LapsADComputerSelfPermission: OU=Newton Servers,DC=build", "laps_ace"),
        ("OU ACEs for SELF:\n", "OU ACEs for SELF (another OU):\n", "laps_ace"),
    ],
)
def test_stage_4_stops_on_each_deviation(server: Server, old: str, new: str, check: str) -> None:
    output = _s4_output().replace(old, new)
    assert output != _s4_output(), old
    verdict = _verdict(server, "s4-laps", output)
    one = [c for c in verdict["checks"] if c["name"] == check][0]
    assert one["ok"] is False
    assert verdict["code"] == "readback_failed"


def test_a_crlf_output_reads_like_the_lf_one(server: Server) -> None:
    """Out-File writes CRLF and a BOM; the parsers read the same lines."""
    output = "\ufeff" + _s4_output().replace("\n", "\r\n")
    verdict = _verdict(server, "s4-laps", output)
    assert verdict["code"] == "", verdict


# ---------------------------------------------------------------------------
# the secret and the guards
# ---------------------------------------------------------------------------


def test_the_helper_derives_the_dsrm_secret_of_the_plan_model(server: Server) -> None:
    digest = plan.digest(_plan())
    for info in [plan.DSRM_INFO, plan.ADMIN_INFO]:
        out = server.drive({"mode": "secret", "key": KEY_HEX, "digest": digest, "info": info})
        assert out["secret"] == plan.derive_secret(KEY_HEX, digest, info)


def _resume_of(first: dict[str, Any], start: str, *, secrets_from: str | None = None) -> dict[str, Any]:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(first)
    inputs["start_stage"] = start
    inputs["secrets_from"] = plan.digest(first) if secrets_from is None else secrets_from
    return _plan(inputs)


def test_a_resume_plans_promotion_installs_the_first_plans_dsrm(server: Server) -> None:
    """DESIGN-1.5 open point 71 (review finding 4 of task 8 part E): a
    resume plan that promotes DC1 derives the DSRM secret from its signed
    secrets_from, the first plan's digest, never from its own digest, so
    it is the one every approval of the build shows; every entry it writes
    records that salt."""
    first = _plan()
    _seed_done(server, first, ["0", "1"])
    resumed = _resume_of(first, "2")
    assert plan.digest(resumed) != plan.digest(first)
    server.append({"stage": "2", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP})
    result = _call(server, resumed, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1)
    assert result["answer"]["status"] == "rebooting", result
    written = [c["secret"] for c in result["calls"] if c["kind"] == "secret"]
    assert written == [plan.derive_secret(KEY_HEX, plan.digest(first), plan.DSRM_INFO)]
    assert plan.derive_secret(KEY_HEX, plan.digest(resumed), plan.DSRM_INFO) not in json.dumps(result)
    mine = [e for e in server.journal() if e["digest"] == plan.digest(resumed) and e["state"] != "checkpointed"]
    assert [e["state"] for e in mine] == ["started", "rebooting"]
    assert {e["secrets"] for e in mine} == {plan.digest(first)}


def test_a_first_plans_entries_record_its_own_digest_as_the_salt(server: Server) -> None:
    the_plan = _plan()
    _seed_done(server, the_plan, ["0"])
    result = _call(server, the_plan, "1", ops={"s1-base": _ok(_fixture("s1-base.txt"))}, boot=BOOT_0)
    assert result["answer"]["status"] == "rebooting", result
    mine = [e for e in server.journal() if e["stage"] == "1"]
    assert mine and {e["secrets"] for e in mine} == {plan.digest(the_plan)}


@pytest.mark.parametrize("recorded", ["digest", "field"])
def test_a_resume_plan_whose_secrets_from_is_not_the_runs_is_refused(server: Server, recorded: str) -> None:
    """The salt of the run is the one its journal records (the field, or
    the digest of an entry that has none): a resume plan that names another
    is plan_mismatch, before anything is run or written."""
    first = _plan()
    if recorded == "digest":
        _seed_done(server, first, ["0", "1"])
    else:
        digest = plan.digest(first)
        server.seed([{"stage": s, "state": st, "digest": digest, "secrets": "ef" * 32}
                     for s in ["0", "1"] for st in ["started", "done"]])
    wrong = _resume_of(first, "2", secrets_from="ab" * 32)
    before = server.journal()
    result = _call(server, wrong, "2", "checkpoint")
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "plan_mismatch"), result
    assert "secrets" in result["error"]
    assert server.journal() == before
    if recorded == "field":
        # the recorded salt, not the entry's digest, is the run's
        right = _resume_of(first, "2", secrets_from="ef" * 32)
        assert _call(server, right, "2", "checkpoint")["answer"].get("code") != "plan_mismatch"


def test_a_resume_of_a_resume_keeps_the_first_plans_salt(server: Server) -> None:
    """A second resume continues the first resume's digest and still names
    the first plan's: the salt the journal recorded under the first resume."""
    first = _plan()
    _seed_done(server, first, ["0"])
    second = _resume_of(first, "1")
    server.append({"stage": "1", "state": "started", "digest": plan.digest(second), "secrets": plan.digest(first)})
    server.append({"stage": "1", "state": "done", "digest": plan.digest(second), "secrets": plan.digest(first)})
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(second)
    inputs["start_stage"] = "2"
    inputs["secrets_from"] = plan.digest(second)
    wrong = _plan(inputs)
    result = _call(server, wrong, "2", "checkpoint")
    assert result["answer"]["code"] == "plan_mismatch", result
    inputs["secrets_from"] = plan.digest(first)
    right = _plan(inputs)
    result = _call(server, right, "2", "checkpoint")
    assert result["answer"].get("code") != "plan_mismatch", result


def _hand_plan_bytes(extra: dict[str, str], drop: tuple[str, ...] = ()) -> bytes:
    """Canonical plan bytes made by hand: a pair the plan model refuses."""
    lines = plan.canonical_bytes(_plan()).decode("ascii").splitlines()
    pairs = dict(line.split("=", 1) for line in lines[1:])
    for key in drop:
        pairs.pop(key, None)
    pairs.update(extra)
    text = "\n".join([lines[0]] + [f"{k}={pairs[k]}" for k in sorted(pairs)]) + "\n"
    return text.encode("ascii")


@pytest.mark.parametrize(
    "extra",
    [
        {"secrets_from": "ab" * 32},
        {"resume_from": "ab" * 32, "start_stage": "1"},
        {"resume_from": "ab" * 32, "start_stage": "1", "secrets_from": "AB" * 32},
        {"resume_from": "ab" * 32, "start_stage": "1", "secrets_from": "ab" * 31},
    ],
    ids=["secrets-from-alone", "resume-without-secrets-from", "upper-case", "short"],
)
def test_the_helper_refuses_plan_bytes_with_a_secrets_from_out_of_its_rule(server: Server, extra: dict[str, str]) -> None:
    raw = _hand_plan_bytes(extra)
    digest = hashlib.sha256(raw).hexdigest()
    request = json.dumps({"run": RUN, "plan": base64.b64encode(raw).decode("ascii"), "stage": "0", "action": "run",
                          "token": approval_token(KEY_HEX, digest, NBF, EXP), "nbf": NBF, "exp": EXP})
    result = server.drive({"mode": "request", "request": request,
                           "fake": {"ops": {}, "groups": [], "directory": True, "restart": True, "results": {},
                                    "running": []}})
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "schema"), result
    assert "secrets_from" in result["error"]
    assert _ops_called(result) == []
    assert server.journal() == []


def test_stage_10_still_has_no_template_in_the_helper(server: Server) -> None:
    """Stage 10 is the runner's, through newton-audit: the helper runs
    nothing there.  Stages 7, 8 and 9 have their own runs
    (test_build_stage7_helper.py, test_build_stage8_helper.py,
    test_build_stage9_helper.py); stages 5 and 6 are task 6,
    test_build_baseline.py."""
    the_plan = _plan()
    _seed_done(server, the_plan, ["0", "1", "2", "3", "4", "5", "6", "8", "9"])
    before = server.journal()
    result = _call(server, the_plan, "10")
    assert result["answer"]["code"] == "schema"
    assert "not built yet" in result["error"]
    assert server.journal() == before


# ---------------------------------------------------------------------------
# the password task (IC-open-2): a bounded start, and no kill on the limit
# ---------------------------------------------------------------------------


def _task(server: Server, *, start_at: float | None, run_for: float | None, result: int = 0,
          existing: str | None = None, wait: int | None = None,
          start_on_disable: bool = False, result_lag: float | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mode": "task",
        "op": "s3-recyclebin",
        "fake": {"task": {"start_at": start_at, "run_for": run_for, "result": result, "existing": existing,
                          "start_on_disable": start_on_disable, "result_lag": result_lag}},
    }
    if wait is not None:
        payload["wait"] = wait
    return server.drive(payload)


def _task_calls(out: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [c for c in out["calls"] if c["kind"] == kind]


def test_a_password_task_that_ends_reports_its_result(server: Server) -> None:
    """The measured shape: the task runs, ends with 0 and is unregistered."""
    out = _task(server, start_at=2, run_for=139, result=0)
    assert "error" not in out, out
    assert out["task"] == {"outcome": "ended", "result": 0, "found": ""}
    registered = _task_calls(out, "register")
    assert len(registered) == 1 and registered[0]["run_level"] == "Highest"
    assert _task_calls(out, "stop") == []
    assert [c["registered"] for c in _task_calls(out, "unregister")][-1] is True


@pytest.mark.parametrize("lag", [1, 3, 9])
def test_a_task_whose_result_lags_its_state_reports_the_real_result(server: Server, lag: float) -> None:
    """Measured (lab run 7, 2026-11-24, s7-provision on Server 2025): the task ended with 0 in 3 s, State read
    Ready while LastTaskResult still read 267009, and the helper reported exit 267009 (op_failed)."""
    out = _task(server, start_at=2, run_for=3, result=0, result_lag=lag)
    assert "error" not in out, out
    assert out["task"] == {"outcome": "ended", "result": 0, "found": ""}


def test_a_task_whose_result_never_settles_is_not_reported_as_success(server: Server) -> None:
    out = _task(server, start_at=2, run_for=3, result=0, result_lag=10_000)
    assert "error" not in out, out
    assert out["task"]["outcome"] == "ended" and out["task"]["result"] == 267009


def test_a_password_task_result_above_int32_is_the_signed_hresult(server: Server) -> None:
    """LastTaskResult is a UInt32: 0x80070005 is reported, not a cast error."""
    out = _task(server, start_at=2, run_for=5, result=0x80070005)
    assert "error" not in out, out
    assert out["task"] == {"outcome": "ended", "result": 0x80070005 - 2**32, "found": ""}


def test_a_password_task_that_never_starts_fails_fast(server: Server) -> None:
    """A task that stays at 267011 (has not run) is given up on within the
    start bound, not after the whole wait of 600 s, and is unregistered."""
    out = _task(server, start_at=None, run_for=None)
    assert "error" not in out, out
    assert out["clock"] <= 130, out["clock"]
    assert out["task"]["outcome"] == "not_started"
    assert _task_calls(out, "stop") == []
    assert [c["registered"] for c in _task_calls(out, "unregister")][-1] is True


def test_a_password_task_still_running_at_the_limit_is_left_to_finish(server: Server) -> None:
    """The overall limit never kills a running op: the task is neither
    stopped nor unregistered, and the outcome says it is still running."""
    out = _task(server, start_at=2, run_for=None)
    assert "error" not in out, out
    assert _task_calls(out, "stop") == []
    assert out["task"]["outcome"] == "running"
    after_start = [c for c in _task_calls(out, "unregister") if c["registered"]]
    assert after_start == []


def test_a_password_task_of_an_earlier_request_still_running_is_not_replaced(server: Server) -> None:
    """A task of that name still running from an earlier request is not
    unregistered, and no second task is registered over it."""
    out = _task(server, start_at=2, run_for=10, existing="Running")
    assert "still running" in out.get("error", ""), out
    assert _task_calls(out, "unregister") == []
    assert _task_calls(out, "register") == []
    assert _task_calls(out, "password") == []


# ---------------------------------------------------------------------------
# A session that drops while the password task runs
# ---------------------------------------------------------------------------

#: The op of each stage that runs in the password task, and its measured output.
#: Stage 4 is not here: since the maintainer's decision of 2026-11-13 it ends with a
#: reboot, and test_build_stage4_reboot.py holds its record path.
TASK_STAGES = {
    "3": ("s3-recyclebin", "s3-recyclebin.txt"),
}


def _drop_during(server: Server, the_plan: dict[str, Any], stage: str, op: str, cp: str, boot: str = BOOT_0) -> None:
    """Run the stage and drop the session while its op runs in the task."""
    ops: dict[str, dict[str, Any]] = {op: {"drop": True, "result": 0, "output": ""}}
    if stage == "2":
        ops.update(_role())
    dropped = _call(server, the_plan, stage, ops=ops, checkpoint=cp, boot=boot)
    assert dropped.get("dropped") is True, dropped
    assert _states(server, stage) == ["checkpointed", "started"]


@pytest.mark.parametrize("stage", sorted(TASK_STAGES))
def test_a_session_dropped_while_the_task_runs_is_recorded_by_status(server: Server, stage: str) -> None:
    """The task finishes after the helper's session dropped: a status
    request reads the op's own result file and writes the terminal entry
    the helper would have written, instead of answering started for ever."""
    op, fixture = TASK_STAGES[stage]
    the_plan = _plan()
    cp = f"cp-{stage}"
    _seed_before(server, the_plan, stage, cp)
    _drop_during(server, the_plan, stage, op, cp)

    result = _call(server, the_plan, stage, "status", checkpoint=cp, results={op: _ok(_fixture(fixture))})
    assert result["answer"]["status"] == "done", result
    assert result["answer"]["ok"] is True
    assert result["answer"]["checks"] and all(c["ok"] for c in result["answer"]["checks"])
    assert _states(server, stage) == ["checkpointed", "started", "done"]
    assert _ops_called(result) == []
    assert _kinds(result, "task-removed") == ["task-removed"]

    # Recorded once: a second status answers from the journal.
    again = _call(server, the_plan, stage, "status", checkpoint=cp, results={op: _ok(_fixture(fixture))})
    assert again["answer"]["status"] == "done"
    assert _states(server, stage) == ["checkpointed", "started", "done"]


def test_a_dropped_task_that_failed_stops_the_stage(server: Server) -> None:
    """The result file of a failed op is parsed like any output: stopped."""
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    _drop_during(server, the_plan, "3", "s3-recyclebin", "cp-3")
    failed = {"result": 1, "output": "task identity: nbuild\\newton-build | auth Kerberos\nFAIL: System.Exception: boom\n"}
    result = _call(server, the_plan, "3", "status", checkpoint="cp-3", results={"s3-recyclebin": failed})
    _stopped(server, result, "3", "op_failed")


def test_a_dropped_task_still_running_leaves_the_stage_started(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    _drop_during(server, the_plan, "3", "s3-recyclebin", "cp-3")
    result = _call(server, the_plan, "3", "status", checkpoint="cp-3", running=["s3-recyclebin"])
    assert result["answer"]["status"] == "started", result
    assert result["answer"]["checks"], result
    assert _states(server, "3") == ["checkpointed", "started"]
    assert _kinds(result, "task-state") == ["task-state"]
    assert _kinds(result, "read-result", "task-removed") == []


def test_a_dropped_task_with_no_result_file_stops_the_stage(server: Server) -> None:
    """The task is over and the op wrote no result file: it did not run
    to its end (or never ran), so the stage stops."""
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    _drop_during(server, the_plan, "3", "s3-recyclebin", "cp-3")
    result = _call(server, the_plan, "3", "status", checkpoint="cp-3")
    _stopped(server, result, "3", "op_failed")
    assert _kinds(result, "task-removed") == ["task-removed"]


def test_a_session_dropped_during_the_promotion_is_recorded_and_restarts(server: Server) -> None:
    """Stage 2: the promotion finished after the drop.  The status request
    records rebooting, restarts, and the stage goes on at the first boot."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _drop_during(server, the_plan, "2", "s2-promote", CP, boot=BOOT_1)

    result = _call(
        server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_1,
        results={"s2-promote": _ok(_fixture("s2-promote.txt"))},
    )
    assert result["answer"]["status"] == "rebooting", result
    assert _states(server, "2") == ["checkpointed", "started", "rebooting"]
    assert _restarts(result) == 1
    assert _kinds(result, "secret-removed") == ["secret-removed"]
    assert server.journal()[-1]["boot"] == BOOT_1

    result = _call(
        server, the_plan, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))},
        checkpoint=CP, boot=BOOT_2,
    )
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s2-groups"]


def test_a_promotion_that_failed_after_the_drop_does_not_restart(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _drop_during(server, the_plan, "2", "s2-promote", CP, boot=BOOT_1)
    output = _fixture("s2-promote.txt").replace("Status         : Success", "Status         : Error")
    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_1,
                   results={"s2-promote": _ok(output)})
    _stopped(server, result, "2", "op_failed")
    assert _restarts(result) == 0


def test_the_result_file_of_an_earlier_run_is_cleared_before_the_started_entry(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    before = len(server.journal())
    result = _call(
        server, the_plan, "3", ops={"s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))}, checkpoint="cp-3"
    )
    assert result["answer"]["status"] == "done", result
    clears = [c for c in result["calls"] if c["kind"] == "clear"]
    assert clears and clears[0]["op"] == "s3-recyclebin"
    assert clears[0]["journal"] == before


def test_every_op_writes_its_result_file_after_its_output(server: Server) -> None:
    """The op's last act: the exit code to <op>.rc, after the output file
    is closed, created new and flushed to the disk."""
    scripts = _render(server, _stage_values(server))
    for op, script in scripts.items():
        lines = script.splitlines()
        assert f"$ResultFile = 'C:\\NewtonBuild\\out\\{op}.rc'" in lines, op
        out = next(i for i, line in enumerate(lines) if "Out-File -FilePath $OutFile" in line)
        assert "[System.IO.FileMode]::CreateNew" in lines[out + 1], op
        assert "$resultStream.Flush($true)" in lines[out + 2], op
        assert lines[out + 3] == "exit $global:NewtonRc", op


# ---------------------------------------------------------------------------
# IC-open-2 through the stage: a task still running, a task never started
# ---------------------------------------------------------------------------


def test_a_task_still_running_at_the_limit_leaves_the_stage_started_then_status_records_it(
    server: Server,
) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    result = _call(
        server, the_plan, "3", ops={"s3-recyclebin": {"outcome": "running", "result": -1, "output": ""}},
        checkpoint="cp-3",
    )
    assert result["answer"]["status"] == "started", result
    assert _states(server, "3") == ["checkpointed", "started"]
    result = _call(server, the_plan, "3", "status", checkpoint="cp-3",
                   results={"s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))})
    assert result["answer"]["status"] == "done", result


def test_a_task_that_never_started_stops_the_stage(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    result = _call(
        server, the_plan, "3", ops={"s3-recyclebin": {"outcome": "not_started", "result": -1, "output": ""}},
        checkpoint="cp-3",
    )
    _stopped(server, result, "3", "op_failed")
    failed = [c for c in result["answer"]["checks"] if not c["ok"]]
    assert "did not start within 120 s" in failed[0]["detail"]


def test_a_post_boot_task_still_running_at_the_wait_limit_stops_the_stage_with_no_restart(server: Server) -> None:
    """The helper's own wait for s2-groups ends with the task still
    running: the stage stops op_failed and the server is not restarted
    (the task is not stopped: the fake records no stop)."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))}, checkpoint=CP, boot=BOOT_1)
    result = _call(
        server, the_plan, "2", "status", ops={"s2-groups": {"outcome": "running", "result": -1, "output": ""}},
        checkpoint=CP, boot=BOOT_2,
    )
    _stopped(server, result, "2", "op_failed")
    assert _restarts(result) == 0


def test_a_stage_whose_task_still_runs_from_an_earlier_request_is_refused(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    result = _call(
        server, the_plan, "3", ops={"s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))},
        checkpoint="cp-3", running=["s3-recyclebin"],
    )
    assert result["answer"]["status"] == "refused", result
    assert result["answer"]["code"] == "out_of_order"
    assert _states(server, "3") == ["checkpointed"]
    assert _ops_called(result) == []


# ---------------------------------------------------------------------------
# Stage 2 reads the role of the server before it promotes
# ---------------------------------------------------------------------------
#
# s2-role-workgroup.txt, s2-role-promoted.txt and s2-role-dc.txt are the
# output of the s2-role op on BUILD1 (MEASURED-1.5, "Stage 2 resumed: the
# role of the server"): after stage 1, after Install-ADDSForest with no
# reboot yet (DomainRole 3, ProductType LanmanNT, the NTDS parameters of
# the new forest, Get-ADDomain not answering), and after the first boot
# (DomainRole 5, Get-ADDomain answering).  s2-role-key-login.txt is the
# same op run over the newton-build S4U key login itself on the promoted
# DC, after the stage 4 boot (MEASURED-1.5 "Stage 4 reboot, 2026-11-13/14";
# IC-7): its lines equal s2-role-dc.txt's.

#: The measured Get-ADDomain line of a DC whose directory does not answer.
AD_DOWN = (
    "Get-ADDomain: FAIL Microsoft.ActiveDirectory.Management.ADServerDownException: "
    "Unable to find a default server with Active Directory Web Services running."
)

BOOT_6 = "2026-11-13T14:40:05.5000000Z"
BOOT_7 = "2026-11-13T14:50:05.5000000Z"
CP2 = "pve:731:nb-stage2-resume"


def _role_verdict(server: Server, output: str) -> dict[str, Any]:
    return _verdict(server, "s2-role", output)


def test_the_role_read_is_the_measured_op(server: Server) -> None:
    script = _render(server, _stage_values(server), ["s2-role"])["s2-role"]
    for needle in [
        "$cs = Get-CimInstance -ClassName Win32_ComputerSystem",
        "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions').ProductType",
        "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'",
        "$d = Get-ADDomain -ErrorAction Stop",
    ]:
        assert needle in script
    assert "Install-ADDSForest" not in script


def test_the_role_of_the_measured_workgroup_server_lets_the_promotion_run(server: Server) -> None:
    verdict = _role_verdict(server, _fixture("s2-role-workgroup.txt"))
    assert verdict["code"] == "", verdict
    assert verdict.get("promoted") is False


@pytest.mark.parametrize("name", ["s2-role-promoted.txt", "s2-role-dc.txt", "s2-role-key-login.txt"])
def test_the_measured_forest_root_of_the_plan_skips_the_promotion(server: Server, name: str) -> None:
    """Promoted and not rebooted yet (DomainRole 3!), or a DC after its
    boot: both are this plan's forest root, so the promotion is skipped."""
    verdict = _role_verdict(server, _fixture(name))
    assert verdict["code"] == "", verdict
    assert verdict.get("promoted") is True


def test_a_dc_whose_directory_does_not_answer_is_still_the_plan_root(server: Server) -> None:
    output = re.sub(r"(?m)^Get-ADDomain: .*$", AD_DOWN, _fixture("s2-role-dc.txt"))
    verdict = _role_verdict(server, output)
    assert verdict["code"] == "", verdict
    assert verdict.get("promoted") is True


def _other_domain(text: str) -> str:
    return (
        text.replace("Domain build.newton.test", "Domain other.newton.test")
        .replace("Root Domain DC=build,DC=newton,DC=test", "Root Domain DC=other,DC=newton,DC=test")
        .replace("DNSRoot build.newton.test", "DNSRoot other.newton.test")
    )


@pytest.mark.parametrize(
    ("name", "change", "code"),
    [
        # A DC (or a promoted server) of another domain.
        ("s2-role-dc.txt", _other_domain, "domain_mismatch"),
        ("s2-role-promoted.txt", _other_domain, "domain_mismatch"),
        # The DNS name of the plan with another NetBIOS name.
        ("s2-role-dc.txt", lambda t: t.replace("NetBIOSName NBUILD", "NetBIOSName NOTHER"), "domain_mismatch"),
        # Only one of the two reads says this forest: refused.
        (
            "s2-role-dc.txt",
            lambda t: t.replace("Root Domain DC=build,DC=newton,DC=test", "Root Domain DC=other,DC=newton,DC=test"),
            "domain_mismatch",
        ),
        # A member server of a domain: ServerNT, PartOfDomain True.
        (
            "s2-role-workgroup.txt",
            lambda t: t.replace(
                "DomainRole 2 | PartOfDomain False | Domain WORKGROUP | Workgroup WORKGROUP",
                "DomainRole 3 | PartOfDomain True | Domain corp.example.test | Workgroup ",
            ),
            "not_workgroup",
        ),
        # A workgroup server that holds NTDS parameters is not the
        # measured workgroup server.
        (
            "s2-role-workgroup.txt",
            lambda t: t.replace("NTDS Parameters: absent", "NTDS Parameters: present | Root Domain DC=build,DC=newton,DC=test | Machine DN Name x"),
            "not_workgroup",
        ),
    ],
)
def test_any_other_role_refuses_the_promotion(server: Server, name: str, change: Any, code: str) -> None:
    measured = _fixture(name)
    output = change(measured)
    assert output != measured
    verdict = _role_verdict(server, output)
    assert verdict["code"] == code, verdict
    assert verdict.get("promoted") is not True


def test_a_role_read_with_a_line_missing_stops(server: Server) -> None:
    output = "\n".join(l for l in _fixture("s2-role-dc.txt").splitlines() if not l.startswith("ProductType: "))
    verdict = _role_verdict(server, output)
    assert verdict["code"] == "readback_failed", verdict


@pytest.mark.parametrize(
    "old_new",
    [
        # The PartOfDomain field gone.
        (" | PartOfDomain False | ", " | "),
        # A DomainRole that is not one digit.
        ("DomainRole 2 |", "DomainRole 22 |"),
        # A PartOfDomain that is not True or False.
        ("PartOfDomain False", "PartOfDomain false"),
    ],
)
def test_a_role_read_with_a_malformed_cs_line_stops(server: Server, old_new: tuple[str, str]) -> None:
    """IC-1: the cs line is there but does not match its pattern: the
    role read stops readback_failed, and the server is never taken for
    one stage 2 may promote or skip."""
    old, new = old_new
    measured = _fixture("s2-role-workgroup.txt")
    assert measured.count(old) == 1
    verdict = _role_verdict(server, measured.replace(old, new))
    assert verdict["code"] == "readback_failed", verdict
    assert verdict.get("promoted") is not True
    assert [c["ok"] for c in verdict["checks"]] == [False]


def _render_calls(result: dict[str, Any]) -> list[str]:
    return [c["script"] for c in result["calls"] if c["kind"] == "op"]


@pytest.mark.parametrize(
    ("name", "change"),
    [
        ("dc", _other_domain),
        ("promoted", _other_domain),
        ("workgroup", lambda t: t.replace(
            "DomainRole 2 | PartOfDomain False | Domain WORKGROUP | Workgroup WORKGROUP",
            "DomainRole 3 | PartOfDomain True | Domain corp.example.test | Workgroup ",
        )),
    ],
)
def test_stage_2_on_a_server_of_another_role_stops_before_any_promotion(
    server: Server, name: str, change: Any
) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    output = change(_fixture(f"s2-role-{name}.txt"))
    result = _call(server, the_plan, "2", ops={"s2-role": _ok(output)}, checkpoint=CP, boot=BOOT_1)
    assert result["answer"]["status"] == "stopped", result
    assert result["answer"]["code"] in {"domain_mismatch", "not_workgroup"}
    assert _ops_called(result) == ["s2-role"]
    assert _kinds(result, "secret", "restart") == []
    assert all("Install-ADDSForest" not in s for s in _render_calls(result))


def _stop_refused_restart(server: Server, the_plan: dict[str, Any]) -> str:
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
          checkpoint=CP, boot=BOOT_1, restart=False)
    return BOOT_1


def _stop_groups_failed(server: Server, the_plan: dict[str, Any]) -> str:
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
          checkpoint=CP, boot=BOOT_1)
    output = _fixture("s2-groups.txt").replace(", Schema Admins", "")
    _call(server, the_plan, "2", "status", ops={"s2-groups": _ok(output)}, checkpoint=CP, boot=BOOT_2)
    return BOOT_2


def _stop_directory_unready(server: Server, the_plan: dict[str, Any]) -> str:
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
          checkpoint=CP, boot=BOOT_1)
    _call(server, the_plan, "2", "status", directory=False, checkpoint=CP, boot=BOOT_2)
    return BOOT_2


def _stop_generation_id_missing(server: Server, the_plan: dict[str, Any]) -> str:
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
          checkpoint=CP, boot=BOOT_1)
    _call(server, the_plan, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))},
          checkpoint=CP, boot=BOOT_2)
    absent = {"s2-genid": _ok(_fixture("s2-genid-absent.txt"))}
    for boot in [BOOT_3, BOOT_4, BOOT_5]:
        _call(server, the_plan, "2", "status", ops=absent, checkpoint=CP, boot=boot)
    return BOOT_5


def _stop_readback_failed(server: Server, the_plan: dict[str, Any]) -> str:
    _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
          checkpoint=CP, boot=BOOT_1)
    _call(server, the_plan, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))},
          checkpoint=CP, boot=BOOT_2)
    groups = [g for g in _s4u_groups() if "-519" not in g]
    _call(server, the_plan, "2", "status",
          ops={"s2-genid": _ok(_fixture("s2-genid-present.txt")), "s2-read": _ok(_fixture("s2-read.txt"))},
          groups=groups, checkpoint=CP, boot=BOOT_3)
    return BOOT_3


#: Each stop of stage 2 after a successful promotion, the reason it
#: stops with, and the role the server is in then.
STOPS = {
    "refused_restart": (_stop_refused_restart, "error", "s2-role-promoted.txt"),
    "groups_failed": (_stop_groups_failed, "op_failed", "s2-role-dc.txt"),
    "directory_unready": (_stop_directory_unready, "directory_unready", "ad-down"),
    "generation_id_missing": (_stop_generation_id_missing, "generation_id_missing", "s2-role-dc.txt"),
    "readback_failed": (_stop_readback_failed, "readback_failed", "s2-role-dc.txt"),
}


@pytest.mark.parametrize("stop", sorted(STOPS))
def test_a_resumed_stage_2_after_the_promotion_never_promotes_again(server: Server, stop: str) -> None:
    """A stage 2 that stopped after its promotion succeeded, resumed by a
    new plan (resume_from, start_stage 2), reads the role, finds this
    plan's forest root and goes on to the reboot and the post-promotion
    steps: Install-ADDSForest is never rendered and no DSRM file is
    written."""
    make_stop, reason, role = STOPS[stop]
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    boot = make_stop(server, the_plan)
    last = server.journal()[-1]
    assert (last["stage"], last["state"], last["reason"]) == ("2", "stopped", reason), last

    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "2"
    resumed = _plan(inputs)
    server.append({"stage": "2", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP2})

    if role == "ad-down":
        output = re.sub(r"(?m)^Get-ADDomain: .*$", AD_DOWN, _fixture("s2-role-dc.txt"))
    else:
        output = _fixture(role)
    result = _call(server, resumed, "2", ops={"s2-role": _ok(output)}, checkpoint=CP2, boot=boot)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s2-role"]
    assert all("Install-ADDSForest" not in s for s in _render_calls(result))
    assert _kinds(result, "secret") == []
    assert _restarts(result) == 1
    entries = [e for e in server.journal() if e["digest"] == plan.digest(resumed)]
    assert [e["state"] for e in entries] == ["checkpointed", "started", "rebooting"]

    # The post-promotion steps go on: the groups (Add-ADGroupMember of a
    # member that is there already answers ok, measured), then a reboot.
    result = _call(server, resumed, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))},
                   checkpoint=CP2, boot=BOOT_6)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s2-groups"]
    assert all("Install-ADDSForest" not in s for s in _render_calls(result))


def test_the_promotion_still_runs_on_the_measured_workgroup_server(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s2-role", "s2-promote"]
    names = [c["name"] for c in result["answer"]["checks"]]
    assert names[0] == "role"


# ---------------------------------------------------------------------------
# A template stage left started after its token's EXP
# ---------------------------------------------------------------------------
#
# The status record path writes the terminal entry of a stage whose
# session dropped while its op ran in the password task.  It records what
# already happened and never runs an op, so it has the bound a rebooting
# stage has: EXP plus PostBootGraceSeconds (DESIGN-1.5 "The helper").

GRACE = 900


def _recycle_ok() -> dict[str, dict[str, Any]]:
    return {"s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))}


def _dropped_stage_3(server: Server) -> dict[str, Any]:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    _drop_during(server, the_plan, "3", "s3-recyclebin", "cp-3")
    return the_plan


def _status_3(server: Server, the_plan: dict[str, Any], now: int, **fake: Any) -> dict[str, Any]:
    return _call(server, the_plan, "3", "status", checkpoint="cp-3", now=now, **fake)


@pytest.mark.parametrize("now", [EXP - 60, EXP])
def test_a_dropped_stage_3_is_recorded_by_a_status_before_its_exp(server: Server, now: int) -> None:
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, now, results=_recycle_ok())
    assert result["answer"]["status"] == "done", result
    assert _states(server, "3") == ["checkpointed", "started", "done"]
    assert _ops_called(result) == []


@pytest.mark.parametrize("now", [EXP + 1, EXP + GRACE // 2, EXP + GRACE])
def test_a_dropped_stage_3_is_recorded_after_its_exp_inside_the_grace(server: Server, now: int) -> None:
    """Past EXP the status still records the op's own result file: the
    journal does not stay started for ever.  No op runs."""
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, now, results=_recycle_ok())
    assert result["answer"]["status"] == "done", result
    assert result["answer"]["checks"] and all(c["ok"] for c in result["answer"]["checks"])
    assert _states(server, "3") == ["checkpointed", "started", "done"]
    assert _ops_called(result) == []
    assert _kinds(result, "task-removed") == ["task-removed"]


def test_after_exp_inside_the_grace_no_result_file_stops_the_stage(server: Server) -> None:
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, EXP + 300)
    _stopped(server, result, "3", "op_failed")
    assert _ops_called(result) == []


def test_after_exp_inside_the_grace_a_task_still_running_leaves_the_stage_started(server: Server) -> None:
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, EXP + 300, running=["s3-recyclebin"])
    assert result["answer"]["status"] == "started", result
    assert _states(server, "3") == ["checkpointed", "started"]
    assert _kinds(result, "read-result", "task-removed") == []


def test_after_exp_and_the_grace_the_result_file_is_still_recorded(server: Server) -> None:
    """Past the bound the op is over and its result file says what
    happened: that is recorded (the Recycle Bin is on; a resume reads the
    state first, s3-state, and is done on it), never left started."""
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, EXP + GRACE + 60, results=_recycle_ok())
    assert result["answer"]["status"] == "done", result
    assert _states(server, "3") == ["checkpointed", "started", "done"]
    assert _ops_called(result) == []


def test_after_exp_and_the_grace_a_failed_result_file_stops_with_its_code(server: Server) -> None:
    the_plan = _dropped_stage_3(server)
    failed = {"result": 1, "output": "task identity: nbuild\\newton-build | auth Kerberos\nFAIL: System.Exception: boom\n"}
    result = _status_3(server, the_plan, EXP + GRACE + 60, results={"s3-recyclebin": failed})
    _stopped(server, result, "3", "op_failed")


def test_after_exp_and_the_grace_no_result_file_stops_grace_passed(server: Server) -> None:
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, EXP + GRACE + 60)
    _stopped(server, result, "3", "grace_passed")
    assert _ops_called(result) == []
    assert _kinds(result, "task-removed") == ["task-removed"]


def test_after_exp_and_the_grace_a_task_still_running_is_refused_and_named(server: Server) -> None:
    """The task still runs past the bound: the answer is a refusal that
    names it, never done, and nothing is written; once the task is over
    the next status stops the stage, so the journal does not stay
    started."""
    the_plan = _dropped_stage_3(server)
    result = _status_3(server, the_plan, EXP + GRACE + 60, running=["s3-recyclebin"])
    answer = result["answer"]
    assert (answer["ok"], answer["status"], answer["code"]) == (False, "refused", "expired"), result
    assert any("NewtonBuild-s3-recyclebin" in c["detail"] for c in answer["checks"]), answer
    assert _states(server, "3") == ["checkpointed", "started"]
    assert _kinds(result, "read-result", "task-removed") == []

    result = _status_3(server, the_plan, EXP + GRACE + 600)
    _stopped(server, result, "3", "grace_passed")


def test_a_stage_2_promotion_recorded_after_exp_inside_the_grace_reboots(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _drop_during(server, the_plan, "2", "s2-promote", CP, boot=BOOT_1)
    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_1, now=EXP + 300,
                   results={"s2-promote": _ok(_fixture("s2-promote.txt"))})
    assert result["answer"]["status"] == "rebooting", result
    assert _states(server, "2") == ["checkpointed", "started", "rebooting"]
    assert _restarts(result) == 1
    assert _ops_called(result) == []


def test_a_stage_2_promotion_recorded_after_the_grace_stops_with_no_restart(server: Server) -> None:
    """Past the bound a rebooting entry could never be completed (its
    post-boot work is refused past EXP plus the grace), so the promotion's
    result is recorded as a stop and the server is not restarted."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _drop_during(server, the_plan, "2", "s2-promote", CP, boot=BOOT_1)
    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_1, now=EXP + GRACE + 60,
                   results={"s2-promote": _ok(_fixture("s2-promote.txt"))})
    _stopped(server, result, "2", "grace_passed")
    assert _restarts(result) == 0
    assert _ops_called(result) == []
    assert any(c["name"] == "promotion" and c["ok"] for c in result["answer"]["checks"]), result
    assert _kinds(result, "secret-removed") == ["secret-removed"]


@pytest.mark.parametrize("now", [EXP + 1, EXP + GRACE + 60])
def test_the_record_bound_opens_nothing_else_after_exp(server: Server, now: int) -> None:
    """Only a status of a template stage left started gets the bound: a
    run of it, a status of a stage that is pending or done, and a status
    of a stage left started that has no password task are refused
    expired and write nothing."""
    the_plan = _dropped_stage_3(server)
    before = server.journal()
    run = _call(server, the_plan, "3", ops=_recycle_ok(), checkpoint="cp-3", now=now)
    assert (run["answer"]["status"], run["answer"]["code"]) == ("refused", "expired"), run
    assert _ops_called(run) == []
    done = _call(server, the_plan, "1", "status", now=now)
    assert (done["answer"]["status"], done["answer"]["code"]) == ("refused", "expired"), done
    server.append({"stage": "4", "state": "checkpointed", "digest": plan.digest(the_plan), "checkpoint": "cp-4"})
    before = server.journal()
    pending = _call(server, the_plan, "4", "status", checkpoint="cp-4", now=now)
    assert (pending["answer"]["status"], pending["answer"]["code"]) == ("refused", "expired"), pending
    assert server.journal() == before

    # Stage 1 left started (its op runs in the helper's own session).
    digest = plan.digest(the_plan)
    fresh = Server(server.root.parent / "fresh")
    fresh.seed([
        {"stage": "0", "state": "started", "digest": digest},
        {"stage": "0", "state": "done", "digest": digest},
        {"stage": "1", "state": "started", "digest": digest},
    ])
    stage_1 = _call(fresh, the_plan, "1", "status", now=now, results={"s1-base": _ok("")})
    assert (stage_1["answer"]["status"], stage_1["answer"]["code"]) == ("refused", "expired"), stage_1
    assert _states(fresh, "1") == ["started"]


# ---------------------------------------------------------------------------
# The run path's wait for its task ends inside the token window
# ---------------------------------------------------------------------------


def _task_waits(result: dict[str, Any]) -> list[int]:
    return [c["wait"] for c in result["calls"] if c["kind"] == "op" and c["task"]]


def test_the_run_path_waits_ten_minutes_for_its_task_with_the_window_open(server: Server) -> None:
    """The longest measured task is the promotion, 139 to 144 s
    (MEASURED-1.5); the wait is 600 s, inside the 30-minute stage token."""
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    result = _call(server, the_plan, "3", ops=_recycle_ok(), checkpoint="cp-3", now=BASE)
    assert result["answer"]["status"] == "done", result
    assert _task_waits(result) == [600]


@pytest.mark.parametrize("left", [400, 31, 30, 0])
def test_the_run_path_wait_ends_before_the_exp_of_its_token(server: Server, left: int) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    now = EXP - left
    result = _call(server, the_plan, "3", ops=_recycle_ok(), checkpoint="cp-3", now=now)
    assert result["answer"]["status"] == "done", result
    waits = _task_waits(result)
    assert len(waits) == 1
    assert 0 <= waits[0] <= max(0, left - 30), waits


def test_the_promotion_wait_ends_before_the_exp_of_its_token(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1, now=EXP - 250)
    assert result["answer"]["status"] == "rebooting", result
    assert _task_waits(result) == [220]


def test_the_stage_4_wait_ends_before_the_exp_of_its_token(server: Server) -> None:
    """A review, T1: the clamp at the s4-laps call site itself.  Without
    -WaitSeconds the task would be waited for 600 s, past the token."""
    the_plan = _plan()
    _seed_before(server, the_plan, "4", "cp-4")
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint="cp-4", now=EXP - 200)
    assert _task_waits(result) == [170], result


#: A review, T4: the least token time a stage 2 run starts with.  The
#: longest measured promotion took 144 s from the helper's call (139 s
#: and 142 s in the other runs; MEASURED-1.5 "The ops of stages 0 to 4"
#: and "Stage 2 resumed"), and s2-role runs before it (9 s in a task);
#: 180 s holds both with room, plus the 30 s answer margin.
PROMOTION_MINIMUM = 180 + 30


@pytest.mark.parametrize("left", [PROMOTION_MINIMUM - 1, 100, 30, 0])
def test_a_stage_2_run_with_too_little_token_left_is_refused_before_anything_starts(
    server: Server, left: int
) -> None:
    """No promotion starts that its run cannot answer for inside the
    token, so dsrm.bin is never deleted under a starting promotion."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    before = server.journal()
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1, now=EXP - left)
    answer = result["answer"]
    assert (answer["ok"], answer["status"], answer["code"]) == (False, "refused", "window_short"), result
    assert result["calls"] == []
    assert server.journal() == before


def test_a_stage_2_run_with_the_minimum_left_runs(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1, now=EXP - PROMOTION_MINIMUM)
    assert result["answer"]["status"] == "rebooting", result
    assert _task_waits(result) == [PROMOTION_MINIMUM - 30]


def test_the_promotion_wait_is_computed_after_the_role_read(server: Server) -> None:
    """A review, T5: the seconds s2-role takes come out of the wait, not
    out of the 30 s answer margin."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    role = {"s2-role": {**_ok(_fixture("s2-role-workgroup.txt")), "advance": 40}}
    result = _call(server, the_plan, "2", ops={**role, "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1, now=EXP - 400)
    assert result["answer"]["status"] == "rebooting", result
    assert _task_waits(result) == [400 - 40 - 30]


def test_a_password_task_never_waits_as_long_as_a_stage_token(server: Server) -> None:
    out = _task(server, start_at=2, run_for=None)
    assert out["task"]["outcome"] == "running"
    assert 600 <= out["clock"] <= 610, out["clock"]
    assert out["clock"] < 1800


@pytest.mark.parametrize(("start_at", "outcome"), [(2, "running"), (None, "not_started")])
def test_a_password_task_waits_no_longer_than_it_is_given(
    server: Server, start_at: float | None, outcome: str
) -> None:
    out = _task(server, start_at=start_at, run_for=None, wait=50)
    assert "error" not in out, out
    assert out["task"]["outcome"] == outcome
    assert out["clock"] <= 52, out["clock"]


# ---------------------------------------------------------------------------
# Nit: the not_started give-up and a task that starts at that moment
# ---------------------------------------------------------------------------


def test_a_task_that_starts_as_the_helper_gives_up_is_waited_for(server: Server) -> None:
    """The task starts between the last poll and the give-up: the helper
    disables it first (a disabled task cannot start), reads it again, finds
    it running and waits for it, so an op that ran is never reported as
    one that did not start."""
    out = _task(server, start_at=None, run_for=10, result=0, start_on_disable=True)
    assert "error" not in out, out
    assert out["task"]["outcome"] == "ended", out
    assert out["task"]["result"] == 0
    kinds = [c["kind"] for c in out["calls"] if c["kind"] in {"disable", "unregister"}]
    assert kinds[0] == "disable"


def test_a_task_that_never_starts_is_disabled_then_unregistered_and_reported(server: Server) -> None:
    out = _task(server, start_at=None, run_for=None)
    assert out["task"]["outcome"] == "not_started", out
    kinds = [c["kind"] for c in out["calls"] if c["kind"] in {"disable", "unregister"}]
    assert kinds == ["disable", "unregister"]
    found = out["task"]["found"]
    assert "267011" in found and "no task" in found, found


def test_the_stage_reports_what_the_give_up_found(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", "cp-3")
    ran = {"outcome": "not_started", "result": -1, "output": "",
           "found": "disabled, it had not run (LastTaskResult 267011); after the unregister: no task"}
    result = _call(server, the_plan, "3", ops={"s3-recyclebin": ran}, checkpoint="cp-3")
    _stopped(server, result, "3", "op_failed")
    failed = [c for c in result["answer"]["checks"] if not c["ok"]]
    assert "after the unregister: no task" in failed[0]["detail"], failed


# ---------------------------------------------------------------------------
# IC-3: the record path records only the plan the stage started under
# ---------------------------------------------------------------------------


def test_a_resume_plan_status_does_not_record_the_stage_started_under_the_run_plan(server: Server) -> None:
    """Stage 2 started under plan A and its session dropped.  A status
    under resume plan B must not record A's promotion as B's: it is
    refused plan_mismatch and writes nothing; B's own run then reads the
    role first and takes the forest root of the plan through it."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    _drop_during(server, the_plan, "2", "s2-promote", CP, boot=BOOT_1)

    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "2"
    resumed = _plan(inputs)
    server.append({"stage": "2", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP2})
    before = server.journal()

    result = _call(server, resumed, "2", "status", checkpoint=CP2, boot=BOOT_1,
                   results={"s2-promote": _ok(_fixture("s2-promote.txt"))})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "plan_mismatch"), result
    assert "another plan" in result.get("error", ""), result
    assert server.journal() == before
    assert _restarts(result) == 0
    assert _kinds(result, "read-result", "task-removed") == []

    result = _call(server, resumed, "2", ops={"s2-role": _ok(_fixture("s2-role-promoted.txt"))},
                   checkpoint=CP2, boot=BOOT_1)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s2-role"]


# ---------------------------------------------------------------------------
# IC-4: a session that drops while a post-boot op runs in its task
# ---------------------------------------------------------------------------

POST_BOOT_OPS = ["s2-groups", "s2-genid", "s2-read"]


def _stage_2_rebooting(server: Server) -> dict[str, Any]:
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1)
    assert result["answer"]["status"] == "rebooting", result
    return the_plan


def _drop_post_boot(server: Server, the_plan: dict[str, Any], ops: dict[str, dict[str, Any]], boot: str) -> None:
    before = server.journal()
    dropped = _call(server, the_plan, "2", "status", ops=ops, checkpoint=CP, boot=boot,
                    groups=_s4u_groups())
    assert dropped.get("dropped") is True, dropped
    assert server.journal() == before


def test_the_post_boot_result_files_are_cleared_before_each_rebooting_entry(server: Server) -> None:
    """A result file of a post-boot op is one of this boot: stage 2
    clears all three before it writes rebooting and restarts."""
    the_plan = _plan()
    _seed_before(server, the_plan, "2", CP)
    before = len(server.journal())
    result = _call(server, the_plan, "2", ops={**_role(), "s2-promote": _ok(_fixture("s2-promote.txt"))},
                   checkpoint=CP, boot=BOOT_1)
    assert result["answer"]["status"] == "rebooting", result
    clears = {c["op"]: c["journal"] for c in result["calls"] if c["kind"] == "clear" and c["op"] in POST_BOOT_OPS}
    # The started entry is at `before`; the rebooting entry comes after the clears.
    assert clears == {op: before + 1 for op in POST_BOOT_OPS}, result["calls"]


def test_a_status_while_an_earlier_s2_groups_task_runs_is_in_progress_then_records(server: Server) -> None:
    the_plan = _stage_2_rebooting(server)
    _drop_post_boot(server, the_plan, {"s2-groups": {"drop": True}}, BOOT_2)

    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_2, running=["s2-groups"])
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "rebooting"), result
    assert any(c["name"] == "s2-groups" and "still runs" in c["detail"] for c in result["answer"]["checks"])
    assert _states(server, "2") == ["checkpointed", "started", "rebooting"]
    assert _ops_called(result) == [] and _restarts(result) == 0

    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_2,
                   results={"s2-groups": _ok(_fixture("s2-groups.txt"))})
    assert result["answer"]["status"] == "rebooting", result
    assert _states(server, "2") == ["checkpointed", "started", "rebooting", "rebooting"]
    assert _ops_called(result) == []
    assert _restarts(result) == 1


def _stage_2_at_second_boot(server: Server) -> dict[str, Any]:
    the_plan = _stage_2_rebooting(server)
    result = _call(server, the_plan, "2", "status", ops={"s2-groups": _ok(_fixture("s2-groups.txt"))},
                   checkpoint=CP, boot=BOOT_2)
    assert result["answer"]["status"] == "rebooting", result
    return the_plan


def test_a_status_while_an_earlier_s2_genid_task_runs_is_in_progress_then_records(server: Server) -> None:
    the_plan = _stage_2_at_second_boot(server)
    _drop_post_boot(server, the_plan, {"s2-genid": {"drop": True}}, BOOT_3)

    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_3, running=["s2-genid"])
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "rebooting"), result
    assert _ops_called(result) == []

    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_3, groups=_s4u_groups(),
                   results={"s2-genid": _ok(_fixture("s2-genid-present.txt"))},
                   ops={"s2-read": _ok(_fixture("s2-read.txt"))})
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == ["s2-read"]


def test_a_status_while_an_earlier_s2_read_task_runs_is_in_progress_then_records(server: Server) -> None:
    the_plan = _stage_2_at_second_boot(server)
    _drop_post_boot(server, the_plan, {"s2-genid": _ok(_fixture("s2-genid-present.txt")),
                                        "s2-read": {"drop": True}}, BOOT_3)

    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_3, running=["s2-read"])
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "rebooting"), result
    assert _states(server, "2")[-1] == "rebooting"

    result = _call(server, the_plan, "2", "status", checkpoint=CP, boot=BOOT_3, groups=_s4u_groups(),
                   results={"s2-genid": _ok(_fixture("s2-genid-present.txt")),
                            "s2-read": _ok(_fixture("s2-read.txt"))})
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == []
    assert _states(server, "2")[-1] == "done"


@pytest.mark.parametrize("op", POST_BOOT_OPS)
def test_a_resumed_stage_2_is_refused_while_a_post_boot_task_still_runs(server: Server, op: str) -> None:
    """A review: stage 2 stopped while a post-boot task still ran
    (its wait ended): a resume plan's run of stage 2 must not read the
    role, clear the post-boot result files and restart the server over
    that task.  It is refused out_of_order and writes nothing."""
    the_plan = _stage_2_rebooting(server)
    result = _call(server, the_plan, "2", "status", ops={"s2-groups": {"outcome": "running", "result": -1, "output": ""}},
                   checkpoint=CP, boot=BOOT_2)
    _stopped(server, result, "2", "op_failed")

    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "2"
    resumed = _plan(inputs)
    server.append({"stage": "2", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP2})
    before = server.journal()

    result = _call(server, resumed, "2", ops={"s2-role": _ok(_fixture("s2-role-dc.txt"))},
                   checkpoint=CP2, boot=BOOT_2, running=[op])
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result
    assert op in result.get("error", ""), result
    assert server.journal() == before
    assert _ops_called(result) == [] and _restarts(result) == 0
    assert [c for c in result["calls"] if c["kind"] == "clear"] == []
