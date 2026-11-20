# The probe of the undo task the Windows write helper registers.
#
# The real scheduler adapter of write.ps1 talks to the COM scheduler of the
# domain controller.  This probe dot-sources write.ps1, puts a local object
# in place of that COM service (New-Object -ComObject is shadowed here, every
# other New-Object goes to the real cmdlet), calls the REAL Register method
# of the adapter, and reports the task definition it registered.  No
# scheduler, no host and no socket is used.
#
#     pwsh -NoProfile -File win_write_undo_task_probe.ps1
#
# The answer is one JSON object on stdout.

param()

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$mcpRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $mcpRoot 'newton_mcp/ad/collector/write.ps1')

$script:Registered = New-Object System.Collections.ArrayList

function New-NewtonProbeObject {
    param([hashtable]$Properties)
    return [pscustomobject]$Properties
}

function New-NewtonProbeService {
    $service = New-NewtonProbeObject @{ Connected = $false }
    $service | Add-Member -MemberType ScriptMethod -Name Connect -Value {
        $this.Connected = $true
    }
    $service | Add-Member -MemberType ScriptMethod -Name NewTask -Value {
        param([int]$Flags)
        $actions = New-NewtonProbeObject @{ Items = (Microsoft.PowerShell.Utility\New-Object System.Collections.ArrayList) }
        $actions | Add-Member -MemberType ScriptMethod -Name Create -Value {
            param([int]$Type)
            $action = [pscustomobject]@{ Type = $Type; Path = ''; Arguments = '' }
            [void]$this.Items.Add($action)
            return $action
        }
        $triggers = New-NewtonProbeObject @{ Items = (Microsoft.PowerShell.Utility\New-Object System.Collections.ArrayList) }
        $triggers | Add-Member -MemberType ScriptMethod -Name Create -Value {
            param([int]$Type)
            $trigger = [pscustomobject]@{ Type = $Type; Enabled = $false; StartBoundary = '' }
            [void]$this.Items.Add($trigger)
            return $trigger
        }
        return [pscustomobject]@{
            Principal = [pscustomobject]@{ LogonType = 0 }
            Settings = [pscustomobject]@{ Enabled = $false; StartWhenAvailable = $false }
            Actions = $actions
            Triggers = $triggers
        }
    }
    $service | Add-Member -MemberType ScriptMethod -Name GetFolder -Value {
        param([string]$Path)
        $folder = [pscustomobject]@{ Path = $Path }
        $folder | Add-Member -MemberType ScriptMethod -Name RegisterTaskDefinition -Value {
            param($Name, $Definition, $Flags, $User, $Password, $LogonType)
            [void]$script:Registered.Add([pscustomobject]@{
                Name = $Name; Definition = $Definition; Flags = $Flags; LogonType = $LogonType
            })
            return $null
        }
        return $folder
    }
    return $service
}

# Only the COM scheduler is replaced; every other New-Object is the cmdlet.
function New-Object {
    param(
        [Parameter(Position = 0)][string]$TypeName,
        [Parameter(Position = 1)][object[]]$ArgumentList,
        [string]$ComObject
    )
    if ($ComObject -eq 'Schedule.Service') { return New-NewtonProbeService }
    if ($ComObject) { throw "the probe knows no COM object $ComObject" }
    if ($null -ne $ArgumentList) {
        return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
    }
    return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
}

$adapter = New-NewtonSchedulerAdapter
$adapter.Register('NewtonUndo-probe', '2027-01-01T00:10:00Z', '-NoProfile -File write.ps1 -Undo probe')

$out = @()
foreach ($one in $script:Registered) {
    $definition = $one.Definition
    $out += [ordered]@{
        name = [string]$one.Name
        start_when_available = [bool]$definition.Settings.StartWhenAvailable
        enabled = [bool]$definition.Settings.Enabled
        trigger_types = @($definition.Triggers.Items | ForEach-Object { [int]$_.Type })
        start_boundary = @($definition.Triggers.Items | ForEach-Object { [string]$_.StartBoundary })
    }
}
[Console]::Out.Write((@{ registered = $out } | ConvertTo-Json -Depth 6 -Compress) + "`n")
