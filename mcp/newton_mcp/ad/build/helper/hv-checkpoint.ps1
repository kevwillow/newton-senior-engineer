# hv-checkpoint.ps1: the forced command of the hv-checkpoint login on the Hyper-V host (PLAN-1.5 task 7,
# DESIGN-1.5 "Checkpoints", Hyper-V; MEASURED-1.5 section 4).
#
# sshd runs this script for every login of the account and hands it the client's words in SSH_ORIGINAL_COMMAND.
# It answers exactly two commands, for the VMs named in its allowlist file (one VM name per line):
#
#   create <vm> <name>   sets the VM's checkpoint type to ProductionOnly, takes the checkpoint <name> and answers it
#                        as one JSON object;
#   list <vm>            answers every checkpoint of the VM as a JSON array, oldest first (an array even for one).
#
# Each checkpoint is {name, id, created (UTC, to the second), vm, checkpoint_type (the VM's own CheckpointType:
# Get-VMSnapshot's SnapshotType says Standard for a production checkpoint too, so it is not the type)}.
# Anything else answers "refused" (exit 1) before any Hyper-V cmdlet runs; a cmdlet that fails answers "failed"
# (exit 2).  The account's rights are wider than this script (Hyper-V Administrators can restore, delete and change
# VMs): this script is the boundary, as the build helper is for newton-build.

param([string]$AllowlistPath = (Join-Path $PSScriptRoot 'vm.txt'))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The words of a request: a VM name and a checkpoint name are letters, digits, '.', '_' and '-' (a checkpoint name
# no '.'), starting with a letter or a digit; one space between words, nothing before or after.
$script:RequestPattern = '\A(?:(?<verb>create) (?<vm>[A-Za-z0-9][A-Za-z0-9._-]{0,63}) (?<name>[A-Za-z0-9][A-Za-z0-9_-]{0,63})|(?<verb>list) (?<vm>[A-Za-z0-9][A-Za-z0-9._-]{0,63}))\z'

function Write-NewtonAnswer([string]$Text, [int]$Code) {
    [Console]::Out.Write($Text + "`n")
    [Console]::Out.Flush()
    exit $Code
}

function Get-NewtonAllowlist([string]$Path) {
    # The allowlist: one VM name per line, compared exactly (case and all).  A missing or unreadable file allows
    # nothing.  The guard is the exact -ccontains match below against a VM name the request pattern already
    # constrains; this line filter only keeps odd lines out of the list and is not itself a guard (task 7 triage S10).
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $names = @()
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $name = $line.Trim()
        if ($name -cmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') { $names += $name }
    }
    return $names
}

function ConvertTo-NewtonCheckpoint($Snapshot, $Vm) {
    $created = ([datetime]$Snapshot.CreationTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    return [ordered]@{
        name = [string]$Snapshot.Name
        id = ([guid]$Snapshot.Id).ToString('D')
        created = $created
        vm = [string]$Vm.Name
        checkpoint_type = [string]$Vm.CheckpointType
    }
}

function Get-NewtonVm([string]$Name) {
    $found = @(Get-VM -Name $Name | Where-Object { $_.Name -ceq $Name })
    if ($found.Count -ne 1) { throw 'the VM is not exactly one VM' }
    return $found[0]
}

function Get-NewtonSnapshots {
    # The VM object, never its name: the Hyper-V cmdlets match -Name without case and with wildcards.
    param($Vm)
    return @(Get-VMSnapshot -VM $Vm | Where-Object { $_.VMName -ceq $Vm.Name } | Sort-Object -Property CreationTime)
}

$command = [string]$env:SSH_ORIGINAL_COMMAND
$m = [regex]::Match($command, $script:RequestPattern)
if (-not $m.Success) { Write-NewtonAnswer 'refused' 1 }
$verb = $m.Groups['verb'].Value
$vmName = $m.Groups['vm'].Value
if (-not ((Get-NewtonAllowlist $AllowlistPath) -ccontains $vmName)) { Write-NewtonAnswer 'refused' 1 }

if ($verb -ceq 'list') {
    try {
        $vm = Get-NewtonVm $vmName
        $listed = @(Get-NewtonSnapshots $vm | ForEach-Object { ConvertTo-NewtonCheckpoint $_ $vm })
        $json = ConvertTo-Json -InputObject @($listed) -Compress -Depth 3
    } catch {
        Write-NewtonAnswer 'failed' 2
    }
    Write-NewtonAnswer $json 0
}

$name = $m.Groups['name'].Value
try {
    $vm = Get-NewtonVm $vmName
    $taken = @(Get-NewtonSnapshots $vm | Where-Object { $_.Name -ceq $name })
} catch {
    Write-NewtonAnswer 'failed' 2
}
# One checkpoint per name: a second one of the same name would make the list ambiguous.
if ($taken.Count -ne 0) { Write-NewtonAnswer 'refused' 1 }
try {
    Set-VM -VM $vm -CheckpointType ProductionOnly
    Checkpoint-VM -VM $vm -SnapshotName $name
    $vm = Get-NewtonVm $vmName
    $made = @(Get-NewtonSnapshots $vm | Where-Object { $_.Name -ceq $name })
    if ($made.Count -ne 1) { throw 'the checkpoint is not listed once' }
    $json = ConvertTo-Json -InputObject (ConvertTo-NewtonCheckpoint $made[0] $vm) -Compress -Depth 3
} catch {
    Write-NewtonAnswer 'failed' 2
}
Write-NewtonAnswer $json 0
