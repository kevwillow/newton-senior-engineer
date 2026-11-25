# Newton AD build, stage 6, op s6-gpo-dc.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s6-gpo-dc.txt'
$ResultFile = 'C:\NewtonBuild\out\s6-gpo-dc.rc'
$BaselineVersion = '2026.11'
$GpoName = 'Newton Baseline 2026.11 Domain Controllers'
$GpoLink = 'dc'
$Settings = @('HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature|1', 'HKLM\System\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity|2', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|BackupDirectory|2', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|ADPasswordEncryptionEnabled|1', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|ADBackupDSRMPassword|1')
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
Import-Module ActiveDirectory
$gpmc = Get-WindowsFeature -Name GPMC
'GPMC: ' + $gpmc.InstallState
if ($gpmc.InstallState -ne 'Installed') {
    $r = Install-WindowsFeature -Name GPMC
    'Install-WindowsFeature GPMC: Success ' + $r.Success + ' RestartNeeded ' + $r.RestartNeeded + ' ExitCode ' + $r.ExitCode
}
Import-Module GroupPolicy
$dom = Get-ADDomain
$target = $dom.DistinguishedName
if ($GpoLink -ceq 'dc') { $target = $dom.DomainControllersContainer } elseif ($GpoLink -cne 'domain') { throw 'the link of the GPO is not one of the baseline' }
'domain: ' + $dom.DNSRoot + ' | target ' + $target
$before = @(Get-GPO -All | Where-Object { $_.DisplayName -ceq $GpoName })
'before: GPOs of the name: ' + $before.Count
if ($before.Count -ne 0) { throw 'a GPO of the name of the baseline GPO is there already' }
$gpo = New-GPO -Name $GpoName -Comment ('Newton AD build baseline ' + $BaselineVersion)
'New-GPO: ' + $gpo.DisplayName + ' | Id ' + $gpo.Id
foreach ($setting in $Settings) {
    $part = $setting.Split('|')
    $null = Set-GPRegistryValue -Guid $gpo.Id -Key $part[0] -ValueName $part[1] -Type DWord -Value ([int]$part[2])
    'Set-GPRegistryValue ' + $part[0] + '\' + $part[1] + ' = ' + $part[2] + ': ok'
}
$link = New-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes
'New-GPLink: ' + $link.DisplayName + ' | Target ' + $link.Target + ' | Enabled ' + $link.Enabled + ' | Order ' + $link.Order
'read-back:'
$g = Get-GPO -Guid $gpo.Id
'  GPO ' + $g.DisplayName + ' | Id ' + $g.Id + ' | GpoStatus ' + $g.GpoStatus + ' | Computer DSVersion ' + $g.Computer.DSVersion + ' SysvolVersion ' + $g.Computer.SysvolVersion + ' | User DSVersion ' + $g.User.DSVersion + ' SysvolVersion ' + $g.User.SysvolVersion
foreach ($setting in $Settings) {
    $part = $setting.Split('|')
    $v = Get-GPRegistryValue -Guid $gpo.Id -Key $part[0] -ValueName $part[1]
    '  GPO value ' + $part[0] + '\' + $part[1] + ' = ' + $v.Value + ' | ' + $v.Type + ' | ' + $v.PolicyState
}
foreach ($l in (Get-GPInheritance -Target $target).GpoLinks) { '  link ' + $l.DisplayName + ' | Enabled ' + $l.Enabled + ' | Enforced ' + $l.Enforced + ' | Order ' + $l.Order }
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
