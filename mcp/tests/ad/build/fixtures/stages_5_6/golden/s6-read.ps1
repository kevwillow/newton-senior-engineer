# Newton AD build, stage 6, op s6-read.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s6-read.txt'
$ResultFile = 'C:\NewtonBuild\out\s6-read.rc'
$GpoNames = @('Newton Baseline 2026.11 Domain', 'Newton Baseline 2026.11 Domain Controllers')
$Settings = @('HKLM\System\CurrentControlSet\Control\Lsa|LmCompatibilityLevel|5', 'HKLM\System\CurrentControlSet\Control\Lsa|NoLMHash|1', 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec|537395200', 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec|537395200', 'HKLM\System\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM|1', 'HKLM\System\CurrentControlSet\Control\Lsa|RestrictAnonymous|1', 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature|1', 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature|1', 'HKLM\System\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity|2', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|BackupDirectory|2', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|ADPasswordEncryptionEnabled|1', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|ADBackupDSRMPassword|1')
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
Import-Module ActiveDirectory
Import-Module GroupPolicy
$gp = gpupdate.exe /target:computer /force
'gpupdate /target:computer /force exit ' + $LASTEXITCODE
foreach ($line in $gp) { if ($line.Trim()) { '  gpupdate ' + $line.Trim() } }
foreach ($setting in $Settings) {
    $part = $setting.Split('|')
    $item = Get-ItemProperty -LiteralPath ('Registry::' + $part[0]) -Name $part[1] -ErrorAction SilentlyContinue
    if ($null -eq $item) { 'registry ' + $part[0] + '\' + $part[1] + ' : absent' } else { 'registry ' + $part[0] + '\' + $part[1] + ' = ' + $item.($part[1]) }
}
# Windows LAPS (AD-A-46): the policy of the Domain Controllers GPO is
# applied by the refresh above, the processing writes the password of the
# local administrator of this DC to the directory, and the read-back
# proves that the computer object of this DC carries it.  Only the time
# the password expires is read; the encrypted DSRM password is never
# printed, only whether it is there.
try {
    $null = Import-Module LAPS -ErrorAction Stop
    'LAPS module: ' + (Get-Module LAPS).Version
} catch {
    'LAPS module: absent (' + $_.Exception.Message + ')'
}
try {
    Invoke-LapsPolicyProcessing -ErrorAction Stop
    'Invoke-LapsPolicyProcessing: ok'
} catch {
    'Invoke-LapsPolicyProcessing: FAIL ' + $_.Exception.GetType().FullName + ' | ' + $_.Exception.Message
}
$computer = $null
$expiry = ''
$dsrm = 'absent'
try {
    $computer = Get-ADComputer -Identity $env:COMPUTERNAME -Properties msLAPS-PasswordExpirationTime, msLAPS-EncryptedDSRMPassword
    $expiry = [string]$computer.'msLAPS-PasswordExpirationTime'
    if ($null -ne $computer.'msLAPS-EncryptedDSRMPassword') { $dsrm = 'present' }
} catch {
    'computer object: FAIL ' + $_.Exception.GetType().FullName + ' | ' + $_.Exception.Message
}
$computer = $null
'  computer object ' + $env:COMPUTERNAME + ' | msLAPS-PasswordExpirationTime ' + $expiry + ' | msLAPS-EncryptedDSRMPassword ' + $dsrm
$cfg = 'C:\NewtonBuild\out\s6-secedit.inf'
if (Test-Path -LiteralPath $cfg) { Remove-Item -LiteralPath $cfg -Force }
$null = secedit.exe /export /cfg $cfg /areas SECURITYPOLICY /quiet
'secedit /export /areas SECURITYPOLICY exit ' + $LASTEXITCODE
foreach ($line in (Get-Content -LiteralPath $cfg -Encoding Unicode)) { 'secedit ' + $line }
Remove-Item -LiteralPath $cfg -Force
$root = (Get-ADDomain).DistinguishedName
$p = Get-ADDefaultDomainPasswordPolicy -Identity $root
'password policy: MinPasswordLength ' + $p.MinPasswordLength + ' | PasswordHistoryCount ' + $p.PasswordHistoryCount + ' | MaxPasswordAge ' + $p.MaxPasswordAge + ' | MinPasswordAge ' + $p.MinPasswordAge + ' | ComplexityEnabled ' + $p.ComplexityEnabled + ' | ReversibleEncryptionEnabled ' + $p.ReversibleEncryptionEnabled + ' | LockoutThreshold ' + $p.LockoutThreshold + ' | LockoutDuration ' + $p.LockoutDuration + ' | LockoutObservationWindow ' + $p.LockoutObservationWindow
foreach ($name in $GpoNames) { $g = Get-GPO -Name $name; 'GPO ' + $g.DisplayName + ' | GpoStatus ' + $g.GpoStatus + ' | Computer DSVersion ' + $g.Computer.DSVersion + ' SysvolVersion ' + $g.Computer.SysvolVersion }
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
