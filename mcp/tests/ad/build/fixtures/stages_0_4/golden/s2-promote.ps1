# Newton AD build, stage 2, op s2-promote.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s2-promote.txt'
$ResultFile = 'C:\NewtonBuild\out\s2-promote.rc'
$DnsName = 'build.newton.test'
$Netbios = 'NBUILD'
$Level = 'Win2025'
$SecretFile = 'C:\NewtonBuild\dsrm.bin'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
Add-Type -AssemblyName System.Security
$sec = ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($SecretFile), $null, 'LocalMachine'))) -AsPlainText -Force
Remove-Item -LiteralPath $SecretFile; 'dsrm.bin deleted: ' + (-not (Test-Path -LiteralPath $SecretFile))
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Install-ADDSForest -DomainName $DnsName -DomainNetbiosName $Netbios -ForestMode $Level -DomainMode $Level -InstallDns -SafeModeAdministratorPassword $sec -NoRebootOnCompletion -Force
'Install-ADDSForest returned after ' + [int]$sw.Elapsed.TotalSeconds + ' s'
$r | Format-List * | Out-String -Width 250
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
