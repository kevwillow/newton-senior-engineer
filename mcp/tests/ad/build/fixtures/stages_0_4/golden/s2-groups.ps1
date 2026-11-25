# Newton AD build, stage 2, op s2-groups.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s2-groups.txt'
$ResultFile = 'C:\NewtonBuild\out\s2-groups.rc'
$BuildUser = 'newton-build'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
'token groups at task start: ' + ((whoami /groups /fo csv /nh | Where-Object { $_ -match '-512"|-518"|-519"|S-1-5-32-544' } | ForEach-Object { ($_ -split '","')[2] }) -join ', ')
foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') { Add-ADGroupMember -Identity $g -Members $BuildUser; 'Add-ADGroupMember ''' + $g + ''' ' + $BuildUser + ': ok' }
'Get-ADPrincipalGroupMembership: ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | ForEach-Object Name | Sort-Object) -join ', ')
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
