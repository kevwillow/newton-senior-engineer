# Newton AD build, stage 4, op s4-groups.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s4-groups.txt'
$ResultFile = 'C:\NewtonBuild\out\s4-groups.rc'
$BuildUser = 'newton-build'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$dom = Get-ADDomain
'LastBootUpTime: ' + (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
'domain: ' + $dom.DNSRoot + ' | DomainSID ' + $dom.DomainSID
'Get-ADPrincipalGroupMembership: ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | Sort-Object -Property Name | ForEach-Object { $_.Name + ' (' + $_.SID + ')' }) -join ', ')
foreach ($rid in '519', '518') { $g = Get-ADGroup -Identity ([string]$dom.DomainSID + '-' + $rid); '  ' + $g.Name + ' (' + $g.SID + ') members: ' + ((Get-ADGroupMember -Identity $g -Recursive | ForEach-Object SamAccountName | Sort-Object) -join ', ') }
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
