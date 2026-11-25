# Newton AD build, stage 2, op s2-genid.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s2-genid.txt'
$ResultFile = 'C:\NewtonBuild\out\s2-genid.rc'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$c = Get-ADComputer -Identity $env:COMPUTERNAME -Properties msDS-GenerationId, whenCreated
$g = $c.'msDS-GenerationId'
'msDS-GenerationId on ' + $c.DistinguishedName + ': ' + $(if ($g) { 'present, ' + $g.Length + ' bytes, ' + (($g | ForEach-Object { $_.ToString('x2') }) -join '') } else { 'absent' })
'uptime s ' + [int]((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).TotalSeconds
Get-WinEvent -LogName 'Directory Service' -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 2168, 2170, 2172, 2173, 2179, 1109 } | Sort-Object TimeCreated | ForEach-Object { '  DS event ' + $_.Id + ' at ' + $_.TimeCreated.ToUniversalTime().ToString('o') + ': ' + ($_.Message -split "`n")[0].Trim() }
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
