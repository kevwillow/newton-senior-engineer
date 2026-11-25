# Newton AD build, stage 3, op s3-state.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s3-state.txt'
$ResultFile = 'C:\NewtonBuild\out\s3-state.rc'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$f = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'
'now: EnabledScopes count ' + @($f.EnabledScopes).Count + ' | FeatureScope ' + ($f.FeatureScope -join ',') + ' | RequiredForestMode ' + $f.RequiredForestMode
'now: EnabledScopes:'; $f.EnabledScopes | ForEach-Object { '  ' + $_ }
'msDS-EnabledFeature on Partitions: ' + ((Get-ADObject ('CN=Partitions,' + (Get-ADRootDSE).configurationNamingContext) -Properties msDS-EnabledFeature).'msDS-EnabledFeature' -join ' | ')
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
