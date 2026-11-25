# Newton AD build, stage 3, op s3-recyclebin.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s3-recyclebin.txt'
$ResultFile = 'C:\NewtonBuild\out\s3-recyclebin.rc'
$DnsName = 'build.newton.test'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
'token groups: ' + ((whoami /groups /fo csv /nh | Where-Object { $_ -match '-512"|-518"|-519"' } | ForEach-Object { ($_ -split '","')[0].Trim('"') }) -join ', ')
$f = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'
'before: EnabledScopes count ' + @($f.EnabledScopes).Count + ' | FeatureScope ' + ($f.FeatureScope -join ',') + ' | RequiredForestMode ' + $f.RequiredForestMode
$sw = [Diagnostics.Stopwatch]::StartNew()
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $DnsName -Confirm:$false
'Enable-ADOptionalFeature returned in ' + $sw.ElapsedMilliseconds + ' ms'
$f = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'
'after: EnabledScopes:'; $f.EnabledScopes | ForEach-Object { '  ' + $_ }
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
