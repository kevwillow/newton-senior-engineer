# Newton AD build, stage 2, op s2-read.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s2-read.txt'
$ResultFile = 'C:\NewtonBuild\out\s2-read.rc'
$DnsName = 'build.newton.test'
$BuildUser = 'newton-build'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$sw = [Diagnostics.Stopwatch]::StartNew()
$dd = dcdiag /q; 'dcdiag /q exit ' + $LASTEXITCODE + ' in ' + [int]$sw.Elapsed.TotalSeconds + ' s, ' + @($dd).Count + ' lines:'; $dd
$sw.Restart(); $d = dcdiag; 'dcdiag exit ' + $LASTEXITCODE + ' in ' + [int]$sw.Elapsed.TotalSeconds + ' s; test lines:'; $d | Select-String -Pattern 'passed test|failed test'
Get-SmbShare | Where-Object Name -in 'SYSVOL', 'NETLOGON' | Format-Table -AutoSize Name, Path | Out-String
'SYSVOLReady: ' + (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysvolReady
foreach ($n in @('_ldap._tcp.dc._msdcs.', '_kerberos._tcp.', '_gc._tcp.', '_ldap._tcp.pdc._msdcs.')) {
    $name = $n + $DnsName
    try { Resolve-DnsName -Name $name -Type SRV -DnsOnly -ErrorAction Stop | Where-Object Type -eq 'SRV' | ForEach-Object { 'SRV ' + $_.Name + ' -> ' + $_.NameTarget + ':' + $_.Port } } catch { 'SRV ' + $name + ' FAIL: ' + $_.Exception.Message }
}
$f = Get-ADForest; $dm = Get-ADDomain
'ForestMode ' + $f.ForestMode + ' DomainMode ' + $dm.DomainMode + ' | forest ' + $f.Name + ' | NetBIOS ' + $dm.NetBIOSName + ' | DomainSID ' + $dm.DomainSID
'msDS-Behavior-Version: forest ' + (Get-ADObject ('CN=Partitions,' + (Get-ADRootDSE).configurationNamingContext) -Properties msDS-Behavior-Version).'msDS-Behavior-Version' + ' domain ' + (Get-ADObject $dm.DistinguishedName -Properties msDS-Behavior-Version).'msDS-Behavior-Version'
'dns client after promotion: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses }) -join ',')
'DNS forwarders: ' + ((Get-DnsServerForwarder).IPAddress.IPAddressToString -join ',')
$BuildUser + ' memberships (Get-ADPrincipalGroupMembership): ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | ForEach-Object Name | Sort-Object) -join ', ')
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
