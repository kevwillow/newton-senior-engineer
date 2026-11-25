# Newton AD build, stage 1, op s1-base.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s1-base.txt'
$ResultFile = 'C:\NewtonBuild\out\s1-base.rc'
$HostName = 'BDC1'
$Ip = '192.0.2.41'
$TimePeer = '192.0.2.1'
$Forwarders = @('192.0.2.1')
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
function Get-NewtonIpLine {
    $address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $address.InterfaceIndex
    'ip: ' + $address.IPAddress + '/' + $address.PrefixLength + ' ' + $address.PrefixOrigin + ' gw ' + (@($route | ForEach-Object { $_.NextHop }) -join ',')
}
'before ' + (Get-NewtonIpLine)
$sw = [Diagnostics.Stopwatch]::StartNew()
if ($env:COMPUTERNAME -ne $HostName) {
    Rename-Computer -NewName $HostName -Force -WarningAction Continue 3>&1 | ForEach-Object { 'Rename-Computer: ' + $_ }
}
'Rename-Computer done in ' + $sw.ElapsedMilliseconds + ' ms'
$sw.Restart()
w32tm /config ('/manualpeerlist:' + $TimePeer + ',0x8') /syncfromflags:manual /reliable:yes /update
'w32tm /config exit ' + $LASTEXITCODE
Restart-Service -Name w32time
w32tm /query /configuration | Select-String -Pattern 'NtpServer|Type:|AnnounceFlags'
'w32tm done in ' + $sw.ElapsedMilliseconds + ' ms'
$index = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip).InterfaceIndex
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $Forwarders
'dns client: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index).ServerAddresses -join ',')
$sw.Restart()
$r = Install-WindowsFeature AD-Domain-Services, RSAT-AD-Tools, Windows-Server-Backup
'Install-WindowsFeature in ' + $sw.ElapsedMilliseconds + ' ms: Success ' + $r.Success + ' RestartNeeded ' + $r.RestartNeeded + ' ExitCode ' + $r.ExitCode
$r.FeatureResult | Format-Table -AutoSize Name, Success, RestartNeeded | Out-String -Width 200
'after ' + (Get-NewtonIpLine)
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
