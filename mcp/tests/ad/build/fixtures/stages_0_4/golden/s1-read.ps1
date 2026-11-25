# Newton AD build, stage 1, op s1-read.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s1-read.txt'
$ResultFile = 'C:\NewtonBuild\out\s1-read.rc'
$Ip = '192.0.2.41'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Workgroup ' + $cs.Workgroup
'hostname: ' + (hostname)
'LastBootUpTime: ' + (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
Get-WindowsFeature AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-AD-PowerShell, RSAT-ADDS, RSAT-AD-AdminCenter, RSAT-ADDS-Tools, RSAT-ADLDS, Windows-Server-Backup | Format-Table -AutoSize Name, InstallState | Out-String
$address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $address.InterfaceIndex
'ip: ' + $address.IPAddress + '/' + $address.PrefixLength + ' ' + $address.PrefixOrigin + ' gw ' + (@($route | ForEach-Object { $_.NextHop }) -join ',')
'dns client: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $address.InterfaceIndex).ServerAddresses -join ',')
'w32tm source: ' + (w32tm /query /source)
w32tm /query /configuration | Select-String -Pattern 'NtpServer:|Type:'
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
