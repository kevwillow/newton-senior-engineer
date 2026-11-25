# Newton AD build, stage 0, op s0-read.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s0-read.txt'
$ResultFile = 'C:\NewtonBuild\out\s0-read.rc'
$DnsName = 'build.newton.test'
$Ip = '192.0.2.41'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$os = Get-CimInstance -ClassName Win32_OperatingSystem
'os: ' + $os.Caption + ' | Version ' + $os.Version + ' | BuildNumber ' + $os.BuildNumber + ' | OperatingSystemSKU ' + $os.OperatingSystemSKU
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Workgroup ' + $cs.Workgroup
(Get-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-PowerShell, RSAT-ADDS-Tools | ForEach-Object { $_.Name + ' ' + $_.InstallState }) -join ' | '
$address = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip -ErrorAction SilentlyContinue)
if ($address.Count -eq 1) {
    'Get-NetIPAddress: ' + $address[0].InterfaceAlias + ' ' + $address[0].IPAddress + ' /' + $address[0].PrefixLength + ' PrefixOrigin ' + $address[0].PrefixOrigin
    foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
        'Get-NetRoute 0.0.0.0/0: ' + $route.InterfaceAlias + ' NextHop ' + $route.NextHop + ' RouteMetric ' + $route.RouteMetric
    }
} else {
    'Get-NetIPAddress: absent'
}
$free = [int64](Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace
'C: free bytes ' + $free + ' (' + [Math]::Round($free / 1GB, 1).ToString([Globalization.CultureInfo]::InvariantCulture) + ' GB)'
$sw = [Diagnostics.Stopwatch]::StartNew()
try {
    $answer = Resolve-DnsName -Name $DnsName -DnsOnly -ErrorAction Stop
    'Resolve-DnsName ' + $DnsName + ' -DnsOnly True OK in ' + $sw.ElapsedMilliseconds + ' ms: ' + (($answer | ForEach-Object { [string]$_.Type + ' ' + [string]$_.IPAddress }) -join '; ')
} catch {
    'Resolve-DnsName ' + $DnsName + ' -DnsOnly True FAIL in ' + $sw.ElapsedMilliseconds + ' ms: ' + $_.Exception.GetType().FullName + ' | NativeErrorCode ' + $_.Exception.NativeErrorCode + ' | ' + $_.Exception.Message + ' | ' + $_.FullyQualifiedErrorId
}
$agent = Get-Service -Name QEMU-GA -ErrorAction SilentlyContinue
if ($agent) { 'QEMU-GA: ' + $agent.Status + ', ' + $agent.StartType } else { 'QEMU-GA: absent' }
$serial = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq 'VirtIO Serial Driver' })
if ($serial.Count -gt 0) {
    foreach ($device in $serial) { 'VirtIO Serial Driver: ' + $device.Status + ', ' + $device.Class + ', ' + $device.InstanceId }
} else {
    'VirtIO Serial Driver: absent'
}
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
