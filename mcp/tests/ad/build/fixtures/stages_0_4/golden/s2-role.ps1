# Newton AD build, stage 2, op s2-role.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s2-role.txt'
$ResultFile = 'C:\NewtonBuild\out\s2-role.rc'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Domain ' + $cs.Domain + ' | Workgroup ' + $cs.Workgroup
'ProductType: ' + (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
$ntds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
if ($ntds) { 'NTDS Parameters: present | Root Domain ' + $ntds.'Root Domain' + ' | Machine DN Name ' + $ntds.'Machine DN Name' } else { 'NTDS Parameters: absent' }
$svc = Get-Service -Name NTDS -ErrorAction SilentlyContinue
'NTDS service: ' + $(if ($svc) { [string]$svc.Status + ', ' + [string]$svc.StartType } else { 'absent' })
try { $d = Get-ADDomain -ErrorAction Stop; 'Get-ADDomain: DNSRoot ' + $d.DNSRoot + ' | NetBIOSName ' + $d.NetBIOSName } catch { 'Get-ADDomain: FAIL ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message }
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
