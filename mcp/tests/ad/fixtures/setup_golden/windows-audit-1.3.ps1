# Newton's Active Directory collector setup.
# Device: windc1   Host: windc1.win.newton.test   Domain: win.newton.test
#
# Read this script, then run it as a Domain Admin on the domain
# controller.  Every step is idempotent: running it a second time
# changes nothing the second time.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Domain = 'win.newton.test'
$Device = 'windc1'
$CollectorHost = 'windc1.win.newton.test'
$AuditName = 'newton-audit'
$OpsName = 'newton-ops'
$AdDir = 'C:\ProgramData\Newton\ad'
$SshdConfig = 'C:\ProgramData\ssh\sshd_config'
$SshdBackup = 'C:\ProgramData\ssh\sshd_config.bak-newton'
$RestartTask = 'Newton-Ad-SshdRestart'
$BlockMarker = '# newton-ad collector'


Write-Host 'Step 1: the newton-audit account'
$user = Get-ADUser -Filter "SamAccountName -eq '$AuditName'"
if (-not $user) {
    $random = New-Object 'System.Byte[]' 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) } finally { $generator.Dispose() }
    $password = [Convert]::ToBase64String($random)
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    $user = New-ADUser -Name $AuditName -SamAccountName $AuditName `
        -UserPrincipalName ($AuditName + '@' + $Domain) -AccountPassword $secure `
        -Enabled $true -PasswordNeverExpires $true
    $password = $null
    $secure = $null
    Write-Host 'Created newton-audit with a random password. It was not shown and it was not stored.'
} else {
    Write-Host 'newton-audit exists. Its password is left alone.'
    $memberOf = @()
    try {
        $memberOf = @((Get-ADUser -Filter "SamAccountName -eq '$AuditName'" -Properties MemberOf).MemberOf)
    } catch {
        $memberOf = @()
    }
    $groups = @($memberOf | Where-Object { $_ } | ForEach-Object { (Get-ADObject -Identity $_).Name })
    Write-Host ('newton-audit is in these groups: ' + ($groups -join ', '))
}
$openSshUsers = Get-ADGroup -Identity ('CN=OpenSSH Users,CN=Builtin,' + (Get-ADDomain).DistinguishedName)
$members = @(Get-ADGroupMember -Identity $openSshUsers -ErrorAction SilentlyContinue)
$isMember = $false
foreach ($member in $members) {
    $memberName = $member.PSObject.Properties['SamAccountName']
    if (($null -ne $memberName) -and ([string]$memberName.Value -eq $AuditName)) { $isMember = $true }
}
if (-not $isMember) {
    Add-ADGroupMember -Identity $openSshUsers -Members $AuditName
    Write-Host 'newton-audit is now a member of the domain-local OpenSSH Users group.'
} else {
    Write-Host 'newton-audit is already a member of the domain-local OpenSSH Users group.'
}


Write-Host 'Step 2: the collector files'
New-Item -ItemType Directory -Path $AdDir -Force | Out-Null
$collectorB64 = @(
'IyB0aGUgc3R1YiBvZiB0aGUgY29sbGVjdG9yLCBnb2xkZW4K'
)
$collectorB64 = $collectorB64 -join ''
$queriesB64 = @(
'eyJxdWVyaWVzIjogW119Cg=='
)
$queriesB64 = $queriesB64 -join ''
$forbiddenB64 = @(
'eyJmb3JiaWRkZW4iOiBbXX0K'
)
$forbiddenB64 = $forbiddenB64 -join ''
[System.IO.File]::WriteAllBytes((Join-Path $AdDir 'collector.ps1'), [System.Convert]::FromBase64String($collectorB64))
[System.IO.File]::WriteAllBytes((Join-Path $AdDir 'queries.json'), [System.Convert]::FromBase64String($queriesB64))
[System.IO.File]::WriteAllBytes((Join-Path $AdDir 'forbidden.json'), [System.Convert]::FromBase64String($forbiddenB64))
$expected = @{
    'collector.ps1' = '9390ff822ba876162f5337f8f06ee24a2582a47742d95ca1122b274070103e78'
    'queries.json' = '99d9e7655e12570b9f9aeb608530ec4a1976698ce2b940d2a4f072b0c542ca99'
    'forbidden.json' = '9c478e91c89f31b36eec5767147d5279224e921942dba057a91929bde0efff98'
}
foreach ($name in @('collector.ps1', 'queries.json', 'forbidden.json')) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $AdDir $name)).Hash.ToLowerInvariant()
    if ($hash -ne $expected[$name]) {
        throw ('the sha256 of ' + $name + ' does not match the package')
    }
    Write-Host ('sha256 ' + $name + ' ' + $hash)
}


Write-Host 'Step 3: the access control list'
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$auditUser = @(Get-ADUser -Filter "SamAccountName -eq '$AuditName'")
if ($auditUser.Count -ne 1) { throw 'the newton-audit account is missing' }
$auditSid = $auditUser[0].SID
# The install root is shared with the write path: the account of the
# write path reads it, and it reads nothing else of it.  The account
# is looked up the way the account of the collector is looked up: one
# exact match of the SamAccountName.  It may be absent, and then there
# is no rule for it and there is no error.
$opsUser = @(Get-ADUser -Filter "SamAccountName -eq '$OpsName'")
if ($opsUser.Count -gt 1) { throw 'there is more than one newton-ops account' }
$opsSid = $null
if ($opsUser.Count -eq 1) { $opsSid = $opsUser[0].SID }
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$noInheritance = [System.Security.AccessControl.InheritanceFlags]::None
$children = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$paths = @(
    @{ path = $AdDir; inheritance = $children },
    @{ path = (Join-Path $AdDir 'collector.ps1'); inheritance = $none },
    @{ path = (Join-Path $AdDir 'queries.json'); inheritance = $none },
    @{ path = (Join-Path $AdDir 'forbidden.json'); inheritance = $none }
)
foreach ($entry in $paths) {
    $acl = Get-Acl -LiteralPath $entry.path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $acl.SetOwner($administrators)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $entry.inheritance, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $entry.inheritance, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($auditSid, 'ReadAndExecute', $entry.inheritance, $none, $allow)))
    Set-Acl -LiteralPath $entry.path -AclObject $acl
}
if ($null -ne $opsSid) {
    # The read of the write account is on the root and on nothing else:
    # the rule is explicit and it inherits nothing.
    $rootAcl = Get-Acl -LiteralPath $AdDir
    $rootAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSid, 'ReadAndExecute', $noInheritance, $none, $allow)))
    Set-Acl -LiteralPath $AdDir -AclObject $rootAcl
    Write-Host 'The read of newton-ops on the install root was kept: the write path reads it.'
} else {
    Write-Host 'There is no newton-ops account: the install root does not give it a read.'
}
Write-Host 'The directory and the three files are protected: Administrators and SYSTEM have full control, newton-audit has read and execute.'


Write-Host 'Step 4: the authorized key'
$keyLine = 'restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f'
[System.IO.File]::WriteAllText((Join-Path $AdDir 'authorized_keys'), $keyLine + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
Write-Host 'The authorized key is written with the restrict option.'


Write-Host 'Step 5: the sshd configuration'
if (-not (Test-Path -LiteralPath $SshdConfig)) { throw 'the sshd configuration is missing' }
if (-not (Test-Path -LiteralPath $SshdBackup)) {
    Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force
    Write-Host 'The sshd configuration is backed up once, as .bak-newton.'
}
$config = Get-Content -LiteralPath $SshdConfig -Raw
$sshdChanged = $false
if ($config -notlike ('*' + $BlockMarker + '*')) {
    $netbios = ([string](Get-ADDomain).NetBIOSName).ToLowerInvariant()
    $blockLines = @(
        $BlockMarker
        ("Match User $($netbios)\newton-audit")
        '    AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/authorized_keys'
        '    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad\collector.ps1'
        '    PermitTTY no'
        '    AllowTcpForwarding no'
        '    X11Forwarding no'
    )
    $block = ($blockLines -join "`n") + "`n"
    if (-not $config.EndsWith("`n")) { $block = "`n" + $block }
    [System.IO.File]::WriteAllText($SshdConfig, $config + $block, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $true
    Write-Host 'The collector block is in the sshd configuration.'
} else {
    Write-Host 'The collector block is already in the sshd configuration.'
}
$sshdExe = $null
$sshdCommand = Get-Command sshd.exe -ErrorAction SilentlyContinue
if ($sshdCommand) { $sshdExe = $sshdCommand.Source }
if (-not $sshdExe) {
    $candidate = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
    if (Test-Path -LiteralPath $candidate) { $sshdExe = $candidate }
}
if (-not $sshdExe) {
    $candidate = Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'
    if (Test-Path -LiteralPath $candidate) { $sshdExe = $candidate }
}
if (-not $sshdExe) {
    [System.IO.File]::WriteAllText($SshdConfig, $config, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $false
    throw 'sshd.exe was not found. The sshd configuration was put back.'
}
$sshdExit = 0
try {
    & $sshdExe -t
    $sshdExit = $LASTEXITCODE
} catch {
    $sshdExit = 1
}
if ($sshdExit -ne 0) {
    [System.IO.File]::WriteAllText($SshdConfig, $config, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $false
    throw 'sshd refused the configuration. The configuration was put back.'
}
Write-Host 'sshd accepted the configuration.'


Write-Host 'Step 6: the sshd restart'
Unregister-ScheduledTask -TaskName $RestartTask -Confirm:$false -ErrorAction SilentlyContinue
if ($sshdChanged) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Restart-Service sshd -Force"'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(8)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $RestartTask -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host 'A one-shot SYSTEM task restarts sshd in 8 seconds. The session ends then.'
    Write-Host 'The task is removed by the next run of this script.'
} else {
    Write-Host 'The sshd configuration did not change. Nothing is restarted and no task is left behind.'
}


Write-Host 'Step 7: the inventory entry'
Write-Host ''
Write-Host ('[devices.' + $Device + ']')
Write-Host 'platform = "ad-windows"'
Write-Host ('host = "' + $CollectorHost + '"')
Write-Host ('user = "newton-audit@' + $Domain + '"')
Write-Host 'experimental_readonly = true'
Write-Host 'key_file = "<the private key of the audit key, on the Newton host>"'
Write-Host 'known_hosts = "<the pinned known_hosts of the collector host>"'
Write-Host ('domain = "' + $Domain + '"')
Write-Host ''
Write-Host ('The installed public key (sha256): 394cb0357cefcb7cbe8da2a7ff052c6beca6ec5c51750812a33c11b6368021e2')
Write-Host 'The user principal name is the form the ssh client accepts. The domain\user form is refused by the client.'
