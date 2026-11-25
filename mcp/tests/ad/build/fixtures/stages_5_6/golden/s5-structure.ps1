# Newton AD build, stage 5, op s5-structure.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s5-structure.txt'
$ResultFile = 'C:\NewtonBuild\out\s5-structure.rc'
$OuTree = @('IT/Servers', 'Staff')
$Groups = @('IT Admins', 'Staff Users')
$OwnerAdmin = 'owner-admin'
$AdministratorOption = 'random-password'
$AdminSecretFile = 'C:\NewtonBuild\admin.bin'
$PasswordMinLength = '14'
$PasswordHistory = '24'
$PasswordMaxAgeDays = '365'
$PasswordMinAgeDays = '1'
$LockoutThreshold = '10'
$LockoutMinutes = '15'
$LockoutWindowMinutes = '15'
$PsoName = 'Newton Tier 0 Admins'
$PsoPrecedence = '10'
$PsoMinLength = '20'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Security
function ConvertTo-NewtonDnValue {
    param([string]$Value)
    $escaped = [regex]::Replace($Value, '([,\\#+<>;"=])', '\$1')
    if ($escaped.StartsWith(' ')) { $escaped = '\' + $escaped }
    if ($escaped.EndsWith(' ')) { $escaped = $escaped.Substring(0, $escaped.Length - 1) + '\ ' }
    return $escaped
}
function Read-NewtonSecretFile {
    param([string]$Path)
    $plain = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($Path), $null, 'LocalMachine'))
    Remove-Item -LiteralPath $Path
    return (ConvertTo-SecureString $plain -AsPlainText -Force)
}
$adminSecret = Read-NewtonSecretFile $AdminSecretFile
'admin secret file deleted: ' + (-not (Test-Path -LiteralPath $AdminSecretFile))
if (@('random-password', 'disabled') -cnotcontains $AdministratorOption) {
    throw 'the option of the built-in Administrator is not one of the baseline'
}
$dom = Get-ADDomain
$root = $dom.DistinguishedName
$sid = [string]$dom.DomainSID
$users = 'CN=Users,' + $root
'domain: ' + $dom.DNSRoot + ' | DomainSID ' + $sid
$ous = New-Object System.Collections.ArrayList
foreach ($path in $OuTree) {
    $parent = $root
    foreach ($name in $path.Split('/')) {
        $dn = 'OU=' + (ConvertTo-NewtonDnValue $name) + ',' + $parent
        $found = $null
        try { $found = Get-ADOrganizationalUnit -Identity $dn } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $found = $null }
        if ($found) { 'OU present: ' + $dn } else { New-ADOrganizationalUnit -Name $name -Path $parent -ProtectedFromAccidentalDeletion $true; 'OU created: ' + $dn }
        if (-not $ous.Contains($dn)) { [void]$ous.Add($dn) }
        $parent = $dn
    }
}
foreach ($group in $Groups) {
    $found = $null
    try { $found = Get-ADGroup -Identity $group } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $found = $null }
    if ($found) { 'group present: ' + $group } else { New-ADGroup -Name $group -SamAccountName $group -GroupScope Global -GroupCategory Security -Path $users; 'group created: ' + $group }
}
$marker = 'Newton AD build: the owner''s admin account'
$found = $null
try { $found = Get-ADUser -Identity $OwnerAdmin -Properties Description } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $found = $null }
if ($found) {
    # Only the account an earlier run of this stage made (it carries the
    # marker) goes on to Domain Admins and Protected Users; any other
    # account of that name stops the op here, before any write.
    if ([string]$found.Description -cne $marker) {
        'owner admin present, not made by this build: ' + $OwnerAdmin
        throw 'the owner admin account is there and was not made by this build'
    }
    'owner admin present: ' + $OwnerAdmin
} else {
    New-ADUser -Name $OwnerAdmin -SamAccountName $OwnerAdmin -UserPrincipalName ($OwnerAdmin + '@' + $dom.DNSRoot) -AccountPassword $adminSecret -Enabled $true -ChangePasswordAtLogon $true -Path $users -Description $marker
    'owner admin created: ' + $OwnerAdmin
}
$adminSecret = $null
foreach ($rid in '512', '525') { $g = Get-ADGroup -Identity ($sid + '-' + $rid); Add-ADGroupMember -Identity $g -Members $OwnerAdmin; 'Add-ADGroupMember ' + $rid + ' ' + $OwnerAdmin + ': ok' }
# The owner's admin account is sensitive: its credentials may not be
# delegated to another service (the NOT_DELEGATED bit of
# userAccountControl, 0x100000).  Protected Users says the same for the
# members of that group, but the bit is the account's own.
Set-ADAccountControl -Identity $OwnerAdmin -AccountNotDelegated $true
'Set-ADAccountControl AccountNotDelegated: ok'
Set-ADDefaultDomainPasswordPolicy -Identity $root -MinPasswordLength ([int]$PasswordMinLength) -PasswordHistoryCount ([int]$PasswordHistory) -MaxPasswordAge ([TimeSpan]::FromDays([int]$PasswordMaxAgeDays)) -MinPasswordAge ([TimeSpan]::FromDays([int]$PasswordMinAgeDays)) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -LockoutThreshold ([int]$LockoutThreshold) -LockoutDuration ([TimeSpan]::FromMinutes([int]$LockoutMinutes)) -LockoutObservationWindow ([TimeSpan]::FromMinutes([int]$LockoutWindowMinutes))
'Set-ADDefaultDomainPasswordPolicy: ok'
# The machine account quota of the domain head is 0: no ordinary account
# may join a computer (AD-A-44).  The quota before the write and the one
# after it are read back, so the check names both.
$quota = (Get-ADObject -Identity $root -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'
'machine account quota before: ' + $quota
Set-ADObject -Identity $root -Replace @{ 'ms-DS-MachineAccountQuota' = '0' }
'Set-ADObject ms-DS-MachineAccountQuota: ok'
$quota = (Get-ADObject -Identity $root -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'
'machine account quota after: ' + $quota
$pso = $null
try { $pso = Get-ADFineGrainedPasswordPolicy -Identity $PsoName } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $pso = $null }
if ($pso) {
    'PSO present: ' + $PsoName
} else {
    New-ADFineGrainedPasswordPolicy -Name $PsoName -Precedence ([int]$PsoPrecedence) -MinPasswordLength ([int]$PsoMinLength) -PasswordHistoryCount ([int]$PasswordHistory) -MaxPasswordAge ([TimeSpan]::FromDays([int]$PasswordMaxAgeDays)) -MinPasswordAge ([TimeSpan]::FromDays([int]$PasswordMinAgeDays)) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -LockoutThreshold ([int]$LockoutThreshold) -LockoutDuration ([TimeSpan]::FromMinutes([int]$LockoutMinutes)) -LockoutObservationWindow ([TimeSpan]::FromMinutes([int]$LockoutWindowMinutes)) -ProtectedFromAccidentalDeletion $true
    'PSO created: ' + $PsoName
}
Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects (Get-ADGroup -Identity ($sid + '-512'))
'Add-ADFineGrainedPasswordPolicySubject 512: ok'
$builtin = Get-ADUser -Identity ($sid + '-500')
if ($AdministratorOption -ceq 'random-password') {
    # A random password made here, from the system's CSPRNG, held only in
    # this process and shown to nobody (an open point of DESIGN-1.5: the
    # design's "derived" password has no info string of its own).
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 48
    $rng.GetBytes($bytes)
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*-+=_'
    $all = -join $sets
    $chars = New-Object System.Collections.Generic.List[char]
    for ($i = 0; $i -lt 4; $i++) { $chars.Add($sets[$i][$bytes[$i] % $sets[$i].Length]) }
    for ($i = 4; $i -lt 32; $i++) { $chars.Add($all[$bytes[$i] % $all.Length]) }
    $builtinSecret = New-Object System.Security.SecureString
    foreach ($c in $chars) { $builtinSecret.AppendChar($c) }
    $chars.Clear(); [Array]::Clear($bytes, 0, $bytes.Length)
    Set-ADAccountPassword -Identity $builtin -Reset -NewPassword $builtinSecret
    $builtinSecret.Dispose()
    'built-in Administrator: password reset'
} else {
    Disable-ADAccount -Identity $builtin
    'built-in Administrator: disabled'
    # The disabled built-in Administrator is a member of Protected Users
    # (RID 525) as well: the audit findings that skip a member of that
    # group (AD-A-06, AD-A-09) skip the account, and its credentials
    # may not be delegated to another service.
    $protected = Get-ADGroup -Identity ($sid + '-525')
    Add-ADGroupMember -Identity $protected -Members $builtin.SamAccountName
    'Add-ADGroupMember 525 ' + $builtin.SamAccountName + ': ok'
}
'read-back:'
foreach ($dn in $ous) { $o = Get-ADOrganizationalUnit -Identity $dn -Properties ProtectedFromAccidentalDeletion; '  OU ' + $o.DistinguishedName + ' | Protected ' + $o.ProtectedFromAccidentalDeletion }
foreach ($group in $Groups) { $g = Get-ADGroup -Identity $group; '  group ' + $g.SamAccountName + ' | ' + $g.GroupScope + ' | ' + $g.GroupCategory + ' | ' + $g.DistinguishedName }
$u = Get-ADUser -Identity $OwnerAdmin -Properties pwdLastSet, UserPrincipalName, userAccountControl
'  owner admin ' + $u.SamAccountName + ' | Enabled ' + $u.Enabled + ' | UPN ' + $u.UserPrincipalName + ' | pwdLastSet ' + $u.pwdLastSet + ' | ' + $u.DistinguishedName
'  owner admin groups: ' + ((Get-ADPrincipalGroupMembership -Identity $OwnerAdmin | Sort-Object -Property Name | ForEach-Object { $_.Name + ' (' + $_.SID + ')' }) -join ', ')
'  owner admin UAC ' + [int]$u.userAccountControl + ' | NOT_DELEGATED ' + ((([int]$u.userAccountControl) -band 0x100000) -ne 0)
$p = Get-ADDefaultDomainPasswordPolicy -Identity $root
'  password policy: MinPasswordLength ' + $p.MinPasswordLength + ' | PasswordHistoryCount ' + $p.PasswordHistoryCount + ' | MaxPasswordAge ' + $p.MaxPasswordAge + ' | MinPasswordAge ' + $p.MinPasswordAge + ' | ComplexityEnabled ' + $p.ComplexityEnabled + ' | ReversibleEncryptionEnabled ' + $p.ReversibleEncryptionEnabled + ' | LockoutThreshold ' + $p.LockoutThreshold + ' | LockoutDuration ' + $p.LockoutDuration + ' | LockoutObservationWindow ' + $p.LockoutObservationWindow
$f = Get-ADFineGrainedPasswordPolicy -Identity $PsoName
'  PSO ' + $f.Name + ' | Precedence ' + $f.Precedence + ' | MinPasswordLength ' + $f.MinPasswordLength + ' | PasswordHistoryCount ' + $f.PasswordHistoryCount + ' | MaxPasswordAge ' + $f.MaxPasswordAge + ' | MinPasswordAge ' + $f.MinPasswordAge + ' | ComplexityEnabled ' + $f.ComplexityEnabled + ' | ReversibleEncryptionEnabled ' + $f.ReversibleEncryptionEnabled + ' | LockoutThreshold ' + $f.LockoutThreshold + ' | LockoutDuration ' + $f.LockoutDuration + ' | LockoutObservationWindow ' + $f.LockoutObservationWindow
'  PSO applies to: ' + ((@($f.AppliesTo) | Sort-Object) -join '; ')
$b = Get-ADUser -Identity ($sid + '-500') -Properties PasswordLastSet
'  built-in Administrator ' + $b.SamAccountName + ' (' + $b.SID + ') | Enabled ' + $b.Enabled + ' | PasswordLastSet ' + $b.PasswordLastSet.ToUniversalTime().ToString('o')
if ($AdministratorOption -ceq 'disabled') {
    # The membership of the built-in Administrator in Protected Users,
    # read through the group (the read of the group, not of the
    # principal: MEASURED-1.5, stage 9).
    $inProtected = @(Get-ADGroupMember -Identity ($sid + '-525') | Where-Object { $_.SamAccountName -ceq $b.SamAccountName })
    '  protected users: ' + $b.SamAccountName + ' (' + $b.SID + ') | ' + $(if ($inProtected.Count -eq 1) { 'member' } else { 'not a member' })
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
