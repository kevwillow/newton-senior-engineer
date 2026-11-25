# Newton AD build, stage 4, op s4-state.
# Rendered by the build helper from the approved plan; the values are the ones of the plan.
$OutFile = 'C:\NewtonBuild\out\s4-state.txt'
$ResultFile = 'C:\NewtonBuild\out\s4-state.rc'
$BuildUser = 'newton-build'
$global:NewtonRc = 0
& {
try {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
'task start ' + (Get-Date).ToUniversalTime().ToString('o')
$sc = (Get-ADRootDSE).schemaNamingContext
$names = 'ms-LAPS-Password', 'ms-LAPS-PasswordExpirationTime', 'ms-LAPS-EncryptedPassword', 'ms-LAPS-EncryptedPasswordHistory', 'ms-LAPS-EncryptedDSRMPassword', 'ms-LAPS-EncryptedDSRMPasswordHistory', 'ms-Mcs-AdmPwd'
'schema now : objectVersion ' + (Get-ADObject $sc -Properties objectVersion).objectVersion
foreach ($n in $names) { $o = Get-ADObject -SearchBase $sc -LDAPFilter ('(cn=' + $n + ')') -Properties lDAPDisplayName, schemaIDGUID; if ($o) { '  ' + $n + ' : present, lDAPDisplayName ' + $o.lDAPDisplayName + ', schemaIDGUID ' + [guid]$o.schemaIDGUID } else { '  ' + $n + ' : absent' } }
$cc = Get-ADObject ('CN=Computer,' + $sc) -Properties mayContain
'  computer mayContain msLAPS-*: ' + ((@($cc.mayContain) | Where-Object { $_ -like 'msLAPS-*' } | Sort-Object) -join ', ')
$ou = 'OU=Domain Controllers,' + (Get-ADDomain).DistinguishedName
'OU read: ' + $ou
$map = @{}; foreach ($n in $names) { $o = Get-ADObject -SearchBase $sc -LDAPFilter ('(cn=' + $n + ')') -Properties lDAPDisplayName, schemaIDGUID; if ($o) { $map[[string][guid]$o.schemaIDGUID] = $o.lDAPDisplayName } }
'OU ACEs for SELF:'
(Get-Acl -Path ('AD:' + $ou)).Access | Where-Object { $_.IdentityReference -like '*SELF' } | ForEach-Object { '  ' + $_.IdentityReference + ' | ' + $_.ActiveDirectoryRights + ' | ' + $_.AccessControlType + ' | ObjectType ' + $_.ObjectType + ' (' + $map[[string]$_.ObjectType] + ') | InheritanceType ' + $_.InheritanceType + ' | InheritedObjectType ' + $_.InheritedObjectType + ' | IsInherited ' + $_.IsInherited }
'Get-ADPrincipalGroupMembership now: ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | ForEach-Object Name | Sort-Object) -join ', ')
foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') { '  ' + $g + ' members: ' + ((Get-ADGroupMember -Identity $g | ForEach-Object SamAccountName | Sort-Object) -join ', ') }
} catch {
'FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
$global:NewtonRc = 1
}
'task end ' + (Get-Date).ToUniversalTime().ToString('o')
} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
exit $global:NewtonRc
