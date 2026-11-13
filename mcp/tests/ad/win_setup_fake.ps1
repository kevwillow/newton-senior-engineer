# The fake of Active Directory and of the tools of the Windows setup.
#
# The model of the directory comes from the JSON file named by the
# environment variable NEWTON_FAKE_AD: the objects of the domain, the
# schema, the accounts and the access control lists.  Every call is
# recorded in $script:FakeCalls, so a test may read what the script
# asked for, and the arguments of dsacls are recorded in
# $script:FakeDsacls, one list of arguments per call.
#
# The fake of New-ADUser holds the parameters of the real cmdlet: it
# has no -UserAccountControl, so a script that passes one is refused
# the way the real cmdlet refuses it.
#
# The fake of dsacls is the measured one: it takes the name of the
# object, /I:S or /I:T and /G with an ace, it resolves the names of the
# schema into their GUIDs, and it stores the rule the way the
# real dsacls stores it.  It prints the whole access control list of
# the object, the way the real dsacls prints it.
#
# The schemaIDGUID of a schema object is a byte array, the way the
# directory answers it: the first three fields of the GUID are little
# endian and the last eight bytes are as they are.
#
# The SYSVOL of the PDC is a share of a Windows host, and the file
# system of this machine has no such share.  The fake serves the share
# from a folder of the sandbox: the folder that stands for it is the
# policyDir of the model, and every read and every write of the share
# is recorded with the path of the share.
#
# The rule of the constructed attributes: the tokenGroups of an object
# is a constructed attribute, and the directory gives it only to a read
# whose scope is Base.  A read of any other scope is refused by the
# directory itself, with the error 8480 of the server, as
# measured on the real controller: the generated setup
# stopped right after the step 1 with
#
#     Get-ADUser : The requested search operation is only supported for base searches
#         + FullyQualifiedErrorId : ActiveDirectoryServer:8480,Microsoft.ActiveDirectory.Management.Commands.GetADUser
#
# so the fake refuses every read of tokenGroups that is not a base
# search, and only a Get-ADObject with -SearchScope Base is allowed.
#
# The backup of the policy is unreliable over an S4U session (an SSH
# key login): measured "Backup-GPO : Access is denied.
# (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))" in such a
# session, while the read of the GPT.INI of the policy answered OK,
# and the same code had passed over a key login earlier the same day.
# The model may hold the flag that makes the cmdlet throw that error.

$script:FakeModel = $null
if ($env:NEWTON_FAKE_AD -and (Test-Path -LiteralPath $env:NEWTON_FAKE_AD)) {
    $script:FakeModel = Get-Content -LiteralPath $env:NEWTON_FAKE_AD -Raw | ConvertFrom-Json
} else {
    throw 'the fake needs a model: set NEWTON_FAKE_AD'
}
# The real cmdlets of the file system, taken before the fake takes their
# names: the module of a cmdlet of the file system is not the same in
# every version of PowerShell, and the fake names the real one by the
# command it is.
$script:RealGetContent = Get-Command Get-Content -CommandType Cmdlet
$script:RealSetContent = Get-Command Set-Content -CommandType Cmdlet
$script:RealTestPath = Get-Command Test-Path -CommandType Cmdlet
$script:FakeCalls = New-Object System.Collections.ArrayList
$script:FakeDsacls = New-Object System.Collections.ArrayList
$script:FakeReads = New-Object System.Collections.ArrayList
$script:FakeWrites = New-Object System.Collections.ArrayList
$script:FakeAclRules = @{}
foreach ($property in $script:FakeModel.acl.PSObject.Properties) {
    $rules = New-Object System.Collections.ArrayList
    foreach ($record in @($property.Value)) { [void]$rules.Add($record) }
    $script:FakeAclRules[$property.Name] = $rules
}

# The folder of the sandbox that stands for the share of the SYSVOL of
# the PDC.  The model may name it, and the path the directory answers
# for the policy is the one of the share.
$script:FakePolicyDir = ''
$script:FakePolicyPath = ''
$policyDirProperty = $script:FakeModel.PSObject.Properties['policyDir']
if ($null -ne $policyDirProperty) {
    $script:FakePolicyDir = [string]$policyDirProperty.Value
}
foreach ($object in @($script:FakeModel.objects)) {
    $property = $object.PSObject.Properties['gPCFileSysPath']
    if ($null -eq $property) { continue }
    $value = [string]$property.Value
    if (-not $value) { continue }
    $script:FakePolicyPath = $value
    if ((-not $script:FakePolicyDir) -and (-not $value.StartsWith('\\'))) {
        $script:FakePolicyDir = $value
    }
}

function Add-FakeCall([string]$Cmdlet, [hashtable]$Arguments) {
    $record = [ordered]@{ cmdlet = $Cmdlet }
    foreach ($key in $Arguments.Keys) { $record[$key] = $Arguments[$key] }
    [void]$script:FakeCalls.Add([PSCustomObject]$record)
}

# The error of the directory when the tokenGroups of an object is asked
# for in a read that is not a base search.  The two lines are the ones
# read on the real controller.
$script:FakeTokenGroupsMessage = @(
    'Get-ADUser : The requested search operation is only supported for base searches'
    '    + FullyQualifiedErrorId : ActiveDirectoryServer:8480,Microsoft.ActiveDirectory.Management.Commands.GetADUser'
) -join "`n"

function Test-FakeTokenGroupsRequest([string[]]$Properties) {
    # True when the caller asks for the tokenGroups of the object.
    if (-not $Properties) { return $false }
    foreach ($property in $Properties) {
        if ([string]$property -eq 'tokenGroups') { return $true }
    }
    return $false
}

function Stop-FakeTokenGroupsRead {
    # The refusal of the directory: the run stops with the error 8480.
    #
    # The message is written to the error stream as it is: the
    # rendering of PowerShell wraps the lines of a message, and it was
    # read whole.
    [Console]::Error.WriteLine($script:FakeTokenGroupsMessage)
    $exception = [System.Exception]::new($script:FakeTokenGroupsMessage)
    $record = [System.Management.Automation.ErrorRecord]::new(
        $exception,
        'ActiveDirectoryServer:8480,Microsoft.ActiveDirectory.Management.Commands.GetADUser',
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $null)
    throw $record
}

function Copy-FakeObject([object]$Object) {
    $copy = [PSCustomObject]@{}
    foreach ($property in $Object.PSObject.Properties) {
        $copy | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
    }
    # The real cmdlet answers the distinguished name of the object
    # under that name, and the model may hold it under 'dn'.
    if ($null -eq $copy.PSObject.Properties['DistinguishedName']) {
        $dn = $Object.PSObject.Properties['dn']
        if ($null -ne $dn) {
            $copy | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value ([string]$dn.Value)
        }
    }
    return $copy
}

function Get-FakeDn([object]$Object) {
    # The distinguished name of an object of the model, under the name
    # the cmdlets use and under the short one.
    $property = $Object.PSObject.Properties['DistinguishedName']
    if ($null -ne $property) { return [string]$property.Value }
    $property = $Object.PSObject.Properties['dn']
    if ($null -ne $property) { return [string]$property.Value }
    return ''
}

function New-FakeRule([object]$Record) {
    $identity = [PSCustomObject]@{ Value = [string]$Record.sid }
    $identity | Add-Member -MemberType ScriptMethod -Name Translate -Value { param($type) return $this }
    $isInherited = $false
    $property = $Record.PSObject.Properties['inherited']
    if ($null -ne $property) { $isInherited = [bool]$property.Value }
    $rule = [PSCustomObject]@{
        IdentityReference = $identity
        ActiveDirectoryRights = [string]$Record.rights
        ObjectType = [string]$Record.objectType
        InheritedObjectType = [string]$Record.inheritedObjectType
        InheritanceType = [string]$Record.inheritanceType
        ObjectFlags = [System.Security.AccessControl.ObjectAceFlags][int]$Record.objectFlags
        AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    }
    # A rule of the model is inherited when the model says so, and
    # explicit otherwise.
    $rule | Add-Member -MemberType NoteProperty -Name 'IsInherited' -Value $isInherited
    return $rule
}

function ConvertTo-FakeByteArray([object]$Value) {
    # The schemaIDGUID of the directory is a byte array: the first
    # three fields of the GUID are little endian and the last eight
    # bytes are as they are.  The model holds the bytes, and the fake
    # answers them as a byte array.
    $bytes = New-Object 'System.Byte[]' 16
    for ($index = 0; $index -lt 16; $index++) {
        $bytes[$index] = [byte]$Value[$index]
    }
    # The comma keeps the array whole: PowerShell unrolls a collection
    # that a function writes out.
    return ,$bytes
}

function Get-FakeSchemaGuid([string]$DisplayName) {
    foreach ($object in @($script:FakeModel.schema)) {
        if ([string]$object.lDAPDisplayName -eq $DisplayName) {
            return ([guid][byte[]]$object.schemaIDGUID).ToString()
        }
    }
    return ''
}

function Get-FakeExtendedRightGuid([string]$RightName) {
    # The GUID of an extended right, by the name the ace of dsacls
    # carries.  The ace carries the DISPLAY name of the right ("Reset
    # Password"), and that form was measured to work.  The
    # name of the object is its CN ("User-Force-Change-Password"), and
    # the lookup of the script is by that name, so the fake
    # answers to the display name and to the name.
    #
    # The extended rights live under CN=Extended-Rights, and they are
    # not objects of the schema: a search of the schema finds nothing
    # at all.
    foreach ($object in @($script:FakeModel.objects)) {
        $guid = $object.PSObject.Properties['rightsGuid']
        if ($null -eq $guid) { continue }
        foreach ($key in @('displayName', 'name')) {
            $property = $object.PSObject.Properties[$key]
            if ($null -eq $property) { continue }
            if ([string]$property.Value -eq $RightName) { return [string]$guid.Value }
        }
    }
    return ''
}

function Get-FakeFlag([string]$Name) {
    # The flag of the model, and false when the model does not hold it.
    $property = $script:FakeModel.PSObject.Properties[$Name]
    if ($null -eq $property) { return $false }
    return [bool]$property.Value
}

function Resolve-FakeSharePath([string]$Path) {
    # The local file of a path of the SYSVOL share of the PDC, and
    # nothing for every other path.  The path of the share is
    # \\<server>\SYSVOL\<domain>\Policies\{<guid>}\<the rest>, and the
    # share of the name of the domain is not one of them: the fake has
    # no share for it.
    if (-not $Path) { return $null }
    if ($Path -notmatch '^\\\\[^\\]+\\SYSVOL\\[^\\]+\\Policies\\\{[^}]+\}(.*)$') { return $null }
    if (-not $script:FakePolicyDir) { return $null }
    $rest = $Matches[1]
    if (-not $rest) { return $script:FakePolicyDir }
    $rest = ($rest -replace '\\', '/') -replace '^/', ''
    return (Join-Path $script:FakePolicyDir $rest)
}

function Get-FakeRules([string]$Dn) {
    if (-not $script:FakeAclRules.ContainsKey($Dn)) { return @() }
    $rules = @()
    foreach ($record in @($script:FakeAclRules[$Dn])) { $rules += (New-FakeRule $record) }
    return $rules
}

function Get-FakeDescriptor([string]$Dn) {
    $rules = @(Get-FakeRules $Dn)
    $descriptor = [PSCustomObject]@{}
    # The real descriptor answers the explicit rules, the inherited
    # ones, or both.  A rule of the model is inherited when the model
    # says so, and explicit otherwise.
    #
    # The real GetAccessRules takes the inherited rules first and the
    # explicit ones second: ($true, $false) answers every rule of the
    # object, and ($false, $true) answers the explicit rules only.
    $descriptor | Add-Member -MemberType ScriptMethod -Name GetAccessRules -Value {
        param($includeInherited, $explicitOnly, $type)
        $answer = @()
        foreach ($rule in $rules) {
            $isInherited = [bool]$rule.IsInherited
            if ($isInherited) {
                if ($explicitOnly) { continue }
                if (-not $includeInherited) { continue }
            }
            $answer += $rule
        }
        return $answer
    }.GetNewClosure()
    return $descriptor
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$SearchBase,
        [string]$SearchScope,
        [string]$Filter,
        [string]$LDAPFilter,
        [string[]]$Properties
    )
    Add-FakeCall 'Get-ADObject' @{
        identity = $Identity; searchBase = $SearchBase; searchScope = $SearchScope
        filter = $Filter; ldapFilter = $LDAPFilter; properties = $Properties
    }
    if ((Test-FakeTokenGroupsRequest $Properties) -and ([string]$SearchScope -ne 'Base')) {
        # The tokenGroups of an object is a constructed attribute, and
        # the directory gives it only to a base search.
        Stop-FakeTokenGroupsRead
    }
    if ($Identity) {
        $object = $null
        foreach ($candidate in @($script:FakeModel.objects)) {
            if ((Get-FakeDn $candidate) -eq $Identity) { $object = $candidate; break }
        }
        if ($null -eq $object) {
            foreach ($candidate in @($script:FakeModel.users)) {
                if ((Get-FakeDn $candidate) -eq $Identity) { $object = $candidate; break }
            }
        }
        if ($null -eq $object) { throw ('the object was not found: ' + $Identity) }
        $copy = Copy-FakeObject $object
        $copy | Add-Member -MemberType NoteProperty -Name 'nTSecurityDescriptor' -Value (Get-FakeDescriptor $Identity)
        return $copy
    }
    $found = @()
    if ($LDAPFilter -match '^\(lDAPDisplayName=(.+)\)$') {
        $displayName = $Matches[1]
        foreach ($candidate in @($script:FakeModel.schema)) {
            if ([string]$candidate.lDAPDisplayName -eq $displayName) {
                $copy = Copy-FakeObject $candidate
                # The real cmdlet answers the schemaIDGUID as a byte
                # array and not as a string.
                $copy.schemaIDGUID = ConvertTo-FakeByteArray $candidate.schemaIDGUID
                $found += $copy
            }
        }
        return $found
    }
    # A search under a base: the objects of the model that are under
    # it, the way the real cmdlet answers them.  The base is the
    # search base of the search, and the scope says how deep it goes:
    # 'Base' is the object of the base itself, 'OneLevel' is the
    # objects below the base that are not below another object of the
    # base, and 'Subtree' is every object below it.
    $class = ''
    if ($LDAPFilter -match 'objectClass=([A-Za-z0-9-]+)') { $class = $Matches[1] }
    $base = [string]$SearchBase
    $scope = [string]$SearchScope
    $oneLevel = $scope -eq 'OneLevel'
    # The accounts of the model are objects of the directory too: a
    # base search of the account of the write account finds it here.
    $candidates = @()
    foreach ($candidate in @($script:FakeModel.objects)) { $candidates += $candidate }
    foreach ($candidate in @($script:FakeModel.users)) { $candidates += $candidate }
    foreach ($candidate in $candidates) {
        $dn = Get-FakeDn $candidate
        if ($base) {
            if ($dn -eq $base) {
                if ($oneLevel) { continue }
            } else {
                if ($scope -eq 'Base') { continue }
                # A descendant of the base holds the base at the end of
                # its distinguished name.
                $suffix = ',' + $base
                if (-not $dn.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                if ($oneLevel) {
                    # 'OneLevel' is the objects below the base that are
                    # not below another object of the base.
                    $rest = $dn.Substring(0, $dn.Length - $suffix.Length)
                    if ($rest.Contains(',')) { continue }
                }
            }
        }
        if ($class) {
            $classes = @()
            $classProperty = $candidate.PSObject.Properties['objectClass']
            if ($null -ne $classProperty) { $classes = @($classProperty.Value) }
            $namedProperty = $candidate.PSObject.Properties['class']
            $named = ''
            if ($null -ne $namedProperty) { $named = [string]$namedProperty.Value }
            if (($classes -notcontains $class) -and ($named -ne $class)) { continue }
        }
        $copy = Copy-FakeObject $candidate
        # The real cmdlet answers the security descriptor of the object
        # when the caller asks for it.
        $copy | Add-Member -MemberType NoteProperty -Name 'nTSecurityDescriptor' -Value (Get-FakeDescriptor (Get-FakeDn $candidate))
        $found += $copy
    }
    return $found
}

function Get-ADUser {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Filter,
        [string[]]$Properties
    )
    Add-FakeCall 'Get-ADUser' @{ identity = $Identity; filter = $Filter; properties = $Properties }
    if (Test-FakeTokenGroupsRequest $Properties) {
        # The cmdlet is never a base search, and the directory gives the
        # tokenGroups of an object only to a base search.
        Stop-FakeTokenGroupsRead
    }
    # The cmdlet answers the default property set and the properties it
    # is asked for, and nothing else: userAccountControl is NOT in the
    # default property set.
    $wanted = @('DistinguishedName', 'SID', 'SamAccountName', 'Name')
    if ($Properties) { $wanted += @($Properties) }
    $found = @()
    foreach ($user in @($script:FakeModel.users)) {
        if ($Identity -and [string]$user.sam -ne $Identity) { continue }
        if ($Filter -and ($Filter -notlike ('*' + [string]$user.sam + '*'))) { continue }
        $copy = [PSCustomObject]@{}
        foreach ($name in $wanted) {
            $property = $user.PSObject.Properties[$name]
            if ($null -ne $property) {
                $copy | Add-Member -MemberType NoteProperty -Name $name -Value $property.Value
            }
        }
        $found += $copy
    }
    return $found
}

function New-ADUser {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$SamAccountName,
        [string]$UserPrincipalName,
        [object]$AccountPassword,
        [bool]$Enabled,
        [bool]$PasswordNeverExpires
    )
    Add-FakeCall 'New-ADUser' @{
        name = $Name; sam = $SamAccountName; upn = $UserPrincipalName
        enabled = $Enabled; passwordNeverExpires = $PasswordNeverExpires
    }
    # The account is there after the cmdlet: the script reads it again.
    $newTokenGroups = @()
    $tokenProperty = $script:FakeModel.newUser.PSObject.Properties['tokenGroups']
    if ($null -ne $tokenProperty) { $newTokenGroups = @($tokenProperty.Value) }
    $script:FakeModel.users += [PSCustomObject]@{
        sam = $SamAccountName
        SamAccountName = $SamAccountName
        Name = $SamAccountName
        DistinguishedName = [string]$script:FakeModel.newUser.DistinguishedName
        SID = [string]$script:FakeModel.newUser.SID
        userAccountControl = 512
        tokenGroups = $newTokenGroups
    }
    return $null
}

function Set-ADObject {
    [CmdletBinding()]
    param(
        [string]$Identity,
        [hashtable]$Replace
    )
    Add-FakeCall 'Set-ADObject' @{ identity = $Identity; replace = $Replace }
}

function Get-ADRootDSE {
    [CmdletBinding()]
    param([string[]]$Properties)
    Add-FakeCall 'Get-ADRootDSE' @{ properties = $Properties }
    return [PSCustomObject]@{ dsServiceName = [string]$script:FakeModel.roleOwner }
}

function Get-ADDomain {
    [CmdletBinding()]
    param()
    # The PDCEmulator is the FQDN of the controller that holds the
    # role, as measured on WSBXDC1.win2.newton.test.
    $pdc = ([string]$script:FakeModel.computerName).ToLowerInvariant() + '.' + [string]$script:FakeModel.domain
    $property = $script:FakeModel.PSObject.Properties['pdcEmulator']
    if ($null -ne $property) { $pdc = [string]$property.Value }
    return [PSCustomObject]@{
        DNSName = [string]$script:FakeModel.domain
        NetBIOSName = [string]$script:FakeModel.netbios
        DistinguishedName = [string]$script:FakeModel.domainDn
        PDCEmulator = $pdc
    }
}

function Get-ADComputer {
    [CmdletBinding()]
    param([string]$Identity)
    Add-FakeCall 'Get-ADComputer' @{ identity = $Identity }
    return [PSCustomObject]@{
        Name = [string]$script:FakeModel.computerName
        DistinguishedName = [string]$script:FakeModel.computerDn
    }
}

function dsacls {
    $arguments = @()
    foreach ($argument in $args) { $arguments += [string]$argument }
    [void]$script:FakeDsacls.Add($arguments)
    $global:LASTEXITCODE = 0
    # A call that fails: the exit code of the model is the one of the
    # real dsacls, and the reason is on the error stream.
    $failure = 0
    $failureProperty = $script:FakeModel.PSObject.Properties['dsaclsExit']
    if ($null -ne $failureProperty) { $failure = [int]$failureProperty.Value }
    if ($failure -ne 0) {
        $global:LASTEXITCODE = $failure
        Write-Output 'dsacls: the access control list of the object could not be read'
        return
    }
    if (-not $script:FakeModel.dsaclsWorks) { return }
    $path = $arguments[0]
    $inheritance = 'None'
    $spec = $null
    for ($index = 1; $index -lt $arguments.Count; $index++) {
        if ($arguments[$index] -eq '/I:S') { $inheritance = 'Descendents' }
        if ($arguments[$index] -eq '/I:T') { $inheritance = 'All' }
        if ($arguments[$index] -eq '/G') { $spec = $arguments[$index + 1] }
    }
    if ($null -eq $spec) { $global:LASTEXITCODE = 87; return }
    # The ace is <SID>:<right>[;<attribute>;<class>].
    $fields = $spec.Split(';')
    $trustee = $fields[0].Split(':')
    $sid = $trustee[0]
    $rights = $trustee[1]
    $record = [ordered]@{ sid = $sid }
    if ($rights -eq 'WP') {
        $record['rights'] = 'WriteProperty'
        $record['objectType'] = (Get-FakeSchemaGuid $fields[1])
        if ($fields.Count -gt 2) {
            $record['inheritedObjectType'] = (Get-FakeSchemaGuid $fields[2])
            $record['objectFlags'] = 3
        } else {
            $record['inheritedObjectType'] = '00000000-0000-0000-0000-000000000000'
            $record['objectFlags'] = 1
        }
        $record['inheritanceType'] = $inheritance
    } elseif ($rights -eq 'CA') {
        # An extended right: the right of a password reset, with the
        # class of the objects it is inherited to.  The GUID of the
        # right is the one of the extended rights of the domain.
        $record['rights'] = 'ExtendedRight'
        $record['objectType'] = (Get-FakeExtendedRightGuid $fields[1])
        $record['inheritedObjectType'] = (Get-FakeSchemaGuid $fields[2])
        $record['objectFlags'] = 3
        $record['inheritanceType'] = $inheritance
    } else {
        $record['rights'] = 'CreateChild, DeleteChild'
        $record['objectType'] = (Get-FakeSchemaGuid $fields[1])
        $record['inheritedObjectType'] = '00000000-0000-0000-0000-000000000000'
        $record['objectFlags'] = 1
        $record['inheritanceType'] = $inheritance
    }
    if (-not $script:FakeAclRules.ContainsKey($path)) {
        $script:FakeAclRules[$path] = New-Object System.Collections.ArrayList
    }
    [void]$script:FakeAclRules[$path].Add([PSCustomObject]$record)
    # The real dsacls prints the whole access control list of the
    # object it was given: a line for the object and a line for every
    # rule it holds.
    Write-Output $path
    foreach ($rule in @(Get-FakeRules $path)) {
        Write-Output ('    ' + [string]$rule.IdentityReference.Value + ':(A;;' + [string]$rule.ActiveDirectoryRights + ';' + [string]$rule.ObjectType + ';;' + [string]$rule.InheritedObjectType + ')')
    }
}

# The error of the cmdlet when the session has no network credentials.
# The line is the one read on the real controller over an
# SSH key login (an S4U logon): the same code had passed over a key
# login earlier the same day, so the cmdlet is unreliable over such a
# session and not always refused.
$script:FakeBackupGpoMessage = 'Backup-GPO : Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))'

function Stop-FakeBackupGpo {
    # The refusal of the cmdlet: the run stops with the measured
    # error.
    [Console]::Error.WriteLine($script:FakeBackupGpoMessage)
    $exception = [System.Exception]::new($script:FakeBackupGpoMessage)
    $record = [System.Management.Automation.ErrorRecord]::new(
        $exception,
        'Microsoft.PowerShell.Commands.BackupGPOCommand',
        [System.Management.Automation.ErrorCategory]::PermissionDenied,
        $null)
    throw $record
}

function Backup-GPO {
    [CmdletBinding()]
    param([string]$Guid, [string]$Path, [string]$Server)
    Add-FakeCall 'Backup-GPO' @{ guid = $Guid; path = $Path; server = $Server }
    if (Get-FakeFlag 'backupGpoAccessDenied') {
        Stop-FakeBackupGpo
    }
    # The real cmdlet answers the policy it backed up.
    return [PSCustomObject]@{
        DisplayName = 'Default Domain Controllers Policy'
        Guid = $Guid
        Path = $Path
    }
}

function Get-GPO {
    [CmdletBinding()]
    param([string]$Guid, [string]$Server)
    Add-FakeCall 'Get-GPO' @{ guid = $Guid; server = $Server }
    $version = 0
    foreach ($object in @($script:FakeModel.objects)) {
        $property = $object.PSObject.Properties['versionNumber']
        if ($null -ne $property) { $version = [int]$property.Value }
    }
    return [PSCustomObject]@{
        Id = $Guid
        DisplayName = 'Default Domain Controllers Policy'
        VersionNumber = $version
        GpoFileSysPath = $script:FakePolicyPath
    }
}

function gpupdate {
    $global:LASTEXITCODE = 0
}

function secedit {
    $global:LASTEXITCODE = 0
    foreach ($argument in $args) {
        if ([string]$argument -eq '/cfg') { continue }
        if ([string]$argument -like '*:*') { continue }
        if ([string]$argument -like 'USER_RIGHTS') { continue }
        if ([string]$argument -like '/areas') { continue }
        if ([string]$argument -like '/export') { continue }
        if ([string]$argument -like '/quiet') { continue }
        [System.IO.File]::WriteAllText(
            [string]$argument, [string]$script:FakeModel.userRights,
            (New-Object System.Text.UTF8Encoding($false)))
    }
}

# The three cmdlets of the file system.  A path of the SYSVOL share of
# the PDC is served from the folder of the sandbox that stands for it,
# and every path of the machine is left to the real cmdlet.
#
# The read of the share is the one the session without network
# credentials cannot do: the model holds the flag that makes it throw
# the way the measured share answered, E_ACCESSDENIED.

function Get-Content {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)][string[]]$Path,
        [string[]]$LiteralPath,
        [string]$Encoding,
        [switch]$Raw
    )
    $target = ''
    if ($LiteralPath) { $target = [string]$LiteralPath[0] }
    elseif ($Path) { $target = [string]$Path[0] }
    $local = Resolve-FakeSharePath $target
    if ($null -eq $local) {
        & $script:RealGetContent @PSBoundParameters
        return
    }
    [void]$script:FakeReads.Add($target)
    if (Get-FakeFlag 'sysvolAccessDenied') {
        throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
    }
    if (-not (& $script:RealTestPath -LiteralPath $local)) {
        throw (New-Object System.IO.FileNotFoundException('The file was not found.'))
    }
    if ($Encoding) {
        & $script:RealGetContent -LiteralPath $local -Encoding $Encoding -Raw:$Raw
    } else {
        & $script:RealGetContent -LiteralPath $local -Raw:$Raw
    }
}

function Set-Content {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Path,
        [Parameter(Position = 1, ValueFromPipeline = $true)][object[]]$Value,
        [string[]]$LiteralPath,
        [string]$Encoding
    )
    $target = ''
    if ($LiteralPath) { $target = [string]$LiteralPath[0] }
    elseif ($Path) { $target = [string]$Path[0] }
    $local = Resolve-FakeSharePath $target
    if ($null -eq $local) {
        & $script:RealSetContent @PSBoundParameters
        return
    }
    [void]$script:FakeWrites.Add($target)
    if (Get-FakeFlag 'sysvolAccessDenied') {
        throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
    }
    $folder = Split-Path -Parent $local
    if ($folder -and -not (& $script:RealTestPath -LiteralPath $folder)) {
        $null = New-Item -ItemType Directory -Path $folder -Force
    }
    if ($Encoding) {
        & $script:RealSetContent -LiteralPath $local -Value $Value -Encoding $Encoding
    } else {
        & $script:RealSetContent -LiteralPath $local -Value $Value
    }
}

function Test-Path {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string[]]$Path,
        [string[]]$LiteralPath,
        [string]$PathType
    )
    $target = ''
    if ($LiteralPath) { $target = [string]$LiteralPath[0] }
    elseif ($Path) { $target = [string]$Path[0] }
    $local = Resolve-FakeSharePath $target
    if ($null -eq $local) {
        & $script:RealTestPath @PSBoundParameters
        return
    }
    [void]$script:FakeReads.Add($target)
    if (Get-FakeFlag 'sysvolAccessDenied') { return $false }
    return (& $script:RealTestPath -LiteralPath $local)
}
