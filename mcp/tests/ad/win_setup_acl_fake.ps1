# The fake of the access control lists of the file system, and the
# install check of the Windows write helper.
#
# The rules of Test-NewtonSafeAcl and of Test-NewtonRightsWritable are
# the ones of the write helper (write.ps1): the
# helper is not in this tree, so the rules are copied here and the
# fake models the access control list they read.  The copy is the
# rule of the helper, and a change of the helper is a change of this
# file.
#
# The fake of New-Object answers the two types of the Windows access
# control lists, which cannot be built off Windows: the real ones are
# refused by the runtime of PowerShell on Linux.

$script:AllowedWriteSids = @('S-1-5-32-544', 'S-1-5-18')
$script:FakeAcls = @{}

function New-FakeSid([string]$Value) {
    $sid = [PSCustomObject]@{ Value = $Value }
    $sid | Add-Member -MemberType ScriptMethod -Name Translate -Value { param($type) return $this }
    return $sid
}

function New-FakeRule([string]$Sid, [string]$Rights, [string]$Inheritance = '', [string]$Propagation = '') {
    # The rule of the file system.  The flags of the inheritance and of
    # the propagation are held as they are given: a rule that inherits
    # nothing and a rule that inherits the children are not the same
    # rule, and a test has to be able to tell them apart.
    return [PSCustomObject]@{
        IdentityReference = (New-FakeSid $Sid)
        FileSystemRights = [System.Security.AccessControl.FileSystemRights]$Rights
        AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        InheritanceFlags = $Inheritance
        PropagationFlags = $Propagation
    }
}

function New-FakeAcl {
    $acl = [PSCustomObject]@{
        Access = New-Object System.Collections.ArrayList
        Owner = ''
        Protected = $false
    }
    $acl | Add-Member -MemberType ScriptMethod -Name SetAccessRuleProtection -Value {
        param($protect, $preserve)
        $this.Protected = [bool]$protect
    }.GetNewClosure()
    $acl | Add-Member -MemberType ScriptMethod -Name RemoveAccessRule -Value {
        param($rule)
        [void]$this.Access.Remove($rule)
    }.GetNewClosure()
    $acl | Add-Member -MemberType ScriptMethod -Name SetOwner -Value {
        param($owner)
        $this.Owner = [string]$owner.Value
    }.GetNewClosure()
    $acl | Add-Member -MemberType ScriptMethod -Name AddAccessRule -Value {
        param($rule)
        [void]$this.Access.Add($rule)
    }.GetNewClosure()
    return $acl
}

function Get-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath)
    if (-not $script:FakeAcls.ContainsKey($LiteralPath)) {
        $acl = New-FakeAcl
        # The rules a folder of ProgramData inherits: every local user
        # may write in it.
        [void]$acl.Access.Add((New-FakeRule 'S-1-5-32-545' 'Modify'))
        $script:FakeAcls[$LiteralPath] = $acl
    }
    return $script:FakeAcls[$LiteralPath]
}

function Set-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath, [object]$AclObject)
    $script:FakeAcls[$LiteralPath] = $AclObject
}

function New-Object {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$TypeName,
        [Parameter(Position = 1)][object[]]$ArgumentList
    )
    if ($TypeName -eq 'System.Security.Principal.SecurityIdentifier') {
        return (New-FakeSid ([string]$ArgumentList[0]))
    }
    if ($TypeName -eq 'System.Security.AccessControl.FileSystemAccessRule') {
        # The identity of the rule is a SID object, and it may be the
        # SID of an account of the directory, which the fake holds as
        # its text.
        $identity = $ArgumentList[0]
        if ($identity -is [string]) { $identity = (New-FakeSid $identity) }
        $inheritance = ''
        if ($ArgumentList.Count -gt 2) { $inheritance = [string]$ArgumentList[2] }
        $propagation = ''
        if ($ArgumentList.Count -gt 3) { $propagation = [string]$ArgumentList[3] }
        return (New-FakeRule ([string]$identity.Value) ([string]$ArgumentList[1]) $inheritance $propagation)
    }
    Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

function Test-NewtonRightsWritable {
    # Only the write-type rights named by SPEC section 8.  Aggregate masks
    # such as Modify and FullControl also contain read bits and are not used.
    param($Rights)
    $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    return (([int64]$Rights -band [int64]$writeMask) -ne 0)
}

function Test-NewtonSafeAcl {
    # The ACL of the install grants write access to nobody except SYSTEM and
    # Administrators (SPEC section 8).
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $null
        try {
            $sid = [string]$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $false
        }
        if ($script:AllowedWriteSids -contains $sid) { continue }
        if (Test-NewtonRightsWritable $rule.FileSystemRights) { return $false }
    }
    return $true
}

function Test-NewtonInstall {
    # The install of the helper: the files are there and nobody but SYSTEM
    # and Administrators may write them.
    $root = $env:NEWTON_FAKE_ROOT
    if (-not (Test-Path -LiteralPath $root)) { return 'unavailable' }
    foreach ($path in @($env:NEWTON_FAKE_KEY, $env:NEWTON_FAKE_DEVICE)) {
        if (-not (Test-Path -LiteralPath $path)) { return 'unavailable' }
    }
    try {
        foreach ($path in @($root, $env:NEWTON_FAKE_KEY, $env:NEWTON_FAKE_DEVICE)) {
            if (-not (Test-NewtonSafeAcl $path)) { return 'denied' }
        }
    } catch {
        return 'denied'
    }
    return ''
}
