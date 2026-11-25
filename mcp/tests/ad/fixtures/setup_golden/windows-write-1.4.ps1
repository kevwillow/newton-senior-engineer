# Newton's Active Directory write setup (Windows).
# Device: windc1   Host: windc1.win.newton.test   Domain: win.newton.test
#
# Read this script, then run it as a Domain Admin on the domain
# controller.  Every step is idempotent: running it a second time
# changes nothing the second time.
#
# The policy of the PDC is edited in the share of the SYSVOL of the
# PDC, and the backup of it is made on the PDC: the share of the name
# of the domain may be served by another controller, and the policy of
# the PDC is not there.
#
# An SSH key login is an S4U logon: it holds no ticket of the domain.
# Measured on the real PDC on 2026-11-09, in such a session the read of
# the GPT.INI of the policy answered and the write of its template
# answered, and Backup-GPO answered "Access is denied"
# (E_ACCESSDENIED), while the same code had passed over a key login
# earlier the same day.  The backup of a policy over an S4U session is
# unreliable, and the read of the GPT.INI does not promise it.
#
# The step 0 therefore reads the GPT.INI of the policy through the
# share of the PDC and backs the policy up itself, before any change:
# the step 6 uses that backup.  A run that cannot back the policy up
# stops in the step 0.  The run needs a session with network
# credentials: an interactive logon, or a remote logon made with a
# password.
#
# The pre-checks come first and they change nothing in the domain.  A
# run that stops in them leaves the domain as it was: the backup they
# take is a file on the disk of the controller.
#
# The delegation runs on the PDC only: the other domain controllers
# replicate it, so a run on another controller changes nothing there.
#
# The delegation of every delegated location holds one right more, for
# the CREATOR OWNER (S-1-3-0): the right of a password
# reset (Reset Password), on the user objects of the location.  A
# user-create with a secret sets unicodePwd, and the directory checks
# the right of a password reset of the creator of the object.  The
# right is granted to the CREATOR OWNER and not to newton-ops:
# newton-ops may then set the password of the accounts it creates, and
# of no other account, and a password reset is a change Newton never
# makes itself.
#
# That right is found by the CN of its object (User-Force-Change-
# Password), not by its display name (Reset Password): the name of an
# object of the directory is its CN, and a lookup by the display name
# finds nothing at all.  The script checks the display name and the
# GUID of the object before it uses the GUID, and it refuses when they
# are not the measured ones.
#
# The sshd restart is the last step, through a one-shot SYSTEM task: a
# restart of sshd that is a child of this session dies with the
# session.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Domain = 'win.newton.test'
$Device = 'windc1'
$DomainDevice = 'windc1'
$WriteHost = 'windc1.win.newton.test'
$OpsName = 'newton-ops'
$AuditName = 'newton-audit'
$DomainDn = 'DC=win,DC=newton,DC=test'
$DcOuDn = 'OU=Domain Controllers,DC=win,DC=newton,DC=test'
$CreatorOwnerSid = 'S-1-3-0'
# The container of the extended rights of this domain.  The right of a
# password reset lives there: it is not an object of the schema, and
# a search of the schema finds nothing at all.
$ExtendedRightsDn = 'CN=Extended-Rights,CN=Configuration,' + $DomainDn
$DelegatedOus = @(
    'OU=Users,DC=win,DC=newton,DC=test'
    'OU=IT Staff,DC=win,DC=newton,DC=test'
)
$AdDir = 'C:\ProgramData\Newton\ad'
$TxDir = 'C:\ProgramData\Newton\ad\tx'
$HelperPath = 'C:\ProgramData\Newton\ad\write.ps1'
$ApprovalKeyPath = 'C:\ProgramData\Newton\ad\approval.key'
$DeviceFilePath = 'C:\ProgramData\Newton\ad\device.txt'
$AuthorizedKeysPath = 'C:\ProgramData\Newton\ad\write_authorized_keys'
$SshdConfig = 'C:\ProgramData\ssh\sshd_config'
$SshdBackup = 'C:\ProgramData\ssh\sshd_config.bak-newton-write'
$RestartTask = 'Newton-Ad-Write-SshdRestart'
$BlockMarker = '# newton-ad write'
$GpoBackupRoot = 'C:\ProgramData\Newton\ad\gpo-backup'
$DefaultDcPolicyGuid = '6AC1786C-016F-11D2-945F-00C04fB984F9'
# The PDC of the domain, by its FQDN.  It is the answer of
# (Get-ADDomain).PDCEmulator.
$PdcServer = [string](Get-ADDomain).PDCEmulator
# The folder of the Default Domain Controllers Policy in the share of
# the SYSVOL of the PDC.  The share of the name of the domain is not
# used: it may be served by another controller.
$PdcPolicyDir = '\\' + $PdcServer + '\SYSVOL\' + $Domain + '\Policies\{' + $DefaultDcPolicyGuid + '}'
$GptIniPath = $PdcPolicyDir + '\GPT.INI'
$GptTmplPath = $PdcPolicyDir + '\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'


# The helpers of this script.  They are here, and not in the middle of
# a step, so that a step reads as the steps of the contract.

function Get-DnParent([string]$Dn) {
    # The parent of a distinguished name: everything after the first
    # comma that is not escaped.  A comma of a name is written "\,".
    $escaped = $false
    for ($index = 0; $index -lt $Dn.Length; $index++) {
        $character = $Dn[$index]
        if ($escaped) { $escaped = $false; continue }
        if ($character -eq '\') { $escaped = $true; continue }
        if ($character -eq ',') { return $Dn.Substring($index + 1) }
    }
    return ''
}

function Test-PrivilegedSid([string]$Sid) {
    # The privileged set of SPEC-1.4 section 5: the relative
    # identifiers of the privileged groups of any domain of the forest,
    # and the privileged groups of the builtin domain.  The tokenGroups
    # of an account are transitive, so a group that is nested in a
    # privileged group is in the list too.
    foreach ($builtin in @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-32-552')) {
        if ($Sid -eq $builtin) { return $true }
    }
    if (-not $Sid.StartsWith('S-1-5-21-')) { return $false }
    $parts = $Sid.Split('-')
    if ($parts.Count -lt 5) { return $false }
    $rid = 0
    if (-not [int]::TryParse($parts[$parts.Count - 1], [ref]$rid)) { return $false }
    foreach ($privileged in @(498, 512, 516, 518, 519, 520, 521, 525, 526, 527)) {
        if ($rid -eq $privileged) { return $true }
    }
    return $false
}

function Get-SchemaGuid([string]$SchemaDn, [string]$DisplayName, [string]$Class) {
    # The GUID of a schema object, read by its LDAP display name.  The
    # name of a schema object is its CN ("User-Account-Control") and
    # the display name is the one the directory uses
    # ("userAccountControl"), so the name never finds the object.
    # Only the objects that are needed are read.
    #
    # The schemaIDGUID of the directory is a BYTE ARRAY and not a
    # string: a string of it is "104 122 150 191 230 13 208 17 162
    # 133 0 170 0 48 73 226", and it never matches the GUID of the
    # rule of an object.  The bytes are turned into a GUID, and the
    # GUID is what is kept.
    if (-not (Test-Path 'variable:script:NewtonSchemaGuids')) {
        $script:NewtonSchemaGuids = @{}
    }
    $key = $Class + '|' + $DisplayName
    if ($script:NewtonSchemaGuids.ContainsKey($key)) {
        return [string]$script:NewtonSchemaGuids[$key]
    }
    $objects = @(Get-ADObject -SearchBase $SchemaDn -SearchScope Subtree -LDAPFilter "(lDAPDisplayName=$DisplayName)" -Properties schemaIDGUID, objectClass)
    foreach ($object in $objects) {
        if (@($object.objectClass) -contains $Class) {
            $script:NewtonSchemaGuids[$key] = ([guid][byte[]]$object.schemaIDGUID).ToString()
            return [string]$script:NewtonSchemaGuids[$key]
        }
    }
    throw ('the schema of this domain holds no ' + $Class + ' named ' + $DisplayName)
}

function Get-AclRules([string]$Dn) {
    # The rules of the access control list of an object of the
    # directory.  The rules are read as objects and not as SDDL text:
    # the text prints the masks as letters and the trustees as names,
    # and a comparison of that text never matches.
    #
    # GetAccessRules takes the inherited rules first and the explicit
    # ones second: ($true, $false) answers every rule of the object.
    $object = Get-ADObject -Identity $Dn -Properties nTSecurityDescriptor
    return @($object.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
}

function Get-DelegatedObjects([string]$Ou) {
    # The objects below a delegated location, with the rules of their
    # access control lists.  The guard of the right of a password reset
    # reads them: an account that holds the right on an object below
    # the location holds it on that object.
    $found = @()
    foreach ($object in @(Get-ADObject -SearchBase $Ou -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties nTSecurityDescriptor)) {
        if ([string]$object.DistinguishedName -eq $Ou) { continue }
        $found += $object
    }
    return $found
}

function Get-ResetPasswordGuid([string]$ExtendedRightsDn) {
    # The GUID of the right of a password reset, read from the
    # extended rights of this domain.  The rights that are not rights
    # of the schema live under CN=Extended-Rights, and a search of the
    # schema finds nothing at all.
    #
    # The right is found by its CN ("User-Force-Change-Password"): the
    # name of the object is its CN, and the display name of the object
    # is another attribute, so a lookup by the display name finds
    # nothing at all.  Measured on the real
    # controller: "by name Reset Password: 0".
    #
    # The object is checked before its GUID is used: the display name
    # and the GUID have to be the measured ones, or the run is refused.
    # A right with another GUID is not the right of a password reset.
    foreach ($right in @(Get-ADObject -SearchBase $ExtendedRightsDn -SearchScope OneLevel -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGuid, displayName)) {
        if ([string]$right.name -ne 'User-Force-Change-Password') { continue }
        $displayName = $right.PSObject.Properties['displayName']
        $shown = ''
        if ($null -ne $displayName) { $shown = [string]$displayName.Value }
        if ($shown -ne 'Reset Password') {
            throw ('the right of a password reset of this domain has the display name "' + $shown + '" and not "Reset Password"')
        }
        $guid = $right.PSObject.Properties['rightsGuid']
        if ($null -eq $guid) {
            throw 'the right of a password reset of this domain holds no GUID'
        }
        $value = ([string]$guid.Value).ToLowerInvariant()
        if ($value -ne '00299570-246d-11d0-a768-00aa006e0529') {
            throw ('the right of a password reset of this domain has the GUID "' + $value + '" and not "00299570-246d-11d0-a768-00aa006e0529"')
        }
        return $value
    }
    throw 'the extended rights of this domain hold no right named User-Force-Change-Password'
}

function Test-NoResetPasswordRule([string]$Dn, [object[]]$Rules, [string[]]$TrusteeSids, [string]$ResetGuid, [string]$Ou) {
    # The rules of one object, and the right of a password reset.  The
    # rules are read as objects and not as SDDL text: the text prints
    # the trustees as names, and a comparison of that text never
    # matches.
    foreach ($rule in $Rules) {
        if ($TrusteeSids -notcontains [string]$rule.IdentityReference.Value) { continue }
        if ([string]$rule.AccessControlType -ine 'Allow') { continue }
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$rule.ActiveDirectoryRights
        $genericAll = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
        $extended = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)
        $objectType = ([string]$rule.ObjectType).ToLowerInvariant()
        $allExtended = ($objectType -eq ([System.Guid]::Empty).ToString())
        if (-not ($genericAll -or ($extended -and (($objectType -eq $ResetGuid) -or $allExtended)))) { continue }
        throw ('newton-ops holds an effective right of a password reset on ' + $Dn + ', under the delegated location ' + $Ou + '; fix it before running this script again')
    }
}

function Test-NoResetPasswordRight([string]$Ou, [string[]]$TrusteeSids, [string]$ResetGuid) {
    # The write account may not hold the right of a password reset, and
    # it may not hold it on an object below a delegated location
    # either.  The setup grants that right to the CREATOR OWNER, so
    # that the write account may set the password of the accounts it
    # creates and of no other account: an account that holds the right
    # directly could reset the password of any user of the location,
    # and a password reset is a change Newton never makes itself.
    #
    # The rules of the location are read with the inherited ones: a
    # right that the location inherits is a right that the location
    # holds.  The rules of the objects below it are read without the
    # inherited ones: the CREATOR OWNER of an object that newton-ops
    # creates is newton-ops itself, and that is the scope of the grant,
    # not a refusal.
    #
    # GetAccessRules takes the inherited rules first and the explicit
    # ones second: ($true, $false) answers every rule of the object,
    # and ($false, $true) answers the explicit rules only.
    $location = Get-ADObject -Identity $Ou -Properties nTSecurityDescriptor
    $rules = @($location.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    Test-NoResetPasswordRule $Ou $rules $TrusteeSids $ResetGuid $Ou
    foreach ($object in (Get-DelegatedObjects $Ou)) {
        $dn = [string]$object.DistinguishedName
        $rules = @($object.nTSecurityDescriptor.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]))
        Test-NoResetPasswordRule $dn $rules $TrusteeSids $ResetGuid $Ou
    }
}

function Test-AcePresent([string]$Dn, [string]$Sid, [string]$Rights, [string]$ObjectType, [string]$InheritedType, [string]$InheritanceType) {
    # True when the descriptor holds exactly this rule.  The fields of
    # the rule are the ones measured on the domain controller: the
    # rights, the object type, the inherited object type, the
    # inheritance and the trustee.
    $objectAceType = [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent
    $inheritedObjectAceType = [int][System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent
    foreach ($rule in (Get-AclRules $Dn)) {
        if ([string]$rule.IdentityReference.Value -ne $Sid) { continue }
        if (([string]$rule.ActiveDirectoryRights) -ine $Rights) { continue }
        if (([string]$rule.ObjectType) -ine $ObjectType) { continue }
        if (([string]$rule.InheritedObjectType) -ine $InheritedType) { continue }
        if (([string]$rule.InheritanceType) -ine $InheritanceType) { continue }
        $flags = [int]$rule.ObjectFlags
        if (($flags -band $objectAceType) -eq 0) { continue }
        if ($InheritedType -ne [string][System.Guid]::Empty) {
            if (($flags -band $inheritedObjectAceType) -eq 0) { continue }
        }
        return $true
    }
    return $false
}

function Test-NoReplicationRight([string]$Sid, [string[]]$GroupSids) {
    # The account may hold no right that replicates the directory.  The
    # rights that replicate are extended rights: controlAccessRight
    # objects under CN=Extended-Rights,CN=Configuration of this domain.
    # They are not objects of the schema, and a search of the schema
    # finds nothing at all.  No GUID of a schema object is typed in
    # this script.
    $extendedRightsDn = 'CN=Extended-Rights,CN=Configuration,' + $DomainDn
    $wanted = @(
        'DS-Replication-Get-Changes',
        'DS-Replication-Get-Changes-All',
        'DS-Replication-Get-Changes-In-Filtered-Set'
    )
    $found = @{}
    foreach ($right in (Get-ADObject -SearchBase $extendedRightsDn -SearchScope OneLevel -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGuid)) {
        $name = [string]$right.name
        if ($wanted -contains $name) {
            $found[$name] = ([string]$right.rightsGuid).ToLowerInvariant()
        }
    }
    if ($found.Count -lt $wanted.Count) {
        # Rights that could not be read are a refusal and never a pass.
        throw 'the replication rights could not be read from this domain'
    }
    $sids = @($Sid) + @($GroupSids)
    $head = Get-ADObject -Identity $DomainDn -Properties nTSecurityDescriptor
    foreach ($rule in $head.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if (-not $sids.Contains([string]$rule.IdentityReference.Value)) { continue }
        $objectType = ([string]$rule.ObjectType).ToLowerInvariant()
        if ($objectType -and ($found.Values -contains $objectType)) {
            throw 'newton-ops holds a right that replicates the directory; fix it before running this script again'
        }
        if ((-not $objectType) -and (($rule.ActiveRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)) {
            throw 'newton-ops holds every extended right of the head of the domain; fix it before running this script again'
        }
    }
}

function Resolve-NewtonAccountSid([string]$Name) {
    # The SID of an account, by its name.  Windows PowerShell 5.1 only:
    # the translation of a name into a SID is a Windows behaviour, and
    # it is not supported by PowerShell on Linux.
    $account = New-Object System.Security.Principal.NTAccount($Name)
    return [string]$account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Test-BatchLogonRight([string]$RightsFile, [string]$Sid) {
    # True when the SID of the write account is one of the holders of
    # the SeBatchLogonRight, read from the export of secedit.  secedit
    # prints the NAME of an account and the SID of a well known one,
    # so every holder is resolved into a SID.  A line that is not
    # there is a refusal.
    if (-not (Test-Path -LiteralPath $RightsFile)) { return $false }
    $line = $null
    foreach ($text in @(Get-Content -LiteralPath $RightsFile)) {
        if ($text -match '^\s*SeBatchLogonRight\s*=\s*(.*)$') { $line = $Matches[1]; break }
    }
    if ($null -eq $line) { return $false }
    foreach ($holder in ($line -split ',')) {
        $holder = $holder.Trim()
        if (-not $holder) { continue }
        if ($holder.StartsWith('*S-')) {
            if ($holder.Substring(1) -eq $Sid) { return $true }
            continue
        }
        try {
            $resolved = Resolve-NewtonAccountSid $holder
        } catch {
            continue
        }
        if ($resolved -eq $Sid) { return $true }
    }
    return $false
}

function Set-BatchLogonRightInTemplate([string]$Path, [string]$Sid) {
    # The SeBatchLogonRight of the template of a policy: the holders of
    # the right are kept and the SID of the write account is added to
    # them.  The template is UTF-16LE with a BOM and it stays that
    # way, so the policy of the domain is not broken by the edit.
    #
    # The file is read and written with the cmdlets of the file
    # system, so it may live on a share.
    $lines = $null
    try {
        $lines = @(Get-Content -LiteralPath $Path -Encoding Unicode -ErrorAction Stop)
    } catch {
        throw ('the template of the policy is missing or unreadable: ' + $Path)
    }
    $newLines = @()
    $inSection = $false
    $found = $false
    $changed = $false
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith('[')) {
            $inSection = ($trimmed -eq '[Privilege Rights]')
            $newLines += $line
            continue
        }
        if ($inSection -and ($trimmed -match '^(SeBatchLogonRight)\s*=\s*(.*)$')) {
            $found = $true
            $holders = @()
            foreach ($holder in ($Matches[2] -split ',')) {
                $holder = $holder.Trim()
                if ($holder) { $holders += $holder }
            }
            if ($holders -contains ('*' + $Sid)) {
                # The right is already there: the line is kept as it
                # is, and it is never written twice.
                $newLines += $line
            } else {
                $holders += ('*' + $Sid)
                $newLines += ('SeBatchLogonRight = ' + ($holders -join ','))
                $changed = $true
            }
            continue
        }
        $newLines += $line
    }
    if (-not $found) {
        # The line is not there at all: it is added to the section, and
        # the section is added when it is not there either.
        $sectionIndex = -1
        for ($index = 0; $index -lt $newLines.Count; $index++) {
            if ($newLines[$index].Trim() -eq '[Privilege Rights]') { $sectionIndex = $index }
        }
        if ($sectionIndex -lt 0) {
            $newLines += ''
            $newLines += '[Privilege Rights]'
            $newLines += ('SeBatchLogonRight = *' + $Sid)
        } else {
            $inserted = @()
            $inserted += $newLines[0..$sectionIndex]
            $inserted += ('SeBatchLogonRight = *' + $Sid)
            if ($sectionIndex -lt ($newLines.Count - 1)) { $inserted += $newLines[($sectionIndex + 1)..($newLines.Count - 1)] }
            $newLines = $inserted
        }
        $changed = $true
    }
    if ($changed) {
        Set-Content -LiteralPath $Path -Value $newLines -Encoding Unicode | Out-Null
    }
    return $changed
}

function Set-NewtonInstallAcl([string]$Path, [string]$OpsSid, [string]$OpsRights, [string]$Inheritance) {
    # The access control list of a path of the install.  The rules of
    # the path are explicit and the rules it inherits are gone: a
    # folder of ProgramData gives every local user a write, and the
    # helper refuses to answer when it finds one.  Windows PowerShell
    # 5.1 only: the access control list of the file system is a Windows
    # behaviour.
    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($OpsSid)
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $noInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $inherit = [System.Security.AccessControl.InheritanceFlags]$Inheritance
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $acl.SetOwner($administrators)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $inherit, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, $OpsRights, $noInheritance, $none, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Add-NewtonSharedRootRead([string]$Path, [object]$Sid) {
    # The read of the account of the other path of Newton on the
    # shared install root.  The rule is explicit and it inherits
    # nothing: the account reads the root and not the files beside it.
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $noInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Sid, 'ReadAndExecute', $noInheritance, $none, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-ApprovalKeyHex([string]$Passphrase, [string]$DeviceName) {
    # The approval key K: PBKDF2-HMAC-SHA256, the UTF-8 bytes of the
    # passphrase, the salt "newton-approve-v1:" and the device, 600000
    # iterations, 32 bytes.  It is the same key the Newton host derives
    # with derive_k.
    $salt = [System.Text.Encoding]::UTF8.GetBytes('newton-approve-v1:' + $DeviceName)
    $password = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)
    try {
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $bytes = $derive.GetBytes(32)
        return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
    } finally {
        [Array]::Clear($password, 0, $password.Length)
    }
}

function Get-ApprovalFingerprintHex([string]$KeyHex) {
    # The fingerprint of the key: HMAC-SHA256 of the constant message,
    # keyed with the 32 bytes of K.  It is the value the Newton host
    # compares with the one it printed.
    $key = New-Object 'System.Byte[]' ($KeyHex.Length / 2)
    for ($index = 0; $index -lt $key.Length; $index++) {
        $key[$index] = [System.Convert]::ToByte($KeyHex.Substring($index * 2, 2), 16)
    }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
    try {
        $bytes = $hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes('newton-approval-fingerprint-v1'))
        return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
    } finally {
        [Array]::Clear($key, 0, $key.Length)
    }
}


Write-Host 'Step 0: the pre-checks'

# The script must run with an Administrator token.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'this script must run elevated, as an Administrator'
}

# This host must be a domain controller of the domain the setup names.
$localDomain = Get-ADDomain
if ($localDomain.DNSName -ne $Domain) {
    throw ('this host is a domain controller of ' + $localDomain.DNSName + ', not of ' + $Domain)
}
$computer = $null
try { $computer = Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop } catch { $computer = $null }
if (-not $computer) {
    throw 'the computer account of this host was not found'
}
# The computer account of a domain controller is
# CN=<name>,OU=Domain Controllers,<domain>: the OU of the controllers
# is the PARENT of the account, so it is read as the parent and not as
# a prefix of the name.
$computerParent = Get-DnParent $computer.DistinguishedName
if (-not $computerParent.Equals($DcOuDn, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'this host is not in the Domain Controllers OU of the domain'
}

# Every delegated location must exist.
foreach ($ou in $DelegatedOus) {
    $found = $null
    try { $found = Get-ADObject -Identity $ou -ErrorAction Stop } catch { $found = $null }
    if (-not $found) {
        throw ('the delegated location does not exist: ' + $ou)
    }
}

# The PDC of the domain is the controller whose rootDSE names the NTDS
# Settings object the head of the domain points at.  The delegation
# runs there only: the other controllers replicate it.
$rootDse = Get-ADRootDSE -Properties dsServiceName
$domainHead = Get-ADObject -SearchBase $DomainDn -SearchScope Base -LDAPFilter '(objectClass=domainDNS)' -Properties fSMORoleOwner, objectGuid
if (-not $domainHead) {
    throw 'the head of the domain was not found'
}
$isPdc = ([string]$rootDse.dsServiceName).Equals([string]$domainHead.fSMORoleOwner, [System.StringComparison]::OrdinalIgnoreCase)
if ($isPdc) {
    Write-Host 'This host holds the PDC emulator role of the domain.'
} else {
    Write-Host 'This host does not hold the PDC emulator role of the domain.'
}
# An entry that names its own device stands for the domain, and the
# domain has one device that stands for it: when another DC of the
# domain has an entry too, the loader of the inventory refuses the
# inventory and every change of the domain is refused.  The warning
# says so; the run goes on, because a domain device may be a
# controller that does not hold the role.
if (-not $isPdc -and $DomainDevice -eq $Device) {
    Write-Host 'WARNING: this DC does not hold the PDC emulator role and its entry names its own device. If another DC of the domain already has a write entry, run this setup again with --domain-device <that entry''s name>, or every change of the domain is refused.'
}

# The objectGUID of the head of the domain, read with the same base
# read that found the role owner.  The inventory entry of this
# controller carries it: the maq verb targets the head of the domain by
# that guid alone.
$DomainHeadGuid = ([guid]$domainHead.objectGuid).ToString()
if (-not $DomainHeadGuid) {
    throw 'the objectGUID of the head of the domain was not read'
}

# The session must be able to read the share of the SYSVOL of the
# PDC and to back the policy of the PDC up: the policy of the PDC is
# edited there, and the share of the name of the domain is not that
# one: it may be served by another controller.  An SSH key login is an
# S4U logon: it holds no ticket of the domain.  Over such a session
# the read of the GPT.INI of the policy may answer and Backup-GPO may
# fail with E_ACCESSDENIED, as measured on the real PDC
# on 2026-11-09, and the same code had passed over a key login
# earlier the same day.  The read does not promise the backup, so the
# step 0 makes the backup itself, before any change, and a session
# that cannot make it stops here.
#
# The check runs on the PDC only: the other controllers do not touch
# the policy at all.
if ($isPdc) {
    $gptIniReadable = $false
    try {
        $null = Get-Content -LiteralPath $GptIniPath -ErrorAction Stop
        $gptIniReadable = $true
    } catch {
        $gptIniReadable = $false
    }
    if (-not $gptIniReadable) {
        Write-Host ('This session cannot back up the Default Domain Controllers Policy on the PDC (' + $GptIniPath + '), so the policy cannot be edited. Run this script on the PDC in a session with network credentials: an interactive logon, or a remote logon made with a password. An SSH key login (an S4U logon) cannot do this reliably.')
        exit 1
    }
    Write-Host 'This session can read the share of the PDC.'

    # The backup of the policy of the PDC, in a folder of its own named
    # after the time of the run: the step 6 uses it, and it takes no
    # other.  The cmdlet answers the policy it backed up: the object
    # goes to Out-Null, and the owner reads the one line of the step 6.
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $backupDir = Join-Path $GpoBackupRoot $stamp
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    try {
        Backup-GPO -Guid $DefaultDcPolicyGuid -Path $backupDir -Server $PdcServer -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ('This session cannot back up the Default Domain Controllers Policy on the PDC (' + $GptIniPath + '), so the policy cannot be edited. Run this script on the PDC in a session with network credentials: an interactive logon, or a remote logon made with a password. An SSH key login (an S4U logon) cannot do this reliably.')
        exit 1
    }
}


Write-Host 'Step 1: the newton-ops account'

$opsUsers = @(Get-ADUser -Filter "SamAccountName -eq '$OpsName'")
if ($opsUsers.Count -eq 0) {
    if (-not $isPdc) {
        # The account is created on the PDC and it reaches the other
        # controllers by replication.  Wait for it: a controller that
        # has not got it yet cannot install anything.
        $deadline = (Get-Date).AddMinutes(10)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 15
            $opsUsers = @(Get-ADUser -Filter "SamAccountName -eq '$OpsName'")
            if ($opsUsers.Count -gt 0) { break }
        }
        if ($opsUsers.Count -eq 0) {
            throw 'the newton-ops account has not reached this controller within 10 minutes; run this script again later'
        }
        Write-Host 'The newton-ops account reached this controller.'
    } else {
        # The password is generated here, from 32 random bytes, and it
        # is thrown away: it is never shown and it is never stored.  The
        # secure string is built one character at a time, so the
        # password is never a plain string either.
        $random = New-Object 'System.Byte[]' 32
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($random) } finally { $generator.Dispose() }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        $secure = New-Object System.Security.SecureString
        foreach ($byte in $random) { $secure.AppendChar($alphabet[$byte % $alphabet.Length]) }
        $secure.MakeReadOnly()
        # The cmdlet has no -UserAccountControl, and it returns nothing
        # without -PassThru: the account is read again below.
        New-ADUser -Name $OpsName -SamAccountName $OpsName `
            -UserPrincipalName ($OpsName + '@' + $Domain) -AccountPassword $secure `
            -Enabled $true -PasswordNeverExpires $true | Out-Null
        Write-Host 'newton-ops was created with a random password. It was not shown and it was not stored.'
    }
}
# The account is read with its userAccountControl: the cmdlet does not
# answer it otherwise, and a value that cannot be read is a refusal.
$opsUser = Get-ADUser -Identity $OpsName -Properties userAccountControl
$opsDn = $opsUser.DistinguishedName
$opsSid = [string]$opsUser.SID

# The groups of the account are read with a search whose scope is
# Base, on the account itself: the groups of an object are a
# constructed attribute, and the directory gives them only to a read
# of that kind.  A read of any other scope is refused by the directory
# itself, with the error 8480 of the server, as measured
# on the real controller, where the run of the script before the
# account-read fix stopped right after this step.  The write helper of
# this platform reads them the same way (write.ps1, the read of the
# account of the helper).
#
# The groups are read before any change of this step, and a read that
# answers nothing is a refusal.
$groupObjects = @(Get-ADObject -SearchBase $opsUser.DistinguishedName -SearchScope Base -Filter '*' -Properties tokenGroups)
$tokenProperty = $null
if ($groupObjects.Count -eq 1) {
    $tokenProperty = $groupObjects[0].PSObject.Properties['tokenGroups']
}
if (($null -eq $tokenProperty) -or ($null -eq $tokenProperty.Value)) {
    throw 'the groups of newton-ops could not be read; nothing after this point was changed'
}
$tokenGroups = @($tokenProperty.Value)
if ($tokenGroups.Count -eq 0) {
    throw 'the groups of newton-ops could not be read; nothing after this point was changed'
}

$uacProperty = $opsUser.PSObject.Properties['userAccountControl']
if (($null -eq $uacProperty) -or ($null -eq $uacProperty.Value)) {
    throw 'the userAccountControl of newton-ops could not be read'
}
$currentUac = [int]$uacProperty.Value
if ($currentUac -eq 0) {
    throw 'the userAccountControl of newton-ops is 0'
}

# The account may not be delegated: the bit 0x100000 of the
# userAccountControl.  The bit is ADDED to the value that is there:
# the value is never replaced, or the NORMAL_ACCOUNT bit of the
# account would be dropped.
$wantedUac = $currentUac -bor 0x100000
if ($wantedUac -ne $currentUac) {
    Set-ADObject -Identity $opsDn -Replace @{ userAccountControl = $wantedUac }
    Write-Host 'newton-ops may not be delegated.'
}

# The transitive groups of the account may hold no privileged group.
# The set is the one of SPEC-1.4 section 5: the relative identifiers
# of the privileged groups of any domain of the forest, and the
# privileged groups of the builtin domain.
foreach ($groupSid in $tokenGroups) {
    if (Test-PrivilegedSid $groupSid) {
        throw ('newton-ops holds a privileged group (' + $groupSid + '); fix it before running this script again')
    }
}
Write-Host ('newton-ops is in ' + $tokenGroups.Count + ' group(s) and none of them is privileged.')

# The account may hold no right that replicates the directory.  That
# check is the check of AD-A-51 of SPEC-1.3, run against newton-ops.
Test-NoReplicationRight $opsSid $tokenGroups

# The effective trustees of newton-ops may not hold the right of a
# password reset, every extended right, or GenericAll on a delegated
# location or explicitly on an object below it. tokenGroups is
# transitive but omits Everyone and Authenticated Users, so include
# both well-known SIDs. This runs after the account exists on every run
# and before any delegation is changed.
$resetTrustees = @($opsSid) + @($tokenGroups) + @('S-1-1-0', 'S-1-5-11')
$resetPasswordGuid = Get-ResetPasswordGuid $ExtendedRightsDn
foreach ($ou in $DelegatedOus) {
    Test-NoResetPasswordRight $ou $resetTrustees $resetPasswordGuid | Out-Null
}
Write-Host 'newton-ops holds no effective right of a password reset.'


Write-Host 'Step 2: the delegation'
if (-not $isPdc) {
    Write-Host 'delegation: done on the PDC'
} else {
    # The GUIDs of the classes and of the attributes are read from the
    # schema of this domain, at this moment, one object at a time and
    # by its LDAP display name.  No GUID of a schema object is typed in
    # this script.
    $schemaDn = 'CN=Schema,CN=Configuration,' + $DomainDn
    $delegatedRights = @(
    @{ right = 'WP'; objectType = 'property:userAccountControl'; inherited = 'user' }
    @{ right = 'WP'; objectType = 'property:msDS-SupportedEncryptionTypes'; inherited = 'user' }
    @{ right = 'WP'; objectType = 'property:lockoutTime'; inherited = 'user' }
    @{ right = 'WP'; objectType = 'property:name'; inherited = 'user' }
    @{ right = 'WP'; objectType = 'property:cn'; inherited = 'user' }
    @{ right = 'WP'; objectType = 'property:userAccountControl'; inherited = 'computer' }
    @{ right = 'WP'; objectType = 'property:msDS-SupportedEncryptionTypes'; inherited = 'computer' }
    @{ right = 'WP'; objectType = 'property:name'; inherited = 'computer' }
    @{ right = 'WP'; objectType = 'property:cn'; inherited = 'computer' }
    @{ right = 'WP'; objectType = 'property:member'; inherited = 'group' }
    @{ right = 'CCDC'; objectType = 'user'; inherited = '' }
    @{ right = 'CCDC'; objectType = 'computer'; inherited = '' }
    @{ right = 'CA'; objectType = 'Reset Password'; inherited = 'user' }
    )
    foreach ($ou in $DelegatedOus) {
        foreach ($row in $delegatedRights) {
            if ($row.right -eq 'WP') {
                # The right of a property of the objects of a class.
                $attributeName = $row.objectType.Substring('property:'.Length)
                $className = $row.inherited
                $objectTypeGuid = Get-SchemaGuid $schemaDn $attributeName 'attributeSchema'
                $inheritedGuid = Get-SchemaGuid $schemaDn $className 'classSchema'
                $ace = $opsSid + ':WP;' + $attributeName + ';' + $className
                # The measured form: the property right is inherited by
                # the children of the location and not by the location
                # itself.
                $dsaclsArgs = @($ou, '/I:S', '/G', $ace)
                $wantedRights = 'WriteProperty'
                $wantedInheritance = 'Descendents'
                $trustee = $opsSid
            } elseif ($row.right -eq 'CA') {
                # The right of a password reset, for the CREATOR OWNER
                # and for nobody else.  A user-create with a secret
                # sets unicodePwd, and the directory checks the right
                # of a password reset of the creator of the object.
                # The right is granted to the CREATOR OWNER, so that
                # the write account may set the password of the
                # accounts it creates and of no other account: an
                # account that holds the right directly could reset
                # the password of any user of the location, and a
                # password reset is a change Newton never makes
                # itself.
                #
                # The GUID of the right is read by the CN of the
                # object, and the ace carries the DISPLAY name of it:
                # the ace of dsacls takes the display name, and that
                # form was measured to work on the real controller.
                $className = $row.inherited
                $objectTypeGuid = Get-ResetPasswordGuid $ExtendedRightsDn
                $inheritedGuid = Get-SchemaGuid $schemaDn $className 'classSchema'
                $ace = $CreatorOwnerSid + ':CA;' + $row.objectType + ';' + $className
                $dsaclsArgs = @($ou, '/I:S', '/G', $ace)
                $wantedRights = 'ExtendedRight'
                $wantedInheritance = 'Descendents'
                $trustee = $CreatorOwnerSid
            } else {
                # The right of the children of a class: the
                # create-child and the delete-child right in one ace.
                $className = $row.objectType
                $objectTypeGuid = Get-SchemaGuid $schemaDn $className 'classSchema'
                $inheritedGuid = [string][System.Guid]::Empty
                $ace = $opsSid + ':CCDC;' + $className
                $dsaclsArgs = @($ou, '/I:T', '/G', $ace)
                $wantedRights = 'CreateChild, DeleteChild'
                $wantedInheritance = 'All'
                $trustee = $opsSid
            }
            if (Test-AcePresent $ou $trustee $wantedRights $objectTypeGuid $inheritedGuid $wantedInheritance) {
                Write-Host ('  ' + $row.right + ' ' + $row.objectType + ' of ' + $ou + ' is present')
            } else {
                # dsacls is run with an argv array: the name of the
                # object is never a part of a command string.  It
                # prints the WHOLE access control list of the object,
                # so the output is captured and it is printed only when
                # the call failed.  The error preference is lowered for
                # the call: a native command that writes to its error
                # stream would otherwise stop the script before its
                # output was read.
                $savedPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    $out = & dsacls @dsaclsArgs 2>&1
                } finally {
                    $ErrorActionPreference = $savedPreference
                }
                if ($LASTEXITCODE -ne 0) {
                    Write-Host ('dsacls said: ' + (($out | ForEach-Object { [string]$_ }) -join ' '))
                    throw ('dsacls refused the ACE ' + $ace + ' on ' + $ou)
                }
                # The ACE is read back: a grant that is not the one
                # that was asked for is a refusal.
                if (-not (Test-AcePresent $ou $trustee $wantedRights $objectTypeGuid $inheritedGuid $wantedInheritance)) {
                    throw ('the ACE ' + $ace + ' on ' + $ou + ' is not there after the grant')
                }
                Write-Host ('  ' + $row.right + ' ' + $row.objectType + ' of ' + $ou + ' is added')
            }
        }
    }
    # The head of the domain gets one right of its own, and it is not
    # inherited: the machine account quota.
    $headGuid = Get-SchemaGuid $schemaDn 'ms-DS-MachineAccountQuota' 'attributeSchema'
    $headAce = $opsSid + ':WP;ms-DS-MachineAccountQuota'
    $headInherited = [string][System.Guid]::Empty
    if (Test-AcePresent $DomainDn $opsSid 'WriteProperty' $headGuid $headInherited 'None') {
        Write-Host ('  WP property:ms-DS-MachineAccountQuota of ' + $DomainDn + ' is present')
    } else {
        $dsaclsArgs = @($DomainDn, '/G', $headAce)
        # The output of dsacls is captured and printed only when the
        # call failed: the whole access control list of the object is
        # of no use to the owner of the domain.
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $out = & dsacls @dsaclsArgs 2>&1
        } finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Host ('dsacls said: ' + (($out | ForEach-Object { [string]$_ }) -join ' '))
            throw ('dsacls refused the ACE ' + $headAce + ' on ' + $DomainDn)
        }
        if (-not (Test-AcePresent $DomainDn $opsSid 'WriteProperty' $headGuid $headInherited 'None')) {
            throw ('the ACE ' + $headAce + ' on ' + $DomainDn + ' is not there after the grant')
        }
        Write-Host ('  WP property:ms-DS-MachineAccountQuota of ' + $DomainDn + ' is added')
    }
}


Write-Host 'Step 3: the approval key'

# The passphrase is asked here, on the domain controller, twice, and it
# is never echoed.  The secure string is marshalled once and the memory
# it came from is cleared right after.
$secure = Read-Host -AsSecureString -Prompt ('approval passphrase for ' + $DomainDevice)
$secureAgain = Read-Host -AsSecureString -Prompt 'approval passphrase again'
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$bstrAgain = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAgain)
try {
    $passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $passphraseAgain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrAgain)
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrAgain)
    $secure.Dispose()
    $secureAgain.Dispose()
}
if (-not $passphrase) {
    throw 'the approval passphrase must not be empty'
}
if ($passphrase -ne $passphraseAgain) {
    throw 'the two approval passphrases do not match'
}
# The approval key K is the key of the domain: it is derived with the
# name of the device that stands for the domain as its salt, the name
# the Newton host derived its own copy with, so every DC of the domain
# holds the same K (SPEC-1.4-REQUEST section 1).
$keyHex = Get-ApprovalKeyHex $passphrase $DomainDevice
$fingerprint = Get-ApprovalFingerprintHex $keyHex
$passphrase = $null
$passphraseAgain = $null

# The key is written with the access control list of SPEC-1.4 section
# 8: SYSTEM and Administrators have full control and the write account
# may read it.  The key itself is never printed.  A key already installed
# is compared, never written over: the same passphrase changes nothing,
# and another one stops the setup with the key kept, since a DC whose key
# changed refuses every approval.
New-Item -ItemType Directory -Path $AdDir -Force | Out-Null
$installedKey = $null
if (Test-Path -LiteralPath $ApprovalKeyPath) {
    $installedKey = ([System.IO.File]::ReadAllText($ApprovalKeyPath)).Trim()
    if ($installedKey -ne $keyHex) {
        $keyHex = $null
        $installedKey = $null
        throw ('this DC already holds a different approval key: the passphrase typed now is not the one it was set up with. The key was not changed and the setup stopped; its earlier steps (the newton-ops account and its delegation) have already run. Run the setup again with the domain''s approval passphrase. To change the passphrase on purpose, remove ' + $ApprovalKeyPath + ' on every DC of the domain, run the setup again on each, then run newton-ad-setup approval-key for the domain on the Newton host.')
    }
}
if ($null -eq $installedKey) {
    [System.IO.File]::WriteAllText($ApprovalKeyPath, $keyHex + "`n", (New-Object System.Text.UTF8Encoding($false)))
}
$installedKey = $null
$keyHex = $null
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($opsSid)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$keyAcl = Get-Acl -LiteralPath $ApprovalKeyPath
$keyAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keyAcl.Access)) { [void]$keyAcl.RemoveAccessRule($rule) }
$keyAcl.SetOwner($administrators)
$keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $none, $none, $allow)))
$keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $none, $none, $allow)))
$keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, 'Read', $none, $none, $allow)))
Set-Acl -LiteralPath $ApprovalKeyPath -AclObject $keyAcl
Write-Host ('The approval key is installed. Its fingerprint is ' + $fingerprint)
Write-Host 'Compare that fingerprint with the one the Newton host printed.'


Write-Host 'Step 4: the files'

New-Item -ItemType Directory -Path $AdDir -Force | Out-Null

# The access control list of the install root: the rules are explicit
# and the rules the folder inherits from ProgramData are gone.  A local
# user may not write beside the helper.
Set-NewtonInstallAcl $AdDir $opsSid 'ReadAndExecute' 'ContainerInherit, ObjectInherit'

# The install root is shared with the collector: the account of the
# collector reads it, and it reads nothing else of it.  The account is
# looked up the way the account of the write path is looked up: one
# exact match of the SamAccountName.  It may be absent, and then there
# is no rule for it and there is no error.
$auditUsers = @(Get-ADUser -Filter "SamAccountName -eq '$AuditName'")
if ($auditUsers.Count -gt 1) { throw 'there is more than one newton-audit account' }
if ($auditUsers.Count -eq 1) {
    Add-NewtonSharedRootRead $AdDir $auditUsers[0].SID
    Write-Host 'The read of newton-audit on the install root was kept: the collector reads it.'
} else {
    Write-Host 'There is no newton-audit account: the install root does not give it a read.'
}

$helperB64 = @(
'IyB0aGUgc3R1YiBvZiB0aGUgV2luZG93cyB3cml0ZSBoZWxwZXIsIGdvbGRlbgo='
)
$helperB64 = $helperB64 -join ''
[System.IO.File]::WriteAllBytes($HelperPath, [System.Convert]::FromBase64String($helperB64))
$helperHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $HelperPath).Hash.ToLowerInvariant()
if ($helperHash -ne '3f56deedef6b90152d38c5c2f81ea0016887a5b37cd308b7fe0554d2e470ba7c') {
    throw 'the sha256 of write.ps1 does not match the package'
}
Write-Host ('sha256 write.ps1 ' + $helperHash)

# The device name the helper of this controller answers to: the name of
# the device that stands for the domain, the same on every controller
# of the domain.  A request names the domain, and the helper refuses
# with `schema` when the name differs from this one.
[System.IO.File]::WriteAllText($DeviceFilePath, $DomainDevice + "`n", (New-Object System.Text.UTF8Encoding($false)))
Set-NewtonInstallAcl $DeviceFilePath $opsSid 'Read' 'None'

# The access control list of the helper: the rules of the collector.
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($opsSid)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$children = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$helperAcl = Get-Acl -LiteralPath $HelperPath
$helperAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($helperAcl.Access)) { [void]$helperAcl.RemoveAccessRule($rule) }
$helperAcl.SetOwner($administrators)
$helperAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $none, $none, $allow)))
$helperAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $none, $none, $allow)))
$helperAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, 'ReadAndExecute', $none, $none, $allow)))
Set-Acl -LiteralPath $HelperPath -AclObject $helperAcl

# The transaction store: SYSTEM and Administrators have full control
# and the write account may read it, create files in it and write them.
# It may not delete anything.
New-Item -ItemType Directory -Path $TxDir -Force | Out-Null
$txRights = [System.Security.AccessControl.FileSystemRights]'Read, CreateFiles, WriteData'
$txAcl = Get-Acl -LiteralPath $TxDir
$txAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($txAcl.Access)) { [void]$txAcl.RemoveAccessRule($rule) }
$txAcl.SetOwner($administrators)
$txAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $children, $none, $allow)))
$txAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $children, $none, $allow)))
$txAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, $txRights, $children, $none, $allow)))
Set-Acl -LiteralPath $TxDir -AclObject $txAcl
Write-Host 'The helper, the device name and the transaction store are in place.'


Write-Host 'Step 5: the login'

# The authorized key of the write path, with the access control list
# of the measured one: SYSTEM and Administrators have full control and
# the write account may read and execute it.
[System.IO.File]::WriteAllText($AuthorizedKeysPath, 'restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f' + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($opsSid)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$keysAcl = Get-Acl -LiteralPath $AuthorizedKeysPath
$keysAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keysAcl.Access)) { [void]$keysAcl.RemoveAccessRule($rule) }
$keysAcl.SetOwner($administrators)
$keysAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $none, $none, $allow)))
$keysAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $none, $none, $allow)))
$keysAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, 'ReadAndExecute', $none, $none, $allow)))
Set-Acl -LiteralPath $AuthorizedKeysPath -AclObject $keysAcl

# sshd accepts the key only for the builtin OpenSSH Users group, so the
# account joins it.  The group is not privileged.
$openSshUsers = Get-ADGroup -Identity ('CN=OpenSSH Users,CN=Builtin,' + (Get-ADDomain).DistinguishedName)
$isMember = $false
foreach ($member in @(Get-ADGroupMember -Identity $openSshUsers -ErrorAction SilentlyContinue)) {
    $memberName = $member.PSObject.Properties['SamAccountName']
    if (($null -ne $memberName) -and ([string]$memberName.Value -eq $OpsName)) { $isMember = $true }
}
if (-not $isMember) {
    Add-ADGroupMember -Identity $openSshUsers -Members $OpsName
    Write-Host 'newton-ops is now a member of the domain-local OpenSSH Users group.'
} else {
    Write-Host 'newton-ops is already a member of the domain-local OpenSSH Users group.'
}

# The sshd block of the write path.  The configuration is backed up
# once and it is put back when sshd refuses it.
if (-not (Test-Path -LiteralPath $SshdConfig)) { throw 'the sshd configuration is missing' }
if (-not (Test-Path -LiteralPath $SshdBackup)) {
    Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force
    Write-Host 'The sshd configuration is backed up once, as .bak-newton-write.'
}
$config = Get-Content -LiteralPath $SshdConfig -Raw
$sshdChanged = $false
if ($config -notlike ('*' + $BlockMarker + '*')) {
    $netbios = ([string](Get-ADDomain).NetBIOSName).ToLowerInvariant()
    $blockLines = @(
        $BlockMarker
        ("Match User $($netbios)\$OpsName")
        '    AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/write_authorized_keys'
        '    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad\write.ps1'
        '    PermitTTY no'
        '    AllowTcpForwarding no'
        '    PermitTunnel no'
        '    X11Forwarding no'
        '    AllowAgentForwarding no'
    )
    $block = ($blockLines -join "`n") + "`n"
    if (-not $config.EndsWith("`n")) { $block = "`n" + $block }
    [System.IO.File]::WriteAllText($SshdConfig, $config + $block, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $true
    Write-Host 'The write block is in the sshd configuration.'
} else {
    Write-Host 'The write block is already in the sshd configuration.'
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
$sshdSaid = ''
try {
    # The output of sshd is captured: it is printed only when the
    # configuration was refused, because that is the one time the owner
    # has to read it.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $sshdOut = & $sshdExe -t 2>&1
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    $sshdExit = $LASTEXITCODE
    $sshdSaid = (($sshdOut | ForEach-Object { [string]$_ }) -join ' ')
} catch {
    $sshdExit = 1
}
if ($sshdExit -ne 0) {
    [System.IO.File]::WriteAllText($SshdConfig, $config, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $false
    if ($sshdSaid) {
        Write-Host ('sshd said: ' + $sshdSaid)
    }
    throw 'sshd refused the configuration. The configuration was put back.'
}
Write-Host 'sshd accepted the configuration.'


Write-Host 'Step 6: the SeBatchLogonRight'

# The undo task runs as the write account with a S4U token, and it runs
# only when the account holds the SeBatchLogonRight.  The right is
# granted on the PDC only, through the Default Domain Controllers
# Policy, and the holders of the right are kept.
if ($isPdc) {
    # The backup of the policy was made by the step 0, before any
    # change: a run that could not make it stopped there.  The step 6
    # uses that backup and takes no other one.
    Write-Host ('The Default Domain Controllers Policy is backed up in ' + $backupDir)

    # The read of the policy is made on the PDC: the share of the name
    # of the domain may be served by another controller, and the policy
    # of the PDC is not there.
    $gpo = Get-GPO -Guid $DefaultDcPolicyGuid -Server $PdcServer -ErrorAction Stop
    if (-not $gpo) {
        throw 'the Default Domain Controllers Policy was not found on the PDC'
    }

    # The policy object is read by its own name: it is the object
    # CN={<guid>},CN=Policies,CN=System,<domain>, and it holds the path
    # of the folder of the policy.
    $gpoObject = Get-ADObject -Identity ('CN={' + $DefaultDcPolicyGuid + '},CN=Policies,CN=System,' + $DomainDn) -Properties versionNumber, gPCFileSysPath
    if (-not $gpoObject) {
        throw 'the Default Domain Controllers Policy was not found'
    }
    $gpoDir = [string]$gpoObject.gPCFileSysPath
    if (-not $gpoDir) {
        throw 'the Default Domain Controllers Policy has no path'
    }
    # The path the directory answers is only read to prove that the
    # policy is the one of its own GUID.  It is never the path that is
    # written: the files are edited in the share of the SYSVOL of the
    # PDC, because the share of the name of the domain may be served by
    # another controller.
    $wantedPolicyTail = '\Policies\{' + $DefaultDcPolicyGuid + '}'
    if (-not $gpoDir.EndsWith($wantedPolicyTail, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('the path of the Default Domain Controllers Policy does not end with ' + $wantedPolicyTail)
    }

    # The template of the policy is in the folder of the policy of the
    # PDC, and not in the folder of the policies.
    $changed = Set-BatchLogonRightInTemplate $GptTmplPath $opsSid
    if ($changed) {
        Write-Host 'The SeBatchLogonRight of the policy holds newton-ops now, and it holds everyone it held before.'

        # The machine version of the policy goes up in the folder of the
        # policy and in the GPO object, so the controllers take the new
        # template.
        $gptIni = $GptIniPath
        if (Test-Path -LiteralPath $gptIni) {
            $iniLines = @(Get-Content -LiteralPath $gptIni -ErrorAction Stop)
            $newIni = @()
            foreach ($line in $iniLines) {
                if ($line.Trim() -like 'Version=*') {
                    $old = [int](($line -split '=', 2)[1])
                    $newIni += ('Version=' + ($old + 1))
                } else {
                    $newIni += $line
                }
            }
            Set-Content -LiteralPath $gptIni -Value $newIni -Encoding Ascii | Out-Null
        }
        $newVersion = [int]$gpoObject.versionNumber + 1
        Set-ADObject -Identity $gpoObject.DistinguishedName -Replace @{ versionNumber = $newVersion }
        Write-Host ('The machine version of the policy is ' + $newVersion + ' now.')
    } else {
        Write-Host 'The SeBatchLogonRight of the policy holds newton-ops already.'
    }
} else {
    Write-Host 'The SeBatchLogonRight is granted on the PDC only.'
}

gpupdate /target:computer /force | Out-Null
$rightsFile = Join-Path $env:TEMP 'newton-user-rights.txt'
if (Test-Path -LiteralPath $rightsFile) { Remove-Item -LiteralPath $rightsFile -Force }
secedit /export /areas USER_RIGHTS /cfg $rightsFile /quiet | Out-Null
if (-not (Test-Path -LiteralPath $rightsFile)) {
    throw 'the export of secedit failed: the SeBatchLogonRight of newton-ops could not be proved'
}
# The right is proved: the SID of the write account has to be one of
# the holders of the right on this controller.  The export is read by
# the check itself, and the verify prints ONE line: the match object of
# Select-String is not printed, the owner reads the report and nothing
# else.
if (-not (Test-BatchLogonRight $rightsFile $opsSid)) {
    Remove-Item -LiteralPath $rightsFile -Force
    throw 'the SeBatchLogonRight of newton-ops could not be proved on this controller'
}
Remove-Item -LiteralPath $rightsFile -Force
Write-Host 'SeBatchLogonRight holds newton-ops (verified by secedit)'


Write-Host 'Step 7: the inventory entry'
Write-Host ''
Write-Host ('[devices.' + $Device + ']')
Write-Host 'platform = "ad-windows-write"'
Write-Host ('ad_domain = "' + $DomainDevice + '"')
Write-Host ('ad_domain_guid = "' + $DomainHeadGuid + '"')
Write-Host ('host = "' + $WriteHost + '"')
Write-Host ('user = "newton-ops@' + $Domain + '"')
Write-Host 'key_file = "<the private key of the write key, on the Newton host>"'
Write-Host 'known_hosts = "<the pinned known_hosts of the controller>"'
Write-Host ('domain = "' + $Domain + '"')
Write-Host ''
Write-Host ('The installed public key (sha256): 394cb0357cefcb7cbe8da2a7ff052c6beca6ec5c51750812a33c11b6368021e2')
Write-Host ('The key of this controller is ' + $AuthorizedKeysPath)
Write-Host 'The ad_domain of the entry is the inventory name of the device that stands for the domain: the PDC emulator''s own entry. On every other DC, run the setup with --domain-device <that name>.'
Write-Host 'The key_file and known_hosts lines of the entry are placeholders the owner fills in.'


Write-Host 'Step 8: the sshd restart'
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
