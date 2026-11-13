param([string]$Undo)

# The Windows write helper of Newton 1.4 (SPEC-1.4-REQUEST).
#
# The helper runs on the Windows domain controller, under Windows PowerShell
# 5.1, from the sshd ForceCommand, as the write account.  It reads one JSON
# request on stdin (at most 64 KiB) and writes one JSON object on stdout.  It
# exits 0 whatever the outcome.
#
# The other way in is the undo argv, `-Undo <txid>`, used by the undo task and
# never through SSH.  It is refused when SSH_CONNECTION or SSH_CLIENT is set.
#
# The file is dot-sourced by the tests, which call the functions below.  The
# main body runs only when the script is not dot-sourced.

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$null = Add-Type -AssemblyName System.DirectoryServices.Protocols

$script:WriteHelperVersion = '1.4.0'

# The biggest request the helper reads (SPEC section 1).
$script:MaxRequestBytes = 65536

# The install root of the helper (SPEC section 8).
$script:InstallRoot = 'C:\ProgramData\Newton\ad'

# The test seams.  The tests set these before they call the functions; on the
# domain controller they stay empty and the real adapters are built.
$script:LdapAdapter = $null
$script:SchedulerAdapter = $null
$script:FileSystemAdapter = $null
$script:NowOverride = $null
$script:WriteAccountSam = ''
$script:DeviceOverride = ''
$script:KeyOverride = ''

# The patterns of the contract (SPEC section 2).
$script:IntPattern = '\A(0|[1-9][0-9]*)\z'
$script:DevicePattern = '\A[a-z][a-z0-9-]{0,31}\z'
$script:TxidPattern = '\A[0-9a-f]{32}\z'
$script:TokenPattern = '\A[0-9a-f]{64}\z'
$script:RiskPattern = '\A(LOW|MED|HIGH)\z'
$script:GuidPattern = '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z'
$script:SidPattern = '\AS-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}\z'
$script:SamPattern = '\A[a-z0-9][a-z0-9._-]{0,19}\z'
$script:ComputerSamPattern = '\A[a-z0-9][a-z0-9._-]{0,19}\$\z'
$script:EpochPattern = '\A[0-9]{10}\z'

# The fields of every mode (SPEC section 2).  The secret is the only optional
# field, and only a user-create carries one.
$script:ModeFields = @{
    'apply' = @('v', 'mode', 'device', 'txid', 'verb', 'target', 'before', 'after', 'window', 'risk', 'nbf', 'exp', 'token', 'secret')
    'confirm' = @('v', 'mode', 'device', 'txid')
    'abort' = @('v', 'mode', 'device', 'txid')
    'status' = @('v', 'mode', 'device', 'txid')
    'read' = @('v', 'mode', 'device', 'verb', 'target')
}

# The target keys of every verb (SPEC section 3).
$script:TargetKeys = @{
    'uac-clear' = @('bit', 'guid', 'sam', 'sid')
    'disable' = @('guid', 'sam', 'sid')
    'enable' = @('guid', 'sam', 'sid')
    'enc-types' = @('guid', 'sam', 'sid')
    'unlock' = @('guid', 'sam', 'sid')
    'member-add' = @('group_guid', 'group_sam', 'group_sid', 'member_guid', 'member_sam', 'member_sid')
    'member-remove' = @('group_guid', 'group_sam', 'group_sid', 'member_guid', 'member_sam', 'member_sid')
    'maq' = @('guid')
    'user-create' = @('parent_guid', 'sam')
    'move' = @('guid', 'sam', 'sid')
}

# The target a read may use when it knows only the name (SPEC section 6).
$script:ReadTargetKeys = @{
    'uac-clear' = @('sam')
    'disable' = @('sam')
    'enable' = @('sam')
    'enc-types' = @('sam')
    'unlock' = @('sam')
    'member-add' = @('group_sam', 'member_sam')
    'member-remove' = @('group_sam', 'member_sam')
    'maq' = @('guid')
    'user-create' = @('parent_guid', 'sam')
    'move' = @('sam')
}

# The kind of every target value.
$script:TargetKinds = @{
    'uac-clear' = @{ bit = 'int'; guid = 'guid'; sam = 'sam'; sid = 'sid' }
    'disable' = @{ guid = 'guid'; sam = 'sam'; sid = 'sid' }
    'enable' = @{ guid = 'guid'; sam = 'sam'; sid = 'sid' }
    'enc-types' = @{ guid = 'guid'; sam = 'sam'; sid = 'sid' }
    'unlock' = @{ guid = 'guid'; sam = 'sam'; sid = 'sid' }
    'member-add' = @{ group_guid = 'guid'; group_sam = 'sam'; group_sid = 'sid'; member_guid = 'guid'; member_sam = 'sam'; member_sid = 'sid' }
    'member-remove' = @{ group_guid = 'guid'; group_sam = 'sam'; group_sid = 'sid'; member_guid = 'guid'; member_sam = 'sam'; member_sid = 'sid' }
    'maq' = @{ guid = 'guid' }
    'user-create' = @{ parent_guid = 'guid'; sam = 'sam' }
    'move' = @{ guid = 'guid'; sam = 'sam'; sid = 'sid' }
}

# The kind of every value of a before- or after-image.
$script:ValueKinds = @{
    'uac-clear' = @{ uac = 'int' }
    'disable' = @{ uac = 'int' }
    'enable' = @{ uac = 'int' }
    'enc-types' = @{ etypes = 'int_or_absent' }
    'unlock' = @{ lockout = 'int' }
    'member-add' = @{ member = 'present_absent' }
    'member-remove' = @{ member = 'present_absent' }
    'maq' = @{ maq = 'int' }
    'user-create' = @{ object = 'present_absent' }
    'move' = @{ parent = 'guid' }
}

# The single value key of every verb.
$script:ValueKey = @{
    'uac-clear' = 'uac'
    'disable' = 'uac'
    'enable' = 'uac'
    'enc-types' = 'etypes'
    'unlock' = 'lockout'
    'member-add' = 'member'
    'member-remove' = 'member'
    'maq' = 'maq'
    'user-create' = 'object'
    'move' = 'parent'
}

# The bits a uac-clear may clear (SPEC section 3).
$script:UacClearBits = @([int64]4194304, [int64]32, [int64]128, [int64]524288, [int64]65536)

# The ACCOUNTDISABLE bit.
$script:AccountDisable = [int64]2

# The DES bits of msDS-SupportedEncryptionTypes (SPEC section 3).
$script:DesTypeBits = [int64]3

# The bits of msDS-SupportedEncryptionTypes below 64 (SPEC section 3).
$script:EncTypeLowMask = [int64]63

# The DC account bits of the contract (SPEC section 3).
$script:DcAccountBits = @(0x2000, 0x4000000)

# The accounts no verb may write.
$script:KrbtgtRid = 502
$script:KrbtgtSam = 'krbtgt'
$script:RodcKrbtgtPrefix = 'krbtgt_'
$script:InterdomainTrustAccount = 0x800

# The privileged RIDs of any domain (SPEC section 5).
$script:PrivilegedRids = @(498, 512, 516, 518, 519, 520, 521, 525, 526, 527)

# The privileged BUILTIN groups (SPEC section 5).
$script:PrivilegedBuiltin = @(
    'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550'
    'S-1-5-32-551', 'S-1-5-32-552'
)

# The only principals that may hold write rights on the install (SPEC section 8).
$script:AllowedWriteSids = @('S-1-5-32-544', 'S-1-5-18')

# The undo window of an apply (SPEC section 2).
$script:WindowMin = 120
$script:WindowMax = 1800
$script:UnlockWindow = 120

# The approval window of an apply (SPEC section 2).
$script:ApprovalWindowMax = 1800

# The length of the secret of a user-create (SPEC section 2).
$script:SecretMin = 16
$script:SecretMax = 128

# The depth cap of the memberOf walk (SPEC section 5).
$script:PrivilegeDepthCap = 32

# The retry of the transaction lock (SPEC section 6).
$script:LockRetryMs = 200
$script:LockTimeoutSeconds = 30

# The complete object shape used after a GUID, SAM or DN lookup.  AD returns
# only requested attributes, so lookup searches request every value their
# callers may subsequently inspect.
$script:ObjectReadAttributes = [string[]]@(
    'objectGUID', 'objectSid', 'sAMAccountName', 'objectClass',
    'userAccountControl', 'msDS-SupportedEncryptionTypes', 'lockoutTime',
    'adminCount', 'memberOf', 'primaryGroupID', 'uSNChanged',
    'userPrincipalName', 'ms-DS-MachineAccountQuota'
)

# ---------------------------------------------------------------------------
# the small helpers
# ---------------------------------------------------------------------------

function Get-NewtonInstallRoot {
    return $script:InstallRoot
}

function Get-NewtonTxPath {
    return (Join-Path $script:InstallRoot 'tx')
}

function Get-NewtonKeyPath {
    return (Join-Path $script:InstallRoot 'approval.key')
}

function Get-NewtonDevicePath {
    return (Join-Path $script:InstallRoot 'device.txt')
}

function Get-NewtonScriptPath {
    return (Join-Path $script:InstallRoot 'write.ps1')
}

function Get-NewtonRecordPath {
    param([string]$Txid)
    $info = Get-NewtonRecordInfo -Txid $Txid
    if ($null -eq $info) { return $null }
    return [string]$info['path']
}

function Get-NewtonNow {
    # The clock of the helper.  The tests pin it.
    if ($null -ne $script:NowOverride) { return [int64]$script:NowOverride }
    return [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Get-NewtonUtcNow {
    # The wall clock, never the pinned one: the lock retry uses it.
    return [DateTime]::UtcNow
}

function Open-NewtonFile {
    # A narrow file-system seam lets the offline harness reproduce the ACL
    # measured on the DC.  Production always uses System.IO.File directly.
    param([string]$Path, $Mode, $Access, $Share)
    if ($null -ne $script:FileSystemAdapter) {
        return $script:FileSystemAdapter.Open($Path, $Mode, $Access, $Share)
    }
    return [System.IO.File]::Open($Path, $Mode, $Access, $Share)
}

function Read-NewtonFileText {
    param([string]$Path)
    if ($null -ne $script:FileSystemAdapter) {
        return $script:FileSystemAdapter.ReadAllText($Path)
    }
    return [System.IO.File]::ReadAllText($Path)
}

function New-NewtonRefusal {
    param([string]$Code, [string]$Message)
    $exception = [System.Exception]::new($Message)
    $exception.Data['NewtonCode'] = $Code
    return $exception
}

function Throw-NewtonRefusal {
    param([string]$Code, [string]$Message)
    throw (New-NewtonRefusal $Code $Message)
}

function Test-NewtonIOException {
    # True when the failure is an IO error, whatever wrapped it.
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.IO.IOException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Get-NewtonRefusalCode {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 'error' }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.Data -and $exception.Data.Contains('NewtonCode')) {
            return [string]$exception.Data['NewtonCode']
        }
        $exception = $exception.InnerException
    }
    return 'error'
}

function New-NewtonResponse {
    param([string]$Code)
    return [ordered]@{ v = 1; code = $Code }
}

function Get-NewtonLeakedTypeNames {
    # The names of the types of the values that reached the answer of a mode
    # instead of the answer itself.
    param($Response)
    $names = @()
    foreach ($value in @($Response)) {
        if ($null -eq $value) { $names += 'null'; continue }
        $names += $value.GetType().FullName
    }
    return ,$names
}

function ConvertTo-NewtonAnswer {
    # The answer of a mode is one object, never a list.
    #
    # A value that leaked into the answer (the index of a collection of the
    # LDAP adapter, for one) would turn the answer into a JSON list, so the
    # answer is an error and the types of the leaked values go to stderr.
    # Stdout stays the one JSON object.
    param($Response)
    if ($null -ne $Response) {
        if ($Response -is [System.Collections.IDictionary]) { return $Response }
    }
    $names = Get-NewtonLeakedTypeNames $Response
    [Console]::Error.WriteLine('newton: the answer of the mode is not one object: ' + ($names -join ', '))
    return (New-NewtonResponse 'error')
}

function Get-NewtonField {
    # The value of a property, by its exact name: a key that differs only in
    # case is a different key.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name -ceq $Name) { return $property.Value }
    }
    return $null
}

function Get-NewtonFieldNames {
    param($Object)
    $names = New-Object System.Collections.ArrayList
    if ($null -eq $Object) { return $names }
    foreach ($property in $Object.PSObject.Properties) { [void]$names.Add($property.Name) }
    return ,$names
}

function Test-NewtonIsBoolean {
    param($Value)
    return ($Value -is [bool])
}

function Test-NewtonIsInt {
    # True when the value is a number of the contract.  The scanner has
    # already refused every number that is not written in the int form, so a
    # number here is an integer, however big it is.
    param($Value, [string]$Path = '')
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $false }
    if ($Value -is [string]) { return $false }
    if (-not [string]::IsNullOrEmpty($Path)) {
        $text = Get-NewtonNumberText $Path
        if ($null -eq $text) { return $false }
        return ($text -cmatch $script:IntPattern)
    }
    $code = [System.Type]::GetTypeCode($Value.GetType())
    foreach ($numeric in @(
        [System.TypeCode]::SByte
        [System.TypeCode]::Byte
        [System.TypeCode]::Int16
        [System.TypeCode]::UInt16
        [System.TypeCode]::Int32
        [System.TypeCode]::UInt32
        [System.TypeCode]::Int64
        [System.TypeCode]::UInt64
        [System.TypeCode]::Single
        [System.TypeCode]::Double
        [System.TypeCode]::Decimal
    )) {
        if ($code -eq $numeric) { return $true }
    }
    # a whole number that is too big for 64 bits
    return ($Value.GetType().FullName -like 'System.Numerics.*')
}

function Test-NewtonKind {
    # The kind of a value, as the contract names it.
    param([string]$Kind, $Value, [string]$Path = '')
    if ($Kind -eq 'int') { return (Test-NewtonIsInt $Value $Path) }
    if ($Kind -eq 'int_or_absent') {
        if ($Value -is [string]) { return ($Value -ceq 'absent') }
        return (Test-NewtonIsInt $Value $Path)
    }
    if ($Kind -eq 'present_absent') {
        if ($Value -isnot [string]) { return $false }
        return (($Value -ceq 'present') -or ($Value -ceq 'absent'))
    }
    if ($Kind -eq 'guid') {
        if ($Value -isnot [string]) { return $false }
        return ($Value -cmatch $script:GuidPattern)
    }
    if ($Kind -eq 'sid') {
        if ($Value -isnot [string]) { return $false }
        return ($Value -cmatch $script:SidPattern)
    }
    if ($Kind -eq 'sam') {
        if ($Value -isnot [string]) { return $false }
        if ($Value -cmatch $script:SamPattern) { return $true }
        return ($Value -cmatch $script:ComputerSamPattern)
    }
    return $false
}

function ConvertTo-NewtonLowerSam {
    # The name of an account, lowercased.  The directory holds the name as
    # it was written (`Administrator`), but the request schema accepts only
    # a lowercase name and the contract compares the names without their
    # case: the ids of an answer therefore carry the name in lowercase.
    param($Value)
    if ($Value -isnot [string]) { return $Value }
    return $Value.ToLowerInvariant()
}

# ---------------------------------------------------------------------------
# the JSON scanner
#
# The scanner walks the raw text of the request before ConvertFrom-Json sees
# it.  It enforces the rules of SPEC section 2 that the JSON parser of
# Windows PowerShell does not: a duplicate key, two keys that differ only in
# case, and a number that is not written in the int form.
# ---------------------------------------------------------------------------

$script:JsonText = ''
$script:JsonIndex = 0
$script:JsonLength = 0
$script:JsonString = ''
$script:JsonFail = $false
$script:JsonPath = $null
$script:JsonNumbers = $null
$script:JsonStrings = $null
$script:JsonDepth = 0

# The deepest nesting the scanner accepts.  A request of the contract is a
# small object; a deeper one is a schema, and the scan of a deep text stays
# linear in the size of the input.
$script:JsonDepthMax = 32

function Skip-NewtonJsonSpace {
    while ($script:JsonIndex -lt $script:JsonLength) {
        $character = $script:JsonText[$script:JsonIndex]
        if (($character -eq ' ') -or ($character -eq "`t") -or ($character -eq "`n") -or ($character -eq "`r")) {
            $script:JsonIndex = $script:JsonIndex + 1
            continue
        }
        break
    }
}

function Read-NewtonJsonString {
    # The string at the cursor.  The result is in $script:JsonString and
    # $script:JsonFail says whether it was one.
    $script:JsonFail = $false
    $script:JsonString = ''
    if ($script:JsonIndex -ge $script:JsonLength) { $script:JsonFail = $true; return }
    if ($script:JsonText[$script:JsonIndex] -ne '"') { $script:JsonFail = $true; return }
    $script:JsonIndex = $script:JsonIndex + 1
    $builder = New-Object System.Text.StringBuilder
    while ($true) {
        if ($script:JsonIndex -ge $script:JsonLength) { $script:JsonFail = $true; return }
        $character = $script:JsonText[$script:JsonIndex]
        if ($character -eq '"') {
            $script:JsonIndex = $script:JsonIndex + 1
            $script:JsonString = $builder.ToString()
            return
        }
        if ($character -eq '\') {
            $script:JsonIndex = $script:JsonIndex + 1
            if ($script:JsonIndex -ge $script:JsonLength) { $script:JsonFail = $true; return }
            $escape = $script:JsonText[$script:JsonIndex]
            if ($escape -eq '"') { [void]$builder.Append('"') }
            elseif ($escape -eq '\') { [void]$builder.Append('\') }
            elseif ($escape -eq '/') { [void]$builder.Append('/') }
            elseif ($escape -eq 'b') { [void]$builder.Append([char]8) }
            elseif ($escape -eq 'f') { [void]$builder.Append([char]12) }
            elseif ($escape -eq 'n') { [void]$builder.Append([char]10) }
            elseif ($escape -eq 'r') { [void]$builder.Append([char]13) }
            elseif ($escape -eq 't') { [void]$builder.Append([char]9) }
            elseif ($escape -eq 'u') {
                if (($script:JsonIndex + 4) -ge $script:JsonLength) { $script:JsonFail = $true; return }
                $hex = $script:JsonText.Substring($script:JsonIndex + 1, 4)
                if ($hex -notmatch '\A[0-9a-fA-F]{4}\z') { $script:JsonFail = $true; return }
                $code = [int][Convert]::ToInt32($hex, 16)
                $script:JsonIndex = $script:JsonIndex + 4
                [void]$builder.Append([char]$code)
            }
            else { $script:JsonFail = $true; return }
            $script:JsonIndex = $script:JsonIndex + 1
            continue
        }
        if ([int][char]$character -lt 32) { $script:JsonFail = $true; return }
        [void]$builder.Append($character)
        $script:JsonIndex = $script:JsonIndex + 1
    }
}

function Read-NewtonJsonNumber {
    # The number at the cursor.  Only the int form of the contract is
    # allowed: a sign, a fraction or an exponent is refused.
    $start = $script:JsonIndex
    if (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -eq '-')) {
        $script:JsonIndex = $script:JsonIndex + 1
    }
    $digitStart = $script:JsonIndex
    while (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -match '[0-9]')) {
        $script:JsonIndex = $script:JsonIndex + 1
    }
    $digits = $script:JsonIndex - $digitStart
    if ($digits -eq 0) { $script:JsonFail = $true; return }
    if (($script:JsonText[$digitStart] -eq '0') -and ($digits -gt 1)) { $script:JsonFail = $true; return }
    if (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -eq '.')) {
        $script:JsonIndex = $script:JsonIndex + 1
        $fractionStart = $script:JsonIndex
        while (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -match '[0-9]')) {
            $script:JsonIndex = $script:JsonIndex + 1
        }
        if (($script:JsonIndex - $fractionStart) -eq 0) { $script:JsonFail = $true; return }
    }
    if (($script:JsonIndex -lt $script:JsonLength) -and
        (($script:JsonText[$script:JsonIndex] -eq 'e') -or ($script:JsonText[$script:JsonIndex] -eq 'E'))) {
        $script:JsonIndex = $script:JsonIndex + 1
        if (($script:JsonIndex -lt $script:JsonLength) -and
            (($script:JsonText[$script:JsonIndex] -eq '+') -or ($script:JsonText[$script:JsonIndex] -eq '-'))) {
            $script:JsonIndex = $script:JsonIndex + 1
        }
        $exponentStart = $script:JsonIndex
        while (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -match '[0-9]')) {
            $script:JsonIndex = $script:JsonIndex + 1
        }
        if (($script:JsonIndex - $exponentStart) -eq 0) { $script:JsonFail = $true; return }
    }
    $text = $script:JsonText.Substring($start, $script:JsonIndex - $start)
    if ($text -cnotmatch $script:IntPattern) { $script:JsonFail = $true; return }
    $script:JsonString = $text
}

function Read-NewtonJsonValue {
    Skip-NewtonJsonSpace
    if ($script:JsonIndex -ge $script:JsonLength) { return $false }
    $character = $script:JsonText[$script:JsonIndex]
    if ($character -eq '{') { return (Read-NewtonJsonObject) }
    if ($character -eq '[') { return (Read-NewtonJsonArray) }
    if ($character -eq '"') {
        Read-NewtonJsonString
        if ($script:JsonFail) { return $false }
        $script:JsonStrings[($script:JsonPath -join '.')] = $script:JsonString
        return $true
    }
    if (($character -eq '-') -or ($character -match '[0-9]')) {
        Read-NewtonJsonNumber
        if ($script:JsonFail) { return $false }
        $path = ($script:JsonPath -join '.')
        $script:JsonNumbers[$path] = $script:JsonString
        return $true
    }
    if ($script:JsonText.Substring($script:JsonIndex, [Math]::Min(4, $script:JsonLength - $script:JsonIndex)) -ceq 'true') {
        $script:JsonIndex = $script:JsonIndex + 4
        return $true
    }
    if ($script:JsonText.Substring($script:JsonIndex, [Math]::Min(5, $script:JsonLength - $script:JsonIndex)) -ceq 'false') {
        $script:JsonIndex = $script:JsonIndex + 5
        return $true
    }
    if ($script:JsonText.Substring($script:JsonIndex, [Math]::Min(4, $script:JsonLength - $script:JsonIndex)) -ceq 'null') {
        $script:JsonIndex = $script:JsonIndex + 4
        return $true
    }
    return $false
}

function Read-NewtonJsonObject {
    if ($script:JsonDepth -ge $script:JsonDepthMax) { return $false }
    $script:JsonDepth = $script:JsonDepth + 1
    try {
        return (Read-NewtonJsonObjectBody)
    } finally {
        $script:JsonDepth = $script:JsonDepth - 1
    }
}

function Read-NewtonJsonObjectBody {
    $script:JsonIndex = $script:JsonIndex + 1
    $keys = New-Object System.Collections.ArrayList
    $lowered = New-Object System.Collections.ArrayList
    Skip-NewtonJsonSpace
    if (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -eq '}')) {
        $script:JsonIndex = $script:JsonIndex + 1
        return $true
    }
    while ($true) {
        Skip-NewtonJsonSpace
        if ($script:JsonIndex -ge $script:JsonLength) { return $false }
        if ($script:JsonText[$script:JsonIndex] -ne '"') { return $false }
        Read-NewtonJsonString
        if ($script:JsonFail) { return $false }
        $key = $script:JsonString
        if ($keys.Contains($key)) { return $false }
        $lower = $key.ToLowerInvariant()
        if ($lowered.Contains($lower)) { return $false }
        [void]$keys.Add($key)
        [void]$lowered.Add($lower)
        Skip-NewtonJsonSpace
        if ($script:JsonIndex -ge $script:JsonLength) { return $false }
        if ($script:JsonText[$script:JsonIndex] -ne ':') { return $false }
        $script:JsonIndex = $script:JsonIndex + 1
        [void]$script:JsonPath.Add($key)
        $ok = Read-NewtonJsonValue
        [void]$script:JsonPath.RemoveAt($script:JsonPath.Count - 1)
        if (-not $ok) { return $false }
        Skip-NewtonJsonSpace
        if ($script:JsonIndex -ge $script:JsonLength) { return $false }
        $character = $script:JsonText[$script:JsonIndex]
        if ($character -eq ',') {
            $script:JsonIndex = $script:JsonIndex + 1
            continue
        }
        if ($character -eq '}') {
            $script:JsonIndex = $script:JsonIndex + 1
            return $true
        }
        return $false
    }
}

function Read-NewtonJsonArray {
    if ($script:JsonDepth -ge $script:JsonDepthMax) { return $false }
    $script:JsonDepth = $script:JsonDepth + 1
    try {
        return (Read-NewtonJsonArrayBody)
    } finally {
        $script:JsonDepth = $script:JsonDepth - 1
    }
}

function Read-NewtonJsonArrayBody {
    $script:JsonIndex = $script:JsonIndex + 1
    $position = 0
    Skip-NewtonJsonSpace
    if (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -eq ']')) {
        $script:JsonIndex = $script:JsonIndex + 1
        return $true
    }
    while ($true) {
        [void]$script:JsonPath.Add([string]$position)
        $ok = Read-NewtonJsonValue
        [void]$script:JsonPath.RemoveAt($script:JsonPath.Count - 1)
        if (-not $ok) { return $false }
        $position = $position + 1
        Skip-NewtonJsonSpace
        if ($script:JsonIndex -ge $script:JsonLength) { return $false }
        $character = $script:JsonText[$script:JsonIndex]
        if ($character -eq ',') {
            $script:JsonIndex = $script:JsonIndex + 1
            continue
        }
        if ($character -eq ']') {
            $script:JsonIndex = $script:JsonIndex + 1
            return $true
        }
        return $false
    }
}

function Test-NewtonJsonText {
    # The raw text of the request: one JSON object, no duplicate key, no two
    # keys that differ only in case and every number in the int form.
    param([string]$Text)
    $script:JsonText = $Text
    $script:JsonIndex = 0
    $script:JsonLength = $Text.Length
    $script:JsonPath = New-Object System.Collections.ArrayList
    $script:JsonNumbers = @{}
    $script:JsonStrings = @{}
    $script:JsonDepth = 0
    $script:JsonFail = $false
    Skip-NewtonJsonSpace
    if ($script:JsonIndex -ge $script:JsonLength) { return $false }
    if ($script:JsonText[$script:JsonIndex] -ne '{') { return $false }
    if (-not (Read-NewtonJsonObject)) { return $false }
    Skip-NewtonJsonSpace
    if ($script:JsonIndex -ne $script:JsonLength) { return $false }
    return $true
}

function Get-NewtonNumberText {
    # The text of the number at a path, as it was written.
    param([string]$Path)
    if ($script:JsonNumbers -and $script:JsonNumbers.ContainsKey($Path)) {
        return [string]$script:JsonNumbers[$Path]
    }
    return $null
}

function Get-NewtonStringText {
    # The text of the string at a path, as it was written.  The JSON parser
    # of Windows PowerShell 5.1 keeps every string as text; the parser of
    # PowerShell 7 turns a date-like text into a date, so the scanner keeps
    # the text of every string and the helper reads that one.
    param([string]$Path)
    if ($script:JsonStrings -and $script:JsonStrings.ContainsKey($Path)) {
        return [string]$script:JsonStrings[$Path]
    }
    return $null
}

# ---------------------------------------------------------------------------
# the request
# ---------------------------------------------------------------------------

function Get-NewtonIntText {
    # The decimal text of an integer, exactly as it was written.
    param($Value, [string]$Path)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    $text = Get-NewtonNumberText $Path
    if ($null -ne $text) { return $text }
    if (-not (Test-NewtonIsInt $Value)) { return $null }
    return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
}

function Get-NewtonStringValue {
    # The text of a string field: the text the request wrote, never a date
    # the parser of PowerShell 7 made of it.
    param($Value, [string]$Path)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    $text = Get-NewtonStringText $Path
    if ($null -ne $text) { return $text }
    return $null
}

function Compare-NewtonIntText {
    # The order of two decimal texts of the contract: -1, 0 or 1.
    param([string]$Left, [string]$Right)
    $first = $Left.TrimStart('0')
    if ($first -eq '') { $first = '0' }
    $second = $Right.TrimStart('0')
    if ($second -eq '') { $second = '0' }
    if ($first.Length -ne $second.Length) {
        if ($first.Length -lt $second.Length) { return -1 }
        return 1
    }
    return [string]::CompareOrdinal($first, $second)
}

function Test-NewtonIntEqual {
    # Two integers of the request are equal when their texts are.
    param($Left, $Right)
    return ((Compare-NewtonIntText (Get-NewtonIntText $Left '') (Get-NewtonIntText $Right '')) -eq 0)
}

function Test-NewtonIntLess {
    param($Left, $Right)
    return ((Compare-NewtonIntText (Get-NewtonIntText $Left '') (Get-NewtonIntText $Right '')) -lt 0)
}

function Test-NewtonIntGreater {
    param($Left, $Right)
    return ((Compare-NewtonIntText (Get-NewtonIntText $Left '') (Get-NewtonIntText $Right '')) -gt 0)
}

function ConvertTo-NewtonInt64 {
    # The 64-bit value of an integer of the request, or $null when it does
    # not fit.  The bit maths of the contract is 64-bit.
    param($Value)
    $text = Get-NewtonIntText $Value ''
    if ($null -eq $text) { return $null }
    $number = 0
    if (-not [int64]::TryParse($text, [ref]$number)) { return $null }
    return $number
}

function Test-NewtonIntIs {
    param($Value, [string]$Path, [string]$Text)
    if (-not (Test-NewtonIsInt $Value $Path)) { return $false }
    $actual = Get-NewtonIntText $Value $Path
    if ($null -eq $actual) { return $false }
    return ($actual -ceq $Text)
}

function ConvertFrom-NewtonInt {
    # The value of an integer of the request: a 64-bit number, or its exact
    # text when it does not fit in 64 bits.  The canonical bytes keep the
    # text; the bit maths refuses a value it cannot hold.
    param($Value, [string]$Path)
    $text = Get-NewtonIntText $Value $Path
    if ($null -eq $text) { Throw-NewtonRefusal 'schema' 'an integer is not an integer' }
    if ($text -cnotmatch $script:IntPattern) {
        Throw-NewtonRefusal 'schema' 'an integer is not written in the int form'
    }
    $number = 0
    if ([int64]::TryParse($text, [ref]$number)) { return $number }
    return $text
}

function Test-NewtonKeys {
    # The object holds exactly the keys of its verb.
    param($Object, [string[]]$Expected)
    $names = Get-NewtonFieldNames $Object
    if ($names.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        $found = $false
        foreach ($candidate in $names) {
            if ($candidate -ceq $name) { $found = $true; break }
        }
        if (-not $found) { return $false }
    }
    return $true
}

function ConvertTo-NewtonObject {
    # The object of the request, with the exact keys of its verb.
    param($Object, [hashtable]$Kinds, [string[]]$Keys, [string]$Prefix)
    $request = @{}
    foreach ($name in $Keys) {
        $path = $Prefix + $name
        $value = Get-NewtonField $Object $name
        $kind = [string]$Kinds[$name]
        if ($kind -eq 'int' -or $kind -eq 'int_or_absent') {
            if (-not (Test-NewtonKind $kind $value $path)) {
                Throw-NewtonRefusal 'schema' 'a value is not of its kind'
            }
            if (($kind -eq 'int_or_absent') -and ($value -is [string])) {
                $request[$name] = 'absent'
                continue
            }
            $request[$name] = (ConvertFrom-NewtonInt $value $path)
            continue
        }
        $text = Get-NewtonStringValue $value $path
        if ($null -eq $text) {
            Throw-NewtonRefusal 'schema' 'a value is not of its kind'
        }
        if (-not (Test-NewtonKind $kind $text $path)) {
            Throw-NewtonRefusal 'schema' 'a value is not of its kind'
        }
        $request[$name] = $text
    }
    return $request
}

function ConvertFrom-NewtonRequest {
    # One request, checked against the contract (SPEC section 2).
    param([string]$Raw)
    if ($null -eq $Raw) { Throw-NewtonRefusal 'schema' 'the request is empty' }
    if ([System.Text.Encoding]::UTF8.GetByteCount($Raw) -gt $script:MaxRequestBytes) {
        Throw-NewtonRefusal 'schema' 'the request is bigger than 64 KiB'
    }
    if (-not (Test-NewtonJsonText -Text $Raw)) {
        Throw-NewtonRefusal 'schema' 'the request is not one JSON object of the contract'
    }
    $parsed = $null
    try {
        $parsed = ConvertFrom-Json -InputObject $Raw
    } catch {
        Throw-NewtonRefusal 'schema' 'the request is not one JSON object'
    }
    if ($parsed -isnot [System.Management.Automation.PSCustomObject]) {
        Throw-NewtonRefusal 'schema' 'the request is not a JSON object'
    }

    $version = Get-NewtonField $parsed 'v'
    if (-not (Test-NewtonIntIs $version 'v' '1')) {
        Throw-NewtonRefusal 'schema' 'the version is not 1'
    }
    $mode = Get-NewtonStringValue (Get-NewtonField $parsed 'mode') 'mode'
    if (($mode -isnot [string]) -or (-not $script:ModeFields.ContainsKey($mode))) {
        Throw-NewtonRefusal 'schema' 'the mode is not one of the modes'
    }
    $device = Get-NewtonStringValue (Get-NewtonField $parsed 'device') 'device'
    if (($device -isnot [string]) -or ($device -cnotmatch $script:DevicePattern)) {
        Throw-NewtonRefusal 'schema' 'the device is outside its pattern'
    }

    $allowed = $script:ModeFields[$mode]
    $names = Get-NewtonFieldNames $parsed
    foreach ($name in $names) {
        $known = $false
        foreach ($candidate in $allowed) {
            if ($candidate -ceq $name) { $known = $true; break }
        }
        if (-not $known) {
            Throw-NewtonRefusal 'schema' 'the request holds a field the mode does not have'
        }
    }
    foreach ($candidate in $allowed) {
        if ($candidate -eq 'secret') { continue }
        $present = $false
        foreach ($name in $names) {
            if ($name -ceq $candidate) { $present = $true; break }
        }
        if (-not $present) {
            Throw-NewtonRefusal 'schema' 'the request is missing a field of its mode'
        }
    }

    $request = @{
        v = 1
        mode = $mode
        device = $device
    }

    if ($mode -eq 'apply' -or $mode -eq 'read') {
        $verb = Get-NewtonStringValue (Get-NewtonField $parsed 'verb') 'verb'
        if (($verb -isnot [string]) -or (-not $script:TargetKeys.ContainsKey($verb))) {
            Throw-NewtonRefusal 'schema' 'the verb is not one of the verbs'
        }
        $request['verb'] = $verb
        $target = Get-NewtonField $parsed 'target'
        if ($null -eq $target -or ($target -isnot [System.Management.Automation.PSCustomObject])) {
            Throw-NewtonRefusal 'schema' 'a target is not an object'
        }
        $reading = ($mode -eq 'read')
        $targetKeys = $script:TargetKeys[$verb]
        if ($reading) {
            $readKeys = $script:ReadTargetKeys[$verb]
            if (Test-NewtonKeys $target $readKeys) { $targetKeys = $readKeys }
        }
        if (-not (Test-NewtonKeys $target $targetKeys)) {
            Throw-NewtonRefusal 'schema' 'the target does not hold the keys of its verb'
        }
        $request['target'] = (ConvertTo-NewtonObject $target $script:TargetKinds[$verb] $targetKeys 'target.')
    }

    if ($mode -eq 'apply') {
        $txid = Get-NewtonStringValue (Get-NewtonField $parsed 'txid') 'txid'
        if (($txid -isnot [string]) -or ($txid -cnotmatch $script:TxidPattern)) {
            Throw-NewtonRefusal 'schema' 'the txid is outside its pattern'
        }
        $request['txid'] = $txid

        $window = Get-NewtonField $parsed 'window'
        if (-not (Test-NewtonIsInt $window 'window')) {
            Throw-NewtonRefusal 'schema' 'the window is not an integer'
        }
        $windowNumber = (ConvertFrom-NewtonInt $window 'window')
        if ((Test-NewtonIntLess $windowNumber $script:WindowMin) -or
            (Test-NewtonIntGreater $windowNumber $script:WindowMax)) {
            Throw-NewtonRefusal 'schema' 'the window is outside its range'
        }
        if (($verb -eq 'unlock') -and (-not (Test-NewtonIntEqual $windowNumber $script:UnlockWindow))) {
            Throw-NewtonRefusal 'schema' 'the window of an unlock is 120'
        }
        $request['window'] = $windowNumber

        foreach ($name in @('nbf', 'exp')) {
            $value = Get-NewtonField $parsed $name
            if (-not (Test-NewtonIsInt $value $name)) {
                Throw-NewtonRefusal 'schema' ('the approval ' + $name + ' is not an integer')
            }
            $number = (ConvertFrom-NewtonInt $value $name)
            $text = Get-NewtonIntText $number ''
            if ($text -cnotmatch $script:EpochPattern) {
                Throw-NewtonRefusal 'schema' ('the approval ' + $name + ' is not ten digits')
            }
            $request[$name] = $number
        }
        if (-not (Test-NewtonIntLess $request['nbf'] $request['exp'])) {
            Throw-NewtonRefusal 'schema' 'the approval window does not move forward'
        }
        $width = (ConvertTo-NewtonInt64 $request['exp'])
        $start = (ConvertTo-NewtonInt64 $request['nbf'])
        if (($null -eq $width) -or ($null -eq $start)) {
            Throw-NewtonRefusal 'schema' 'the approval window is outside the range of the helper'
        }
        if (($width - $start) -gt $script:ApprovalWindowMax) {
            Throw-NewtonRefusal 'schema' 'the approval window is wider than 1800 seconds'
        }

        $risk = Get-NewtonStringValue (Get-NewtonField $parsed 'risk') 'risk'
        if (($risk -isnot [string]) -or ($risk -cnotmatch $script:RiskPattern)) {
            Throw-NewtonRefusal 'schema' 'the risk is not one of LOW, MED or HIGH'
        }
        $request['risk'] = $risk

        $token = Get-NewtonStringValue (Get-NewtonField $parsed 'token') 'token'
        if (($token -isnot [string]) -or ($token -cnotmatch $script:TokenPattern)) {
            Throw-NewtonRefusal 'schema' 'the token is outside its pattern'
        }
        $request['token'] = $token

        foreach ($name in @('before', 'after')) {
            $image = Get-NewtonField $parsed $name
            if ($null -eq $image -or ($image -isnot [System.Management.Automation.PSCustomObject])) {
                Throw-NewtonRefusal 'schema' 'an image is not an object'
            }
            if (-not (Test-NewtonKeys $image @($script:ValueKey[$verb]))) {
                Throw-NewtonRefusal 'schema' 'the image does not hold the keys of its verb'
            }
            $request[$name] = (ConvertTo-NewtonObject $image $script:ValueKinds[$verb] @($script:ValueKey[$verb]) ($name + '.'))
        }

        $hasSecret = $false
        foreach ($name in $names) {
            if ($name -ceq 'secret') { $hasSecret = $true; break }
        }
        if ($hasSecret) {
            if ($verb -ne 'user-create') {
                Throw-NewtonRefusal 'schema' 'only a user-create carries a secret'
            }
            $secret = Get-NewtonStringValue (Get-NewtonField $parsed 'secret') 'secret'
            if ($secret -isnot [string]) {
                Throw-NewtonRefusal 'schema' 'the secret is not text'
            }
            if (($secret.Length -lt $script:SecretMin) -or ($secret.Length -gt $script:SecretMax)) {
                Throw-NewtonRefusal 'schema' 'the secret is outside its length'
            }
            foreach ($character in $secret.ToCharArray()) {
                $code = [int][char]$character
                if (($code -lt 0x21) -or ($code -gt 0x7e)) {
                    Throw-NewtonRefusal 'schema' 'the secret holds a character outside 0x21..0x7e'
                }
            }
            $request['secret'] = $secret
        }
    } elseif ($mode -eq 'confirm' -or $mode -eq 'abort' -or $mode -eq 'status') {
        $txid = Get-NewtonStringValue (Get-NewtonField $parsed 'txid') 'txid'
        if (($txid -isnot [string]) -or ($txid -cnotmatch $script:TxidPattern)) {
            Throw-NewtonRefusal 'schema' 'the txid is outside its pattern'
        }
        $request['txid'] = $txid
    }

    return $request
}

# ---------------------------------------------------------------------------
# the rules of the verbs (SPEC section 3)
# ---------------------------------------------------------------------------

function Get-NewtonRid {
    param($Sid)
    if ($Sid -isnot [string]) { return $null }
    $parts = $Sid.Split('-')
    $tail = $parts[$parts.Count - 1]
    $number = 0
    if (-not [int]::TryParse($tail, [ref]$number)) { return $null }
    return $number
}

function Test-NewtonVerbRules {
    # The rules of the table of section 3 that the request itself answers.
    # The bit maths is 64-bit, as the contract measures it.
    param([hashtable]$Request)
    $verb = [string]$Request['verb']
    $target = $Request['target']
    $before = $Request['before']
    $after = $Request['after']
    if ($verb -eq 'uac-clear') {
        $bit = $target['bit']
        $known = $false
        foreach ($candidate in $script:UacClearBits) {
            if (Test-NewtonIntEqual $candidate $bit) { $known = $true; break }
        }
        if (-not $known) { Throw-NewtonRefusal 'denied' 'the bit is not one of the bits of the table' }
        $mask = (ConvertTo-NewtonInt64 $bit)
        $beforeUac = (ConvertTo-NewtonInt64 $before['uac'])
        if (($null -eq $mask) -or ($null -eq $beforeUac)) {
            Throw-NewtonRefusal 'denied' 'the value is outside the 64-bit range of the helper'
        }
        if (($beforeUac -band $mask) -eq 0) {
            Throw-NewtonRefusal 'denied' 'the bit is not set in the before-image'
        }
        $expected = $beforeUac -band (-bnot $mask)
        if (-not (Test-NewtonIntEqual $after['uac'] $expected)) {
            Throw-NewtonRefusal 'denied' 'the after-image is not the before-image without the bit'
        }
    } elseif ($verb -eq 'disable') {
        $beforeUac = (ConvertTo-NewtonInt64 $before['uac'])
        if ($null -eq $beforeUac) {
            Throw-NewtonRefusal 'denied' 'the value is outside the 64-bit range of the helper'
        }
        if (($beforeUac -band $script:AccountDisable) -ne 0) {
            Throw-NewtonRefusal 'denied' 'the account is already disabled'
        }
        $expected = $beforeUac -bor $script:AccountDisable
        if (-not (Test-NewtonIntEqual $after['uac'] $expected)) {
            Throw-NewtonRefusal 'denied' 'the after-image is not the before-image with the bit'
        }
        $rid = Get-NewtonRid $target['sid']
        if (($null -ne $rid) -and ($rid -eq 500)) {
            Throw-NewtonRefusal 'denied' 'the administrator is never disabled'
        }
    } elseif ($verb -eq 'enable') {
        $beforeUac = (ConvertTo-NewtonInt64 $before['uac'])
        if ($null -eq $beforeUac) {
            Throw-NewtonRefusal 'denied' 'the value is outside the 64-bit range of the helper'
        }
        if (($beforeUac -band $script:AccountDisable) -eq 0) {
            Throw-NewtonRefusal 'denied' 'the account is not disabled'
        }
        $expected = $beforeUac -band (-bnot $script:AccountDisable)
        if (-not (Test-NewtonIntEqual $after['uac'] $expected)) {
            Throw-NewtonRefusal 'denied' 'the after-image is not the before-image without the bit'
        }
    } elseif ($verb -eq 'enc-types') {
        $beforeTypes = 0
        if ($before['etypes'] -ne 'absent') { $beforeTypes = (ConvertTo-NewtonInt64 $before['etypes']) }
        $afterTypes = 0
        if ($after['etypes'] -ne 'absent') { $afterTypes = (ConvertTo-NewtonInt64 $after['etypes']) }
        if (($null -eq $beforeTypes) -or ($null -eq $afterTypes)) {
            Throw-NewtonRefusal 'denied' 'the value is outside the 64-bit range of the helper'
        }
        if (($afterTypes -band $script:DesTypeBits) -ne 0) {
            Throw-NewtonRefusal 'denied' 'DES is never enabled'
        }
        if (($afterTypes -band (-bnot $script:EncTypeLowMask)) -ne
            ($beforeTypes -band (-bnot $script:EncTypeLowMask))) {
            Throw-NewtonRefusal 'denied' 'the bits above 63 may not change'
        }
        if ($afterTypes -eq $beforeTypes) {
            Throw-NewtonRefusal 'denied' 'the encryption types do not change'
        }
    } elseif ($verb -eq 'unlock') {
        if (-not (Test-NewtonIntGreater $before['lockout'] 0)) {
            Throw-NewtonRefusal 'denied' 'the account is not locked out'
        }
        if (-not (Test-NewtonIntEqual $after['lockout'] 0)) {
            Throw-NewtonRefusal 'denied' 'the after-image of an unlock is zero'
        }
    } elseif ($verb -eq 'member-add') {
        if (($before['member'] -ne 'absent') -or ($after['member'] -ne 'present')) {
            Throw-NewtonRefusal 'denied' 'a member-add goes from absent to present'
        }
    } elseif ($verb -eq 'member-remove') {
        if (($before['member'] -ne 'present') -or ($after['member'] -ne 'absent')) {
            Throw-NewtonRefusal 'denied' 'a member-remove goes from present to absent'
        }
    } elseif ($verb -eq 'maq') {
        if ((Test-NewtonIntLess $after['maq'] 0) -or (Test-NewtonIntGreater $after['maq'] 1000)) {
            Throw-NewtonRefusal 'denied' 'the quota is outside 0..1000'
        }
    } elseif ($verb -eq 'user-create') {
        if (($before['object'] -ne 'absent') -or ($after['object'] -ne 'present')) {
            Throw-NewtonRefusal 'denied' 'a user-create goes from absent to present'
        }
    }
}

# ---------------------------------------------------------------------------
# the canonical bytes, the digest and the token (SPEC section 4)
# ---------------------------------------------------------------------------

function Get-NewtonCanonicalValue {
    param($Value)
    if ($Value -is [string]) { return $Value }
    if ($Value -is [int64] -or $Value -is [int32] -or $Value -is [int16] -or $Value -is [byte]) {
        return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    Throw-NewtonRefusal 'schema' 'a value has no canonical form'
}

function Sort-NewtonOrdinal {
    # The keys of the canonical bytes, sorted by byte value (SPEC section 4).
    param([string[]]$Names)
    $sorted = New-Object System.Collections.ArrayList
    foreach ($name in $Names) {
        $position = 0
        while ($position -lt $sorted.Count) {
            if ([string]::CompareOrdinal($name, [string]$sorted[$position]) -lt 0) { break }
            $position = $position + 1
        }
        [void]$sorted.Insert($position, $name)
    }
    return ,$sorted.ToArray()
}

function Get-NewtonCanonicalPairs {
    param($Values)
    if ($null -eq $Values) { return '' }
    $names = @()
    foreach ($name in $Values.Keys) { $names += ([string]$name) }
    $parts = @()
    foreach ($name in (Sort-NewtonOrdinal $names)) {
        $parts += ($name + '=' + (Get-NewtonCanonicalValue $Values[$name]))
    }
    return ($parts -join ',')
}

function Get-NewtonCanonicalBytes {
    # The eleven lines of SPEC section 4, in ASCII only.
    param([hashtable]$Request)
    foreach ($field in @('device', 'txid', 'verb')) {
        if (-not $Request.ContainsKey($field)) {
            Throw-NewtonRefusal 'schema' 'the request does not hold the fields of a request'
        }
    }
    $risk = [string]$Request['risk']
    if ($risk -cnotmatch $script:RiskPattern) {
        Throw-NewtonRefusal 'schema' 'the request does not hold a risk level'
    }
    $secretLine = '-'
    if ($Request.ContainsKey('secret')) {
        $secret = [string]$Request['secret']
        $secretLine = (Get-NewtonSha256Hex ([System.Text.Encoding]::ASCII.GetBytes($secret)))
    }
    $windowLine = ''
    if ($Request.ContainsKey('window')) {
        $windowLine = (Get-NewtonCanonicalValue $Request['window'])
    }
    $lines = @(
        'newton-ad-request-v1',
        ('device=' + $Request['device']),
        ('txid=' + $Request['txid']),
        ('verb=' + $Request['verb']),
        ('target=' + (Get-NewtonCanonicalPairs $Request['target'])),
        ('before=' + (Get-NewtonCanonicalPairs $Request['before'])),
        ('after=' + (Get-NewtonCanonicalPairs $Request['after'])),
        ('window=' + $windowLine),
        ('risk=' + $risk),
        ('secret=' + $secretLine),
        'helper=1'
    )
    return ,([System.Text.Encoding]::ASCII.GetBytes(($lines -join "`n") + "`n"))
}

function Get-NewtonSha256Hex {
    param([byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash($Bytes)
        return (-join ($hash | ForEach-Object { $_.ToString('x2') }))
    } finally {
        $algorithm.Dispose()
    }
}

function Get-NewtonDigest {
    param([hashtable]$Request)
    return (Get-NewtonSha256Hex (Get-NewtonCanonicalBytes $Request))
}

function Get-NewtonToken {
    # HMAC-SHA256(K, "newton-approval-v2\n" + digest + "\n" + nbf + "\n" + exp + "\n")
    param([byte[]]$Key, [string]$Digest, $NotBefore, $NotAfter)
    $message = "newton-approval-v2`n" + $Digest + "`n" + $NotBefore.ToString() + "`n" + $NotAfter.ToString() + "`n"
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $hash = $hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($message))
        return (-join ($hash | ForEach-Object { $_.ToString('x2') }))
    } finally {
        $hmac.Dispose()
    }
}

function Test-NewtonConstantTime {
    # The comparison of the token: the same length and no early exit.
    param([string]$Left, [string]$Right)
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    $leftBytes = [System.Text.Encoding]::ASCII.GetBytes($Left)
    $rightBytes = [System.Text.Encoding]::ASCII.GetBytes($Right)
    if ($leftBytes.Length -ne $rightBytes.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $leftBytes.Length; $index++) {
        $difference = $difference -bor ($leftBytes[$index] -bxor $rightBytes[$index])
    }
    return ($difference -eq 0)
}

# ---------------------------------------------------------------------------
# the install: the key, the device name and the ACL
# ---------------------------------------------------------------------------

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

function Get-NewtonDeviceName {
    # The name of the device that stands for the domain, the same on every DC (SPEC section 8).
    if ($script:DeviceOverride -ne '') { return $script:DeviceOverride }
    $path = Get-NewtonDevicePath
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $text = [System.IO.File]::ReadAllText($path)
    return $text.Trim()
}

function ConvertFrom-NewtonHex {
    # .NET Framework/Windows PowerShell 5.1 has no built-in hex decoder.
    # Decode pairs explicitly and reject malformed text.
    param([string]$Hex)
    if ($null -eq $Hex) { throw 'hex text is missing' }
    if (($Hex.Length % 2) -ne 0) { throw 'hex text has odd length' }
    if (($Hex.Length -gt 0) -and ($Hex -cnotmatch '\A[0-9a-fA-F]+\z')) {
        throw 'hex text contains a non-hex character'
    }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return ,$bytes
}

function Get-NewtonKeyBytes {
    # The approval key K of this DC (SPEC section 8).
    if ($script:KeyOverride -ne '') {
        try { return ,(ConvertFrom-NewtonHex $script:KeyOverride) } catch { return $null }
    }
    $path = Get-NewtonKeyPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $text = [System.IO.File]::ReadAllText($path)
    $hex = $text.Trim()
    if ($hex -cnotmatch '\A[0-9a-f]{64}\z') { return $null }
    try { return ,(ConvertFrom-NewtonHex $hex) } catch { return $null }
}

function Test-NewtonInstall {
    # The install of the helper: the files are there and nobody but SYSTEM
    # and Administrators may write them.
    $root = Get-NewtonInstallRoot
    if (-not (Test-Path -LiteralPath $root)) { return 'unavailable' }
    foreach ($path in @((Get-NewtonKeyPath), (Get-NewtonDevicePath))) {
        if (-not (Test-Path -LiteralPath $path)) { return 'unavailable' }
    }
    try {
        foreach ($path in @($root, (Get-NewtonKeyPath), (Get-NewtonDevicePath))) {
            if (-not (Test-NewtonSafeAcl $path)) { return 'denied' }
        }
    } catch {
        return 'denied'
    }
    return ''
}

# ---------------------------------------------------------------------------
# the LDAP adapter
#
# Every LDAP call of the helper goes through one adapter.  The tests swap in
# a fake adapter; the
# helper never talks to the directory in any other way.
# ---------------------------------------------------------------------------

function New-NewtonLdapAdapter {
    # The real adapter (SPEC section 9): one signed and sealed connection to
    # this DC, bound with the default credentials.
    #
    # A caller may hand in its own connection object: the
    # adapter then sends every request to it and to nothing else.  The tests
    # use that to run the real Modify and Add without a DC.
    param($Connection = $null)
    $hostName = ''
    if ($null -eq $Connection) {
        $hostName = [System.Net.Dns]::GetHostEntry('').HostName
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($hostName)
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.Bind()
        $Connection = $connection
    }
    $adapter = [pscustomobject]@{
        Connection = $Connection
        Host = $hostName
        Log = (New-Object System.Collections.ArrayList)
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name Search -Value {
        param($Base, $Filter, $Scope, $Attributes)
        [void]$this.Log.Add(('search ' + $Base + ' ' + $Filter + ' ' + $Scope))
        $scopeValue = [System.DirectoryServices.Protocols.SearchScope]::Subtree
        if ($Scope -eq 'base') { $scopeValue = [System.DirectoryServices.Protocols.SearchScope]::Base }
        if ($Scope -eq 'one') { $scopeValue = [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
        $attrs = @()
        foreach ($attribute in @($Attributes)) { $attrs += [string]$attribute }
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $Base, $Filter, $scopeValue, [string[]]$attrs
        )
        $response = $this.Connection.SendRequest($request)
        $entries = @()
        foreach ($entry in $response.Entries) {
            $map = @{}
            foreach ($name in $entry.Attributes.AttributeNames) {
                $key = ([string]$name).ToLowerInvariant()
                $attribute = Get-NewtonDirectoryAttribute $entry $name
                if ($key -eq 'objectsid' -or $key -eq 'objectguid' -or $key -eq 'tokengroups') {
                    $map[$key] = @($attribute.GetValues([byte[]]))
                } else {
                    $map[$key] = @($attribute.GetValues([string]))
                }
            }
            $entries += ,@{ dn = [string]$entry.DistinguishedName; attrs = $map }
        }
        return ,$entries
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name Modify -Value {
        param($Dn, $Attribute, $OldValues, $NewValues)
        [void]$this.Log.Add(('modify ' + $Dn + ' ' + $Attribute))
        $request = [System.DirectoryServices.Protocols.ModifyRequest]::new($Dn)
        foreach ($value in @($OldValues)) {
            # the index of the collection is discarded: it would leak into
            # the answer of the mode.
            [void]$request.Modifications.Add((New-NewtonDirectoryModification 1 $Attribute @([string]$value)))
        }
        foreach ($value in @($NewValues)) {
            [void]$request.Modifications.Add((New-NewtonDirectoryModification 0 $Attribute @([string]$value)))
        }
        $null = $this.Connection.SendRequest($request)
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name ModifyDN -Value {
        param($Dn, $NewParentDn, $NewRdn)
        [void]$this.Log.Add(('modifydn ' + $Dn + ' ' + $NewParentDn + ' ' + $NewRdn))
        $request = [System.DirectoryServices.Protocols.ModifyDNRequest]::new($Dn, $NewParentDn, $NewRdn)
        $null = $this.Connection.SendRequest($request)
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name Add -Value {
        param($Dn, $Attributes)
        [void]$this.Log.Add(('add ' + $Dn))
        $request = [System.DirectoryServices.Protocols.AddRequest]::new($Dn)
        foreach ($name in $Attributes.Keys) {
            $values = $Attributes[$name]
            if ($values -is [byte[]]) {
                # the index of the collection is discarded.
                [void]$request.Attributes.Add([System.DirectoryServices.Protocols.DirectoryAttribute]::new([string]$name, $values))
                continue
            }
            $texts = @()
            foreach ($value in @($values)) { $texts += [string]$value }
            [void]$request.Attributes.Add([System.DirectoryServices.Protocols.DirectoryAttribute]::new([string]$name, [string[]]$texts))
        }
        $null = $this.Connection.SendRequest($request)
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name Delete -Value {
        param($Dn)
        [void]$this.Log.Add(('delete ' + $Dn))
        $request = [System.DirectoryServices.Protocols.DeleteRequest]::new($Dn)
        $null = $this.Connection.SendRequest($request)
    }
    return $adapter
}

function New-NewtonDirectoryModification {
    # Windows Server 2025/.NET Framework exposes only the parameterless
    # constructor: set the fields, then add each value.
    param([int]$Operation, [string]$Name, [string[]]$Values)
    $operationValue = [System.Enum]::ToObject([System.DirectoryServices.Protocols.DirectoryAttributeOperation], $Operation)
    $modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $modification.Name = $Name
    $modification.Operation = $operationValue
    foreach ($value in @($Values)) { [void]$modification.Add($value) }
    return ,$modification
}

function Get-NewtonDirectoryAttribute {
    # One attribute of one entry.  A DirectoryAttribute unrolls when it is
    # returned from a function, so it goes back with the comma operator.
    param($Entry, [string]$Name)
    $attribute = $Entry.Attributes[$Name]
    if ($null -eq $attribute) { return $null }
    return ,$attribute
}

function Get-NewtonLdapAdapter {
    if ($null -ne $script:LdapAdapter) { return $script:LdapAdapter }
    $script:LdapAdapter = New-NewtonLdapAdapter
    return $script:LdapAdapter
}

function Get-NewtonLdapResultCode {
    # The result code of a failed LDAP call (SPEC section 9).
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 0 }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        $responseProperty = $exception.PSObject.Properties['Response']
        if (($null -ne $responseProperty) -and ($null -ne $responseProperty.Value)) {
            $resultProperty = $responseProperty.Value.PSObject.Properties['ResultCode']
            if ($null -ne $resultProperty) { return [int]$resultProperty.Value }
        }
        $exception = $exception.InnerException
    }
    return 0
}

function Get-NewtonLdapCode {
    # The code of the contract for a failed LDAP call: 16 is a conflict, 50
    # is denied, 32 is not found and anything else is an error.
    param($ErrorRecord)
    $code = Get-NewtonLdapResultCode $ErrorRecord
    if ($code -eq 16) { return 'conflict' }
    if ($code -eq 50) { return 'denied' }
    if ($code -eq 32) { return 'not_found' }
    return 'error'
}

# ---------------------------------------------------------------------------
# the directory
# ---------------------------------------------------------------------------

function Get-NewtonAttr {
    # The values of one attribute of an entry, as they were read.
    param($Entry, [string]$Name)
    if ($null -eq $Entry) { return $null }
    $attributes = $Entry['attrs']
    if ($null -eq $attributes) { return $null }
    $key = $Name.ToLowerInvariant()
    if (-not $attributes.ContainsKey($key)) { return $null }
    return ,$attributes[$key]
}

function Get-NewtonAttrString {
    # The first value of one attribute, as text.  A single value unrolls to a
    # string, and indexing a string gives a character: the array is built
    # first (SPEC section 9).
    param($Entry, [string]$Name, [int]$Index = 0)
    $values = Get-NewtonAttr $Entry $Name
    if ($null -eq $values) { return $null }
    if ($values -is [string]) {
        if ($Index -ne 0) { return $null }
        return $values
    }
    if ($values -is [byte[]]) { return $null }
    $list = @($values)
    if ($list.Count -le $Index) { return $null }
    $value = $list[$Index]
    if ($value -is [byte[]]) { return $null }
    return [string]$value
}

function Get-NewtonAttrStrings {
    # Every value of one attribute, as text.
    param($Entry, [string]$Name)
    $values = Get-NewtonAttr $Entry $Name
    if ($null -eq $values) { return ,@() }
    if ($values -is [string]) { return ,@($values) }
    if ($values -is [byte[]]) { return ,@() }
    $list = @()
    foreach ($value in @($values)) {
        if ($value -is [byte[]]) { continue }
        $list += [string]$value
    }
    return ,$list
}

function Get-NewtonAttrBytes {
    # The bytes of one attribute.
    param($Entry, [string]$Name)
    $values = Get-NewtonAttr $Entry $Name
    if ($null -eq $values) { return $null }
    if ($values -is [byte[]]) { return ,$values }
    foreach ($value in @($values)) {
        if ($value -is [byte[]]) { return ,$value }
    }
    return $null
}

function Get-NewtonAttrByteArrays {
    # Every binary value of an attribute (tokenGroups is multi-valued).
    param($Entry, [string]$Name)
    $values = Get-NewtonAttr $Entry $Name
    if ($null -eq $values) { return ,@() }
    if ($values -is [byte[]]) { return ,@($values) }
    $result = @()
    foreach ($value in @($values)) {
        if ($value -is [byte[]]) { $result += ,$value }
    }
    return ,$result
}

function Get-NewtonAttrInt {
    # The first value of one attribute, as an integer.
    param($Entry, [string]$Name)
    $text = Get-NewtonAttrString $Entry $Name 0
    if ($null -eq $text) { return $null }
    $number = 0
    if (-not [int64]::TryParse($text, [ref]$number)) { return $null }
    return $number
}

function ConvertFrom-NewtonSidBytes {
    # The text of a SID, from its bytes.  The SecurityIdentifier of the
    # .NET Framework only runs on Windows; the format is the same.
    param([byte[]]$Bytes)
    if (($null -eq $Bytes) -or ($Bytes.Length -lt 8)) { return '' }
    $authority = 0
    for ($index = 2; $index -le 7; $index++) {
        $authority = ($authority -shl 8) -bor [int64]$Bytes[$index]
    }
    $parts = @('S', [string][int]$Bytes[0], [string]$authority)
    $count = [int]$Bytes[1]
    $offset = 8
    for ($index = 0; $index -lt $count; $index++) {
        if (($offset + 4) -gt $Bytes.Length) { break }
        $value = [int64]$Bytes[$offset]
        $value = $value -bor ([int64]$Bytes[$offset + 1] -shl 8)
        $value = $value -bor ([int64]$Bytes[$offset + 2] -shl 16)
        $value = $value -bor ([int64]$Bytes[$offset + 3] -shl 24)
        $parts += [string]$value
        $offset = $offset + 4
    }
    return ($parts -join '-')
}

function Get-NewtonSid {
    # The SID of an entry, read from its bytes.
    param($Entry)
    $bytes = Get-NewtonAttrBytes $Entry 'objectSid'
    if ($null -eq $bytes) { return '' }
    if ($bytes.Length -eq 0) { return '' }
    try {
        return [string][System.Security.Principal.SecurityIdentifier]::new($bytes, 0).Value
    } catch {
        return (ConvertFrom-NewtonSidBytes $bytes)
    }
}

function Get-NewtonGuid {
    # The objectGUID of an entry, read from its bytes.
    param($Entry)
    $bytes = Get-NewtonAttrBytes $Entry 'objectGuid'
    if ($null -eq $bytes) { return '' }
    if ($bytes.Length -eq 0) { return '' }
    try {
        return [string]([guid]::new($bytes)).ToString()
    } catch {
        return ''
    }
}

function ConvertTo-NewtonGuidFilter {
    # The LDAP filter of one objectGUID: the raw bytes, escaped.
    param([string]$Guid)
    $bytes = ([guid]$Guid).ToByteArray()
    $parts = @()
    foreach ($byte in $bytes) { $parts += ('\{0:X2}' -f [int]$byte) }
    return ('(objectGUID=' + ($parts -join '') + ')')
}

function ConvertTo-NewtonSidBytes {
    # The bytes of one SID, the way the directory stores it.
    param([string]$Sid)
    $parts = $Sid.Split('-')
    if ($parts.Count -lt 3) { return $null }
    $revision = 0
    $authority = 0
    if (-not [int]::TryParse($parts[1], [ref]$revision)) { return $null }
    if (-not [int64]::TryParse($parts[2], [ref]$authority)) { return $null }
    $subAuthorities = @()
    for ($index = 3; $index -lt $parts.Count; $index++) {
        $number = 0
        if (-not [int64]::TryParse($parts[$index], [ref]$number)) { return $null }
        $subAuthorities += $number
    }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte]$revision)
    $bytes.Add([byte]$subAuthorities.Count)
    $authorityBytes = [System.BitConverter]::GetBytes([int64]$authority)
    for ($index = 5; $index -ge 0; $index--) { $bytes.Add($authorityBytes[$index]) }
    foreach ($number in $subAuthorities) {
        $value = [System.BitConverter]::GetBytes([int64]$number)
        for ($index = 0; $index -lt 4; $index++) { $bytes.Add($value[$index]) }
    }
    return ,$bytes.ToArray()
}

function ConvertTo-NewtonSidFilter {
    # The LDAP filter of one objectSid: the raw bytes, escaped.
    param([string]$Sid)
    $bytes = ConvertTo-NewtonSidBytes $Sid
    if ($null -eq $bytes) { return $null }
    $parts = @()
    foreach ($byte in $bytes) { $parts += ('\{0:X2}' -f [int]$byte) }
    return ('(objectSid=' + ($parts -join '') + ')')
}

function Search-Newton {
    param($Adapter, [string]$Base, [string]$Filter, [string]$Scope, [string[]]$Attributes)
    $entries = $Adapter.Search($Base, $Filter, $Scope, $Attributes)
    $list = @()
    foreach ($entry in @($entries)) { $list += $entry }
    return ,$list
}

function ConvertTo-NewtonFilterText {
    # The value of an LDAP filter, escaped as the filter of RFC 4515.
    param([string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $parts = @()
    foreach ($byte in $bytes) {
        $character = [char]$byte
        if (($character -eq '\') -or ($character -eq '*') -or ($character -eq '(') -or
            ($character -eq ')') -or ($byte -eq 0)) {
            $parts += ('\{0:X2}' -f [int]$byte)
            continue
        }
        $parts += [string]$character
    }
    return ($parts -join '')
}

function Split-NewtonDn {
    # The relative name and the parent DN of a distinguished name.  A comma
    # inside an escaped value does not separate the two.
    param([string]$Dn)
    $index = 0
    while ($index -lt $Dn.Length) {
        $character = $Dn[$index]
        if ($character -eq '\') { $index = $index + 2; continue }
        if ($character -eq ',') {
            return @{ rdn = $Dn.Substring(0, $index); parent = $Dn.Substring($index + 1) }
        }
        $index = $index + 1
    }
    return @{ rdn = $Dn; parent = '' }
}

function Get-NewtonParentDn {
    # The DN of the parent of an object.  The directory has no parent
    # attribute (measured on 2026-11-09), so the parent comes from the DN.
    param($Object)
    if ($null -eq $Object) { return '' }
    $parts = Split-NewtonDn ([string]$Object['dn'])
    return [string]$parts['parent']
}

function Get-NewtonRdn {
    # The relative name of an object: the first part of its DN.
    param($Object)
    if ($null -eq $Object) { return '' }
    $parts = Split-NewtonDn ([string]$Object['dn'])
    return [string]$parts['rdn']
}

function Test-NewtonMemberPresent {
    # The member is in the group.  The presence is a base-scope search on
    # the group with the member filter, so a group of more than 1500
    # members still works and the whole list is never read.
    param($Adapter, [string]$GroupDn, [string]$MemberDn)
    if (($null -eq $GroupDn) -or ($GroupDn -eq '')) { return $false }
    if (($null -eq $MemberDn) -or ($MemberDn -eq '')) { return $false }
    $filter = '(member=' + (ConvertTo-NewtonFilterText $MemberDn) + ')'
    $entries = Search-Newton $Adapter $GroupDn $filter 'base' ([string[]]@('objectClass'))
    if ($entries.Count -eq 0) { return $false }
    return $true
}

function Find-NewtonObjectByGuid {
    # The object of one objectGUID, or $null.
    param($Adapter, [string]$Guid, [string]$DomainDn = '')
    if ($DomainDn -eq '') { $DomainDn = Get-NewtonDomainDn $Adapter }
    if ($DomainDn -eq '') { return $null }
    $entries = Search-Newton $Adapter $DomainDn (ConvertTo-NewtonGuidFilter $Guid) 'sub' $script:ObjectReadAttributes
    foreach ($entry in $entries) { return $entry }
    return $null
}

function Find-NewtonObjectBySam {
    # The object of one sAMAccountName.  Zero or more than one match is not
    # found.
    param($Adapter, [string]$Sam, [string]$DomainDn = '')
    if ($DomainDn -eq '') { $DomainDn = Get-NewtonDomainDn $Adapter }
    if ($DomainDn -eq '') { return $null }
    $entries = Search-Newton $Adapter $DomainDn ('(sAMAccountName=' + $Sam + ')') 'sub' $script:ObjectReadAttributes
    if ($entries.Count -ne 1) { return $null }
    return $entries[0]
}

function Find-NewtonObjectByDn {
    # The object of one DN.
    param($Adapter, [string]$Dn)
    $entries = Search-Newton $Adapter $Dn '(objectClass=*)' 'base' $script:ObjectReadAttributes
    if ($entries.Count -eq 0) { return $null }
    return $entries[0]
}

function Find-NewtonCreatedObject {
    # The object a user-create made.  The undo needs the members and the
    # groups of that object, so this read asks for them: the read of every
    # other object never asks for the member list.
    param($Adapter, [string]$Guid, [string]$DomainDn)
    if ($DomainDn -eq '') { $DomainDn = Get-NewtonDomainDn $Adapter }
    if ($DomainDn -eq '') { return $null }
    $entries = Search-Newton $Adapter $DomainDn (ConvertTo-NewtonGuidFilter $Guid) 'sub' ([string[]]@(
        'objectGUID', 'userAccountControl', 'uSNChanged', 'member', 'memberOf'
    ))
    if ($entries.Count -eq 0) { return $null }
    return $entries[0]
}

function Get-NewtonRootDse {
    param($Adapter)
    $entries = Search-Newton $Adapter '' '(objectClass=*)' 'base' ([string[]]@(
        'defaultNamingContext', 'dsServiceName'
    ))
    if ($entries.Count -eq 0) { return $null }
    return $entries[0]
}

function Get-NewtonDomainHead {
    # The domain head: the object with the class domainDNS.
    param($Adapter, [string]$DomainDn)
    $entries = Search-Newton $Adapter $DomainDn '(objectClass=domainDNS)' 'base' ([string[]]@(
        'fSMORoleOwner', 'ms-DS-MachineAccountQuota', 'objectSid'
    ))
    if ($entries.Count -eq 0) { return $null }
    return $entries[0]
}

function Get-NewtonDomainDn {
    param($Adapter)
    $root = Get-NewtonRootDse $Adapter
    if ($null -eq $root) { return '' }
    $dn = Get-NewtonAttrString $root 'defaultNamingContext' 0
    if ($null -eq $dn) { return '' }
    return $dn
}

function Get-NewtonDomainDnsName {
    # The DNS name of the domain: the DC= parts of the domain DN joined by
    # dots.  The domainDNS head of a real DC has no dNSDomainName (measured
    # on WINDC1 on 2026-11-13).  Any other part, or an empty label, gives ''.
    param($Adapter, [string]$DomainDn)
    if ($DomainDn -eq '') { return '' }
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($part in $DomainDn.Split(',')) {
        if ($part -notmatch '\A\s*[Dd][Cc]=([A-Za-z0-9-]+)\s*\z') { return '' }
        [void]$labels.Add($Matches[1].ToLowerInvariant())
    }
    if ($labels.Count -eq 0) { return '' }
    return ($labels -join '.')
}

function Get-NewtonDomainSid {
    param($Adapter, [string]$DomainDn)
    $head = Get-NewtonDomainHead $Adapter $DomainDn
    if ($null -eq $head) { return '' }
    return (Get-NewtonSid $head)
}

function Test-NewtonIsPdc {
    # Both values are NTDS Settings DNs on a real DC.
    param($Adapter, [string]$DomainDn)
    $root = Get-NewtonRootDse $Adapter
    if ($null -eq $root) { return $false }
    $serviceName = Get-NewtonAttrString $root 'dsServiceName' 0
    if (($null -eq $serviceName) -or ($serviceName -eq '')) { return $false }
    $head = Get-NewtonDomainHead $Adapter $DomainDn
    if ($null -eq $head) { return $false }
    $owner = Get-NewtonAttrString $head 'fSMORoleOwner' 0
    if (($null -eq $owner) -or ($owner -eq '')) { return $false }
    return ($serviceName -ieq $owner)
}

# ---------------------------------------------------------------------------
# the privileged objects (SPEC section 5)
# ---------------------------------------------------------------------------

function Test-NewtonPrivilegedSid {
    # A SID of a privileged group: one of the RIDs of the table, under the SID
    # of any domain, or one of the BUILTIN groups.
    param([string]$Sid)
    if (($null -eq $Sid) -or ($Sid -eq '')) { return $false }
    if ($script:PrivilegedBuiltin -contains $Sid) { return $true }
    $parts = $Sid.Split('-')
    if ($parts.Count -ne 8) { return $false }
    if (($parts[0] -cne 'S') -or ($parts[1] -cne '1') -or ($parts[2] -cne '5') -or ($parts[3] -cne '21')) {
        return $false
    }
    $rid = 0
    if (-not [int]::TryParse($parts[7], [ref]$rid)) { return $false }
    return ($script:PrivilegedRids -contains $rid)
}

function Test-NewtonPrivilegedEntry {
    # One entry is privileged when its own SID is one of the privileged ones,
    # when its adminCount is 1, or when it is nested in a privileged group.
    # The walk fails closed: the depth cap and a group that cannot be read
    # count as privileged.
    param($Adapter, $Entry, [string]$DomainSid, [hashtable]$Visited, [int]$Depth)
    if ($null -eq $Entry) { return $false }
    $sid = Get-NewtonSid $Entry
    if (Test-NewtonPrivilegedSid $sid) { return $true }
    $adminCount = Get-NewtonAttrInt $Entry 'adminCount'
    if (($null -ne $adminCount) -and ($adminCount -eq 1)) { return $true }
    if ($Depth -ge $script:PrivilegeDepthCap) { return $true }
    foreach ($dn in (Get-NewtonAttrStrings $Entry 'memberOf')) {
        if ($dn -eq '') { continue }
        if ($Visited.ContainsKey($dn)) { continue }
        $Visited[$dn] = $true
        $group = Find-NewtonObjectByDn $Adapter $dn
        if ($null -eq $group) { return $true }
        if (Test-NewtonPrivilegedEntry $Adapter $group $DomainSid $Visited ($Depth + 1)) { return $true }
    }
    return $false
}

function Test-NewtonNestedPrivileged {
    # The object is nested in a privileged group.
    param($Adapter, $Entry, [string]$DomainSid)
    $visited = @{}
    return (Test-NewtonPrivilegedEntry $Adapter $Entry $DomainSid $visited 0)
}

function Test-NewtonPrimaryGroupPrivileged {
    # The primary group of the object is a privileged one.
    param($Adapter, $Entry, [string]$DomainSid)
    $primary = Get-NewtonAttrInt $Entry 'primaryGroupID'
    if ($null -eq $primary) { return $false }
    if ($primary -le 0) { return $false }
    $sid = $DomainSid + '-' + $primary.ToString()
    if (Test-NewtonPrivilegedSid $sid) { return $true }
    $filter = ConvertTo-NewtonSidFilter $sid
    if ($null -eq $filter) { return $false }
    $domainDn = Get-NewtonDomainDn $Adapter
    if ($domainDn -eq '') { return $true }
    $entries = Search-Newton $Adapter $domainDn $filter 'sub' $script:ObjectReadAttributes
    foreach ($group in $entries) {
        if (Test-NewtonNestedPrivileged $Adapter $group $DomainSid) { return $true }
    }
    return $false
}

function Test-NewtonWriteAccountPrivileged {
    # The write account is never in a privileged group (SPEC section 5).
    param($Adapter, [string]$DomainDn)
    $sam = Get-NewtonWriteAccountSam
    if ($sam -eq '') { return $true }
    $account = Find-NewtonObjectBySam $Adapter $sam $DomainDn
    if ($null -eq $account) { return $true }
    $entries = Search-Newton $Adapter ([string]$account['dn']) '(objectClass=*)' 'base' ([string[]]@('tokenGroups'))
    if ($entries.Count -ne 1) { return $true }
    $rawGroups = Get-NewtonAttr $entries[0] 'tokenGroups'
    if ($null -eq $rawGroups) { return $true }
    $groups = New-Object System.Collections.ArrayList
    if ($rawGroups -is [byte[]]) {
        [void]$groups.Add($rawGroups)
    } else {
        foreach ($value in @($rawGroups)) {
            if ($value -isnot [byte[]]) { return $true }
            [void]$groups.Add($value)
        }
    }
    if ($groups.Count -eq 0) { return $true }
    foreach ($bytes in $groups) {
        $sid = ConvertFrom-NewtonSidBytes $bytes
        if (($sid -eq '') -or ($sid -cnotmatch '\AS-1-[0-9]+(?:-[0-9]+)+\z')) { return $true }
        if (Test-NewtonPrivilegedSid $sid) { return $true }
    }
    return $false
}

function Test-NewtonWriteAccountTarget {
    # The resolved target and member may never be the account this helper runs as.
    param($Adapter, $Resolved)
    $sam = Get-NewtonWriteAccountSam
    if ($sam -eq '') { return $false }
    $account = Find-NewtonObjectBySam $Adapter $sam $Resolved['domain_dn']
    if ($null -eq $account) { return $false }
    $writeSid = Get-NewtonSid $account
    if ($writeSid -eq '') { return $true }
    $ids = $Resolved['ids']
    foreach ($name in @('sid', 'group_sid', 'member_sid')) {
        if (-not $ids.ContainsKey($name)) { continue }
        if ([string]$ids[$name] -ieq $writeSid) { return $true }
    }
    return $false
}

function Test-NewtonProtectedWriteTarget {
    # RID 502, every krbtgt name and every inter-domain trust account are denied.
    param($Resolved)
    $ids = $Resolved['ids']
    foreach ($prefix in @('', 'group_', 'member_')) {
        $samName = $prefix + 'sam'
        if ($ids.ContainsKey($samName)) {
            $sam = ([string]$ids[$samName]).ToLowerInvariant()
            if (($sam -eq $script:KrbtgtSam) -or $sam.StartsWith($script:RodcKrbtgtPrefix)) {
                return $true
            }
        }
        $sidName = $prefix + 'sid'
        if ($ids.ContainsKey($sidName)) {
            $rid = Get-NewtonRid $ids[$sidName]
            if (($null -ne $rid) -and ($rid -eq $script:KrbtgtRid)) { return $true }
        }
    }
    foreach ($name in @('object', 'group', 'member')) {
        if (-not $Resolved.ContainsKey($name)) { continue }
        $control = Get-NewtonAttrInt $Resolved[$name] 'userAccountControl'
        if (($null -ne $control) -and (($control -band $script:InterdomainTrustAccount) -ne 0)) {
            return $true
        }
    }
    return $false
}

function Get-NewtonWriteAccountSam {
    # The account the helper writes as: the session of the sshd ForceCommand.
    if ($script:WriteAccountSam -ne '') { return $script:WriteAccountSam }
    $name = ''
    try {
        $name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch {
        $name = ''
    }
    if ($name -ne '') {
        $index = $name.LastIndexOf('\')
        if ($index -ge 0) { $name = $name.Substring($index + 1) }
    }
    if ($name -eq '') { $name = 'newton-ops' }
    return $name
}

function Test-NewtonPrivileged {
    # Every object of the target: is one of them privileged?
    param($Adapter, $Entries, [string]$DomainSid)
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        if (Test-NewtonNestedPrivileged $Adapter $entry $DomainSid) { return $true }
        if (Test-NewtonPrimaryGroupPrivileged $Adapter $entry $DomainSid) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# the target of a request
# ---------------------------------------------------------------------------

function Get-NewtonTarget {
    # The objects of the target of a request, with their ids and their facts.
    # $null when the target is not there.
    param($Adapter, [hashtable]$Request)
    $verb = [string]$Request['verb']
    $target = $Request['target']
    $domainDn = Get-NewtonDomainDn $Adapter
    $domainSid = Get-NewtonDomainSid $Adapter $domainDn

    if ($verb -eq 'member-add' -or $verb -eq 'member-remove') {
        $group = Resolve-NewtonOne $Adapter $target 'group_'
        if ($null -eq $group) { return $null }
        $member = Resolve-NewtonOne $Adapter $target 'member_'
        if ($null -eq $member) { return $null }
        $ids = @{
            group_guid = (Get-NewtonGuid $group)
            group_sid = (Get-NewtonSid $group)
            group_sam = (ConvertTo-NewtonLowerSam (Get-NewtonAttrString $group 'sAMAccountName' 0))
            member_guid = (Get-NewtonGuid $member)
            member_sid = (Get-NewtonSid $member)
            member_sam = (ConvertTo-NewtonLowerSam (Get-NewtonAttrString $member 'sAMAccountName' 0))
        }
        $live = @{ member = 'absent' }
        if (Test-NewtonMemberPresent $Adapter ([string]$group['dn']) ([string]$member['dn'])) {
            $live['member'] = 'present'
        }
        $facts = @{
            group = (Get-NewtonFacts $Adapter $group $domainSid)
            member = (Get-NewtonFacts $Adapter $member $domainSid)
        }
        return @{ ids = $ids; live = $live; facts = $facts; group = $group; member = $member; domain_dn = $domainDn; domain_sid = $domainSid }
    }

    if ($verb -eq 'user-create') {
        $parent = Find-NewtonObjectByGuid $Adapter ([string]$target['parent_guid'])
        if ($null -eq $parent) { return $null }
        $ids = @{
            parent_guid = (Get-NewtonGuid $parent)
            sam = (ConvertTo-NewtonLowerSam ([string]$target['sam']))
        }
        $live = @{ object = 'absent' }
        $existing = Find-NewtonObjectBySam $Adapter ([string]$target['sam'])
        if ($null -ne $existing) { $live['object'] = 'present' }
        if ($live['object'] -eq 'absent') {
            # the user principal name of the new user must be free too
            $dnsName = Get-NewtonDomainDnsName $Adapter $domainDn
            if ($dnsName -eq '') { Throw-NewtonRefusal 'error' 'the DNS name of the domain is not known' }
            $upn = [string]$target['sam'] + '@' + $dnsName
            $filter = '(userPrincipalName=' + (ConvertTo-NewtonFilterText $upn) + ')'
            $entries = Search-Newton $Adapter $domainDn $filter 'sub' ([string[]]@('objectGUID'))
            if ($entries.Count -gt 0) { $live['object'] = 'present' }
        }
        $facts = @{ target = (Get-NewtonFacts $Adapter $parent $domainSid) }
        return @{ ids = $ids; live = $live; facts = $facts; parent = $parent; domain_dn = $domainDn; domain_sid = $domainSid }
    }

    $object = Resolve-NewtonOne $Adapter $target ''
    if ($null -eq $object) { return $null }
    if ($verb -eq 'maq') {
        $ids = @{ guid = (Get-NewtonGuid $object) }
        $live = @{ maq = 0 }
        $quota = Get-NewtonAttrInt $object 'ms-DS-MachineAccountQuota'
        if ($null -ne $quota) { $live['maq'] = $quota }
        $facts = @{ target = (Get-NewtonFacts $Adapter $object $domainSid) }
        return @{ ids = $ids; live = $live; facts = $facts; object = $object; domain_dn = $domainDn; domain_sid = $domainSid }
    }
    $ids = @{
        guid = (Get-NewtonGuid $object)
        sid = (Get-NewtonSid $object)
        sam = (ConvertTo-NewtonLowerSam (Get-NewtonAttrString $object 'sAMAccountName' 0))
    }
    $facts = @{ target = (Get-NewtonFacts $Adapter $object $domainSid) }
    return @{
        ids = $ids
        live = (Get-NewtonLive $Adapter $verb $object)
        facts = $facts
        object = $object
        domain_dn = $domainDn
        domain_sid = $domainSid
    }
}

function Resolve-NewtonOne {
    # The object of a target or of a group or a member: by guid when it has
    # one, else by name.  The sid and the sam must agree.
    param($Adapter, $Target, [string]$Prefix)
    $guid = $null
    $sid = $null
    $sam = $null
    foreach ($name in $Target.Keys) {
        $key = ([string]$name)
        if ($key -ceq ($Prefix + 'guid')) { $guid = [string]$Target[$name] }
        if ($key -ceq ($Prefix + 'sid')) { $sid = [string]$Target[$name] }
        if ($key -ceq ($Prefix + 'sam')) { $sam = [string]$Target[$name] }
    }
    $object = $null
    if ($null -ne $guid) {
        $object = Find-NewtonObjectByGuid $Adapter $guid
        if ($null -eq $object) { return $null }
        if ($null -ne $sid) {
            $live = Get-NewtonSid $object
            if ($live -ine $sid) { return $null }
        }
        if ($null -ne $sam) {
            $live = Get-NewtonAttrString $object 'sAMAccountName' 0
            if ($null -eq $live) { $live = '' }
            if ($live -ine $sam) { return $null }
        }
        return $object
    }
    if ($null -eq $sam) { return $null }
    return (Find-NewtonObjectBySam $Adapter $sam)
}

function Get-NewtonFacts {
    # The facts of one object (SPEC section 6).
    param($Adapter, $Entry, [string]$DomainSid)
    $classes = @()
    foreach ($value in (Get-NewtonAttrStrings $Entry 'objectClass')) { $classes += $value }
    $adminCount = 0
    $count = Get-NewtonAttrInt $Entry 'adminCount'
    if ($null -ne $count) { $adminCount = $count }
    $uac = Get-NewtonAttrInt $Entry 'userAccountControl'
    $dcAccount = $false
    if ($null -ne $uac) {
        foreach ($bit in $script:DcAccountBits) {
            if (($uac -band $bit) -ne 0) { $dcAccount = $true; break }
        }
    }
    $privileged = $false
    if (Test-NewtonNestedPrivileged $Adapter $Entry $DomainSid) { $privileged = $true }
    if (-not $privileged) {
        if (Test-NewtonPrimaryGroupPrivileged $Adapter $Entry $DomainSid) { $privileged = $true }
    }
    return [ordered]@{
        admin_count = $adminCount
        dc_account = $dcAccount
        privileged = $privileged
        object_class = $classes
        pdc = (Test-NewtonIsPdc $Adapter (Get-NewtonDomainDn $Adapter))
    }
}

function Get-NewtonLive {
    # The live values of one object, in the shape of the verb.
    param($Adapter, [string]$Verb, $Object)
    if ($Verb -eq 'uac-clear' -or $Verb -eq 'disable' -or $Verb -eq 'enable') {
        $uac = 0
        $value = Get-NewtonAttrInt $Object 'userAccountControl'
        if ($null -ne $value) { $uac = $value }
        return @{ uac = $uac }
    }
    if ($Verb -eq 'enc-types') {
        $value = Get-NewtonAttrInt $Object 'msDS-SupportedEncryptionTypes'
        if ($null -eq $value) { return @{ etypes = 'absent' } }
        return @{ etypes = $value }
    }
    if ($Verb -eq 'unlock') {
        $lockout = 0
        $value = Get-NewtonAttrInt $Object 'lockoutTime'
        if ($null -ne $value) { $lockout = $value }
        return @{ lockout = $lockout }
    }
    if ($Verb -eq 'maq') {
        $quota = 0
        $value = Get-NewtonAttrInt $Object 'ms-DS-MachineAccountQuota'
        if ($null -ne $value) { $quota = $value }
        return @{ maq = $quota }
    }
    if ($Verb -eq 'move') {
        $parentDn = Get-NewtonParentDn $Object
        if ($parentDn -eq '') { return @{ parent = '' } }
        $parent = Find-NewtonObjectByDn $Adapter $parentDn
        if ($null -eq $parent) { return @{ parent = '' } }
        return @{ parent = (Get-NewtonGuid $parent) }
    }
    Throw-NewtonRefusal 'error' 'the verb has no live values'
}

function Test-NewtonImageEqual {
    # Two images of the same shape are equal when every value is.
    param($Left, $Right)
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    foreach ($key in $Left.Keys) {
        if (-not $Right.ContainsKey($key)) { return $false }
        $first = $Left[$key]
        $second = $Right[$key]
        if (($first -is [string]) -or ($second -is [string])) {
            if ([string]$first -cne [string]$second) { return $false }
            continue
        }
        if (-not (Test-NewtonIntEqual $first $second)) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------
# the writes
# ---------------------------------------------------------------------------

function Get-NewtonAttributeOfVerb {
    # The LDAP attribute the verb writes.
    param([string]$Verb)
    if ($Verb -eq 'uac-clear' -or $Verb -eq 'disable' -or $Verb -eq 'enable') { return 'userAccountControl' }
    if ($Verb -eq 'enc-types') { return 'msDS-SupportedEncryptionTypes' }
    if ($Verb -eq 'unlock') { return 'lockoutTime' }
    if ($Verb -eq 'maq') { return 'ms-DS-MachineAccountQuota' }
    return 'member'
}

function Get-NewtonBeforeValues {
    # The LDAP values of the before-image.
    param([hashtable]$Request, $Resolved)
    $verb = [string]$Request['verb']
    $before = $Request['before']
    if ($verb -eq 'member-add') { return @() }
    if ($verb -eq 'member-remove') {
        return @([string]$Resolved['member']['dn'])
    }
    if ($verb -eq 'move') { return @() }
    if ($verb -eq 'enc-types') {
        if ($before['etypes'] -eq 'absent') { return @() }
        return @([string]$before['etypes'])
    }
    $key = ($script:ValueKinds[$verb].Keys | Select-Object -First 1)
    return @([string]$before[$key])
}

function Get-NewtonAfterValues {
    # The LDAP values of the after-image.
    param([hashtable]$Request, $Resolved)
    $verb = [string]$Request['verb']
    $after = $Request['after']
    if ($verb -eq 'member-add') {
        return @([string]$Resolved['member']['dn'])
    }
    if ($verb -eq 'member-remove') { return @() }
    if ($verb -eq 'move') { return @() }
    if ($verb -eq 'enc-types') {
        if ($after['etypes'] -eq 'absent') { return @() }
        return @([string]$after['etypes'])
    }
    $key = ($script:ValueKinds[$verb].Keys | Select-Object -First 1)
    return @([string]$after[$key])
}

function Get-NewtonMoveDn {
    # The DN of the target of a move.
    param($Resolved)
    return [string]$Resolved['object']['dn']
}

function Get-NewtonTargetDn {
    # The DN the verb writes to.
    param([hashtable]$Request, $Resolved)
    $verb = [string]$Request['verb']
    if ($verb -eq 'member-add' -or $verb -eq 'member-remove') {
        return [string]$Resolved['group']['dn']
    }
    if ($verb -eq 'user-create') {
        return ('CN=' + [string]$Request['target']['sam'] + ',' + [string]$Resolved['parent']['dn'])
    }
    return [string]$Resolved['object']['dn']
}

function ConvertTo-NewtonPasswordBytes {
    # The bytes of the unicodePwd of a user-create: the UTF-16LE of the
    # quoted password.  The password is never handed to a cmdlet as plain
    # text, and the bytes are cleared by the caller.
    param([string]$Secret)
    $secure = New-Object System.Security.SecureString
    foreach ($character in $Secret.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    $pointer = [System.IntPtr]::Zero
    $bytes = $null
    $quoted = $null
    try {
        $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure)
        $bytes = New-Object byte[] ($secure.Length * 2)
        [System.Runtime.InteropServices.Marshal]::Copy($pointer, $bytes, 0, $bytes.Length)
    } finally {
        if ($pointer -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer)
        }
        $secure.Dispose()
    }
    $quoted = New-Object byte[] ($bytes.Length + 4)
    $quoted[0] = 0x22
    $quoted[1] = 0x00
    [System.Array]::Copy($bytes, 0, $quoted, 2, $bytes.Length)
    $quoted[$quoted.Length - 2] = 0x22
    $quoted[$quoted.Length - 1] = 0x00
    [System.Array]::Clear($bytes, 0, $bytes.Length)
    return ,$quoted
}

function Invoke-NewtonWrite {
    # The write of the after-image: one modify, one add or one rename.
    param([hashtable]$Request, $Resolved, $Adapter)
    $verb = [string]$Request['verb']
    if ($verb -eq 'move') {
        # a move is a rename of the object: the directory refuses a modify
        # of distinguishedName with 53 (measured on 2026-11-09).
        $newParent = $Resolved['new_parent']
        if ($null -eq $newParent) { Throw-NewtonRefusal 'error' 'the new parent is not there' }
        $Adapter.ModifyDN(
            (Get-NewtonMoveDn $Resolved),
            [string]$newParent['dn'],
            (Get-NewtonRdn $Resolved['object'])
        )
        return
    }
    if ($verb -eq 'user-create') {
        $sam = [string]$Request['target']['sam']
        $domainDns = Get-NewtonDomainDnsName $Adapter $Resolved['domain_dn']
        if ($domainDns -eq '') { Throw-NewtonRefusal 'error' 'the DNS name of the domain is not known' }
        $attributes = @{
            'cn' = @($sam)
            'sAMAccountName' = @($sam)
            'userPrincipalName' = @($sam + '@' + $domainDns)
            'userAccountControl' = @('514')
            'objectClass' = @('top', 'person', 'organizationalPerson', 'user')
        }
        if ($Request.ContainsKey('secret')) {
            $password = ConvertTo-NewtonPasswordBytes ([string]$Request['secret'])
            try {
                $attributes['unicodePwd'] = $password
                $Adapter.Add((Get-NewtonTargetDn $Request $Resolved), $attributes)
            } finally {
                [System.Array]::Clear($password, 0, $password.Length)
            }
            return
        }
        $Adapter.Add((Get-NewtonTargetDn $Request $Resolved), $attributes)
        return
    }
    $attribute = Get-NewtonAttributeOfVerb $verb
    $oldValues = Get-NewtonBeforeValues $Request $Resolved
    $newValues = Get-NewtonAfterValues $Request $Resolved
    $Adapter.Modify((Get-NewtonTargetDn $Request $Resolved), $attribute, $oldValues, $newValues)
}

function Invoke-NewtonUndoWrite {
    # The undo of one write: the inverse, in one modify, one add or one
    # rename.
    param([hashtable]$Request, $Resolved, $Adapter, [ref]$Conflicts, [ref]$Failed)
    $verb = [string]$Request['verb']
    $dn = Get-NewtonTargetDn $Request $Resolved
    try {
        if ($verb -eq 'move') {
            # the undo renames the object back, but only when it still sits
            # in the parent the apply put it in.
            $object = $Resolved['object']
            $newParent = $Resolved['new_parent']
            $oldParent = $Resolved['old_parent']
            if (($null -eq $object) -or ($null -eq $newParent) -or ($null -eq $oldParent)) {
                $Conflicts.Value += $dn
                return
            }
            $current = Get-NewtonParentDn $object
            if ($current -ine [string]$newParent['dn']) {
                $Conflicts.Value += $dn
                return
            }
            $Adapter.ModifyDN(
                [string]$object['dn'],
                [string]$oldParent['dn'],
                (Get-NewtonRdn $object)
            )
            return
        }
        if ($verb -eq 'user-create') {
            $created = $Resolved['created_guid']
            if ([string]::IsNullOrEmpty([string]$created)) {
                $Conflicts.Value += [string]$Resolved['object_guid']
                return
            }
            $object = Find-NewtonCreatedObject $Adapter ([string]$created) ([string]$Resolved['domain_dn'])
            if ($null -eq $object) {
                $Conflicts.Value += [string]$created
                return
            }
            $uac = Get-NewtonAttrInt $object 'userAccountControl'
            if (($null -eq $uac) -or (($uac -band $script:AccountDisable) -eq 0)) {
                $Conflicts.Value += [string]$created
                return
            }
            $usn = Get-NewtonAttrInt $object 'uSNChanged'
            $recorded = $Resolved['created_usn']
            if (($null -eq $usn) -or ($null -eq $recorded) -or ($usn -ne $recorded)) {
                $Conflicts.Value += [string]$created
                return
            }
            if ((Get-NewtonAttrStrings $object 'member').Count -gt 0) {
                $Conflicts.Value += [string]$created
                return
            }
            if ((Get-NewtonAttrStrings $object 'memberOf').Count -gt 0) {
                $Conflicts.Value += [string]$created
                return
            }
            $Adapter.Delete([string]$object['dn'])
            return
        }
        $attribute = Get-NewtonAttributeOfVerb $verb
        $oldValues = Get-NewtonAfterValues $Request $Resolved
        $newValues = Get-NewtonBeforeValues $Request $Resolved
        $Adapter.Modify($dn, $attribute, $oldValues, $newValues)
    } catch {
        $code = Get-NewtonLdapCode $_
        if ($code -eq 'conflict') {
            $Conflicts.Value += $dn
            return
        }
        $Failed.Value = $true
    }
}

# ---------------------------------------------------------------------------
# the transaction store
# ---------------------------------------------------------------------------

function ConvertTo-NewtonStoredValue {
    # The value of a request as it is kept in the record: an integer that
    # fits in 64 bits stays an integer, a bigger one keeps its text.
    param($Value)
    if ($Value -is [int64] -or $Value -is [int32] -or $Value -is [int16] -or $Value -is [byte]) {
        return [int64]$Value
    }
    if ($Value -is [hashtable]) {
        $stored = @{}
        foreach ($key in $Value.Keys) { $stored[$key] = (ConvertTo-NewtonStoredValue $Value[$key]) }
        return $stored
    }
    return $Value
}

function ConvertTo-NewtonRequestShape {
    # A request that was read back from a record: the shape the helper uses.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $result = @{}
        foreach ($property in $Value.PSObject.Properties) {
            $result[$property.Name] = (ConvertTo-NewtonRequestShape $property.Value)
        }
        return $result
    }
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        $list = @()
        foreach ($item in $Value) { $list += (ConvertTo-NewtonRequestShape $item) }
        return ,$list
    }
    return $Value
}

function New-NewtonRecord {
    param([hashtable]$Request, [int64]$UndoAt)
    $stored = @{}
    foreach ($key in $Request.Keys) {
        $name = [string]$key
        if ($name -eq 'secret') { continue }
        if ($name -eq 'token') { continue }
        $stored[$name] = (ConvertTo-NewtonStoredValue $Request[$key])
    }
    return [ordered]@{
        v = 1
        txid = [string]$Request['txid']
        request = $stored
        created = $null
        state = 'armed'
        undo_at = $UndoAt
        restored = $false
        conflicts = @()
    }
}

function Get-NewtonRecordFileInfo {
    # The record name is either the append-only '<txid>.<n>.json' form or
    # the legacy '<txid>.json' form, which is generation zero.  A leftover
    # '*.new' file is not a record and never reserves a transaction id.
    param($File)
    $name = [string]$File.Name
    if ($name -cmatch '\A([0-9a-f]{32})\.([0-9]+)\.json\z') {
        $generation = [int64]0
        if (-not [int64]::TryParse($Matches[2], [ref]$generation)) { return $null }
        return @{
            txid = [string]$Matches[1]
            generation = $generation
            legacy = $false
            path = [string]$File.FullName
        }
    }
    if ($name -cmatch '\A([0-9a-f]{32})\.json\z') {
        return @{
            txid = [string]$Matches[1]
            generation = [int64]0
            legacy = $true
            path = [string]$File.FullName
        }
    }
    return $null
}

function Get-NewtonRecordFileInfos {
    # Every file whose name is a transaction record.  Invalid JSON is still
    # a record for replay detection, although it cannot be used as state.
    $directory = Get-NewtonTxPath
    $infos = @()
    if (-not (Test-Path -LiteralPath $directory)) { return ,$infos }
    $files = @()
    try {
        $files = @(Get-ChildItem -LiteralPath $directory -File -ErrorAction SilentlyContinue)
    } catch {
        return ,$infos
    }
    foreach ($file in $files) {
        $info = Get-NewtonRecordFileInfo $file
        if ($null -ne $info) { $infos += ,$info }
    }
    return ,$infos
}

function Get-NewtonRecordInfo {
    # The current record of one transaction is its highest generation.  A
    # numbered generation wins a tie with the legacy generation zero.
    param([string]$Txid)
    $best = $null
    foreach ($info in (Get-NewtonRecordFileInfos)) {
        if ([string]$info['txid'] -cne $Txid) { continue }
        if (($null -eq $best) -or
            ([int64]$info['generation'] -gt [int64]$best['generation']) -or
            (([int64]$info['generation'] -eq [int64]$best['generation']) -and
             (-not [bool]$info['legacy']) -and [bool]$best['legacy'])) {
            $best = $info
        }
    }
    return $best
}

function Get-NewtonRecordGenerationPath {
    param([string]$Txid, [int64]$Generation)
    return (Join-Path (Get-NewtonTxPath) ($Txid + '.' + [string]$Generation + '.json'))
}

function New-NewtonRecordExclusive {
    # Every record is a new file.  CreateNew is the append-only store's
    # refusal boundary: a collision never overwrites the other writer.
    #
    # The bytes of the record are on the disk before the write they
    # guard: Flush($true) asks for the flush of the file itself and not
    # only of the buffer of the process, and a record that is in the
    # buffer of the process is a record that a power cut loses.
    param([string]$Path, $Record)
    $json = $Record | ConvertTo-Json -Depth 12 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $stream = Open-NewtonFile -Path $Path -Mode 'CreateNew' -Access 'Write' -Share 'None'
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Close()
    }
}

function Add-NewtonRecord {
    # Append one generation after the current record.  The transaction-store
    # lock makes a collision impossible during an ordinary run; if CreateNew
    # nevertheless finds the path, fail closed with error.
    param([string]$Txid, $Record)
    $info = Get-NewtonRecordInfo -Txid $Txid
    $generation = [int64]0
    if ($null -ne $info) {
        if ([int64]$info['generation'] -eq [int64]::MaxValue) {
            Throw-NewtonRefusal 'error' 'the transaction record generation is exhausted'
        }
        $generation = [int64]$info['generation'] + 1
    }
    $path = Get-NewtonRecordGenerationPath -Txid $Txid -Generation $generation
    try {
        New-NewtonRecordExclusive -Path $path -Record $Record
    } catch {
        Throw-NewtonRefusal 'error' 'the append-only transaction record could not be created'
    }
    return $path
}

function Read-NewtonRecord {
    param([string]$Path)
    try {
        $text = Read-NewtonFileText $Path
    } catch {
        return $null
    }
    try {
        return (ConvertFrom-Json -InputObject $text)
    } catch {
        return $null
    }
}

function Set-NewtonRecordState {
    # The state of a record, in a new generation of the store.  The path
    # of the new record is the answer, and $null when the state could
    # not be written: a caller that ignores the answer would tell the
    # owner that a transaction is confirmed while its record says
    # nothing.
    param([string]$Path, [string]$State, $Restored, $Conflicts)
    $seed = Read-NewtonRecord $Path
    if ($null -eq $seed) { return $null }
    $txid = [string]$seed.txid
    $info = Get-NewtonRecordInfo -Txid $txid
    if ($null -eq $info) { return $null }
    $record = Read-NewtonRecord ([string]$info['path'])
    if ($null -eq $record) { return $null }
    $record.state = $State
    if ($null -ne $Restored) { $record.restored = $Restored }
    if ($null -ne $Conflicts) { $record.conflicts = $Conflicts }
    return (Add-NewtonRecord -Txid $txid -Record $record)
}

function Enter-NewtonLock {
    # The lock of the transaction store: it is held for the whole run.
    $path = Join-Path (Get-NewtonTxPath) '.lock'
    $directory = Get-NewtonTxPath
    if (-not (Test-Path -LiteralPath $directory)) {
        try {
            $null = New-Item -ItemType Directory -Path $directory -Force
        } catch {
            return $null
        }
    }
    $deadline = (Get-NewtonUtcNow).AddSeconds($script:LockTimeoutSeconds)
    while ($true) {
        try {
            return (Open-NewtonFile -Path $path -Mode ([System.IO.FileMode]::OpenOrCreate) -Access ([System.IO.FileAccess]::Read) -Share ([System.IO.FileShare]::None))
        } catch {
            $exception = $_.Exception
            while ($null -ne $exception) {
                if ($exception -is [System.UnauthorizedAccessException]) {
                    [Console]::Error.WriteLine($exception.Message)
                    return $null
                }
                $exception = $exception.InnerException
            }
            if (-not (Test-NewtonIOException $_)) { return $null }
            if ((Get-NewtonUtcNow) -gt $deadline) { return $null }
            Start-Sleep -Milliseconds $script:LockRetryMs
        }
    }
}

function Get-NewtonRecords {
    # The current record of every transaction, grouped by txid.  Legacy files
    # are generation zero; leftover *.new files were excluded by the parser.
    $records = @()
    $current = @{}
    foreach ($info in (Get-NewtonRecordFileInfos)) {
        $txid = [string]$info['txid']
        $best = $null
        if ($current.ContainsKey($txid)) { $best = $current[$txid] }
        if (($null -eq $best) -or
            ([int64]$info['generation'] -gt [int64]$best['generation']) -or
            (([int64]$info['generation'] -eq [int64]$best['generation']) -and
             (-not [bool]$info['legacy']) -and [bool]$best['legacy'])) {
            $current[$txid] = $info
        }
    }
    foreach ($txid in @($current.Keys)) {
        $info = $current[$txid]
        $record = Read-NewtonRecord ([string]$info['path'])
        if ($null -eq $record) { continue }
        $records += @{ path = [string]$info['path']; record = $record }
    }
    return ,$records
}

# ---------------------------------------------------------------------------
# the undo task (SPEC section 7 and section 9)
# ---------------------------------------------------------------------------

function New-NewtonSchedulerAdapter {
    # The COM scheduler of the domain controller (SPEC section 9).  The
    # ScheduledTasks cmdlets and schtasks do not work as the write account.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    $adapter = [pscustomobject]@{
        Service = $service
        Log = (New-Object System.Collections.ArrayList)
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name Register -Value {
        param([string]$Name, [string]$StartBoundary, [string]$Arguments)
        [void]$this.Log.Add(('register ' + $Name + ' ' + $StartBoundary + ' ' + $Arguments))
        $definition = $this.Service.NewTask(0)
        $definition.Principal.LogonType = 2
        $definition.Settings.Enabled = $true
        $definition.Settings.StartWhenAvailable = $true
        $action = $definition.Actions.Create(0)
        $action.Path = 'powershell.exe'
        $action.Arguments = $Arguments
        $trigger = $definition.Triggers.Create(1)
        $trigger.Enabled = $true
        $trigger.StartBoundary = $StartBoundary
        $null = $this.Service.GetFolder('\').RegisterTaskDefinition($Name, $definition, 6, $null, $null, 2)
    }
    $adapter | Add-Member -MemberType ScriptMethod -Name Delete -Value {
        param([string]$Name)
        [void]$this.Log.Add(('delete ' + $Name))
        $this.Service.GetFolder('\').DeleteTask($Name, 0)
    }
    return $adapter
}

function Get-NewtonSchedulerAdapter {
    if ($null -ne $script:SchedulerAdapter) { return $script:SchedulerAdapter }
    $script:SchedulerAdapter = New-NewtonSchedulerAdapter
    return $script:SchedulerAdapter
}

function Register-NewtonUndoTask {
    # The one-shot task that runs the undo at the deadline.
    param([string]$Txid, [int64]$UndoAt)
    $scheduler = Get-NewtonSchedulerAdapter
    $name = 'newton-undo-' + $Txid
    $boundary = [DateTimeOffset]::FromUnixTimeSeconds($UndoAt).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Get-NewtonScriptPath) + '" -Undo ' + $Txid
    $scheduler.Register($name, $boundary, $arguments)
}

function Unregister-NewtonUndoTask {
    param([string]$Txid)
    $scheduler = Get-NewtonSchedulerAdapter
    $scheduler.Delete('newton-undo-' + $Txid)
}

# ---------------------------------------------------------------------------
# the modes (SPEC section 6)
# ---------------------------------------------------------------------------

function Invoke-NewtonRead {
    param([hashtable]$Request, $Adapter)
    $resolved = Get-NewtonTarget $Adapter $Request
    if ($null -eq $resolved) { return (New-NewtonResponse 'not_found') }
    $response = New-NewtonResponse 'ok'
    $response['live'] = $resolved['live']
    $response['ids'] = $resolved['ids']
    $response['facts'] = $resolved['facts']
    return $response
}

function Get-NewtonRisk {
    # The level the helper derives itself (SPEC section 4).
    param([string]$Verb, $Facts)
    foreach ($name in $Facts.Keys) {
        $one = $Facts[$name]
        if ($null -eq $one) { continue }
        if ([bool]$one['privileged']) { return 'HIGH' }
        if ([int]$one['admin_count'] -eq 1) { return 'HIGH' }
        if ([bool]$one['dc_account']) { return 'HIGH' }
    }
    if ($Verb -eq 'unlock') { return 'LOW' }
    return 'MED'
}

function Test-NewtonPrivilegedVerb {
    # The rules of section 5 that the verb and the target answer.
    param([hashtable]$Request, $Resolved, $Adapter)
    $verb = [string]$Request['verb']
    $facts = $Resolved['facts']
    if (Test-NewtonWriteAccountTarget $Adapter $Resolved) {
        Throw-NewtonRefusal 'denied' 'the write account is never a target or member'
    }
    if (Test-NewtonProtectedWriteTarget $Resolved) {
        Throw-NewtonRefusal 'denied' 'krbtgt and trust accounts are never written'
    }
    $privileged = $false
    foreach ($name in $facts.Keys) {
        if ([bool]$facts[$name]['privileged']) { $privileged = $true; break }
    }
    if ($privileged) {
        if ($verb -eq 'member-add' -or $verb -eq 'member-remove') {
            Throw-NewtonRefusal 'privileged' 'the group is a privileged group'
        }
        if (($verb -ne 'uac-clear') -and ($verb -ne 'enc-types') -and ($verb -ne 'unlock')) {
            Throw-NewtonRefusal 'privileged' 'the target is privileged'
        }
        if ($verb -eq 'uac-clear') {
            if ($Request['target']['bit'] -eq 524288) {
                Throw-NewtonRefusal 'privileged' 'the trust bit is never cleared on a privileged account'
            }
        }
    }
    foreach ($name in $facts.Keys) {
        if (-not [bool]$facts[$name]['dc_account']) { continue }
        # the rules of section 3 that name a domain controller account
        if ($verb -eq 'disable') {
            Throw-NewtonRefusal 'denied' 'a domain controller account is never disabled'
        }
        if ($verb -eq 'move') {
            Throw-NewtonRefusal 'denied' 'a domain controller account is never moved'
        }
        if (($verb -eq 'uac-clear') -and (Test-NewtonIntEqual $Request['target']['bit'] 524288)) {
            Throw-NewtonRefusal 'denied' 'the trust bit is never cleared on a domain controller account'
        }
    }
    if (($verb -eq 'disable') -or ($verb -eq 'enable')) {
        $classes = @()
        foreach ($name in $facts.Keys) {
            foreach ($value in @($facts[$name]['object_class'])) { $classes += [string]$value }
        }
        $allowed = $false
        foreach ($value in $classes) {
            if (($value -ieq 'user') -or ($value -ieq 'computer')) { $allowed = $true; break }
        }
        if (-not $allowed) {
            Throw-NewtonRefusal 'denied' 'only a user or a computer may be disabled or enabled'
        }
    }
    if ($verb -eq 'maq') {
        $classes = @()
        foreach ($name in $facts.Keys) {
            foreach ($value in @($facts[$name]['object_class'])) { $classes += [string]$value }
        }
        $allowed = $false
        foreach ($value in $classes) {
            if ($value -ieq 'domainDNS') { $allowed = $true; break }
        }
        if (-not $allowed) {
            Throw-NewtonRefusal 'denied' 'the target of a maq is the domain head'
        }
    }
    if (Test-NewtonWriteAccountPrivileged $Adapter $Resolved['domain_dn']) {
        Throw-NewtonRefusal 'privileged' 'the write account is in a privileged group'
    }
}

function Set-NewtonMoveParent {
    # The two parents of a move: the new one comes from the after-image and
    # the old one from the before-image.
    param([hashtable]$Request, $Resolved, $Adapter)
    $newParent = Find-NewtonObjectByGuid $Adapter ([string]$Request['after']['parent'])
    if ($null -eq $newParent) { return $null }
    $Resolved['new_parent'] = $newParent
    $oldParent = $null
    if ($Request.ContainsKey('before')) {
        $oldParent = Find-NewtonObjectByGuid $Adapter ([string]$Request['before']['parent'])
    }
    $Resolved['old_parent'] = $oldParent
    return $newParent
}

function Test-NewtonMoveParent {
    # The rules of a move: the new parent is an OU or a container, and
    # neither the old nor the new parent is the Domain Controllers OU.
    param([hashtable]$Request, $Resolved, $Adapter)
    $newParent = Set-NewtonMoveParent -Request $Request -Resolved $Resolved -Adapter $Adapter
    if ($null -eq $newParent) {
        Throw-NewtonRefusal 'not_found' 'the new parent is not there'
    }
    $classes = @()
    foreach ($value in (Get-NewtonAttrStrings $newParent 'objectClass')) { $classes += $value }
    $allowed = $false
    foreach ($value in $classes) {
        if (($value -ieq 'organizationalUnit') -or ($value -ieq 'container')) { $allowed = $true; break }
    }
    if (-not $allowed) {
        Throw-NewtonRefusal 'denied' 'the new parent is not an organizational unit or a container'
    }
    $domainDn = [string]$Resolved['domain_dn']
    $dcOu = 'OU=Domain Controllers,' + $domainDn
    $oldParent = $Resolved['old_parent']
    if ($null -ne $oldParent) {
        if (Test-NewtonDcOu ([string]$oldParent['dn']) $dcOu) {
            Throw-NewtonRefusal 'denied' 'the old parent is the Domain Controllers OU'
        }
    }
    if (Test-NewtonDcOu ([string]$newParent['dn']) $dcOu) {
        Throw-NewtonRefusal 'denied' 'the new parent is the Domain Controllers OU'
    }
}

function Test-NewtonDcOu {
    param([string]$Dn, [string]$DcOu)
    if (($null -eq $Dn) -or ($Dn -eq '')) { return $false }
    if ($Dn -ieq $DcOu) { return $true }
    return ($Dn.EndsWith(',' + $DcOu, [StringComparison]::OrdinalIgnoreCase))
}

function Invoke-NewtonApply {
    param([hashtable]$Request, $Adapter)
    $txid = [string]$Request['txid']
    $key = Get-NewtonKeyBytes
    if ($null -eq $key) { return (New-NewtonResponse 'unavailable') }
    $expected = Get-NewtonToken -Key $key -Digest (Get-NewtonDigest $Request) -NotBefore $Request['nbf'] -NotAfter $Request['exp']
    if (-not (Test-NewtonConstantTime $expected ([string]$Request['token']))) {
        return (New-NewtonResponse 'bad_token')
    }
    $now = Get-NewtonNow
    $nbf = (ConvertTo-NewtonInt64 $Request['nbf'])
    $exp = (ConvertTo-NewtonInt64 $Request['exp'])
    if (($null -eq $nbf) -or ($null -eq $exp)) {
        return (New-NewtonResponse 'schema')
    }
    if (($now - ($nbf - 60)) -lt 0) { return (New-NewtonResponse 'expired') }
    if ($now -gt $exp) { return (New-NewtonResponse 'expired') }

    $undoAt = $now + [int64]$Request['window']
    $record = New-NewtonRecord -Request $Request -UndoAt $undoAt
    # Replay means any legacy or numbered record already reserves this txid.
    # The check and CreateNew both run inside the transaction-store lock.
    if ($null -ne (Get-NewtonRecordInfo -Txid $txid)) {
        return (New-NewtonResponse 'replay')
    }
    $path = Get-NewtonRecordGenerationPath -Txid $txid -Generation 0
    try {
        New-NewtonRecordExclusive -Path $path -Record $record
    } catch {
        # A CreateNew collision after the replay check means another writer
        # violated the lock.  It is an error, never a replay, and this writer
        # has changed no record.
        return (New-NewtonResponse 'error')
    }

    # the rules of the table of the contract come after the token, the
    # approval window and the replay (SPEC section 4).
    try {
        Test-NewtonVerbRules -Request $Request
    } catch {
        $code = Get-NewtonRefusalCode $_
        $null = Set-NewtonRecordState -Path $path -State 'refused'
        return (New-NewtonResponse $code)
    }

    $writeCompleted = $false
    $resolved = $null
    try {
        $domainDn = Get-NewtonDomainDn $Adapter
        if (-not (Test-NewtonIsPdc $Adapter $domainDn)) {
            $null = Set-NewtonRecordState -Path $path -State 'refused'
            return (New-NewtonResponse 'not_pdc')
        }

        $resolved = Get-NewtonTarget $Adapter $Request
        if ($null -eq $resolved) {
            $null = Set-NewtonRecordState -Path $path -State 'refused'
            return (New-NewtonResponse 'not_found')
        }

        $derived = Get-NewtonRisk ([string]$Request['verb']) $resolved['facts']
        if ($derived -cne [string]$Request['risk']) {
            $null = Set-NewtonRecordState -Path $path -State 'refused'
            return (New-NewtonResponse 'risk_mismatch')
        }

        try {
            Test-NewtonPrivilegedVerb -Request $Request -Resolved $resolved -Adapter $Adapter
            if ([string]$Request['verb'] -eq 'move') {
                Test-NewtonMoveParent -Request $Request -Resolved $resolved -Adapter $Adapter
            }
        } catch {
            $code = Get-NewtonRefusalCode $_
            $null = Set-NewtonRecordState -Path $path -State 'refused'
            if ($code -eq 'not_found') { return (New-NewtonResponse 'not_found') }
            return (New-NewtonResponse $code)
        }

        if (-not (Test-NewtonImageEqual $resolved['live'] $Request['before'])) {
            $null = Set-NewtonRecordState -Path $path -State 'refused'
            $response = New-NewtonResponse 'conflict'
            $response['live'] = $resolved['live']
            return $response
        }

        if ([string]$Request['verb'] -ne 'unlock') {
            try {
                Register-NewtonUndoTask -Txid $txid -UndoAt $undoAt
            } catch {
                $null = Set-NewtonRecordState -Path $path -State 'refused'
                return (New-NewtonResponse 'unavailable')
            }
        }

        try {
            Invoke-NewtonWrite -Request $Request -Resolved $resolved -Adapter $Adapter
        } catch {
            $code = Get-NewtonLdapCode $_
            if (($code -ne 'conflict') -and ([string]$Request['verb'] -ne 'unlock')) {
                # A failure other than a conflict runs the undo at once (SPEC
                # section 6): the server may have applied the write and lost
                # the answer.  The target is read again first.  A target
                # that still shows the before-image was never written, and
                # the record is refused below.  One that shows anything else
                # is undone now, and the record says what the undo restored.
                # A target that cannot be read again leaves the record armed
                # and the undo task registered: the task undoes it at
                # undo_at.
                $landed = $false
                try {
                    $again = Get-NewtonTarget $Adapter $Request
                    if ($null -ne $again) {
                        $landed = -not (Test-NewtonImageEqual $again['live'] $Request['before'])
                    }
                } catch {
                    return (New-NewtonResponse $code)
                }
                if ($landed) {
                    try {
                        $current = Read-NewtonRecord $path
                        if ($null -ne $current) {
                            $null = Invoke-NewtonUndoRecord -Path $path -Record $current -Adapter $Adapter
                            return (New-NewtonResponse $code)
                        }
                    } catch { }
                    # The undo did not run to its end: the record stays
                    # armed and the task undoes it at undo_at.
                    return (New-NewtonResponse $code)
                }
            }
            if ([string]$Request['verb'] -ne 'unlock') {
                try { Unregister-NewtonUndoTask -Txid $txid } catch { }
            }
            $null = Set-NewtonRecordState -Path $path -State 'refused' -Restored $false -Conflicts @()
            return (New-NewtonResponse $code)
        }
        $writeCompleted = $true

        $created = $null
        if ([string]$Request['verb'] -eq 'user-create') {
            $object = Find-NewtonObjectBySam $Adapter ([string]$Request['target']['sam'])
            if ($null -ne $object) {
                $created = @{
                    guid = (Get-NewtonGuid $object)
                    usn_changed = (Get-NewtonAttrInt $object 'uSNChanged')
                }
            }
            # The undo of a user-create needs the GUID and the uSNChanged
            # of the new object: without the two of them it can never
            # delete it.  The object is deleted at once when one of them
            # is missing, or when the record that holds them cannot be
            # written, and the answer is an error.  The helper never
            # answers ok without the two facts in the record.
            $facts = (($null -ne $created) -and
                (-not [string]::IsNullOrEmpty([string]$created['guid'])) -and
                ($null -ne $created['usn_changed']))
            if ($facts) {
                $resolved['created_guid'] = $created['guid']
                $resolved['created_usn'] = $created['usn_changed']
                $currentPath = Get-NewtonRecordPath $txid
                $record = Read-NewtonRecord $currentPath
                if ($null -eq $record) {
                    $facts = $false
                } else {
                    try {
                        $record.created = $created
                        $path = Add-NewtonRecord -Txid $txid -Record $record
                    } catch {
                        $facts = $false
                    }
                }
            }
            if (-not $facts) {
                $createdDn = Get-NewtonTargetDn $Request $resolved
                $restored = $false
                $conflicts = @()
                try {
                    $Adapter.Delete($createdDn)
                    $restored = $true
                } catch {
                    $conflicts = @($createdDn)
                }
                $state = 'undo_failed'
                if ($restored) { $state = 'undone' }
                # The record of the outcome comes before the cancel of
                # the task: the task that fires anyway finds a record
                # that is not armed and does nothing.
                $null = Set-NewtonRecordState -Path $path -State $state -Restored $restored -Conflicts $conflicts
                try { Unregister-NewtonUndoTask -Txid $txid } catch { }
                return (New-NewtonResponse 'error')
            }
        }

        # The first record is already armed.  Only unlock changes that state:
        # it has no undo task and becomes confirmed after the write.
        if ([string]$Request['verb'] -eq 'unlock') {
            $null = Set-NewtonRecordState -Path $path -State 'confirmed'
        }

        $response = New-NewtonResponse 'ok'
        $response['live'] = (Get-NewtonLiveAfter $Request $resolved $Adapter)
        $response['undo_at'] = $undoAt
        if ($null -ne $created) { $response['created'] = $created }
        return $response
    } catch {
        $code = Get-NewtonRefusalCode $_
        if ($writeCompleted) {
            # the write happened: the undo runs now and the record says what
            # it really restored.
            try {
                $current = Read-NewtonRecord $path
                if ($null -ne $current) {
                    $null = Invoke-NewtonUndoRecord -Path $path -Record $current -Adapter $Adapter
                } else {
                    $null = Set-NewtonRecordState -Path $path -State 'undo_failed' -Restored $false -Conflicts @()
                }
            } catch {
                $null = Set-NewtonRecordState -Path $path -State 'undo_failed' -Restored $false -Conflicts @()
            }
        } else {
            if ([string]$Request['verb'] -ne 'unlock') {
                try { Unregister-NewtonUndoTask -Txid $txid } catch { }
            }
            $null = Set-NewtonRecordState -Path $path -State 'refused' -Restored $false -Conflicts @()
        }
        return (New-NewtonResponse $code)
    }
}
function Get-NewtonLiveAfter {
    # The live values after the write: the target is read back (SPEC
    # section 6, step 7).
    param([hashtable]$Request, $Resolved, $Adapter)
    $verb = [string]$Request['verb']
    if ($verb -eq 'member-add' -or $verb -eq 'member-remove') {
        $group = Resolve-NewtonOne $Adapter $Request['target'] 'group_'
        if ($null -eq $group) { return $Resolved['live'] }
        $live = @{ member = 'absent' }
        if (Test-NewtonMemberPresent $Adapter ([string]$group['dn']) ([string]$Resolved['member']['dn'])) {
            $live['member'] = 'present'
        }
        return $live
    }
    if ($verb -eq 'user-create') {
        $existing = Find-NewtonObjectBySam $Adapter ([string]$Request['target']['sam'])
        $live = @{ object = 'absent' }
        if ($null -ne $existing) { $live['object'] = 'present' }
        return $live
    }
    if ($verb -eq 'move') {
        $object = Resolve-NewtonOne $Adapter $Request['target'] ''
        if ($null -eq $object) { return $Resolved['live'] }
        $parentDn = Get-NewtonParentDn $object
        $parent = $null
        if ($parentDn -ne '') { $parent = Find-NewtonObjectByDn $Adapter $parentDn }
        if ($null -eq $parent) { return $Resolved['live'] }
        return @{ parent = (Get-NewtonGuid $parent) }
    }
    $object = Resolve-NewtonOne $Adapter $Request['target'] ''
    if ($null -eq $object) { return $Resolved['live'] }
    return (Get-NewtonLive $Adapter $verb $object)
}

function Invoke-NewtonConfirm {
    # The confirm mode: the confirmation is recorded before the undo is
    # cancelled.  A confirmation that is not recorded leaves the undo
    # armed, and the undo puts the change back: the change that every
    # controller verified is undone, and that is the safe answer.
    #
    # The cancel of the task comes after the record, and a cancel that
    # fails does not change the answer: the record says confirmed, and
    # the task that fires anyway finds a confirmed record and does
    # nothing.
    param([hashtable]$Request, $Adapter)
    $txid = [string]$Request['txid']
    $path = Get-NewtonRecordPath $txid
    $record = Read-NewtonRecord $path
    if ($null -eq $record) { return (New-NewtonResponse 'not_found') }
    $state = [string]$record.state
    # An unlock arms no undo and is confirmed at the apply: the confirm
    # CORE sends after it re-reads the target and answers ok.  A confirmed
    # record of any other verb, and any record that is neither armed nor
    # confirmed, is a conflict.
    $confirmedUnlock = ($state -eq 'confirmed') -and ([string]$record.request.verb -ceq 'unlock')
    if (($state -ne 'armed') -and (-not $confirmedUnlock)) { return (New-NewtonResponse 'conflict') }
    $stored = ConvertTo-NewtonRequestShape $record.request
    $live = $null
    try {
        $resolved = Get-NewtonTarget $Adapter $stored
        if ($null -eq $resolved) { return (New-NewtonResponse 'conflict') }
        $live = $resolved['live']
    } catch {
        return (New-NewtonResponse 'conflict')
    }
    if (-not (Test-NewtonImageEqual $live $stored['after'])) {
        return (New-NewtonResponse 'conflict')
    }
    if ($confirmedUnlock) { return (New-NewtonResponse 'ok') }
    $written = $null
    try {
        $written = Set-NewtonRecordState -Path $path -State 'confirmed'
    } catch {
        return (New-NewtonResponse 'error')
    }
    if ([string]::IsNullOrEmpty([string]$written)) {
        # The record of the confirmation is not there: the undo stays
        # armed and it puts the change back.
        return (New-NewtonResponse 'error')
    }
    try {
        Unregister-NewtonUndoTask -Txid $txid
    } catch {
        [Console]::Error.WriteLine(
            'the undo task of the transaction was not cancelled; it will find a confirmed record and do nothing')
    }
    return (New-NewtonResponse 'ok')
}

function Invoke-NewtonUndoRecord {
    # The undo of one record.
    param([string]$Path, $Record, $Adapter)
    $stored = ConvertTo-NewtonRequestShape $Record.request
    $conflicts = @()
    $failed = $false
    try {
        $resolved = Get-NewtonTarget $Adapter $stored
    } catch {
        $resolved = $null
    }
    if ($null -eq $resolved) {
        $failed = $true
    } else {
        $created = Get-NewtonField $Record 'created'
        if ($null -ne $created) {
            $resolved['created_guid'] = [string](Get-NewtonField $created 'guid')
            $resolved['created_usn'] = (Get-NewtonField $created 'usn_changed')
        }
        if ([string]$stored['verb'] -eq 'move') {
            $null = Set-NewtonMoveParent -Request $stored -Resolved $resolved -Adapter $Adapter
        }
        Invoke-NewtonUndoWrite -Request $stored -Resolved $resolved -Adapter $Adapter -Conflicts ([ref]$conflicts) -Failed ([ref]$failed)
    }
    $state = 'undone'
    if ($failed -or ($conflicts.Count -gt 0)) { $state = 'undo_failed' }
    $null = Set-NewtonRecordState -Path $Path -State $state -Restored (-not $failed -and ($conflicts.Count -eq 0)) -Conflicts $conflicts
    if ([string]$stored['verb'] -ne 'unlock') {
        try { Unregister-NewtonUndoTask -Txid ([string]$stored['txid']) } catch { }
    }
    return @{ restored = (-not $failed -and ($conflicts.Count -eq 0)); conflicts = $conflicts; state = $state }
}

function Invoke-NewtonAbort {
    param([hashtable]$Request, $Adapter)
    $txid = [string]$Request['txid']
    $path = Get-NewtonRecordPath $txid
    $record = Read-NewtonRecord $path
    if ($null -eq $record) { return (New-NewtonResponse 'not_found') }
    $state = [string]$record.state
    if ($state -ne 'armed') { return (New-NewtonResponse 'conflict') }
    $result = Invoke-NewtonUndoRecord -Path $path -Record $record -Adapter $Adapter
    $response = New-NewtonResponse 'ok'
    $response['restored'] = $result['restored']
    $response['conflicts'] = $result['conflicts']
    return $response
}

function Invoke-NewtonStatus {
    param([hashtable]$Request)
    $txid = [string]$Request['txid']
    $path = Get-NewtonRecordPath $txid
    $record = Read-NewtonRecord $path
    if ($null -eq $record) { return (New-NewtonResponse 'not_found') }
    $response = New-NewtonResponse 'ok'
    $response['state'] = [string]$record.state
    $response['undo_at'] = $record.undo_at
    $response['restored'] = $record.restored
    $response['conflicts'] = @($record.conflicts)
    return $response
}

function Invoke-NewtonSweep {
    # The start-up sweep: every armed record whose deadline has passed is
    # undone.  It never confirms anything.
    param($Adapter)
    $now = Get-NewtonNow
    foreach ($item in (Get-NewtonRecords)) {
        $record = $item['record']
        if ([string]$record.state -ne 'armed') { continue }
        $undoAt = 0
        if (-not [int64]::TryParse([string]$record.undo_at, [ref]$undoAt)) { continue }
        if ($undoAt -gt $now) { continue }
        $null = Invoke-NewtonUndoRecord -Path $item['path'] -Record $record -Adapter $Adapter
    }
}

function Invoke-NewtonWriteMode {
    # The mode of a request, under the lock.
    param([hashtable]$Request)
    $mode = [string]$Request['mode']
    $adapter = Get-NewtonLdapAdapter
    if ($mode -eq 'read') {
        $readLock = Enter-NewtonLock
        if ($null -eq $readLock) { return (New-NewtonResponse 'unavailable') }
        try {
            Invoke-NewtonSweep -Adapter $adapter
        } finally {
            $readLock.Close()
        }
        return (Invoke-NewtonRead -Request $Request -Adapter $adapter)
    }
    $lock = Enter-NewtonLock
    if ($null -eq $lock) { return (New-NewtonResponse 'unavailable') }
    try {
        Invoke-NewtonSweep -Adapter $adapter
        if ($mode -eq 'apply') {
            return (Invoke-NewtonApply -Request $Request -Adapter $adapter)
        }
        if ($mode -eq 'confirm') { return (Invoke-NewtonConfirm -Request $Request -Adapter $adapter) }
        if ($mode -eq 'abort') { return (Invoke-NewtonAbort -Request $Request -Adapter $adapter) }
        return (Invoke-NewtonStatus -Request $Request)
    } finally {
        $lock.Close()
    }
}

function Invoke-NewtonRequest {
    # One request, read on stdin: the whole flow.
    param([string]$Raw)
    try {
        $request = ConvertFrom-NewtonRequest -Raw $Raw
        $device = Get-NewtonDeviceName
        if (($device -eq '') -or ($device -cne [string]$request['device'])) {
            return (New-NewtonResponse 'schema')
        }
        return (ConvertTo-NewtonAnswer (Invoke-NewtonWriteMode -Request $request))
    } catch {
        return (New-NewtonResponse (Get-NewtonRefusalCode $_))
    }
}

# ---------------------------------------------------------------------------
# the undo mode
# ---------------------------------------------------------------------------

function Invoke-NewtonUndoMode {
    # The undo of one txid, run by the undo task.
    param([string]$Txid)
    if (($env:SSH_CONNECTION -ne $null) -or ($env:SSH_CLIENT -ne $null)) {
        return (New-NewtonResponse 'schema')
    }
    if ($Txid -cnotmatch $script:TxidPattern) {
        return (New-NewtonResponse 'schema')
    }
    $lock = Enter-NewtonLock
    if ($null -eq $lock) { return (New-NewtonResponse 'unavailable') }
    try {
        $adapter = Get-NewtonLdapAdapter
        Invoke-NewtonSweep -Adapter $adapter
        $path = Get-NewtonRecordPath $Txid
        $record = Read-NewtonRecord $path
        if ($null -eq $record) { return (New-NewtonResponse 'not_found') }
        $state = [string]$record.state
        if ($state -ne 'armed') {
            $response = New-NewtonResponse 'ok'
            $response['restored'] = $false
            $response['conflicts'] = @()
            return (ConvertTo-NewtonAnswer $response)
        }
        $result = Invoke-NewtonUndoRecord -Path $path -Record $record -Adapter $adapter
        $response = New-NewtonResponse 'ok'
        $response['restored'] = $result['restored']
        $response['conflicts'] = $result['conflicts']
        return (ConvertTo-NewtonAnswer $response)
    } finally {
        $lock.Close()
    }
}

function Read-NewtonStdin {
    # The request on stdin, at most 64 KiB.
    $reader = [Console]::In
    $builder = New-Object System.Text.StringBuilder
    $chunk = New-Object char[] 4096
    $total = 0
    while ($true) {
        $read = $reader.Read($chunk, 0, $chunk.Length)
        if ($read -le 0) { break }
        $total = $total + $read
        [void]$builder.Append($chunk, 0, $read)
        if ($total -gt $script:MaxRequestBytes) { break }
    }
    return $builder.ToString()
}

# ---------------------------------------------------------------------------
# the main body
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $response = $null
    try {
        $install = Test-NewtonInstall
        if ($install -ne '') {
            $response = New-NewtonResponse $install
        } elseif ($args.Count -gt 0) {
            $response = New-NewtonResponse 'schema'
        } elseif (-not [string]::IsNullOrEmpty($Undo)) {
            $response = Invoke-NewtonUndoMode $Undo
        } else {
            $raw = Read-NewtonStdin
            $response = Invoke-NewtonRequest -Raw $raw
        }
    } catch {
        $response = New-NewtonResponse (Get-NewtonRefusalCode $_)
    }
    # the answer of the process is one JSON object, always.
    $response = ConvertTo-NewtonAnswer $response
    $json = $response | ConvertTo-Json -Depth 12 -Compress
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::Out.Write($json + "`n")
    exit 0
}
